"""B-1: family-relative percentiles on the scored output.

The percentile is what the report and the JSON output carry, so the property
that matters is direction: 0.0 must be the MOST anomalous row. Getting it
backwards produces a plausible-looking number on every row and would rank the
report upside down without anything failing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline import anomaly, features
from dfir_triage_pipeline.anomaly import Scored, assign_percentiles


def _scored(*values: float) -> list[Scored]:
    return [Scored(event=f"e{i}", score=v, is_outlier=False) for i, v in enumerate(values)]


class TestAssignPercentiles:
    def test_lowest_score_is_most_anomalous(self) -> None:
        """Lower decision_function = more anomalous = percentile 0."""
        out = assign_percentiles(_scored(0.3, -0.2, 0.1), "prefetch")
        by_event = {s.event: s.percentile_in_family for s in out}
        assert by_event["e1"] == 0.0            # -0.2, the most anomalous
        assert by_event["e2"] < by_event["e0"]  # 0.1 before 0.3

    def test_percentiles_span_the_range(self) -> None:
        out = assign_percentiles(_scored(*[float(i) for i in range(10)]), "prefetch")
        pcts = sorted(s.percentile_in_family for s in out)
        assert pcts == [0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0]

    def test_ties_share_a_percentile(self) -> None:
        """Isolation Forest cannot isolate identical rows, so ties are common.

        Splitting them would invent an ordering the model did not produce.
        """
        out = assign_percentiles(_scored(-0.1, -0.1, -0.1, 0.5), "evtx.powershell")
        tied = [s.percentile_in_family for s in out[:3]]
        assert tied == [0.0, 0.0, 0.0]
        assert out[3].percentile_in_family == 75.0

    def test_family_is_recorded(self) -> None:
        out = assign_percentiles(_scored(0.1, 0.2), "amcache")
        assert {s.family for s in out} == {"amcache"}

    def test_empty_is_empty(self) -> None:
        assert assign_percentiles([], "prefetch") == []

    def test_single_row(self) -> None:
        out = assign_percentiles(_scored(0.42), "prefetch")
        assert out[0].percentile_in_family == 0.0

    def test_other_fields_survive(self) -> None:
        """Scored is frozen, so the helper rebuilds it. Nothing may be lost."""
        original = [Scored(event="keep-me", score=-0.3, is_outlier=True)]
        out = assign_percentiles(original, "prefetch")
        assert out[0].event == "keep-me"
        assert out[0].score == -0.3
        assert out[0].is_outlier is True

    def test_input_order_is_preserved(self) -> None:
        """The caller extends a list with these; reordering would misalign
        nothing today but is a trap left for later."""
        out = assign_percentiles(_scored(0.9, 0.1, 0.5), "prefetch")
        assert [s.event for s in out] == ["e0", "e1", "e2"]


EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")

needs_collection = pytest.mark.skipif(
    not (EVIDENCE / "collection_clean_b").is_dir(),
    reason="clean_b collection is required",
)


@pytest.fixture(scope="module")
def clean_b_scored():
    """Fit and score clean_b once; three tests read the same result.

    D-035 is the reason for the emptiness assertions. A fixture that silently
    produced nothing would let every test here pass while proving nothing.
    """
    events = collect_events(EVIDENCE / "collection_clean_b")[0]
    assert events, "fixture produced no events; the tests would pass vacuously"
    rarity = features.build_rarity_index(events)
    scored = anomaly.PerFamilyModel().fit(events, rarity).score(events, rarity)
    assert scored, "no rows scored"
    return scored


@needs_collection
class TestPerFamilyIntegration:
    """The percentile has to arrive through the real scoring path, not only
    through the helper called directly."""

    def test_every_scored_row_carries_a_percentile(self, clean_b_scored) -> None:
        assert all(s.family for s in clean_b_scored), "a scored row carries no family"
        assert all(s.percentile_in_family is not None for s in clean_b_scored)
        assert all(0.0 <= s.percentile_in_family < 100.0 for s in clean_b_scored)

    def test_percentile_is_within_family_not_global(self, clean_b_scored) -> None:
        """Every family must contain a 0.0 -- its own most anomalous row.

        This is the property that makes the number comparable across families.
        A global ranking would produce exactly one 0.0 in the whole result.
        """
        by_family: dict[str, list[float]] = {}
        for s in clean_b_scored:
            by_family.setdefault(s.family, []).append(s.percentile_in_family)

        assert len(by_family) > 1, "only one family scored; the test proves nothing"
        for family, pcts in by_family.items():
            assert min(pcts) == 0.0, f"{family} has no most-anomalous row"

    def test_outliers_rank_ahead_of_the_rest(self, clean_b_scored) -> None:
        """The flag is the score thresholded, so rank and flag must agree."""
        for family in {s.family for s in clean_b_scored}:
            rows = [s for s in clean_b_scored if s.family == family]
            flagged = [s.percentile_in_family for s in rows if s.is_outlier]
            clean = [s.percentile_in_family for s in rows if not s.is_outlier]
            if flagged and clean:
                assert max(flagged) <= min(clean), f"{family}: flag and rank disagree"


class TestModellabilityGuards:
    """Two guards added 2026-09-14 after stress-testing worst cases (D-041).

    Both exist because the layer was reporting numbers it should have refused
    to report: a family with 470 rows and 4 distinct vectors produced
    percentiles that looked like a ranking, and scoring a different host's
    collection flagged half its rows with no indication the run was
    uninterpretable.
    """

    def test_degenerate_family_is_not_fitted(self):
        """Enough rows, no variety. MIN_TRAINING_ROWS measures quantity; this
        measures whether the quantity carries information."""
        from datetime import UTC, datetime, timedelta

        from dfir_triage_pipeline import features
        from dfir_triage_pipeline.model import Event

        base = datetime(2026, 9, 14, tzinfo=UTC)
        # 200 rows, all identical in feature space: same binary, same hour.
        events = [
            Event(
                timestamp=base + timedelta(seconds=i),
                source_artifact="evtx.security",
                event_type="logon_success",
                action="a",
                source_file="f",
                source_locator=f"L{i}",
                timestamp_type="recorded",
                user="u",
                details={"path_basename_canonical": "same.exe"},
            )
            for i in range(200)
        ]
        model = anomaly.PerFamilyModel().fit(events, features.build_rarity_index(events))
        assert "evtx.security" not in model.models
        assert "evtx.security" in model.unscored_families
        assert "distinct feature vectors" in model.unscored_families.reason("evtx.security")

    def test_unscored_families_records_which_reason(self):
        """A bare set could not distinguish 'too few rows' from 'no variety' --
        two different findings with two different fixes."""
        families = anomaly.UnscoredFamilies()
        families.add("a", "below MIN_TRAINING_ROWS", 10)
        families.add("b", "only 4 distinct feature vectors in 470 rows", 470)
        assert "a" in families and "b" in families
        assert families == {"a", "b"}  # set-like, so existing callers are unchanged
        # Worst first: many rows and no variety is the more surprising case.
        assert families.lines()[0].startswith("  b:")

    def test_baseline_warning_is_silent_when_the_rate_is_normal(self):
        assert anomaly.baseline_warning(anomaly.CONTAMINATION) == ""
        assert anomaly.baseline_warning(0.078) == ""

    def test_baseline_warning_fires_on_a_mismatched_collection(self):
        """Measured: fitting on host 2 and scoring host 1 flags 50.3% of rows
        against a 5% setting. Nothing errors, and every row being unusual means
        the ordering among them carries no information."""
        warning = anomaly.baseline_warning(0.503)
        assert "BASELINE MISMATCH" in warning
        assert "different" in warning

    def test_warning_threshold_is_a_multiple_of_contamination(self):
        """Tied to CONTAMINATION rather than hardcoded, so changing one does not
        silently invalidate the other."""
        just_under = anomaly.CONTAMINATION * anomaly.BASELINE_MISMATCH_FACTOR
        assert anomaly.baseline_warning(just_under) == ""
        assert anomaly.baseline_warning(just_under * 1.01) != ""


class TestScorerRegistry:
    """DFIR_ANOMALY_SCORER selects the anomaly algorithm (OD-01 Phase 5).

    Isolation Forest is the default and the fallback; alternatives plug in
    behind the flag through a closed registry. These pin the two properties that
    keep the swap safe: the default path is the exact committed estimator, and
    an unknown name fails loudly instead of silently scoring with the default.
    """

    def test_unset_flag_uses_the_moda_default(self, monkeypatch):
        # Default switched to MODA*-G on 2026-09-22 (user decision). Unset flag
        # now selects moda_g; Isolation Forest is one env var away (below).
        monkeypatch.delenv(anomaly.SCORER_FLAG, raising=False)
        assert anomaly.AnomalyModel(200).scorer_name == "moda_g"
        assert anomaly.DEFAULT_SCORER == "moda_g"

    def test_isolation_forest_is_still_the_exact_committed_estimator(self, monkeypatch):
        # IF stays fully available and byte-exact when selected. The inertness
        # proof (flag=isolation_forest reproduces the committed pipeline) rests
        # on these kwargs, so they are still asserted after the default switch.
        from sklearn.ensemble import IsolationForest

        monkeypatch.setenv(anomaly.SCORER_FLAG, "isolation_forest")
        m = anomaly.AnomalyModel(200)
        assert m.scorer_name == "isolation_forest"
        assert isinstance(m._forest, IsolationForest)
        assert m._forest.n_estimators == 200
        assert m._forest.contamination == anomaly.CONTAMINATION
        assert m._forest.random_state == anomaly.RANDOM_SEED
        assert m._forest.max_samples == 1.0

    def test_unknown_scorer_raises_rather_than_falling_back(self, monkeypatch):
        monkeypatch.setenv(anomaly.SCORER_FLAG, "not_a_scorer")
        with pytest.raises(ValueError, match="unknown DFIR_ANOMALY_SCORER"):
            anomaly.AnomalyModel(200)

    def test_alternatives_are_registered_names(self):
        # Registered so the flag accepts them; their wrappers are lazy-imported
        # only when selected, so this does not require deepod or the MODA
        # artifact to be installed.
        assert "dif" in anomaly._SCORER_REGISTRY
        assert "moda_g" in anomaly._SCORER_REGISTRY

    def test_selecting_dif_without_deepod_fails_clearly(self, monkeypatch):
        # If deepod is absent the error names the fix, not a traceback from
        # inside the wrapper. No-op when deepod IS installed.
        try:
            import deepod  # noqa: F401
        except ImportError:
            monkeypatch.setenv(anomaly.SCORER_FLAG, "dif")
            with pytest.raises(RuntimeError, match="deepod"):
                anomaly.AnomalyModel(200)

    def test_the_default_scorer_puts_an_obvious_outlier_at_the_anomalous_end(self):
        """Sign-convention guard on the DEFAULT scorer (MODA*-G since 2026-09-22):
        lower decision_function = more anomalous. A row with an extreme value
        among a cloud of zeros must score most anomalous. This is stated as a
        scorer property, not an IF detail -- every registered scorer's wrapper
        must satisfy it, and with the flag unset this now exercises MODA."""
        from dfir_triage_pipeline.features import FeatureTable

        names = ("a", "b")
        rows = [(0.0, 0.0)] * 30 + [(9999.0, 9999.0)]
        table = FeatureTable(names=names, rows=rows, events=list(range(len(rows))))
        scored = anomaly.AnomalyModel(50).fit(table).score(table)
        most_anomalous = min(scored, key=lambda s: s.score)
        assert most_anomalous.event == len(rows) - 1


class TestEnsembleAndCategoricalScorers:
    """OD-01 Phase 5 experiments 2 (SDC categorical) and 3 (IF+MODA ensemble).

    Both are registered scorers; both are lazy-imported and removable. These pin
    that they are wired, sign-correct, and -- for the categorical path -- that
    the FeatureTable's categorical attribute is inert on `rows` so the IF path
    stays byte-identical.
    """

    def test_ensemble_is_registered(self):
        assert "ensemble_if_moda" in anomaly._SCORER_REGISTRY

    def test_ensemble_places_an_obvious_outlier_at_the_anomalous_end(self, monkeypatch):
        import numpy as np

        from dfir_triage_pipeline.features import FeatureTable

        np.random.seed(4)
        names = ("a", "b")
        rows = [tuple(np.random.randn(2)) for _ in range(40)] + [(60.0, 60.0)]
        table = FeatureTable(names=names, rows=rows, events=list(range(len(rows))))

        # monkeypatch.setenv RESTORES the prior value on teardown. A bare
        # os.environ.pop here would DELETE the flag, and since the default is now
        # moda_g an unset flag means MODA -- so a raw pop would silently switch
        # every test that runs after this one in the same process to MODA, which
        # is exactly the leak that made the gate hang after the default flip.
        monkeypatch.setenv(anomaly.SCORER_FLAG, "ensemble_if_moda")
        scored = anomaly.AnomalyModel(60).fit(table).score(table)
        assert min(scored, key=lambda s: s.score).event == len(rows) - 1

    def test_categorical_attribute_does_not_touch_rows(self):
        # The MODA SDC path reads FeatureTable.categorical; it must never appear
        # in rows/names, so the IF path and every hash are unchanged.
        from dfir_triage_pipeline.features import FeatureTable

        plain = FeatureTable(names=("a",), rows=[(1.0,)], events=[object()])
        withcat = FeatureTable(
            names=("a",), rows=[(1.0,)], events=[object()],
            categorical={"mime_type": ("application/pdf",)},
        )
        assert plain.rows == withcat.rows
        assert plain.names == withcat.names
        assert plain.categorical == {}

    def test_moda_sdc_ranks_a_rare_category_as_anomalous(self):
        import numpy as np

        from dfir_triage_pipeline._scorers_moda import make_moda_scorer
        from dfir_triage_pipeline.features import FeatureTable

        np.random.seed(5)
        names = ("a", "b")
        rows = [tuple(np.random.randn(2)) for _ in range(40)]
        cat = tuple(["common"] * 39 + ["rare-unique-value"])
        train = FeatureTable(names, rows[:39], list(range(39)),
                             categorical={"mime_type": cat[:39]})
        allt = FeatureTable(names, rows, list(range(40)),
                            categorical={"mime_type": cat})
        sc = make_moda_scorer(200, 0.05, 20260830)
        sc.fit_table(train)
        df = sc.decision_function_table(allt)
        assert int(np.argmin(df)) == 39  # the rare-category row
