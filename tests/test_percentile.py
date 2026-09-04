"""B-1: family-relative percentiles on the scored output.

The percentile is what the report and the JSON output carry, so the property
that matters is direction: 0.0 must be the MOST anomalous row. Getting it
backwards produces a plausible-looking number on every row and would rank the
report upside down without anything failing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dfir_triage_pipeline import anomaly, features
from dfir_triage_pipeline.anomaly import Scored, assign_percentiles
from dfir_triage_pipeline.ingest import collect_events


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
