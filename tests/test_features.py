"""Feature layer and anomaly model (B-10, B-11, B-12).

The thing these tests exist to prevent is a model that separates the collections
rather than the behaviours. On this corpus that is the easy failure: three
collections from one machine over nine days, so nearly every raw field encodes
which collection a row came from.
"""

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dfir_triage_pipeline import anomaly, features
from dfir_triage_pipeline.ingest import collect_events
from dfir_triage_pipeline.model import Event


def _event(ts, artifact="prefetch", leaf="a.exe", run_count=None, canonical=None):
    details = {}
    if leaf:
        details["path_basename_canonical"] = leaf
    if run_count is not None:
        details["run_count"] = str(run_count)
    if canonical:
        details["path_canonical"] = canonical
    return Event(
        timestamp=ts,
        source_artifact=artifact,
        event_type="process_exec",
        action="ran",
        source_file="f",
        source_locator="l",
        timestamp_type="last_run",
        details=details,
    )


BASE = datetime(2026, 8, 23, 22, 0, tzinfo=UTC)


class TestExclusions:
    def test_leaking_fields_are_named_with_their_measurement(self):
        """The exclusion list is evidence, not preference. Each entry must
        carry the measurement that disqualified the field, so a later reader
        can check the reasoning instead of trusting it."""
        for field in ("path", "source_file", "source_artifact", "user"):
            assert field in features.EXCLUDED_FIELDS
            assert "%" in features.EXCLUDED_FIELDS[field]

    def test_hour_and_weekday_are_excluded_despite_being_in_the_plan(self):
        """Measured at 86.0% and 84.2% single-field accuracy against a 79.8%
        baseline. Hours 21-23 hold a third of s1_v2 and about 1% of the
        baselines -- the operator ran the scenario in the evening, so this is
        session identity rather than behaviour."""
        assert "hour_of_day" in features.EXCLUDED_FIELDS
        assert "is_weekend" in features.EXCLUDED_FIELDS

    def test_no_excluded_field_appears_as_a_feature(self):
        for name in features.FEATURE_NAMES:
            assert name not in features.EXCLUDED_FIELDS


class TestFeatures:
    def test_missing_run_count_is_flagged_not_imputed(self):
        """Substituting a mean would invent an execution history the artifact
        never recorded, and the model cannot tell an imputed value from a
        measured one."""
        table = features.build([_event(BASE, leaf="x.exe")])
        row = dict(zip(table.names, table.rows[0], strict=True))
        assert row["run_count"] == 0.0
        assert row["run_count_is_known"] == 0.0

    def test_rarity_comes_from_training_not_from_the_scored_set(self):
        """The whole point of rarity. Recomputing it per collection would make
        every binary averagely rare within its own collection, hiding exactly
        the binary that appears nowhere else."""
        train = [_event(BASE, leaf="common.exe") for _ in range(50)]
        rarity = features.build_rarity_index(train)

        scored = features.build([_event(BASE, leaf="never_seen.exe")], rarity)
        row = dict(zip(scored.names, scored.rows[0], strict=True))
        assert row["executable_is_unseen"] == 1.0
        assert row["executable_rarity"] == 0.0

    def test_rarity_without_a_training_profile_sees_nothing_as_unseen(self):
        """Guards the default. build() without a profile computes rarity from
        its own input, which is right for fitting and wrong for scoring."""
        table = features.build([_event(BASE, leaf="only.exe")])
        row = dict(zip(table.names, table.rows[0], strict=True))
        assert row["executable_is_unseen"] == 0.0

    def test_first_sighting_has_no_interval(self):
        """A gap of zero and a gap that does not exist are different claims."""
        table = features.build([_event(BASE, leaf="x.exe")])
        row = dict(zip(table.names, table.rows[0], strict=True))
        assert row["previous_run_is_known"] == 0.0

    def test_interval_is_measured_between_runs_of_the_same_binary(self):
        events = [
            _event(BASE, leaf="x.exe"),
            _event(BASE + timedelta(seconds=90), leaf="y.exe"),
            _event(BASE + timedelta(seconds=300), leaf="x.exe"),
        ]
        table = features.build(events)
        last = dict(zip(table.names, table.rows[-1], strict=True))
        assert last["previous_run_is_known"] == 1.0
        assert last["seconds_since_previous_run_of_same_executable"] == 300.0

    def test_rows_and_events_stay_in_step(self):
        """A score that cannot be traced to its evidence is unusable under
        CD-003 and CD-004."""
        events = [_event(BASE + timedelta(seconds=i), leaf=f"{i}.exe")
                  for i in range(5)]
        table = features.build(events)
        assert len(table.rows) == len(table.events) == 5

    def test_output_is_ordered_by_time_regardless_of_input_order(self):
        events = [_event(BASE + timedelta(seconds=s)) for s in (30, 0, 60)]
        table = features.build(events)
        assert [e.timestamp for e in table.events] == sorted(
            e.timestamp for e in events
        )

    def test_feature_order_is_fixed(self):
        """A stored model scores by column position, so inserting a feature in
        the middle silently reinterprets every column after it."""
        assert features.FEATURE_NAMES[0] == "run_count"
        assert len(features.FEATURE_NAMES) == len(set(features.FEATURE_NAMES))


class TestModel:
    def test_feature_layout_mismatch_is_refused(self):
        """Scoring is positional. A table with a different layout would be
        scored silently and wrongly rather than failing."""
        train = features.build([_event(BASE + timedelta(seconds=i)) for i in range(60)])
        model = anomaly.AnomalyModel().fit(train)

        wrong = features.FeatureTable(
            names=("a", "b"), rows=[(1.0, 2.0)], events=[_event(BASE)]
        )
        with pytest.raises(ValueError, match="feature layout"):
            model.score(wrong)

    def test_fitting_on_nothing_is_refused(self):
        empty = features.FeatureTable(names=features.FEATURE_NAMES, rows=[], events=[])
        with pytest.raises(ValueError, match="empty"):
            anomaly.AnomalyModel().fit(empty)

    def test_scoring_is_reproducible(self):
        """Isolation Forest samples features and split points. Without a fixed
        seed the same input gives different scores on every run and no result
        could be checked against a previous one."""
        events = [_event(BASE + timedelta(seconds=i), run_count=i % 7)
                  for i in range(120)]
        table = features.build(events)
        a = [s.score for s in anomaly.AnomalyModel().fit(table).score(table)]
        b = [s.score for s in anomaly.AnomalyModel().fit(table).score(table)]
        assert a == b

    def test_unmodelled_family_is_omitted_not_called_normal(self):
        """A family with too few training rows gets no model. Returning "not
        anomalous" for those rows would be a claim the model never made."""
        train = [_event(BASE + timedelta(seconds=i), artifact="prefetch")
                 for i in range(60)]
        rarity = features.build_rarity_index(train)
        model = anomaly.PerFamilyModel().fit(train, rarity)

        mixed = train + [_event(BASE, artifact="browser", leaf="z.exe")]
        scored = model.score(mixed, rarity)
        assert "browser" not in {s.event.source_artifact for s in scored}


class TestOverlap:
    def test_identical_distributions_overlap_fully(self):
        scores = [anomaly.Scored(event=None, score=float(i), is_outlier=False)
                  for i in range(100)]
        assert anomaly.overlap_coefficient(scores, scores) == pytest.approx(1.0)

    def test_disjoint_distributions_do_not_overlap(self):
        a = [anomaly.Scored(event=None, score=float(i), is_outlier=False)
             for i in range(50)]
        b = [anomaly.Scored(event=None, score=float(i + 1000), is_outlier=False)
             for i in range(50)]
        assert anomaly.overlap_coefficient(a, b) == pytest.approx(0.0, abs=0.02)


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")
EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")


@pytest.mark.skipif(
    not (EVIDENCE / "collection_clean_a").is_dir()
    or not (EVIDENCE / "collection_clean_b").is_dir(),
    reason="both baseline collections are required",
)
def test_b12_acceptance_two_baselines_must_score_alike():
    """B-12, the gate on everything downstream.

    clean_a and clean_b are network-identical, neither carries the scenario, and
    they were collected eleven days apart. If a model fitted on one flags the
    other as broadly anomalous, the features have learned collection identity
    and no s1_v2 result can be interpreted.

    This is asserted rather than eyeballed because it is the only evidence that
    the model learned behaviour at all.
    """
    train = collect_events(EVIDENCE / "collection_clean_b")[0]
    test = collect_events(EVIDENCE / "collection_clean_a")[0]

    rarity = features.build_rarity_index(train)
    model = anomaly.PerFamilyModel().fit(train, rarity)

    train_scores = model.score(train, rarity)
    test_scores = model.score(test, rarity)

    overlap = anomaly.overlap_coefficient(train_scores, test_scores)
    assert overlap > 0.80, f"score distributions separated (overlap {overlap:.3f})"

    train_rate = anomaly.summarise(train_scores)["outlier_rate"]
    test_rate = anomaly.summarise(test_scores)["outlier_rate"]
    assert test_rate < train_rate * 3, (
        f"clean_a flagged at {test_rate:.1%} against clean_b's {train_rate:.1%} "
        "despite carrying no attack"
    )


class TestPerFamilyFeatureSets:
    """`FAMILY_FEATURES` restricts each family to columns its records populate.

    Argued in docs/per-family-features.md. The failure this class exists to
    prevent is silent: a name that does not appear in FEATURE_NAMES would be
    looked up by index at build time, and the forest scores by position, so a
    stale or misspelled entry reinterprets every column after it without
    anything raising.
    """

    def test_every_family_name_exists_in_the_global_list(self):
        known = set(features.FEATURE_NAMES)
        for family, names in features.FAMILY_FEATURES.items():
            unknown = set(names) - known
            assert not unknown, f"{family} names features that do not exist: {unknown}"

    def test_no_family_repeats_a_feature(self):
        for family, names in features.FAMILY_FEATURES.items():
            assert len(names) == len(set(names)), f"{family} repeats a feature"

    def test_no_excluded_field_leaks_into_a_family_set(self):
        for family, names in features.FAMILY_FEATURES.items():
            for field in features.EXCLUDED_FIELDS:
                assert field not in names, f"{family} carries excluded {field}"

    def test_browser_omits_the_execution_features(self):
        """A download has never run, so these are undefined rather than zero."""
        browser = features.FAMILY_FEATURES["browser"]
        for name in (
            "run_count",
            "run_count_is_known",
            "seconds_since_previous_run_of_same_executable",
            "previous_run_is_known",
        ):
            assert name not in browser

    def test_prefetch_omits_the_download_features(self):
        """A Prefetch record carries no byte count and no MIME type."""
        prefetch = features.FAMILY_FEATURES["prefetch"]
        for name in (
            "download_size_log10",
            "download_size_is_known",
            "mime_type_is_executable",
            "filename_length",
            "filename_entropy",
        ):
            assert name not in prefetch

    def test_unknown_family_falls_back_to_everything(self):
        """A new parser scores with redundant columns -- measurably worse --
        rather than silently dropping one its artifact does populate."""
        assert features.features_for("not.a.family") == features.FEATURE_NAMES
        assert features.features_for(None) == features.FEATURE_NAMES

    def test_build_emits_exactly_the_family_columns(self):
        events = [_event(BASE + timedelta(minutes=i), leaf=f"b{i}.exe") for i in range(5)]
        for family in ("browser", "prefetch", "amcache"):
            table = features.build(events, None, family)
            assert table.names == features.FAMILY_FEATURES[family]
            assert all(len(r) == len(table.names) for r in table.rows)

    def test_column_values_are_selected_by_name_not_position(self):
        """The values a family receives must equal the full row filtered by
        name. Selecting by a stale index would produce plausible numbers in the
        wrong columns."""
        events = [_event(BASE + timedelta(minutes=i), leaf=f"b{i}.exe") for i in range(5)]
        full = features.build(events, None)
        for family in features.FAMILY_FEATURES:
            reduced = features.build(events, None, family)
            keep = [full.names.index(n) for n in reduced.names]
            for full_row, reduced_row in zip(full.rows, reduced.rows, strict=True):
                assert reduced_row == tuple(full_row[i] for i in keep)
