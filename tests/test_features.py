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
from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline import anomaly, features
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

#: Comfortably above anomaly.MIN_TRAINING_ROWS, so a test that expects a family
#: NOT to be modelled cannot pass for the trivial reason that it had too few
#: rows. Derived from the constant rather than hard-coded, so raising the floor
#: cannot silently make those tests vacuous (D-061's shape).
MIN_ROWS_COMFORTABLY_CLEAR = anomaly.MIN_TRAINING_ROWS * 3


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


class TestExtendedFamiliesFlag:
    """The opt-in 38-family extension (OD-01 re-opened 2026-09-20).

    The flag exists so the 38-family config can be *measured* without the
    committed 7-family headline being silently overwritten. These tests pin the
    two properties that make that safe: off is inert, and on declares exactly
    the four families the row survey found carry a behavioural key -- and only
    those, so a family with no numeric column is never asserted as covered.
    """

    _EXTRA = ("services", "shimcache", "evtx.bits", "userassist")

    def test_off_by_default_the_seven_families_are_the_whole_set(self, monkeypatch):
        monkeypatch.delenv(features.EXTENDED_FLAG, raising=False)
        assert set(features._active_family_features()) == set(features.FAMILY_FEATURES)
        for fam in self._EXTRA:
            assert not features.is_declared(fam)

    def test_a_false_value_is_still_off(self, monkeypatch):
        for value in ("", "0", "false", "False"):
            monkeypatch.setenv(features.EXTENDED_FLAG, value)
            assert not features.is_declared("services")

    def test_on_declares_exactly_the_four_extra_families(self, monkeypatch):
        monkeypatch.setenv(features.EXTENDED_FLAG, "1")
        active = features._active_family_features()
        assert set(active) == set(features.FAMILY_FEATURES) | set(self._EXTRA)
        for fam in self._EXTRA:
            assert features.is_declared(fam)

    def test_on_does_not_declare_families_with_no_behavioural_key(self, monkeypatch):
        monkeypatch.setenv(features.EXTENDED_FLAG, "1")
        # These clear MIN_TRAINING_ROWS but carry no numeric details key, so a
        # column over them would be constant. The flag must not claim them.
        for fam in ("evtx.firewall", "evtx.winlogon", "scheduled_task"):
            assert not features.is_declared(fam)

    def test_extended_sets_use_only_existing_feature_columns(self):
        # The extension adds FAMILIES, never new unmeasured columns: every
        # column an extended family gets is an existing feature name whose
        # per-family leakage was tested in the phase-4 doc (the temporal density
        # columns that leaked on services/shimcache were dropped there).
        for fam in self._EXTRA:
            for name in features._EXTENDED_FAMILY_FEATURES[fam]:
                assert name in features.FEATURE_NAMES

    def test_leaking_temporal_columns_are_absent_from_extended_families(self):
        # services and shimcache leaked on the per-hour density columns (phase-4
        # leakage table); those must not appear in their extended sets. evtx.bits
        # measured clean and keeps them (asserted in the D-074 class).
        leaky = {"events_in_same_hour", "distinct_executables_in_same_hour"}
        for fam in ("services", "shimcache"):
            assert not (set(features._EXTENDED_FAMILY_FEATURES[fam]) & leaky)

    def test_the_committed_map_is_never_mutated_by_the_extension(self):
        # _EXTENDED_FAMILY_FEATURES is a separate dict; FAMILY_FEATURES must
        # stay at its seven families whatever the flag is.
        assert set(features.FAMILY_FEATURES) == {
            "prefetch", "browser", "amcache", "registry",
            "evtx.security", "evtx.system", "evtx.powershell",
        }


class TestD074TemporalDensityLeak:
    """D-074: the per-hour density columns are opt-in by measurement.

    They leaked on three of the four fitting committed families (amcache 0.83,
    prefetch 0.71, evtx.powershell's `events_in_same_hour` 0.95) because those
    families' rows are timestamped by when the collection ran. `_SHARED` no
    longer carries them; a family gets a temporal column only by passing the
    leakage test for it. Measured 2026-09-21.
    """

    _BOTH = {"events_in_same_hour", "distinct_executables_in_same_hour"}

    def test_shared_set_is_rarity_only(self):
        assert not (set(features._SHARED) & self._BOTH)

    def test_leaking_families_carry_neither_temporal_column(self):
        # amcache, prefetch, and the two families that do not fit but only ever
        # had _SHARED: none may carry a per-hour density column now.
        for fam in ("amcache", "prefetch", "evtx.security", "evtx.system", "registry"):
            assert not (set(features.FAMILY_FEATURES[fam]) & self._BOTH)

    def test_browser_keeps_both_it_measured_clean(self):
        # A download carries its own event time; both columns are baseline there.
        assert self._BOTH <= set(features.FAMILY_FEATURES["browser"])

    def test_powershell_keeps_only_the_column_that_did_not_leak(self):
        ps = set(features.FAMILY_FEATURES["evtx.powershell"])
        assert "distinct_executables_in_same_hour" in ps
        assert "events_in_same_hour" not in ps


class TestScriptShapeFeatures:
    """PowerShell script-block features (2026-09-14, D-041).

    A 4104 record carries script TEXT and nothing else -- no executable, no
    path -- so seven of the eight features the family previously received were
    constant and it scored 0.009 distinct vectors per row. Ten times the data
    would have given the same ratio: the problem was the feature set.
    """

    def _ps(self, text, truncated=False):
        details = {"script_block_text": text} if text is not None else {}
        if truncated:
            details["script_block_truncated"] = "true"
        return Event(
            timestamp=BASE,
            source_artifact="evtx.powershell",
            event_type="script_block",
            action="logged",
            source_file="f",
            source_locator="l",
            timestamp_type="recorded",
            details=details,
        )

    def test_absent_text_is_all_zero_not_an_error(self):
        table = features.build([self._ps(None)], None, "evtx.powershell")
        row = dict(zip(table.names, table.rows[0], strict=True))
        assert row["script_length_log10"] == 0.0
        assert row["script_entropy"] == 0.0

    def test_length_is_log_scaled(self):
        short = features.build([self._ps("a" * 100)], None, "evtx.powershell")
        long_ = features.build([self._ps("a" * 100_000)], None, "evtx.powershell")
        i = short.names.index("script_length_log10")
        # Three orders of magnitude apart become 3 apart, not 99,900.
        assert long_.rows[0][i] - short.rows[0][i] == pytest.approx(3.0, abs=0.01)

    def test_entropy_separates_random_from_repetitive(self):
        i = features.FEATURE_NAMES.index("script_entropy")
        names = features.FAMILY_FEATURES["evtx.powershell"]
        i = names.index("script_entropy")
        flat = features.build([self._ps("aaaaaaaaaaaaaaaa")], None, "evtx.powershell")
        varied = features.build(
            [self._ps("aB3$xY9!qW2@zL7#")], None, "evtx.powershell"
        )
        assert varied.rows[0][i] > flat.rows[0][i]

    def test_encoded_marker_is_a_flag_not_the_text(self):
        """The script text itself never enters the model -- only membership of
        a closed marker set, so no corpus-specific string is carried."""
        names = features.FAMILY_FEATURES["evtx.powershell"]
        i = names.index("script_has_encoded_marker")
        encoded = features.build(
            [self._ps("powershell -EncodedCommand SQBFAFgA")], None, "evtx.powershell"
        )
        plain = features.build([self._ps("Get-Process | Sort-Object CPU")], None, "evtx.powershell")
        assert encoded.rows[0][i] == 1.0
        assert plain.rows[0][i] == 0.0

    def test_marker_matching_is_case_insensitive(self):
        names = features.FAMILY_FEATURES["evtx.powershell"]
        i = names.index("script_has_encoded_marker")
        for text in ("-ENC x", "-enc x", "FromBase64String(", "IEX (New-Object Net.WebClient)"):
            table = features.build([self._ps(text)], None, "evtx.powershell")
            assert table.rows[0][i] == 1.0, text

    def test_truncation_flag_is_read_from_details(self):
        names = features.FAMILY_FEATURES["evtx.powershell"]
        i = names.index("script_is_truncated")
        cut = features.build([self._ps("x", truncated=True)], None, "evtx.powershell")
        whole = features.build([self._ps("x")], None, "evtx.powershell")
        assert cut.rows[0][i] == 1.0
        assert whole.rows[0][i] == 0.0

    def test_powershell_family_omits_path_and_interval_features(self):
        """They are undefined for a script block, which is why the family was
        degenerate before."""
        names = features.FAMILY_FEATURES["evtx.powershell"]
        for absent in ("path_depth", "path_is_user_writable", "run_count",
                       "seconds_since_previous_run_of_same_executable"):
            assert absent not in names


class TestPublisherAndLocationFeatures:
    """has_publisher and exec_location_rarity (2026-09-14).

    Both answer the Discord/GIMP case: the model flagged benign installers
    because they were executables in a baseline of books. These describe how a
    binary sits among the others on the host rather than what it is called.
    """

    def _am(self, publisher=None, canonical=None):
        details = {"path_basename_canonical": "x.exe"}
        if publisher is not None:
            details["publisher"] = publisher
        if canonical:
            details["path_canonical"] = canonical
        return Event(
            timestamp=BASE,
            source_artifact="amcache",
            event_type="program_inventoried",
            action="a",
            source_file="f",
            source_locator="l",
            timestamp_type="presence",
            details=details,
        )

    def test_publisher_present_is_one(self):
        names = features.FAMILY_FEATURES["amcache"]
        i = names.index("has_publisher")
        table = features.build([self._am(publisher="igor pavlov")], None, "amcache")
        assert table.rows[0][i] == 1.0

    def test_publisher_absent_is_zero(self):
        """invoice_scan.exe carries None, which is what makes this useful."""
        names = features.FAMILY_FEATURES["amcache"]
        i = names.index("has_publisher")
        assert features.build([self._am()], None, "amcache").rows[0][i] == 0.0

    def test_blank_publisher_counts_as_absent(self):
        names = features.FAMILY_FEATURES["amcache"]
        i = names.index("has_publisher")
        assert features.build([self._am(publisher="   ")], None, "amcache").rows[0][i] == 0.0

    def test_the_vendor_name_never_enters_the_model(self):
        """A boolean, not a category. Two different vendors are identical to the
        model -- 'signed by Igor Pavlov' is tied to what happens to be installed
        here; 'declared a publisher' transfers to another estate."""
        names = features.FAMILY_FEATURES["amcache"]
        i = names.index("has_publisher")
        a = features.build([self._am(publisher="microsoft corporation")], None, "amcache")
        b = features.build([self._am(publisher="igor pavlov")], None, "amcache")
        assert a.rows[0][i] == b.rows[0][i] == 1.0

    def test_location_rarity_is_a_share_of_the_collection(self):
        names = features.FAMILY_FEATURES["prefetch"]
        i = names.index("exec_location_rarity")
        common = "c:" + chr(92) + "windows" + chr(92) + "system32" + chr(92) + "a.exe"
        rare = "c:" + chr(92) + "users" + chr(92) + "u" + chr(92) + "downloads" + chr(92) + "b.exe"
        events = [
            _event(BASE + timedelta(minutes=n), leaf=f"a{n}.exe", canonical=common)
            for n in range(9)
        ] + [_event(BASE + timedelta(minutes=9), leaf="b.exe", canonical=rare)]
        table = features.build(events, None, "prefetch")
        shares = [r[i] for r in table.rows]
        assert max(shares) == pytest.approx(0.9)
        assert min(shares) == pytest.approx(0.1)

    def test_pathless_rows_get_zero_not_a_shared_bucket(self):
        """Grouping every pathless row under "" would make them look
        co-located, which is a fact the artifact never recorded."""
        names = features.FAMILY_FEATURES["prefetch"]
        i = names.index("exec_location_rarity")
        events = [_event(BASE, leaf="a.exe")]  # no canonical path
        assert features.build(events, None, "prefetch").rows[0][i] == 0.0

    def test_location_rarity_is_prefetch_only(self):
        """Rejected for amcache on measurement: 62.6% single-field accuracy
        against a 56.6% baseline, because Amcache inventories software
        installed at different times and the directory mix tracks the
        collection rather than behaviour."""
        assert "exec_location_rarity" in features.FAMILY_FEATURES["prefetch"]
        assert "exec_location_rarity" not in features.FAMILY_FEATURES["amcache"]
        assert "exec_location_rarity" not in features.FAMILY_FEATURES["browser"]

    def test_publisher_is_amcache_only(self):
        """It is the only family whose artifact records one."""
        for family, names in features.FAMILY_FEATURES.items():
            if family != "amcache":
                assert "has_publisher" not in names


class TestUndeclaredFamiliesAreNotModelled:
    """D-063. A family with no entry in FAMILY_FEATURES must be SKIPPED, never
    handed the full feature vocabulary and modelled anyway.

    The layer appeared to cover 38 families while FAMILY_FEATURES still listed
    the original seven, because `features_for` fell back to FEATURE_NAMES for
    anything missing. Nothing reported the difference, so the gap was invisible
    until the ablation measured where the attack entity actually ranked.

    One config change would re-introduce it, which is why this is asserted
    rather than left to the docstring.
    """

    def test_is_declared_agrees_with_the_table(self):
        for family in features.FAMILY_FEATURES:
            assert features.is_declared(family)
        assert not features.is_declared("recyclebin")
        assert not features.is_declared("usn")
        assert not features.is_declared(None)
        assert not features.is_declared("a family nobody has ever written")

    def test_an_undeclared_family_is_never_fitted(self):
        """Enough rows, plenty of variety, and still not modelled -- because
        no one has chosen its features or leakage-tested them."""
        events = [
            _event(BASE + timedelta(minutes=n), artifact="recyclebin",
                   leaf=f"deleted{n}.exe", run_count=n)
            for n in range(MIN_ROWS_COMFORTABLY_CLEAR)
        ]
        model = anomaly.PerFamilyModel().fit(events, None)
        assert "recyclebin" not in model.models, (
            "an undeclared family reached the modelled set; features_for's "
            "fallback to FEATURE_NAMES is back (D-063)"
        )
        assert "FAMILY_FEATURES" in model.unscored_families.reason("recyclebin"), (
            "the family must be skipped for the STATED reason, so the layer's "
            "coverage gap is visible rather than implied by a missing score"
        )

    def test_a_declared_family_with_the_same_rows_IS_fitted(self):
        """The control: identical row count and shape, declared family. Without
        this the test above would pass if fit() were broken outright."""
        events = [
            _event(BASE + timedelta(minutes=n), artifact="prefetch",
                   leaf=f"prog{n}.exe", run_count=n)
            for n in range(MIN_ROWS_COMFORTABLY_CLEAR)
        ]
        model = anomaly.PerFamilyModel().fit(events, None)
        assert "prefetch" in model.models
