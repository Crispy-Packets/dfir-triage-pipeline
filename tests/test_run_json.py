"""`run.json`, the derived exports, and the SHA-256 manifest.

The properties asserted are the ones the design rests on: deterministic bytes
(or the manifest means nothing), the anomaly percentile carried as context
rather than as a verdict (the acceptance gate requires it), and CSVs derived
from the canonical document rather than written independently (two serialisers
of the same data drift).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from dfir_triage_pipeline.core import entity_score, manifest, run_json
from dfir_triage_pipeline.core.findings import Finding, MatchedEvent
from dfir_triage_pipeline.model import Event

BASE = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)


def _event(offset_s, leaf="a.exe", artifact="prefetch"):
    return Event(
        timestamp=BASE + timedelta(seconds=offset_s),
        source_artifact=artifact,
        event_type="process_exec",
        action="ran",
        source_file="C/Windows/prefetch/A.pf",
        source_locator=f"run_slot={offset_s}",
        timestamp_type="last_run",
        details={"path_basename_canonical": leaf},
    )


def _finding(rule_id="R-TEST-0001", entity="a.exe", weight=70, severity="high"):
    return Finding(
        rule_id=rule_id,
        rule_version="2.0.0",
        schema_version="2.0.0",
        title="A test finding",
        severity=severity,
        weight=weight,
        attack_technique="T1204.002",
        matched=(
            MatchedEvent(
                event_id="e1",
                timestamp=BASE,
                timestamp_type="last_run",
                source_artifact="prefetch",
                event_type="process_exec",
                source_file="C/Windows/prefetch/A.pf",
                source_locator="run_slot=0",
            ),
        ),
        entity_keys=(("entity.exe_name", entity),),
        time_claim="observed_occurrence",
        reason="because",
    )


class _Scored:
    """Minimal stand-in for anomaly.Scored."""

    def __init__(self, leaf, pct, family="prefetch"):
        self.event = _event(0, leaf=leaf)
        self.family = family
        self.percentile_in_family = pct
        self.score = pct / 100
        self.is_outlier = pct < 5


def _doc(tmp_path, scores=(), findings=None):
    findings = [_finding()] if findings is None else findings
    events = [_event(i * 10) for i in range(20)]
    return run_json.build(
        collection=tmp_path / "collection_x",
        events=events,
        findings=findings,
        entities=entity_score.aggregate(findings),
        scores=scores,
    )


class TestDeterminism:
    def test_two_builds_produce_identical_bytes(self, tmp_path):
        """The manifest hashes these bytes. If they move between runs over one
        collection, every hash it records is meaningless."""
        a, b = tmp_path / "a.json", tmp_path / "b.json"
        h1 = run_json.write(_doc(tmp_path), a)
        h2 = run_json.write(_doc(tmp_path), b)
        assert h1 == h2
        assert a.read_bytes() == b.read_bytes()

    def test_no_wall_clock_timestamp_of_the_run_itself(self, tmp_path):
        """A generated-at field would make every run differ, which is why there
        is none. Evidence timestamps are fine; the run's own is not."""
        doc = _doc(tmp_path)
        text = json.dumps(doc)
        for forbidden in ("generated_at", "run_timestamp", "created_at"):
            assert forbidden not in text

    def test_keys_are_sorted_on_disk(self, tmp_path):
        path = tmp_path / "run.json"
        run_json.write(_doc(tmp_path), path)
        lines = path.read_text(encoding="utf-8").splitlines()
        top = [ln.strip().split('"')[1] for ln in lines if ln.startswith("  \"")]
        assert top == sorted(top)


class TestAnomalyContext:
    def test_percentile_is_attached_as_context(self, tmp_path):
        doc = _doc(tmp_path, scores=[_Scored("a.exe", 3.49)])
        context = doc["findings"][0]["anomaly_context"]
        assert context["entities"][0]["percentile_in_family"] == 3.49

    def test_context_declares_it_is_not_a_verdict(self, tmp_path):
        """The acceptance gate requires the ML be labelled as prioritisation
        rather than a malicious verdict. The label travels with the data, so a
        consumer cannot strip it by reading only one field."""
        doc = _doc(tmp_path, scores=[_Scored("a.exe", 3.49)])
        assert doc["findings"][0]["anomaly_context"]["is_verdict"] is False
        assert doc["anomalies"]["is_verdict"] is False
        assert "not" in doc["anomalies"]["meaning"].lower()

    def test_is_outlier_is_never_exported(self, tmp_path):
        """A threshold artifact that reads as a judgement. The percentile is the
        reportable form; six of 86 browser rows being flagged says more about a
        5% cut than about those six."""
        doc = _doc(tmp_path, scores=[_Scored("a.exe", 3.49)])
        # Checked against the data, not the whole document: pytest names
        # tmp_path after the test, so the collection path contains the string.
        for entry in doc["anomalies"]["scored_entities"]:
            assert "is_outlier" not in entry
        for finding in doc["findings"]:
            assert "is_outlier" not in json.dumps(finding.get("anomaly_context", {}))

    def test_absent_rather_than_null_when_not_scored(self, tmp_path):
        """A consumer must not be able to mistake 'not scored' for 'scored as
        ordinary'."""
        doc = _doc(tmp_path, scores=[])
        assert "anomaly_context" not in doc["findings"][0]

    def test_best_percentile_wins_for_one_entity(self, tmp_path):
        """An entity is as unusual as its most unusual row; averaging would let
        ordinary rows bury an anomalous one."""
        doc = _doc(tmp_path, scores=[_Scored("a.exe", 40.0), _Scored("a.exe", 2.0)])
        assert doc["findings"][0]["anomaly_context"]["entities"][0][
            "percentile_in_family"
        ] == 2.0


class TestTimelineSlice:
    def test_slice_carries_surrounding_events(self, tmp_path):
        doc = _doc(tmp_path)
        assert doc["findings"][0]["timeline_slice"]["events"]

    def test_slice_is_capped_and_says_so(self, tmp_path):
        """A shortened list that does not announce itself is indistinguishable
        from a quiet period."""
        events = [_event(i) for i in range(200)]  # 200 events in 200 seconds
        doc = run_json.build(
            collection=tmp_path / "c",
            events=events,
            findings=[_finding()],
            entities=[],
        )
        sl = doc["findings"][0]["timeline_slice"]
        assert sl["truncated"] is True
        assert len(sl["events"]) == run_json.MAX_SLICE_EVENTS
        assert sl["events_in_window"] > run_json.MAX_SLICE_EVENTS

    def test_truncation_keeps_the_nearest_events(self, tmp_path):
        """The first N would be the oldest -- the half least likely to explain
        the finding."""
        events = [_event(i) for i in range(200)]
        doc = run_json.build(
            collection=tmp_path / "c",
            events=events,
            findings=[_finding()],
            entities=[],
        )
        kept = doc["findings"][0]["timeline_slice"]["events"]
        offsets = [int(e["source_locator"].split("=")[1]) for e in kept]
        # The finding is at offset 0, so the nearest events are the low ones.
        assert max(offsets) < 100

    def test_slice_events_carry_provenance(self, tmp_path):
        doc = _doc(tmp_path)
        for event in doc["findings"][0]["timeline_slice"]["events"]:
            assert event["source_file"]
            assert event["source_locator"]


class TestDerivedExports:
    def test_findings_csv_is_derived_from_the_document(self, tmp_path):
        doc = _doc(tmp_path, scores=[_Scored("a.exe", 3.49)])
        path = tmp_path / "findings.csv"
        manifest.write_findings_csv(doc, path)
        text = path.read_text(encoding="utf-8")
        assert "R-TEST-0001" in text
        assert "3.4900" in text  # the percentile came through

    def test_findings_csv_names_the_column_as_a_rank(self, tmp_path):
        """`anomaly_percentile`, never `anomaly_score` or `risk`."""
        assert "anomaly_percentile" in manifest.FINDINGS_CSV_COLUMNS
        assert not any(
            c in manifest.FINDINGS_CSV_COLUMNS for c in ("risk", "verdict", "malicious")
        )

    def test_anomalies_csv_holds_every_scored_entity(self, tmp_path):
        doc = _doc(tmp_path, scores=[_Scored("a.exe", 1.0), _Scored("b.exe", 2.0)])
        path = tmp_path / "anomalies.csv"
        manifest.write_anomalies_csv(doc, path)
        rows = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(rows) == 3  # header + two entities

    def test_exports_are_deterministic(self, tmp_path):
        doc = _doc(tmp_path, scores=[_Scored("a.exe", 3.49)])
        h1 = manifest.write_findings_csv(doc, tmp_path / "one.csv")
        h2 = manifest.write_findings_csv(doc, tmp_path / "two.csv")
        assert h1 == h2


class TestManifest:
    def test_manifest_verifies_when_intact(self, tmp_path):
        doc = _doc(tmp_path)
        hashes = {"run.json": run_json.write(doc, tmp_path / "run.json")}
        hashes["findings.csv"] = manifest.write_findings_csv(doc, tmp_path / "findings.csv")
        path = tmp_path / "manifest.sha256"
        manifest.write_manifest(hashes, path)
        assert manifest.verify_manifest(path) == []

    def test_manifest_catches_a_modified_file(self, tmp_path):
        """The whole point: a report that claims to come from a run can be
        checked against the run that produced it."""
        doc = _doc(tmp_path)
        hashes = {"run.json": run_json.write(doc, tmp_path / "run.json")}
        path = tmp_path / "manifest.sha256"
        manifest.write_manifest(hashes, path)

        (tmp_path / "run.json").write_text("tampered", encoding="utf-8")
        mismatches = manifest.verify_manifest(path)
        assert len(mismatches) == 1
        assert mismatches[0][0] == "run.json"

    def test_manifest_catches_a_missing_file(self, tmp_path):
        doc = _doc(tmp_path)
        hashes = {"run.json": run_json.write(doc, tmp_path / "run.json")}
        path = tmp_path / "manifest.sha256"
        manifest.write_manifest(hashes, path)

        (tmp_path / "run.json").unlink()
        assert manifest.verify_manifest(path)[0][2] == "MISSING"

    def test_manifest_format_is_sha256sum_compatible(self, tmp_path):
        """A manifest only this pipeline can check is a weaker claim than one
        anybody can verify with a standard tool."""
        path = tmp_path / "manifest.sha256"
        manifest.write_manifest({"a.txt": "0" * 64}, path)
        line = path.read_text(encoding="utf-8").strip()
        digest, sep, name = line.partition("  ")
        assert len(digest) == 64 and sep == "  " and name == "a.txt"


class TestStatsCarriedThrough:
    def test_search_truncation_reaches_the_document(self, tmp_path):
        """A consumer reading only run.json would otherwise believe the run was
        complete when a chain may have been missed."""

        class _Stats:
            rules_evaluated = 3
            findings_by_rule = {"R-A": 1}
            search_truncated = {"R-B"}

        doc = run_json.build(
            collection=tmp_path / "c",
            events=[_event(0)],
            findings=[_finding()],
            entities=[],
            engine_stats=_Stats(),
        )
        assert doc["rules"]["search_truncated"] == ["R-B"]

    def test_unscored_families_reach_the_document(self, tmp_path):
        from dfir_triage_pipeline.anomaly import UnscoredFamilies

        families = UnscoredFamilies()
        families.add("registry", "below MIN_TRAINING_ROWS", 8)
        doc = run_json.build(
            collection=tmp_path / "c",
            events=[_event(0)],
            findings=[_finding()],
            entities=[],
            unscored_families=families,
        )
        entry = doc["anomalies"]["unscored_families"][0]
        assert entry["family"] == "registry"
        assert entry["rows"] == 8
