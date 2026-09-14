"""The HTML report rendered from `run.json`.

Person A owns the report template; this is a reference renderer proving the
contract is sufficient. What the tests assert is not styling but the four
properties a forensic artifact has to hold: two panels rather than one list,
provenance on the page, no external dependency, and deterministic bytes.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from dfir_triage_pipeline.core import entity_score, report_html, run_json
from dfir_triage_pipeline.core.findings import Finding, MatchedEvent
from dfir_triage_pipeline.model import Event

BASE = datetime(2026, 9, 14, 12, 0, tzinfo=UTC)


def _event(offset_s=0, leaf="a.exe"):
    return Event(
        timestamp=BASE + timedelta(seconds=offset_s),
        source_artifact="prefetch",
        event_type="process_exec",
        action="ran",
        source_file="C/Windows/prefetch/A.pf",
        source_locator=f"run_slot={offset_s}",
        timestamp_type="last_run",
        details={"path_basename_canonical": leaf},
    )


def _finding(severity="critical", entity="evil.exe"):
    return Finding(
        rule_id="R-CORR-0003",
        rule_version="2.0.0",
        schema_version="2.0.0",
        title="An executed binary is also registered to run at logon",
        severity=severity,
        weight=85,
        attack_technique="T1547.001",
        matched=(
            MatchedEvent(
                event_id="abc123",
                timestamp=BASE,
                timestamp_type="last_run",
                source_artifact="prefetch",
                event_type="process_exec",
                source_file="C/Windows/prefetch/EVIL.EXE-1234.pf",
                source_locator="run_slot=0",
                step="execution",
            ),
        ),
        entity_keys=(("entity.exe_name", entity),),
        time_claim="observed_occurrence",
        reason="it ran and it persists",
    )


class _Scored:
    def __init__(self, leaf, pct):
        self.event = _event(leaf=leaf)
        self.family = "prefetch"
        self.percentile_in_family = pct
        self.score = pct / 100
        self.is_outlier = pct < 5


def _doc(tmp_path, findings=None, scores=()):
    findings = [_finding()] if findings is None else findings
    return run_json.build(
        collection=tmp_path / "collection_x",
        events=[_event(i * 10) for i in range(10)],
        findings=findings,
        entities=entity_score.aggregate(findings),
        scores=scores,
    )


class TestSelfContained:
    def test_no_external_resources(self, tmp_path):
        """A forensic artifact must render identically in five years, offline,
        from a case archive. A CDN reference makes the report depend on a
        server outliving it."""
        page = report_html.render(_doc(tmp_path))
        assert not re.search(r'(src|href)\s*=\s*["\']https?:', page, re.I)
        assert "@import" not in page

    def test_no_javascript(self, tmp_path):
        """Nothing in the report should require executing code to read it."""
        assert "<script" not in report_html.render(_doc(tmp_path)).lower()

    def test_css_is_inline(self, tmp_path):
        assert "<style>" in report_html.render(_doc(tmp_path))


class TestPanelSeparation:
    def test_both_panels_exist_and_are_distinct(self, tmp_path):
        """Rule findings and anomaly percentiles are different claims. Merging
        them into one sorted table with one severity column would break the
        acceptance gate whether or not a label appeared above it."""
        page = report_html.render(_doc(tmp_path, scores=[_Scored("evil.exe", 2.0)]))
        assert "Verdict" in page
        assert "Prioritisation" in page
        assert page.index("Verdict") < page.index("Prioritisation")

    def test_prioritisation_panel_carries_the_not_a_verdict_label(self, tmp_path):
        page = report_html.render(_doc(tmp_path, scores=[_Scored("evil.exe", 2.0)]))
        assert "not a malicious verdict" in page.lower()

    def test_anomaly_context_is_labelled_where_it_appears(self, tmp_path):
        """Beside a finding, the percentile must say what it is not."""
        page = report_html.render(_doc(tmp_path, scores=[_Scored("evil.exe", 2.0)]))
        assert "not a verdict" in page.lower()

    def test_percentile_is_never_rendered_as_a_severity(self, tmp_path):
        """The severity classes belong to rule findings only. A percentile
        rendered with one would read as a verdict."""
        page = report_html.render(_doc(tmp_path, scores=[_Scored("evil.exe", 2.0)]))
        panel = page[page.index("Prioritisation"):]
        assert "class='sev" not in panel and 'class="sev' not in panel


class TestProvenance:
    def test_source_file_and_locator_are_on_the_page(self, tmp_path):
        """The clause that makes 'traceable' checkable, rendered rather than
        left in a file the reader has to open."""
        page = report_html.render(_doc(tmp_path))
        assert "C/Windows/prefetch/EVIL.EXE-1234.pf" in page
        assert "run_slot=0" in page

    def test_every_finding_shows_its_rule_and_technique(self, tmp_path):
        page = report_html.render(_doc(tmp_path))
        assert "R-CORR-0003" in page
        assert "T1547.001" in page

    def test_search_truncation_is_surfaced(self, tmp_path):
        """A reader with only this file would otherwise believe the run was
        complete when a chain may have been missed."""

        class _Stats:
            rules_evaluated = 3
            findings_by_rule = {}
            search_truncated = {"R-CORR-0009"}

        doc = run_json.build(
            collection=tmp_path / "c",
            events=[_event()],
            findings=[_finding()],
            entities=[],
            engine_stats=_Stats(),
        )
        page = report_html.render(doc)
        assert "Search truncated" in page
        assert "R-CORR-0009" in page

    def test_unscored_families_are_shown(self, tmp_path):
        from dfir_triage_pipeline.anomaly import UnscoredFamilies

        families = UnscoredFamilies()
        families.add("registry", "below MIN_TRAINING_ROWS", 8)
        doc = run_json.build(
            collection=tmp_path / "c",
            events=[_event()],
            findings=[_finding()],
            entities=[],
            scores=[_Scored("evil.exe", 2.0)],
            unscored_families=families,
        )
        page = report_html.render(doc)
        assert "registry" in page
        assert "MIN_TRAINING_ROWS" in page


class TestDeterminismAndSafety:
    def test_same_document_renders_identical_bytes(self, tmp_path):
        """The manifest covers the report too."""
        doc = _doc(tmp_path, scores=[_Scored("evil.exe", 2.0)])
        assert report_html.render(doc) == report_html.render(doc)

    def test_html_in_evidence_is_escaped(self, tmp_path):
        """Evidence is attacker-controlled. A path containing a script tag must
        not become one in the report."""
        finding = _finding(entity="<script>alert(1)</script>.exe")
        page = report_html.render(_doc(tmp_path, findings=[finding]))
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;" in page

    def test_empty_findings_says_so_rather_than_rendering_nothing(self, tmp_path):
        doc = run_json.build(
            collection=tmp_path / "c",
            events=[_event()],
            findings=[],
            entities=[],
        )
        page = report_html.render(doc)
        assert "No rule matched" in page
        assert "not an absence of output" in page

    def test_no_scoring_says_a_baseline_is_required(self, tmp_path):
        page = report_html.render(_doc(tmp_path, scores=[]))
        assert "baseline collection from the same host is required" in page.lower()


class TestWrite:
    def test_write_returns_a_hash_and_creates_the_file(self, tmp_path):
        doc = _doc(tmp_path)
        run_path = tmp_path / "run.json"
        run_json.write(doc, run_path)
        out = tmp_path / "report.html"
        digest = report_html.write(run_path, out)
        assert out.is_file()
        assert len(digest) == 64
