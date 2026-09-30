"""Invariant tests for the DFIR Triage Viewer.

These encode the guarantees the viewer must never break — the same discipline
the pipeline applies to itself: a claim is only as good as the command that
proves it. Run with:  pytest tests/ -q

They use Streamlit's AppTest harness (executes app.py in-process and surfaces
exceptions) plus direct calls to the pure functions.

Runs under test:
  samples/s1_v3            the real pipeline output (run.json v1.5.0, moda_g)
  tests/fixtures/scenario  legacy v1.4.0 fixture (kept to prove back-compat)
  tests/fixtures/clean     legacy v1.4.0 synthetic clean baseline
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / "app.py"
REAL = ROOT / "samples" / "s1_v3" / "run.json"
SCENARIO = ROOT / "tests" / "fixtures" / "scenario" / "run.json"
CLEAN = ROOT / "tests" / "fixtures" / "clean" / "run.json"
RUNS = {"s1_v3": REAL, "scenario": SCENARIO, "clean": CLEAN}
PANELS = ["All", "Verdict", "Context", "Prioritisation", "Narrative", "Downloads", "Guide"]


def _load_app_module():
    spec = importlib.util.spec_from_file_location("dfir_app", APP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


app = _load_app_module()
from dfir_viewer import components, contract  # noqa: E402


def _app(monkeypatch, run="s1_v3", light=False, qp=None):
    """Start the app on a run. The real run is the default sample; the legacy
    fixtures load through DFIR_RUN, the UI-less path."""
    if run == "s1_v3":
        monkeypatch.delenv("DFIR_RUN", raising=False)
    else:
        monkeypatch.setenv("DFIR_RUN", str(RUNS[run]))
    at = AppTest.from_file(str(APP), default_timeout=90)
    for k, v in (qp or {}).items():
        at.query_params[k] = v
    at.run()
    if light:
        [t for t in at.toggle if t.label == "Light"][0].set_value(True).run()
    return at


def _nav(at):
    for r in list(at.sidebar.radio) + list(at.radio):
        if r.label == "Navigation":
            return r
    raise AssertionError("navigation radio not found")


def _panel(at, name):
    return _nav(at).set_value(name).run()


def _rows(v):
    if v is None:
        return []
    return v.to_dict("records") if isinstance(v, pd.DataFrame) else list(v)


def _md(at):
    return " ".join(m.value for m in at.markdown) + " " + " ".join(
        m.value for m in at.sidebar.markdown)


def _write(tmp_path, run, name="run.json"):
    p = tmp_path / name
    p.write_text(json.dumps(run))
    return p


def _real():
    return json.loads(REAL.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Boot and the one rule                                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("run", ["s1_v3", "scenario", "clean"])
@pytest.mark.parametrize("light", [False, True])
@pytest.mark.parametrize("panel", PANELS)
def test_boots_every_panel_every_run_both_themes(monkeypatch, run, light, panel):
    at = _app(monkeypatch, run, light)
    _panel(at, panel)
    assert not at.exception, f"{run}/{panel}/light={light}: {at.exception}"


SOURCES = [APP, *sorted((ROOT / "dfir_viewer").glob("*.py"))]


def test_source_has_no_write_path():
    """No code path in the app or its package may write, delete, or dump."""
    assert len(SOURCES) >= 6
    for path in SOURCES:
        src = path.read_text(encoding="utf-8")
        assert not re.search(r"open\([^)]*['\"][wax]", src), f"{path.name}: write-mode open()"
        for bad in ("write_text", "write_bytes", "json.dump(", "os.remove",
                    "shutil.rmtree", ".unlink(", ".to_csv(", "shutil.copy"):
            assert bad not in src, f"{path.name}: forbidden write call {bad}"


def test_real_run_is_the_default_and_fixtures_are_never_listed(tmp_path):
    """Only real pipeline output is offered in the UI — a legacy fixture left
    in samples/ stays hidden."""
    (tmp_path / "samples").mkdir()
    shutil.copytree(REAL.parent, tmp_path / "samples" / "s1_v3")
    shutil.copytree(SCENARIO.parent, tmp_path / "samples" / "scenario")
    assert list(app.discover_runs(tmp_path)) == ["s1_v3"]
    assert list(app.discover_runs(ROOT))[0] == "s1_v3"


# --------------------------------------------------------------------------- #
# The v1.5 contract                                                           #
# --------------------------------------------------------------------------- #

def test_schema_accepts_real_and_legacy_rejects_malformed():
    assert app.validate_run(_real()) == []
    assert app.validate_run(json.loads(SCENARIO.read_text())) == []
    assert app.validate_run(json.loads(CLEAN.read_text())) == []
    bad = _real()
    del bad["anomalies"]["scorer"]
    assert any("scorer" in p for p in app.validate_run(bad))
    bad2 = _real()
    bad2["findings"][0]["rule_class"] = "made-up-class"
    assert any("rule_class" in p for p in app.validate_run(bad2))
    bad3 = _real()
    bad3["findings"][0]["severity"] = ["critical"]
    assert any("must be strings" in p for p in app.validate_run(bad3))


def test_rejected_run_stops_render(tmp_path, monkeypatch):
    bad = _real()
    del bad["anomalies"]["scorer"]
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, bad)))
    at = AppTest.from_file(str(APP), default_timeout=90).run()
    md = _md(at)
    assert "RUN REJECTED" in md and "Priority" not in md


def test_normalize_maps_v15_fields():
    v = contract.normalize_run(_real())
    assert v["collection"] == "collection_s1_v3" and v["version"] == "1.5.0"
    f = v["findings"][0]
    assert f["events"] and f["event_ids"] == [e["event_id"] for e in f["events"]]
    inv = next(e for e in v["entities"] if e["value"] == "invoice_scan.exe")
    assert inv["kind"] == "file" and inv["score"] == 99 and inv["raw_sum"] == 225
    assert isinstance(inv["phase_span"], list) and len(inv["phase_span"]) == 2
    assert v["counts"]["findings_total"] == 132


def test_scorer_is_read_from_the_file_not_hardcoded(tmp_path, monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Prioritisation"})
    assert "moda_g" in _md(at)
    run = _real()
    run["anomalies"]["scorer"] = "isolation_forest"
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, run)))
    at2 = AppTest.from_file(str(APP), default_timeout=90)
    at2.query_params["view"] = "Prioritisation"
    at2.run()
    md = _md(at2)
    assert "isolation_forest" in md and "moda_g" not in md


def test_prioritisation_lists_ranking_and_unscored_families(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Prioritisation"})
    rows = _rows(at.dataframe[0].value)
    assert len(rows) == 443 and rows[0]["entity"] == "dllhost.exe" and rows[0]["position"] == 1
    assert rows[0]["in family"] == "1 of 99"
    assert "0 = most unusual" in _md(at)


def test_case_file_shows_triage_score_and_separate_anomaly_rank(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Verdict", "entity": "invoice_scan.exe"})
    md = _md(at)
    assert "<div class='cf-name'>invoice_scan.exe</div>" in md
    assert "Raw sum of rule weights <b>225</b> → triage score <b>99</b>" in md
    assert "Position <b>14</b> of 443" in md and "<b>5 of 344</b> within" in md
    assert "not a verdict" in md
    assert "the 4 Class 2 context finding(s) that name it do not add to it" in md


def test_severity_is_labelled_as_rule_weight(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Guide"})
    assert ("Severity is the weight of the rules that matched, not an assessment "
            "of the entity.") in _md(at)
    at2 = _app(monkeypatch, "s1_v3", qp={"view": "Verdict"})
    assert "triage score" in at2.dataframe[0].value.columns


def test_verdict_and_context_never_share_a_finding():
    v = contract.normalize_run(_real())
    verdict = app._class_scoped(v["by_id"], "corpus-validated")
    context = app._class_scoped(v["by_id"], "known-behavior")
    assert set(verdict).isdisjoint(context)
    assert set(verdict) | set(context) == set(v["by_id"])
    assert len(verdict) == 6


def test_context_groups_unlisted_entities_without_scoring_them():
    v = contract.normalize_run(_real())
    grouped = v["grouped"]
    assert grouped and all(g["score"] is None and not g["listed"] for g in grouped)
    listed = {(e["key"], e["value"]) for e in v["entities"]}
    assert not any((g["key"], g["value"]) in listed for g in grouped)


def test_clean_run_has_empty_context(monkeypatch):
    at = _app(monkeypatch, "clean", qp={"view": "Context"})
    assert "no Class 2" in " ".join(getattr(s, "value", "") for s in at.success)


# --------------------------------------------------------------------------- #
# Manifest — every attested file                                              #
# --------------------------------------------------------------------------- #

def test_manifest_lists_every_file_and_absent_is_not_mismatch():
    attested, results = contract.read_manifest_dir(REAL)
    assert set(attested) == {"anomalies.csv", "findings.csv", "report.html", "run.json"}
    assert results["run.json"] == results["findings.csv"] == "verified"
    assert results["report.html"] in ("verified", "absent")
    assert app.read_manifest(REAL) == attested["run.json"]
    legacy = contract.parse_manifest("a" * 64 + "\n")
    assert legacy == {"run.json": "a" * 64}


def test_manifest_verified_banner_on_real_run(monkeypatch):
    md = _md(_app(monkeypatch, "s1_v3"))
    assert "Manifest verified" in md and "run.json hash matches" in md


@pytest.mark.parametrize("victim", ["run.json", "findings.csv"])
def test_any_tampered_file_trips_mismatch(tmp_path, monkeypatch, victim):
    shutil.copytree(REAL.parent, tmp_path / "r")
    p = tmp_path / "r" / victim
    p.write_bytes(p.read_bytes().replace(b"invoice_scan.exe", b"invoice_scan.exf", 1))
    monkeypatch.setenv("DFIR_RUN", str(tmp_path / "r" / "run.json"))
    at = AppTest.from_file(str(APP), default_timeout=90).run()
    assert "Manifest mismatch" in _md(at)


def test_upload_bundle_verification_is_pure():
    attested = contract.parse_manifest((REAL.parent / "manifest.sha256").read_text())
    files = {"run.json": REAL.read_bytes(), "findings.csv": b"tampered"}
    res = contract.verify_manifest(attested, {n: files.get(n) for n in attested})
    assert res == {"run.json": "verified", "findings.csv": "mismatch",
                   "anomalies.csv": "absent", "report.html": "absent"}


# --------------------------------------------------------------------------- #
# Narration — shown only when accepted and re-checked; never a verdict        #
# --------------------------------------------------------------------------- #

GOOD_NARRATION = (
    "invoice_scan.exe has the highest triage score in this run (99, critical), from "
    "three corpus-validated rules. It was executed (last run 2026-09-13 11:50 UTC) and "
    "is registered to run at logon for user vboxuser under Run\\SecurityUpdate "
    "(R-CORR-0003). The autorun value points at a user-writable path or an interpreter "
    "(R-ATOMIC-0006), and an autorun-registered executable was sent to the Recycle Bin "
    "(R-CORR-0006). The Security event log on winvm was cleared at 12:15 UTC "
    "(R-ATOMIC-0002). In the moda_g anomaly ranking, which measures unusualness and is "
    "not a detection, invoice_scan.exe is rank 14 of 443.")


def _good_narration_run():
    run = _real()
    run["narration"]["text"] = GOOD_NARRATION
    run["narration"]["validation"]["citations"] = {
        "exes": ["invoice_scan.exe"],
        "rule_ids": ["R-ATOMIC-0002", "R-ATOMIC-0006", "R-CORR-0003", "R-CORR-0006"]}
    return run


def test_shipped_narration_is_withheld_by_the_relation_check(monkeypatch):
    """The sample's accepted narration says invoice_scan.exe is ranked first and
    reads percentile 0 as less suspicious; run.json says rank 14 and 0 = most
    unusual. The viewer must not show it."""
    at = _app(monkeypatch, "s1_v3", qp={"view": "Narrative"})
    md = _md(at)
    assert "NARRATION REJECTED" in md and "position 14 of 443" in md
    assert "AI-GENERATED" not in md and "This file is ranked first" not in md


def test_accepted_narration_renders_labelled_with_the_record(tmp_path, monkeypatch):
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, _good_narration_run())))
    at = AppTest.from_file(str(APP), default_timeout=90)
    at.query_params["view"] = "Narrative"
    at.run()
    md = _md(at)
    assert "AI-GENERATED · NOT A VERDICT" in md and "qwen2.5:7b" in md
    assert "not proof the prose is right" in md
    claims = _rows(at.dataframe[0].value)
    inv = next(r for r in claims if r["cited"] == "invoice_scan.exe")
    assert inv["anomaly ranking"].startswith("rank 14 of 443 · 5 of 344 in amcache")


@pytest.mark.parametrize("bad, why", [
    (" invoice_scan.exe is ranked first by moda_g.", "ranked first/top"),
    (" invoice_scan.exe is rank 3 of 443.", "rank 3"),
    (" Its triage score is 98.", "98"),
    (" dllhost.exe is less suspicious than invoice_scan.exe.", "compares or interprets"),
    (" invoice_scan.exe is ranked 2nd by moda_g.", "rank 2"),
    (" Its triage score is 225.", "score of 225"),
    (" It was detected as malicious.", "verdict word"),
    (" dllhost.exe is rank 1 of 443, meaning they are normal.", "compares or interprets"),
    (" vboxuser is ranked first.", "vboxuser ranked first"),
    (" It has a critical severity score of 99.", "severity a number"),
    (" It has a critical severity of 3.", "severity a number"),
])
def test_relation_check_rejects_each_false_pattern(bad, why):
    """Every pattern here is a way the auditor got false prose past the gate."""
    run = _good_narration_run()
    run["narration"]["text"] += bad
    if "dllhost" in bad:
        run["narration"]["validation"]["citations"]["exes"].append("dllhost.exe")
    if "vboxuser" in bad:
        pass  # a user name, not an exe: the rank check must still see it
    v = contract.normalize_run(run)
    gate = contract.narration_gate(run, v)
    assert not gate["show"] and why in gate["reason"], gate["reason"]


def test_narration_never_in_the_verdict_panel(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Verdict"})
    assert "AI-GENERATED" not in _md(at)


def test_rejected_narration_shows_nothing_of_its_prose(tmp_path, monkeypatch):
    run = _real()
    run["narration"]["status"] = "rejected"
    run["narration"]["rejected"] = {"text": "SECRET-REJECTED-PROSE"}
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, run)))
    at = AppTest.from_file(str(APP), default_timeout=90)
    at.query_params["view"] = "Narrative"
    at.run()
    md = _md(at)
    assert "NARRATION REJECTED" in md
    assert "SECRET-REJECTED-PROSE" not in md and "invoice_scan.exe` file has been" not in md


def test_viewer_recheck_withholds_unresolvable_citation(tmp_path, monkeypatch):
    run = _good_narration_run()
    run["narration"]["validation"]["citations"]["exes"].append("ghost.exe")
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, run)))
    at = AppTest.from_file(str(APP), default_timeout=90)
    at.query_params["view"] = "Narrative"
    at.run()
    md = _md(at)
    assert "NARRATION REJECTED" in md and "ghost.exe" in md
    assert "AI-GENERATED" not in md


def test_undeclared_rule_in_prose_is_withheld():
    run = _good_narration_run()
    run["narration"]["text"] += " Also R-ATOMIC-0099."
    gate = contract.narration_gate(run, contract.normalize_run(run))
    assert not gate["show"] and "R-ATOMIC-0099" in gate["reason"]


def test_absent_narration_is_the_normal_case(tmp_path, monkeypatch):
    run = _real()
    del run["narration"]
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, run)))
    at = AppTest.from_file(str(APP), default_timeout=90)
    at.query_params["view"] = "Narrative"
    at.run()
    assert not at.exception
    assert any("no narration" in i.value for i in at.info)


def test_legacy_narration_rejected_when_citation_unresolved(tmp_path, monkeypatch):
    run = json.loads(SCENARIO.read_text())
    run["narration"]["citations"].append("deadbeefdeadbeef")
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, run)))
    at = AppTest.from_file(str(APP), default_timeout=90)
    at.query_params["view"] = "Narrative"
    at.run()
    md = _md(at)
    assert "NARRATION REJECTED" in md and "downloaded binary was executed" not in md


def test_narration_text_is_escaped(tmp_path, monkeypatch):
    run = _good_narration_run()
    run["narration"]["text"] = "<b>bold</b> " + run["narration"]["text"]
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, run)))
    at = AppTest.from_file(str(APP), default_timeout=90)
    at.query_params["view"] = "Narrative"
    at.run()
    md = _md(at)
    assert "&lt;b&gt;bold" in md and "<b>bold</b>" not in md


# --------------------------------------------------------------------------- #
# Time claims, filters, dates                                                 #
# --------------------------------------------------------------------------- #

def test_presence_only_findings_are_not_plotted_in_time():
    run = _real()
    untimed = [f for f in run["findings"] if f["time_claim"] == "none"]
    assert untimed
    svg = app.activity_timeline(run["findings"])
    days = {f["first_timestamp_utc"][:10] for f in run["findings"] if f["time_claim"] != "none"}
    assert svg.count("class='tl-day'") == len(days)
    total = sum(r["total"] for r in app.activity_rows(run["findings"]))
    assert total == len(run["findings"]) - len(untimed)
    assert "No timestamped findings" in app.activity_timeline([])


def test_date_range_excludes_untimed_and_narrows_entities():
    v = contract.normalize_run(_real())
    days = app.run_days(v["findings"])
    flt = {**app.empty_filter(), "days": (days[-1], days[-1])}
    fent, ffind = app.apply_filters(v["all_entities"], v["findings"], flt)
    assert ffind and all(f["time_claim"] != "none" for f in ffind)
    assert all(f["first_timestamp_utc"][:10] == days[-1] for f in ffind)
    ids = {f["finding_id"] for f in ffind}
    assert fent and all(ids & set(e["finding_ids"]) for e in fent)


def test_filters_actually_filter_unit():
    FL = lambda **k: {**app.empty_filter(), **k}  # noqa: E731
    crit = {"severity": "critical", "kind": "binary", "phase_span": ["persist"],
            "techniques": ["T1547.001"], "value": "invoice_scan.exe",
            "rule_ids": ["R-CORR-0003"]}
    usr = {"severity": "high", "kind": "user", "phase_span": ["destroy"],
           "techniques": ["T1070.001"], "value": "vboxuser", "rule_ids": ["R-ATOMIC-0002"]}
    assert app.entity_matches(crit, FL(severity=["critical"]))
    assert not app.entity_matches(usr, FL(severity=["critical"]))
    assert app.entity_matches(usr, FL(kinds=["user"]))
    assert app.entity_matches(crit, FL(family=["T1547"]))
    assert app.entity_matches(crit, FL(query="invoice"))
    assert not app.entity_matches(usr, FL(query="invoice"))


def test_filters_narrow_verdict_table_live(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Verdict"})
    before = len(_rows(at.dataframe[0].value))
    [m for m in at.sidebar.multiselect if m.label == "Priority"][0] \
        .set_value(["critical"]).run()
    after = _rows(at.dataframe[0].value)
    assert 0 < len(after) < before
    assert {r["band"] for r in after} == {"critical"}


def test_active_filter_collapses_overview(monkeypatch):
    at = _app(monkeypatch)
    assert "Priority" in _md(at)
    [m for m in at.sidebar.multiselect if m.label == "Priority"][0] \
        .set_value(["critical"]).run()
    md = _md(at)
    assert "Priority <span" not in md and "Filtered results" in md


# --------------------------------------------------------------------------- #
# Hostile evidence, exports                                                   #
# --------------------------------------------------------------------------- #

SPOOF = ("x</span><div class='banner banner-ok' id='spoof'><span class='seal'>"
         "</span>Manifest verified</div><img src=x onerror=alert(1)>")


def _hostile_run(tmp_path):
    run = _real()
    run["collection"]["name"] = SPOOF
    run["entities"][0]["value"] = SPOOF
    f = next(f for f in run["findings"] if f["finding_id"] in run["entities"][0]["finding_ids"])
    f["title"] = SPOOF
    f["reason"] = SPOOF
    f["notes"] = [SPOOF]
    for ev in f["matched"]:
        ev["source_file"] = SPOOF
    run["anomalies"]["scorer"] = SPOOF
    run["anomalies"]["scored_entities"][0]["entity"] = SPOOF
    return _write(tmp_path, run)


@pytest.mark.parametrize("panel", ["All", "Verdict", "Prioritisation", "Narrative"])
def test_hostile_evidence_is_escaped_everywhere(tmp_path, monkeypatch, panel):
    """A run.json cannot draw its own UI: markup in evidence renders as text."""
    monkeypatch.setenv("DFIR_RUN", str(_hostile_run(tmp_path)))
    at = AppTest.from_file(str(APP), default_timeout=90).run()
    _panel(at, panel)
    assert not at.exception
    md = _md(at)
    assert "id='spoof'" not in md and "<img src=x" not in md
    assert "&lt;div class=&#x27;banner banner-ok&#x27; id=&#x27;spoof&#x27;" in md


def test_components_escape_directly():
    v = contract.normalize_run(_real())
    evil = {"value": SPOOF, "kind": "binary", "severity": "critical", "score": 5,
            "rule_count": 1, "finding_count": 1, "phase_span": ["<b>x</b>"],
            "techniques": ["<i>T</i>"], "rule_ids": ["<r>"], "finding_ids": []}
    for out in (components.case_file(evil, v), components.priority_list([evil])):
        assert "<img" not in out and "id='spoof'" not in out
        assert "<b>x</b>" not in out and "<i>T</i>" not in out


def test_view_export_is_exact_and_in_memory():
    run = _real()
    crit = [f for f in run["findings"] if f["severity"] == "critical"]
    v = contract.normalize_run(run)
    data = app.findings_csv([v["by_id"][f["finding_id"]] for f in crit]) \
        .decode("utf-8").strip().split("\n")
    assert data[0].split(",")[:3] == ["finding_id", "rule_id", "rule_class"]
    assert {row.split(",")[0] for row in data[1:]} == {f["finding_id"] for f in crit}


def test_csv_export_neutralises_formulas():
    evil = {"finding_id": "=HYPERLINK(\"http://x\",\"a\")", "rule_id": "+1",
            "title": "@SUM(A1)", "severity": "-2", "entity_keys": [], "event_ids": []}
    row = app.findings_csv([evil]).decode().splitlines()[1]
    for cell in ("'=HYPERLINK", "'+1", "'@SUM(A1)", "'-2"):
        assert cell in row


def test_malformed_values_are_tolerated(tmp_path, monkeypatch):
    run = _real()
    run["anomalies"]["scored_entities"][0]["percentile_in_family"] = "lots"
    run["entities"][0]["raw_sum"] = None
    run["rules"]["findings_by_rule"]["R-ATOMIC-0016"] = "many"
    monkeypatch.setenv("DFIR_RUN", str(_write(tmp_path, run)))
    at = AppTest.from_file(str(APP), default_timeout=90).run()
    for p in PANELS:
        _panel(at, p)
        assert not at.exception, p


# --------------------------------------------------------------------------- #
# Links, keys, styles                                                         #
# --------------------------------------------------------------------------- #

def test_url_restores_view_and_filters(monkeypatch):
    at = _app(monkeypatch, qp={"view": "Verdict", "sev": ["critical"]})
    assert not at.exception and _nav(at).value == "Verdict"
    rows = _rows(at.dataframe[0].value)
    assert rows and {r["band"] for r in rows} == {"critical"}


def test_url_entity_opens_its_case_file(monkeypatch):
    at = _app(monkeypatch, qp={"view": "Verdict", "entity": "vboxuser"})
    assert "<div class='cf-name'>vboxuser</div>" in _md(at)


def test_share_link_reflects_state(monkeypatch):
    at = _app(monkeypatch)
    _panel(at, "Context")
    [m for m in at.sidebar.multiselect if m.label == "Priority"][0] \
        .set_value(["high"]).run()
    link = at.sidebar.code[0].value
    assert "view=Context" in link and "sev=high" in link


def test_keyboard_shortcuts_drive_nav_theme_and_clear(monkeypatch):
    at = _app(monkeypatch)
    [b for b in at.button if b.key == "k_Guide"][0].click().run()
    assert _nav(at).value == "Guide"
    [b for b in at.button if b.key == "k_theme"][0].click().run()
    assert [t for t in at.toggle if t.label == "Light"][0].value is True
    [m for m in at.sidebar.multiselect if m.label == "Priority"][0] \
        .set_value(["critical"]).run()
    [b for b in at.button if b.key == "k_clear"][0].click().run()
    assert [m for m in at.sidebar.multiselect if m.label == "Priority"][0].value == []


def test_stylesheet_uses_no_generated_class_names():
    css = (ROOT / "dfir_viewer" / "styles.css").read_text(encoding="utf-8")
    css += (ROOT / "dfir_viewer" / "theme.py").read_text(encoding="utf-8")
    assert "st-emotion-cache" not in css
    assert not re.search(r"\.e[0-9a-z]{5,}\d\b|class\*=\"e[0-9a-z]", css)


# --------------------------------------------------------------------------- #
# False-positive framing: Class 2 never reads as Class 1                      #
# --------------------------------------------------------------------------- #

def test_phases_fill_only_from_class1():
    v = contract.normalize_run(_real())
    html = components.killchain_bar(v["findings"])
    # exfiltrate has 11 findings, all Class 2 → hollow node, count 0, "+11 context"
    cell = html.split("exfiltrate:")[1].split("</div></div>")[0]
    assert "0 class 1, 11 class 2" in html and "kc-node on" not in cell
    assert "+11 context" in html


def test_attack_tiles_count_class1_and_mark_context_only():
    v = contract.normalize_run(_real())
    html = components.attack_strip(v["findings"])
    t1041 = html.split("title='T1041")[1].split("</div>\n")[0]
    assert "0 class 1, 11 class 2" in t1041
    assert "<div class='att ctx' title='T1041" in html
    assert "not a judgement about any file" in html


def test_listed_entity_context_findings_are_reachable(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Context", "entity": "invoice_scan.exe"})
    md = _md(at)
    assert "<div class='cf-name'>invoice_scan.exe</div>" in md
    assert "Executable downloaded to a user-writable location" in md


def test_presence_only_findings_listed_after_timed_ones(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Verdict", "entity": "invoice_scan.exe"})
    md = _md(at)
    a = md.index("With an event time"); b = md.index("Presence only — no event time")
    assert a < b


def test_no_binary_label_for_file_names():
    v = contract.normalize_run(_real())
    kinds = {e["kind"] for e in v["all_entities"]}
    assert "binary" not in kinds and "file" in kinds


def test_guide_describes_score_and_class_without_overclaiming(monkeypatch):
    md = _md(_app(monkeypatch, "s1_v3", qp={"view": "Guide"}))
    assert "stands as evidence" not in md
    assert "the sum of the weights of the rules that fired" not in md
    assert "225 → 99" in md and "0 is the most unusual of its kind" in md


def test_relation_check_accepts_true_and_negated_statements():
    run = _good_narration_run()
    run["narration"]["text"] += (" invoice_scan.exe is not malicious by itself as far as "
                                 "the rules can say; they report matches.")
    gate = contract.narration_gate(run, contract.normalize_run(run))
    assert gate["show"], gate["reason"]


def test_tied_percentiles_share_a_family_position():
    v = contract.normalize_run(_real())
    a = contract.anomaly_of(v, "gamebarelevatedft.exe")
    assert components.fam_pos(a) == "=7 of 344 (5 tied)"


def test_context_table_describes_context_findings_only(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Context"})
    rows = {r["entity"]: r for r in _rows(at.dataframe[0].value)}
    one = rows["onedrive.exe"]
    assert "triage score" not in one
    assert one["findings here"] == 5 and "T1041" in one["techniques"]
    assert list(rows)[0] != "invoice_scan.exe"  # not ordered by triage score


def test_entity_link_not_on_page_says_so(monkeypatch):
    at = _app(monkeypatch, "s1_v3", qp={"view": "Context", "entity": "winvm"})
    assert "winvm has no findings on this page" in _md(at)


def test_technique_beside_a_file_shows_parent_name_only(monkeypatch):
    at = _app(monkeypatch, "s1_v3",
              qp={"view": "Verdict", "entity": "npp.8.9.8.installer.x64.exe"})
    md = _md(at)
    cf = md.split("<div class='cf-name'>npp.8.9.8.installer.x64.exe</div>")[1]
    visible = re.sub(r"title='[^']*'", "", cf)
    assert "T1204.002" in visible and "Malicious File" not in visible


def test_sidebar_can_always_be_reopened():
    """The re-open button (stExpandSidebarButton) lives inside stToolbar:
    hiding the toolbar once left a collapsed sidebar with no way back."""
    css = (ROOT / "dfir_viewer" / "styles.css").read_text(encoding="utf-8")
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)   # comments may name it
    css = re.sub(r"@import[^;]*;", "", css)
    for rule in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        selectors, body = rule
        if "display:none" in body.replace(" ", ""):
            assert "stToolbar" not in selectors, selectors.strip()
            assert "stExpandSidebarButton" not in selectors, selectors.strip()
    assert "[data-testid=\"stExpandSidebarButton\"]{ display:flex !important" in css


def test_toolbar_never_blocks_clicks_and_sidebar_starts_open():
    """The visible toolbar once covered the Light toggle when the sidebar was
    closed; and the viewer must open with the sidebar shown at any width."""
    css = (ROOT / "dfir_viewer" / "styles.css").read_text(encoding="utf-8")
    assert re.search(r'\[data-testid="stToolbar"\] \*\{ pointer-events:none', css)
    assert re.search(r'stExpandSidebarButton"\] \*\{ pointer-events:auto', css)
    assert 'initial_sidebar_state="expanded"' in APP.read_text(encoding="utf-8")
