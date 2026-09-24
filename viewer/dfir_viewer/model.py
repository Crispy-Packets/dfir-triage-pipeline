"""The data layer: reading, validating, and filtering one frozen run.

Pure Python — no Streamlit, no HTML. Everything here is a function of the
loaded run and the analyst's filter choices, so it can be unit-tested directly.
Nothing in this module writes, re-scores, or re-orders the run.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from .contract import (CITE_RE, CURRENT_SCHEMA, LEGACY_SCHEMAS, PHASE_ORDER,  # noqa: F401
                       SEV_ORDER, kind_of, narration_citations)

SUPPORTED_SCHEMA = CURRENT_SCHEMA
RULE_CLASSES = {"corpus-validated", "known-behavior"}

# MITRE ATT&CK technique names for the IDs this pipeline emits.
ATTACK_NAMES = {
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1070.004": "Indicator Removal: File Deletion",
    "T1204.002": "User Execution: Malicious File",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1078": "Valid Accounts",
    "T1136.001": "Create Account: Local Account",
    "T1105": "Ingress Tool Transfer",
    "T1036": "Masquerading",
    "T1041": "Exfiltration Over C2 Channel",
    # Added 2026-09-24 (data only -- no rendering change). The first five were
    # already emitted by existing rules and rendered as a bare ID; the last
    # three belong to the rules added for the Windows Server 2022 test.
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1546.003": "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
    "T1052.001": "Exfiltration Over Physical Medium: Exfiltration over USB",
    "T1110": "Brute Force",
    "T1098": "Account Manipulation",
    "T1490": "Inhibit System Recovery",
    "T1505.003": "Server Software Component: Web Shell",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
}

FILTER_KEYS = ("severity", "phase", "family", "technique", "kinds")


# --------------------------------------------------------------------------- #
# Loading and the contract gate                                               #
# --------------------------------------------------------------------------- #

def _is_fixture_file(p: Path) -> bool:
    try:
        with p.open("rb") as fh:
            return b'"_fixture"' in fh.read(4096)
    except OSError:
        return True


def discover_runs(app_dir: Path) -> dict[str, Path]:
    """Real pipeline runs under <app>/samples/*/run.json, newest name first.
    The old v1.4 fixtures are for the test suite only and are never listed —
    even if a copy is still sitting in samples/."""
    runs: dict[str, Path] = {}
    samples = app_dir / "samples"
    if samples.is_dir():
        for p in sorted(samples.glob("*/run.json"), key=lambda p: p.parent.name,
                        reverse=True):
            if not _is_fixture_file(p):
                runs[p.parent.name] = p
    return runs


def read_manifest(run_path: Path) -> str | None:
    """The hash manifest.sha256 attests for run.json (by file name — the
    manifest lists every shipped file, not only run.json)."""
    from .contract import parse_manifest
    mf = run_path.parent / "manifest.sha256"
    if mf.is_file():
        try:
            return parse_manifest(mf.read_text(encoding="utf-8")).get("run.json")
        except Exception:
            return None
    return None


def validate_run(run) -> list[str]:
    """Structural gate for the v1.4.0 contract. Returns a list of problems;
    an empty list means the file may be rendered. The viewer refuses a run it
    cannot trust rather than drawing a half-empty dashboard — the same
    discipline as the narration citation check."""
    errs: list[str] = []
    if not isinstance(run, dict):
        return ["run.json is not a JSON object"]
    for k in ("run_json_version", "findings", "entities", "anomalies"):
        if k not in run:
            errs.append(f"missing required top-level key: {k}")
    ver = str(run.get("run_json_version", ""))
    if ver and ver != CURRENT_SCHEMA and ver not in LEGACY_SCHEMAS:
        major = ver.split(".")[0]
        if major != CURRENT_SCHEMA.split(".")[0]:
            errs.append(f"run_json_version {ver} is not a 1.x contract this viewer reads")

    an = run.get("anomalies")
    if isinstance(an, dict):
        for k in ("scorer", "is_verdict"):
            if k not in an:
                errs.append(f"anomalies.{k} is required (the scorer must be visible)")
    elif an is not None:
        errs.append("anomalies must be an object")

    fs = run.get("findings")
    if isinstance(fs, list):
        req = ("finding_id", "rule_id", "rule_class", "severity", "phase")
        for i, f in enumerate(fs):
            if not isinstance(f, dict):
                errs.append(f"findings[{i}] is not an object")
            else:
                miss = [k for k in req if k not in f]
                if miss:
                    errs.append(f"findings[{i}] missing {miss}")
                bad_t = [k for k in req if k in f and not isinstance(f[k], str)]
                if bad_t:
                    errs.append(f"findings[{i}] fields must be strings: {bad_t}")
            if len(errs) > 10:
                errs.append("… (further finding errors suppressed)")
                break
        bad = {f.get("rule_class") for f in fs if isinstance(f, dict)} - RULE_CLASSES
        bad.discard(None)
        if bad:
            errs.append(f"unknown rule_class value(s): {sorted(map(str, bad))}; "
                        f"allowed: {sorted(RULE_CLASSES)}")
    elif fs is not None:
        errs.append("findings must be a list")

    ents = run.get("entities")
    if ents is not None and not isinstance(ents, list):
        errs.append("entities must be a list")
    elif isinstance(ents, list) and any(not isinstance(e, dict) for e in ents):
        errs.append("every entity must be an object")
    c = run.get("counts")
    if c is not None and not isinstance(c, dict):
        errs.append("counts must be an object")
    return errs


def as_int(v) -> int:
    """A count from the file, or 0 if it is not a number (never trusted blindly)."""
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


# --------------------------------------------------------------------------- #
# Filtering — pure projections, never a mutation                              #
# --------------------------------------------------------------------------- #

def empty_filter() -> dict:
    return {"severity": [], "phase": [], "family": [], "technique": [],
            "kinds": [], "query": "", "days": None}


def finding_day(f) -> str:
    return str(f.get("first_timestamp_utc") or "")[:10]


def is_timed(f) -> bool:
    """time_claim "none" means the event records existence, not when it
    happened — such a finding has no place on a time axis."""
    return str(f.get("time_claim", "")) != "none"


def timed(findings) -> list:
    return [f for f in findings if is_timed(f)]


def run_days(findings) -> list[str]:
    """Every calendar day from the first finding to the last (ISO strings)."""
    from datetime import date, timedelta
    ds = []
    for f in timed(findings):
        try:
            ds.append(date.fromisoformat(finding_day(f)))
        except ValueError:
            continue
    if not ds:
        return []
    lo, hi = min(ds), max(ds)
    return [(lo + timedelta(n)).isoformat() for n in range((hi - lo).days + 1)]


def finding_matches(f, flt) -> bool:
    if flt["severity"] and f.get("severity") not in flt["severity"]:
        return False
    if flt["phase"] and f.get("phase") not in flt["phase"]:
        return False
    if flt["family"] and f.get("technique_family") not in flt["family"]:
        return False
    if flt["technique"] and f.get("attack_technique") not in flt["technique"]:
        return False
    if flt["kinds"]:
        ekinds = {kind_of(k.get("key")) for k in f.get("entity_keys", [])
                  if isinstance(k, dict)}
        if not (ekinds & set(flt["kinds"])):
            return False
    days = flt.get("days")
    if days:
        if not is_timed(f):
            return False  # no time claim: it cannot sit inside a date range
        d = finding_day(f)
        if not d or not (days[0] <= d <= days[1]):
            return False
    q = flt["query"].strip().lower()
    if q:
        hay = " ".join([
            str(f.get("rule_id", "")), str(f.get("attack_technique", "")),
            str(f.get("title", "")),
            " ".join(f"{k.get('key')}={k.get('value')}" for k in f.get("entity_keys", [])),
        ]).lower()
        if q not in hay:
            return False
    return True


def entity_matches(e, flt) -> bool:
    if flt["severity"] and e.get("severity") not in flt["severity"]:
        return False
    if flt["kinds"] and e.get("kind") not in flt["kinds"]:
        return False
    if flt["phase"] and not (set(flt["phase"]) & set(e.get("phase_span", []))):
        return False
    if flt["family"]:
        fams = {t.split(".")[0] for t in e.get("techniques", [])}
        if not (fams & set(flt["family"])):
            return False
    if flt["technique"] and not (set(flt["technique"]) & set(e.get("techniques", []))):
        return False
    q = flt["query"].strip().lower()
    if q:
        hay = " ".join([str(e.get("value", "")), " ".join(e.get("rule_ids", [])),
                        " ".join(e.get("techniques", []))]).lower()
        if q not in hay:
            return False
    return True


def active_filter_count(flt) -> int:
    return (sum(1 for k in FILTER_KEYS if flt[k])
            + (1 if flt["query"].strip() else 0)
            + (1 if flt.get("days") else 0))


def apply_filters(entities, findings, flt):
    """(matching entities, matching findings). A date range narrows entities to
    those with at least one finding inside it — entities carry no time."""
    ffind = [f for f in findings if finding_matches(f, flt)]
    fent = [e for e in entities if entity_matches(e, flt)]
    if flt.get("days"):
        in_range = {f["finding_id"] for f in findings
                    if finding_matches(f, {**empty_filter(), "days": flt["days"]})}
        fent = [e for e in fent if in_range & set(e.get("finding_ids", []))]
    return fent, ffind


def _class_scoped(findings_by_id, rule_class):
    return {k: v for k, v in findings_by_id.items()
            if v.get("rule_class") == rule_class}


def activity_rows(findings) -> list[dict]:
    """The activity chart as a table: one row per active day."""
    from collections import defaultdict
    by = defaultdict(lambda: defaultdict(int))
    for f in timed(findings):
        d = finding_day(f)
        if d:
            by[d][f.get("severity", "info")] += 1
    rows = []
    for d in sorted(by):
        c = by[d]
        rows.append({"day": d, "critical": c["critical"], "high": c["high"],
                     "medium": c["medium"], "low": c["low"],
                     "total": sum(c.values())})
    return rows


# --------------------------------------------------------------------------- #
# Export — built in memory, never written to disk                             #
# --------------------------------------------------------------------------- #

VIEW_COLUMNS = ["finding_id", "rule_id", "rule_class", "severity", "phase",
                "attack_technique", "title", "first_timestamp_utc", "weight",
                "entity_keys", "event_ids"]

_FORMULA_LEAD = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(v) -> str:
    """Neutralise spreadsheet formula injection: evidence strings are
    attacker-controlled, and a cell starting with = + - @ runs as a formula
    when the export is opened in Excel. Prefix a quote so it stays text."""
    s = "" if v is None else str(v)
    return "'" + s if s.startswith(_FORMULA_LEAD) else s


def findings_csv(findings: list[dict]) -> bytes:
    """Serialise findings to CSV in memory for a browser download."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(VIEW_COLUMNS)
    for f in findings:
        w.writerow([_csv_safe(x) for x in (
            f.get("finding_id", ""), f.get("rule_id", ""), f.get("rule_class", ""),
            f.get("severity", ""), f.get("phase", ""), f.get("attack_technique", ""),
            f.get("title", ""), f.get("first_timestamp_utc", ""), f.get("weight", ""),
            "; ".join(f"{k.get('key')}={k.get('value')}" for k in f.get("entity_keys", [])),
            " ".join(f.get("event_ids", [])),
        )])
    return buf.getvalue().encode("utf-8")
