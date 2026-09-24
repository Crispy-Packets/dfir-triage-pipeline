#!/usr/bin/env python3
"""Build v1.4.0 run.json fixtures for the DFIR triage viewer.

WHY THIS SCRIPT EXISTS, STATED PLAINLY
--------------------------------------
Person B's Streamlit build brief specifies a ``run.json`` at schema
``1.4.0`` and says a sample is "provided separately". No such file exists
in the repository: ``__main__.py`` writes ``--output`` (timeline),
``--findings``, ``--entities`` and ``--report`` and nothing else. The JSON
writer (B-8) and the ML section dict (B-10 / A-6) are still open
cross-person dependencies. So a real ``run.json`` cannot be produced today.

This script builds a *fixture* that conforms to the v1.4.0 shape so the
viewer can be developed and demonstrated against it. It is explicit about
which fields are real and which are fixture-assigned, because on this
project a document may not assert a state it has not established with a
command.

REAL, taken verbatim from the pipeline's own s1_v2 output
    finding_id, rule_id, category, severity, weight, attack_technique,
    title, time_claim, window_observed_seconds, entity_keys,
    matched_event_ids, and every source event (source_file,
    source_locator, timestamp, timestamp_type) resolved by event_id
    against the real timeline.csv. Entity scores and per-category
    breakdowns come straight from entity_scores.csv.

FIXTURE-ASSIGNED, derived by the documented tables below
    rule_class  (corpus-validated | known-behavior)  -> CLASS_MAP
    phase       (delivery|execute|persist|destroy|exfiltrate) -> PHASE_MAP
    anomalies   (isolation-forest percentiles)  -> synthesised, is_verdict
                false, flagged in _fixture. Real percentiles are B-10/A-6
                output and do not exist yet.
    narration   model-generated text; every citation resolves to a real
                finding_id in this file (the viewer rejects it otherwise).

Nothing here recomputes detection or scoring. It is a pure projection of
frozen CSV output plus two labelling tables, emitted as JSON.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _outputs_dir() -> Path:
    """Locate the pipeline's real per-collection output folders.

    Resolution order, so this runs on any machine:
      1. $DFIR_OUTPUTS if set,
      2. ../dfir-triage-pipeline/outputs relative to this script (repo layout),
      3. the cloud staging path used when these fixtures were first built.
    """
    import os
    candidates = [
        os.environ.get("DFIR_OUTPUTS"),
        HERE.parent / "dfir-triage-pipeline" / "outputs",
        Path("/mnt/user-data/uploads/FYP/dfir-triage-pipeline/outputs"),
    ]
    for c in candidates:
        if c and Path(c).is_dir():
            return Path(c)
    raise SystemExit(
        "Could not find the pipeline outputs. Set DFIR_OUTPUTS to the folder "
        "containing s1_v2/ and clean_a/ (each with findings.csv, "
        "entity_scores.csv, timeline.csv)."
    )


UPLOADS = _outputs_dir()

SCHEMA_VERSION = "1.4.0"

# --- Documented fixture labelling tables -----------------------------------

# rule_class: which detections stand as a verdict (Class 1, corpus-validated)
# and which are context only (Class 2, known-behavior). The split follows the
# project's own Class 1 / Class 2 discipline: multi-signal corpus-justified
# correlations and the specific high-signal atomics are verdict-grade; the
# broad single-signal rules that fire across benign installer activity are
# context. This is a fixture label, NOT a pipeline output field.
CLASS_MAP = {
    "R-CORR-0001": "corpus-validated",   # downloaded file executed
    "R-CORR-0002": "corpus-validated",   # auth failure -> success
    "R-CORR-0003": "corpus-validated",   # executed binary also autorun-registered
    "R-CORR-0004": "corpus-validated",   # log clear by principal (user-keyed)
    "R-CORR-0006": "corpus-validated",   # cleared log -> same account kept acting
    "R-ATOMIC-0002": "corpus-validated", # windows event log cleared
    "R-ATOMIC-0003": "corpus-validated", # powershell in-memory download/encode
    "R-ATOMIC-0007": "corpus-validated", # privileged account created
    # context / known-behavior
    "R-CORR-0005": "known-behavior",     # executed once, no surviving audit record
    "R-ATOMIC-0001": "known-behavior",   # process from user-writable location
    "R-ATOMIC-0006": "known-behavior",   # autorun value (common for installers)
}

# phase: kill-chain phase for the v1.4.0 phase axis. Driven by the rule's real
# `category`, with one override where a rule's evidence is delivery-shaped.
CATEGORY_TO_PHASE = {
    "anti_forensics": "destroy",
    "execution_context": "execute",
    "persistence": "persist",
    "privilege_escalation": "persist",
}
PHASE_OVERRIDE = {
    "R-CORR-0001": "delivery",   # download -> execution chain, delivery-anchored
}
PHASE_ORDER = ["delivery", "execute", "persist", "destroy", "exfiltrate"]
SEV_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def rule_class(rule_id: str) -> str:
    return CLASS_MAP.get(rule_id, "known-behavior")


def phase_of(rule_id: str, category: str) -> str:
    return PHASE_OVERRIDE.get(rule_id) or CATEGORY_TO_PHASE.get(category, "execute")


def technique_family(technique: str) -> str:
    if not technique:
        return ""
    return technique.split(".")[0]


def kind_of(entity_key: str) -> str:
    return "user" if entity_key == "entity.user" else "binary"


# --- Timeline lookup: event_id -> real source event ------------------------

def load_events(timeline_csv: Path) -> dict[str, dict]:
    events: dict[str, dict] = {}
    with timeline_csv.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            events[row["event_id"]] = {
                "event_id": row["event_id"],
                "timestamp_utc": row["timestamp_utc"],
                "timestamp_type": row["timestamp_type"],
                "source_artifact": row["source_artifact"],
                "event_type": row["event_type"],
                "user": row["user"],
                "path": row["path"],
                "action": row["action"],
                "source_file": row["source_file"],
                "source_locator": row["source_locator"],
                "confidence": row["confidence"],
            }
    return events


def parse_entity_keys(raw: str) -> list[dict]:
    out = []
    for part in [p.strip() for p in raw.split(";") if p.strip()]:
        if "=" in part:
            k, v = part.split("=", 1)
            out.append({"key": k.strip(), "value": v.strip()})
    return out


def parse_breakdown_rules(breakdown: str) -> list[str]:
    # "R-ATOMIC-0006=60(persistence,x1); R-CORR-0001=75(...)" -> [rule_ids]
    return re.findall(r"(R-[A-Z]+-\d+)=", breakdown or "")


# --- Build one run from real CSVs ------------------------------------------

def build_findings(findings_csv: Path, events: dict[str, dict]) -> list[dict]:
    findings = []
    with findings_csv.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            eids = [e for e in (row["matched_event_ids"] or "").split() if e]
            ev_objs = []
            for eid in eids:
                ev = events.get(eid)
                if ev is None:
                    # keep the anchor even if the row is not in the sampled
                    # timeline; never invent its provenance.
                    ev_objs.append({"event_id": eid, "resolved": False})
                else:
                    ev_objs.append({**ev, "resolved": True})
            cat = row["category"]
            rid = row["rule_id"]
            win = row["window_observed_seconds"]
            findings.append({
                "finding_id": row["finding_id"],
                "rule_id": rid,
                "rule_class": rule_class(rid),
                "category": cat,
                "phase": phase_of(rid, cat),
                "severity": row["severity"],
                "weight": int(row["weight"]),
                "title": row["title"],
                "attack_technique": row["attack_technique"],
                "technique_family": technique_family(row["attack_technique"]),
                "first_timestamp_utc": row["first_timestamp_utc"],
                "time_claim": row["time_claim"],
                "window_observed_seconds": (float(win) if win else None),
                "entity_keys": parse_entity_keys(row["entity_keys"]),
                "event_ids": eids,
                "events": ev_objs,
                "provenance": row["provenance"],
                "reason": row["reason"],
            })
    return findings


def build_entities(entities_csv: Path, findings: list[dict]) -> list[dict]:
    by_id = {f["finding_id"]: f for f in findings}
    entities = []
    with entities_csv.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            fids = [x for x in (row["finding_ids"] or "").split() if x]
            fs = [by_id[x] for x in fids if x in by_id]
            sev = max((f["severity"] for f in fs),
                      key=lambda s: SEV_ORDER.get(s, 0), default="low")
            phases = sorted({f["phase"] for f in fs},
                            key=lambda p: PHASE_ORDER.index(p))
            techniques = sorted({f["attack_technique"] for f in fs if f["attack_technique"]})
            rules = parse_breakdown_rules(row["breakdown"]) or \
                sorted({f["rule_id"] for f in fs})
            entities.append({
                "key": row["entity_key"],
                "kind": kind_of(row["entity_key"]),
                "value": row["entity_value"],
                "score": int(row["total_score"]),
                "severity": sev,
                "rule_ids": sorted(set(rules)),
                "rule_count": int(row["rules_contributing"]),
                "techniques": techniques,
                "phase_span": phases,
                "finding_count": int(row["findings_total"]),
                "finding_ids": fids,
                "breakdown": row["breakdown"],
                "category_scores": {
                    "anti_forensics": int(row["anti_forensics"]),
                    "privilege_escalation": int(row["privilege_escalation"]),
                    "execution_context": int(row["execution_context"]),
                    "persistence": int(row["persistence"]),
                },
            })
    return entities


def sort_entities(entities: list[dict]) -> list[dict]:
    """Pipeline multi-key order: severity -> phase_span -> rule_count ->
    score -> alpha. phase_span ranks by its latest (highest-index) phase,
    then by breadth; both descending. Alpha on value ascending, last."""
    def key(e):
        span = e["phase_span"]
        latest = max((PHASE_ORDER.index(p) for p in span), default=-1)
        return (
            -SEV_ORDER.get(e["severity"], 0),
            -latest,
            -len(span),
            -e["rule_count"],
            -e["score"],
            e["value"],
        )
    return sorted(entities, key=key)


def build_anomalies(findings: list[dict], entities: list[dict], collection: str) -> dict:
    """FIXTURE anomaly block. Isolation-forest percentiles per family do not
    exist in the pipeline yet (B-10 / A-6). These percentiles are synthesised
    deterministically from entity scores purely so the prioritisation panel
    has something of the right SHAPE to render; is_verdict is false and the
    block is flagged as fixture. Real values replace this when B ships the
    ML section dict. Percentiles are percentile_in_family, never a raw score
    and never a 0-1 probability, per the UI invariants."""
    # group scored entities by a stand-in family (binary/user), and mark small
    # families unscored to exercise the "not scored" state.
    fam_rows: dict[str, list[dict]] = {}
    for e in entities:
        fam = "evtx.execution" if e["kind"] == "binary" else "evtx.security"
        fam_rows.setdefault(fam, []).append(e)

    MIN_ROWS = 50  # mirrors anomaly.MIN_TRAINING_ROWS intent
    families = {}
    ranked = []
    for fam, rows in sorted(fam_rows.items()):
        scored = len(rows) >= 3  # fixture threshold so the demo has scored data
        if not scored:
            families[fam] = {"scored": False, "n": len(rows),
                             "reason": f"below MIN_TRAINING_ROWS ({MIN_ROWS})"}
            continue
        smax = max(r["score"] for r in rows) or 1
        ents = []
        for r in rows:
            pct = round(100.0 * r["score"] / smax, 1)
            ents.append({
                "key": r["key"], "value": r["value"],
                "percentile_in_family": pct,
                "is_outlier": pct >= 95.0,
            })
            ranked.append({"family": fam, "value": r["value"], "key": r["key"],
                           "percentile_in_family": pct})
        ents.sort(key=lambda x: -x["percentile_in_family"])
        families[fam] = {
            "scored": True, "n": len(rows),
            "outlier_rate": round(sum(e["is_outlier"] for e in ents) / len(ents), 3),
            "entities": ents,
        }
    ranked.sort(key=lambda x: -x["percentile_in_family"])
    return {
        "scorer": "isolation_forest",
        "is_verdict": False,
        "measure": "percentile_in_family",
        "contamination": 0.05,
        "random_seed": 20260830,
        "note": "Prioritisation only. A high percentile means unusual relative "
                "to the family baseline, not malicious.",
        "families": families,
        "top_by_percentile": ranked[:10],
        "_fixture": True,
    }


def counts(findings: list[dict], entities: list[dict]) -> dict:
    from collections import Counter
    return {
        "findings_total": len(findings),
        "findings_by_class": dict(Counter(f["rule_class"] for f in findings)),
        "findings_by_severity": dict(Counter(f["severity"] for f in findings)),
        "findings_by_phase": dict(Counter(f["phase"] for f in findings)),
        "entities_total": len(entities),
        "entities_scored": sum(1 for e in entities if e["score"] > 0),
    }


def assemble(run_id, collection, findings, entities, anomalies, meta, narration=None):
    entities = sort_entities(entities)
    by_kind = {"binary": [], "user": []}
    for e in entities:
        by_kind[e["kind"]].append(e)
    run = {
        "run_json_version": SCHEMA_VERSION,
        "run_id": run_id,
        "collection": collection,
        "generated_by": "viewer/build_fixtures.py",
        "manifest": meta,
        "counts": counts(findings, entities),
        "anomalies": anomalies,
        "entities": entities,
        "entities_by_kind": by_kind,
        "findings": findings,
        "_fixture": {
            "is_fixture": True,
            "real_fields": [
                "finding_id", "rule_id", "category", "severity", "weight",
                "attack_technique", "title", "time_claim",
                "window_observed_seconds", "entity_keys", "event_ids",
                "events.*", "entities.score", "entities.breakdown",
            ],
            "fixture_assigned_fields": [
                "findings.rule_class (CLASS_MAP)",
                "findings.phase (CATEGORY_TO_PHASE + PHASE_OVERRIDE)",
                "anomalies.* (synthesised; real values are B-10/A-6 output)",
                "narration (model-generated, provisional)",
            ],
            "reason": "Pipeline has no JSON writer (B-8) or ML section dict "
                      "(B-10/A-6) yet; this conforms to v1.4.0 for UI work.",
        },
    }
    if narration is not None:
        run["narration"] = narration
    return run


def write_run(run: dict, out_dir: Path) -> str:
    out_dir.mkdir(parents=True, exist_ok=True)
    # run.json (canonical, sorted keys, LF)
    text = json.dumps(run, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    (out_dir / "run.json").write_text(text, encoding="utf-8", newline="\n")

    # findings.csv projection
    fcols = ["finding_id", "rule_id", "rule_class", "phase", "category",
             "severity", "weight", "attack_technique", "technique_family",
             "title", "first_timestamp_utc", "time_claim",
             "window_observed_seconds", "entity_keys", "event_ids"]
    with (out_dir / "findings.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(fcols)
        for f in run["findings"]:
            w.writerow([
                f["finding_id"], f["rule_id"], f["rule_class"], f["phase"],
                f["category"], f["severity"], f["weight"], f["attack_technique"],
                f["technique_family"], f["title"], f["first_timestamp_utc"],
                f["time_claim"],
                "" if f["window_observed_seconds"] is None else f"{f['window_observed_seconds']:.6f}",
                "; ".join(f"{k['key']}={k['value']}" for k in f["entity_keys"]),
                " ".join(f["event_ids"]),
            ])

    # anomalies.csv projection
    with (out_dir / "anomalies.csv").open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["family", "scored", "entity_key", "entity_value",
                    "percentile_in_family", "is_outlier", "scorer"])
        scorer = run["anomalies"]["scorer"]
        for fam, blk in run["anomalies"]["families"].items():
            if not blk.get("scored"):
                w.writerow([fam, "false", "", "", "", "", scorer])
                continue
            for e in blk["entities"]:
                w.writerow([fam, "true", e["key"], e["value"],
                            e["percentile_in_family"], str(e["is_outlier"]).lower(),
                            scorer])

    # manifest.sha256 = SHA-256 of the canonical run.json bytes
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    (out_dir / "manifest.sha256").write_text(
        f"{digest}  run.json\n", encoding="utf-8", newline="\n")
    return digest


def build_scenario():
    coll = "collection_s1_v2"
    events = load_events(UPLOADS / "s1_v2" / "timeline.csv")
    findings = build_findings(UPLOADS / "s1_v2" / "findings.csv", events)
    entities = build_entities(UPLOADS / "s1_v2" / "entity_scores.csv", findings)
    anomalies = build_anomalies(findings, entities, coll)
    meta = {
        "collection": coll,
        "tool": "dfir-triage-pipeline",
        "schema": "rules 1.5.0",
        "events_total": 382,
        "time_range": ["2026-06-20T13:44:00.512871+00:00",
                       "2026-08-23T23:31:48.536586+00:00"],
        "sources": {"evtx.security": 359, "evtx.system": 23},
    }
    # Narration: model-generated, provisional. Every citation below is a real
    # finding_id present in this run; the viewer rejects narration otherwise.
    fid = {f["rule_id"]: f["finding_id"] for f in findings}
    corr3 = next(f["finding_id"] for f in findings if f["rule_id"] == "R-CORR-0003")
    corr1 = next(f["finding_id"] for f in findings if f["rule_id"] == "R-CORR-0001")
    atom2 = next(f["finding_id"] for f in findings if f["rule_id"] == "R-ATOMIC-0002")
    corr6 = next(f["finding_id"] for f in findings if f["rule_id"] == "R-ATOMIC-0002")
    corr6 = next(f["finding_id"] for f in findings if f["rule_id"] == "R-CORR-0006")
    narration = {
        "model": "local-llm (offline)",
        "status": "provisional",
        "generated_utc": "2026-09-22T00:00:00Z",
        "text": (
            "A downloaded binary was executed on the host [[%s]], and a binary "
            "was found registered to run at logon [[%s]] — the pairing the "
            "verdict layer treats as corpus-validated persistence. Separately, "
            "the Windows Security log was cleared [[%s]] and the same account "
            "continued to act afterwards [[%s]]. This description is generated "
            "from the frozen run and adds no findings of its own."
        ) % (corr1, corr3, atom2, corr6),
        "citations": [corr1, corr3, atom2, corr6],
    }
    run = assemble("s1_v2-fixture", coll, findings, entities, anomalies, meta, narration)
    d = write_run(run, HERE / "tests" / "fixtures" / "scenario")
    print("scenario", d, len(findings), "findings", len(entities), "entities")


def build_clean():
    """Synthetic clean baseline: a collection where only benign
    corpus-validated activity was observed. Zero known-behavior findings
    (exercises the empty Context panel) and no critical entity (exercises the
    no-critical Verdict state). Values are illustrative and clearly fixture."""
    coll = "collection_clean_baseline"
    # A handful of benign corpus-validated findings, no critical, no Class 2.
    findings = []
    seed = [
        ("R-CORR-0002", "high", 40, "T1078", "privilege_escalation",
         "A failed logon was followed by a success for the same account",
         "entity.user=analyst", ["b1f0aa11c2d33e44"]),
        ("R-ATOMIC-0007", "high", 40, "T1136.001", "privilege_escalation",
         "A local account was created", "entity.user=svc_backup",
         ["c2e1bb22d3e44f55"]),
        ("R-ATOMIC-0002", "high", 70, "T1070.001", "anti_forensics",
         "Windows event log cleared (scheduled maintenance)",
         "entity.user=admin_local", ["a3d2cc33e4f55006"]),
    ]
    ts = "2026-08-24T09:00:00.000000Z"
    for rid, sev, wt, tech, cat, title, ekey, eids in seed:
        k, v = ekey.split("=", 1)
        findings.append({
            "finding_id": hashlib.sha256((rid + ekey).encode()).hexdigest()[:16],
            "rule_id": rid, "rule_class": rule_class(rid), "category": cat,
            "phase": phase_of(rid, cat), "severity": sev, "weight": wt,
            "title": title, "attack_technique": tech,
            "technique_family": technique_family(tech),
            "first_timestamp_utc": ts, "time_claim": "observed_occurrence",
            "window_observed_seconds": None,
            "entity_keys": [{"key": k, "value": v}],
            "event_ids": eids,
            "events": [{"event_id": e, "resolved": False} for e in eids],
            "provenance": "synthetic clean-baseline fixture event",
            "reason": f"{title} [{v}]",
        })
    # entities from findings
    ent_index: dict[tuple, dict] = {}
    for f in findings:
        for ek in f["entity_keys"]:
            key = (ek["key"], ek["value"])
            e = ent_index.setdefault(key, {
                "key": ek["key"], "kind": kind_of(ek["key"]), "value": ek["value"],
                "score": 0, "severity": "low", "rule_ids": [], "rule_count": 0,
                "techniques": [], "phase_span": [], "finding_count": 0,
                "finding_ids": [], "breakdown": "",
                "category_scores": {"anti_forensics": 0, "privilege_escalation": 0,
                                     "execution_context": 0, "persistence": 0},
            })
            e["score"] += f["weight"]
            e["finding_count"] += 1
            e["finding_ids"].append(f["finding_id"])
            e["rule_ids"] = sorted(set(e["rule_ids"] + [f["rule_id"]]))
            e["rule_count"] = len(e["rule_ids"])
            e["techniques"] = sorted(set(e["techniques"] + [f["attack_technique"]]))
            e["phase_span"] = sorted(set(e["phase_span"] + [f["phase"]]),
                                     key=lambda p: PHASE_ORDER.index(p))
            if SEV_ORDER[f["severity"]] > SEV_ORDER[e["severity"]]:
                e["severity"] = f["severity"]
            e["category_scores"][f["category"]] += f["weight"]
    entities = list(ent_index.values())
    anomalies = build_anomalies(findings, entities, coll)
    meta = {
        "collection": coll, "tool": "dfir-triage-pipeline", "schema": "rules 1.5.0",
        "events_total": 10158,
        "time_range": ["2026-06-20T13:43:25.264433+00:00",
                       "2026-08-24T17:21:37.952731+00:00"],
        "sources": {"evtx.security": 10142, "evtx.system": 16},
        "note": "Synthetic clean baseline fixture (no attack scenario).",
    }
    run = assemble("clean-baseline-fixture", coll, findings, entities, anomalies, meta)
    d = write_run(run, HERE / "tests" / "fixtures" / "clean")
    print("clean", d, len(findings), "findings", len(entities), "entities")


if __name__ == "__main__":
    build_scenario()
    build_clean()
