"""Exports derived from `run.json`, and the SHA-256 manifest over all of them.

Two properties, both structural rather than stylistic.

**The CSVs are derived, not written separately.** `findings.csv` and
`anomalies.csv` are generated from the run document, so they cannot disagree
with it or with the report. Two independent serialisers of the same data drift;
one that reads a canonical source cannot.

**The manifest covers the canonical file and every export.** `groundtruth/`
already carries a SHA-256 manifest for each evidence collection; this extends
the same practice to outputs, so a report can prove which run produced it. The
narration, when it exists, is written back into `run.json` BEFORE the manifest
is computed -- generated content outside the hash coverage is a generated
artifact with no recorded provenance, which is the thing the manifest exists to
prevent.
"""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path
from typing import Any

#: Columns of the derived findings export. Deliberately close to
#: `findings.FINDING_COLUMNS` so an existing consumer is not broken, plus the
#: two columns the run document adds.
FINDINGS_CSV_COLUMNS = (
    "finding_id",
    "rule_id",
    "rule_class",
    "severity",
    "weight",
    "attack_technique",
    "title",
    "first_timestamp_utc",
    "time_claim",
    "window_observed_seconds",
    "entity_keys",
    "matched_event_ids",
    "provenance",
    "reason",
    # From run.json. Named for what it is: a rank, not a severity.
    "anomaly_percentile",
    "anomaly_family",
)

ANOMALIES_CSV_COLUMNS = ("entity", "family", "percentile_in_family")


def _write_csv(rows: list[dict[str, str]], columns: tuple[str, ...], path: Path) -> str:
    """Write a CSV deterministically and return its SHA-256.

    newline="" plus an explicit lineterminator keeps the bytes identical across
    operating systems, matching `timeline.write_csv`. A manifest over
    OS-dependent bytes would fail on the second machine that read it.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_findings_csv(doc: dict[str, Any], path: Path) -> str:
    """Derive `findings.csv` from the run document."""
    rows = []
    for finding in doc["findings"]:
        context = finding.get("anomaly_context") or {}
        entities = context.get("entities") or []
        # The best (lowest) percentile among the finding's entities. A finding
        # naming two entities is as prioritised as its most unusual one.
        best = min(entities, key=lambda e: e["percentile_in_family"], default=None)
        rows.append(
            {
                "finding_id": finding["finding_id"],
                "rule_id": finding["rule_id"],
                "rule_class": finding["rule_class"],
                "severity": finding["severity"],
                "weight": str(finding["weight"]),
                "attack_technique": finding["attack_technique"],
                "title": finding["title"],
                "first_timestamp_utc": finding["first_timestamp_utc"],
                "time_claim": finding["time_claim"],
                "window_observed_seconds": (
                    ""
                    if finding["window_observed_seconds"] is None
                    else f"{finding['window_observed_seconds']:.6f}"
                ),
                "entity_keys": "; ".join(
                    f"{e['key']}={e['value']}" for e in finding["entity_keys"]
                ),
                "matched_event_ids": " ".join(
                    sorted(m["event_id"] for m in finding["matched"])
                ),
                "provenance": " | ".join(
                    f"{m['step'] or m['event_type']}: {m['source_file']} :: "
                    f"{m['source_locator']} @ {m['timestamp_utc']} ({m['timestamp_type']})"
                    for m in finding["matched"]
                ),
                "reason": finding["reason"],
                "anomaly_percentile": (
                    "" if best is None else f"{best['percentile_in_family']:.4f}"
                ),
                "anomaly_family": "" if best is None else best["family"],
            }
        )
    return _write_csv(rows, FINDINGS_CSV_COLUMNS, path)


def write_anomalies_csv(doc: dict[str, Any], path: Path) -> str:
    """Derive `anomalies.csv` from the run document.

    Kept as its own export rather than folded into findings: the prioritisation
    view has to stay visible as a distinct contribution, and most scored
    entities carry no finding at all.
    """
    rows = [
        {
            "entity": a["entity"],
            "family": a["family"],
            "percentile_in_family": f"{a['percentile_in_family']:.4f}",
        }
        for a in doc["anomalies"]["scored_entities"]
    ]
    return _write_csv(rows, ANOMALIES_CSV_COLUMNS, path)


def write_manifest(hashes: dict[str, str], path: Path) -> None:
    """Write the run manifest: one `sha256  filename` line per artifact.

    The format matches `sha256sum` output so it can be verified with a standard
    tool rather than only by this project's own code. A manifest only this
    pipeline can check is a weaker claim than one anybody can.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{hashes[name]}  {name}" for name in sorted(hashes)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def verify_manifest(manifest_path: Path) -> list[tuple[str, str, str]]:
    """Check every file named in a manifest. Returns the mismatches.

    Each mismatch is (filename, expected, actual); `actual` is "MISSING" when
    the file is absent. An empty list means every artifact matches.
    """
    mismatches: list[tuple[str, str, str]] = []
    base = manifest_path.parent
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, _, name = line.partition("  ")
        target = base / name
        if not target.is_file():
            mismatches.append((name, expected, "MISSING"))
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            mismatches.append((name, expected, actual))
    return mismatches
