"""Writing findings out, and the run summary a reader actually reads.

Kept separate from `engine.py` so the engine has no I/O in it and can be
exercised entirely from memory in the Day 4 tests.
"""

from __future__ import annotations

import csv
from collections.abc import Sequence
from pathlib import Path

from .engine import EngineStats
from .findings import FINDING_COLUMNS, Finding, to_row


def write_findings_csv(findings: Sequence[Finding], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" plus an explicit lineterminator keeps output byte-identical
    # across operating systems, matching timeline.write_csv.
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FINDING_COLUMNS, lineterminator="\n")
        writer.writeheader()
        for finding in findings:
            writer.writerow(to_row(finding))


def summary_lines(findings: Sequence[Finding], stats: EngineStats) -> list[str]:
    """The run summary. Every number here is one a reader can check."""
    lines = [
        f"Rules      : {stats.rules_evaluated} evaluated over {stats.events_seen} events",
        f"Findings   : {len(findings)}",
    ]
    for rule_id in sorted(stats.findings_by_rule):
        count = stats.findings_by_rule[rule_id]
        lines.append(f"  {rule_id}: {count}")

    if stats.search_truncated:
        # A truncated search may have skipped a valid chain. Saying so is the
        # difference between a known gap and a silent miss.
        lines.append("SEARCH TRUNCATED -- a valid chain may have been missed:")
        for rule_id in sorted(stats.search_truncated):
            lines.append(f"  {rule_id}")

    if stats.absent_field_skips:
        # A rule whose skip count equals the number of events it selected is
        # doing nothing at all, and this is the only place that becomes visible.
        lines.append("Absent fields (condition false, not an error):")
        for field in sorted(stats.absent_field_skips):
            lines.append(f"  {field}: {stats.absent_field_skips[field]}")

    for finding in findings:
        lines.append("")
        lines.append(
            f"[{finding.severity}] {finding.rule_id} {finding.title} "
            f"(weight {finding.weight}, {finding.attack_technique})"
        )
        lines.append(f"  time claim : {finding.time_claim}")
        if finding.window_observed_seconds is not None:
            lines.append(f"  interval   : {finding.window_observed_seconds:.6f}s")
        if finding.entity_keys:
            keys = ", ".join(f"{k}={v}" for k, v in sorted(finding.entity_keys))
            lines.append(f"  entity     : {keys}")
        for line in finding.provenance_lines():
            lines.append(f"  evidence   : {line}")
        for note in finding.notes:
            lines.append(f"  note       : {note}")
    return lines
