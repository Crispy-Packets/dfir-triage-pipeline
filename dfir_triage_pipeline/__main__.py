from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .core.engine import run as run_rules
from .core.report import summary_lines, write_findings_csv
from .core.ruleset import RuleError, load_rules
from .ingest import collect_events
from .timeline import sort_events, write_csv

#: Rules live beside the package, not inside it, so a checkout without them
#: still produces a timeline. Resolved relative to the repository root.
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dfir_triage_pipeline")
    p.add_argument("collection", type=Path, help="KAPE collection root directory")
    p.add_argument("--output", type=Path, required=True, help="timeline CSV path")
    p.add_argument("--findings", type=Path, help="findings CSV path (optional)")
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="rule directory")
    p.add_argument("--no-rules", action="store_true", help="produce the timeline only")
    p.add_argument("--log-level", default="WARNING")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(message)s")

    if not args.collection.is_dir():
        print(f"error: not a directory: {args.collection}", file=sys.stderr)
        return 2

    events, stats = collect_events(args.collection)
    ordered = sort_events(events)
    write_csv(ordered, args.output)

    print(f"Collection : {args.collection}")
    print(f"Files      : {stats.files_seen} seen, {stats.files_handled} handled, "
          f"{stats.files_skipped} skipped, {stats.files_failed} failed")
    print(f"Events     : {stats.events_total}")
    for artifact in sorted(stats.events_by_artifact):
        print(f"  {artifact}: {stats.events_by_artifact[artifact]}")
    if ordered:
        print(f"Time range : {ordered[0].timestamp_iso} .. {ordered[-1].timestamp_iso}")
    for name, rel, err in stats.failures:
        print(f"  FAILED {name} :: {rel} :: {err}")
    print(f"Output     : {args.output}")

    if args.no_rules:
        return 0
    if not args.rules.is_dir():
        print(f"Rules      : {args.rules} not found; timeline only")
        return 0

    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        # A malformed rule aborts the run rather than silently matching nothing
        # (schema section 3.4). The timeline above is already written.
        print(f"error: {exc}", file=sys.stderr)
        return 3

    findings, engine_stats = run_rules(rules, ordered)
    print()
    for line in summary_lines(findings, engine_stats):
        print(line)

    if args.findings:
        write_findings_csv(findings, args.findings)
        print()
        print(f"Findings   : {args.findings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
