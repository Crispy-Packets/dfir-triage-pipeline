from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .ingest import collect_events
from .timeline import sort_events, write_csv


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dfir_triage_pipeline")
    p.add_argument("collection", type=Path, help="KAPE collection root directory")
    p.add_argument("--output", type=Path, required=True, help="timeline CSV path")
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())