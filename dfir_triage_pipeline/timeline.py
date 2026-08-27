from __future__ import annotations

import csv
from collections.abc import Iterable, Sequence
from pathlib import Path

from .model import Event

COLUMNS = (
    "timestamp_utc",
    "timestamp_type",
    "source_artifact",
    "event_type",
    "user",
    "path",
    "action",
    "event_id",
    "source_file",
    "source_locator",
    "confidence",
)


def sort_events(events: Iterable[Event]) -> list[Event]:
    """Deterministic order. event_id is the final tie-breaker, so ties cannot reorder."""
    return sorted(
        events,
        key=lambda e: (
            e.timestamp,
            e.source_artifact,
            e.source_file,
            e.source_locator,
            e.event_id,
        ),
    )


def to_row(event: Event) -> dict[str, str]:
    return {
        "timestamp_utc": event.timestamp_iso.replace("+00:00", "Z"),
        "timestamp_type": event.timestamp_type,
        "source_artifact": event.source_artifact,
        "event_type": event.event_type,
        "user": event.user or "",
        "path": event.path or "",
        "action": event.action,
        "event_id": event.event_id,
        "source_file": event.source_file,
        "source_locator": event.source_locator,
        "confidence": event.confidence,
    }


def write_csv(events: Sequence[Event], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # newline="" plus an explicit lineterminator keeps output byte-identical across OSes.
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        for event in events:
            writer.writerow(to_row(event))
