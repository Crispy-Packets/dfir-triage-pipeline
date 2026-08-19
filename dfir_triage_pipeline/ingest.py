from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from .model import Event
from .parsers import find_parser

log = logging.getLogger(__name__)


@dataclass
class RunStats:
    files_seen: int = 0
    files_handled: int = 0
    files_skipped: int = 0
    files_failed: int = 0
    events_by_artifact: dict[str, int] = field(default_factory=dict)
    failures: list[tuple[str, str, str]] = field(default_factory=list)

    @property
    def events_total(self) -> int:
        return sum(self.events_by_artifact.values())


def relative_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def collect_events(root: Path) -> tuple[list[Event], RunStats]:
    stats = RunStats()
    events: list[Event] = []

    # sorted() makes traversal order deterministic; rglob order is filesystem-dependent.
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        stats.files_seen += 1
        rel = relative_posix(path, root)

        parser = find_parser(rel)
        if parser is None:
            stats.files_skipped += 1
            continue

        try:
            produced = list(parser.parse(path, rel))
        except Exception as exc:  # noqa: BLE001 - one bad artifact must not end the run
            stats.files_failed += 1
            stats.failures.append((parser.name, rel, f"{type(exc).__name__}: {exc}"))
            log.warning("parser %s failed on %s: %s", parser.name, rel, exc)
            continue

        stats.files_handled += 1
        for event in produced:
            key = event.source_artifact
            stats.events_by_artifact[key] = stats.events_by_artifact.get(key, 0) + 1
        events.extend(produced)

    return events, stats