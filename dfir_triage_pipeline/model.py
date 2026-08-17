from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

CONFIDENCE = ("high", "medium", "low")  # CD-001
_TS = "microseconds"                    # CD-006
_SEP = b"\x1f"


@dataclass(frozen=True, slots=True)
class Event:
    """One normalised forensic observation.

    Frozen by contract (CD-005). Parsers normalise; this class only validates.
    """

    timestamp: datetime          # timezone-aware, zero UTC offset
    source_artifact: str         # "evtx.security" | "evtx.system" | "prefetch"
    event_type: str              # "process_exec" | "log_cleared" | "logon" | ...
    action: str                  # short human-readable verb phrase
    source_file: str             # collection-relative POSIX path (CD-003)
    source_locator: str          # unique within source_file (CD-004)
    host: str | None = None
    user: str | None = None
    path: str | None = None      # full path as recorded; never a basename
    details: dict[str, Any] = field(default_factory=dict, compare=False)  # CD-005
    confidence: str = "high"     # confidence in the ACTION claim only (CD-001)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        if self.timestamp.utcoffset() != timedelta(0):
            raise ValueError("timestamp must be UTC (zero offset), not a local offset")
        if self.confidence not in CONFIDENCE:
            raise ValueError(f"confidence must be one of {CONFIDENCE}")
        if not self.source_file or not self.source_locator:
            raise ValueError("source_file and source_locator are required (provenance)")

    @property
    def timestamp_iso(self) -> str:
        return self.timestamp.isoformat(timespec=_TS)

    @property
    def event_id(self) -> str:
        """Deterministic content hash (CD-002). Same inputs -> same id, every run."""
        h = hashlib.sha256()
        for part in (
            self.timestamp_iso,
            self.source_artifact,
            self.event_type,
            self.action,
            self.source_file,
            self.source_locator,
            self.path or "",
        ):
            h.update(part.encode("utf-8"))
            h.update(_SEP)
        return h.hexdigest()[:16]
