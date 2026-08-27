from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from ..model import Event
from . import register

# FILETIME 0 renders as 1601-01-01. windowsprefetch 4.0.3 drops empty slots
# itself, so this rarely fires -- but an unfiltered epoch value is a valid
# tz-aware UTC datetime the Event guard accepts, and it would sort above every
# real event in the timeline. Kept as a guard, not as a hot path.
EPOCH_SENTINEL = datetime(1601, 1, 2, tzinfo=UTC)

# Byte offset of the run count in a version-30 Prefetch file information block.
#
# windowsprefetch 4.0.3 reads this field at 0xD0, which is wrong for version-30
# records: it lands on an adjacent field and yields values inconsistent with the
# run-time array. Measured on 2026-08-27 across all 835 .pf files in the three
# collections, 610 reported len(timestamps) > runCount at the library's offset,
# including INVOICE_SCAN.EXE reporting 0 against a confirmed execution.
#
# At 0xC8 the invariant len(timestamps) <= runCount holds in 835 of 835 files,
# and no file reports 0 runs while carrying run times. See CD-018 and D-023.
RUN_COUNT_OFFSET_V30 = 0xC8
PREFETCH_VERSION_30 = 30

# A .pf allocated by the OS but never flushed is collected as a run of zero
# bytes. Five such files exist across the three collections (DEFRAG.EXE-738093E8
# in clean_a and clean_b, SVCHOST.EXE-CE29B0F4 in all three); each is in its
# SHA-256 manifest, so they were collected and transferred intact and are not
# corruption in transit. They carry no run times and no executable name.
#
# These yield no records rather than raising: an empty artifact is an absence of
# evidence, not a parser fault, and counting it as a failure would misreport the
# run. The condition is deliberately narrow -- all bytes zero -- so a genuinely
# malformed file still raises and is counted. See D-024.
_EMPTY_PROBE_BYTES = 16


def normalise_run_time(value: datetime) -> datetime:
    """Attach UTC to a naive value; convert an aware one.

    Prefetch run times come from FILETIME, which is defined as UTC.
    windowsprefetch 4.0.3 returns them as naive strings; the spike compared one
    against UTC ground truth to establish that the naive value means UTC. See
    D-013 and docs/evidence/prefetch-spike-s1v2.txt.

    astimezone() on a naive value assumes it is local time and converts it -- a
    silent whole-hour error under this lab's UTC+3 offset, presenting on
    verification day as clock drift rather than as a parser bug.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _is_unwritten(abs_path: Path) -> bool:
    """True when the file carries no header at all -- an allocated but never
    flushed .pf. Probes the header only; a file whose first bytes are zero has
    no valid MAM or SCCA signature and cannot be a parseable record."""
    try:
        with abs_path.open("rb") as fh:
            head = fh.read(_EMPTY_PROBE_BYTES)
    except OSError:
        return False
    return bool(head) and not any(head)


def _true_run_count(abs_path: Path, version: int) -> int | None:
    """Read the run count from the offset that the artifact actually uses.

    Returns None when the value cannot be read, rather than guessing: a missing
    run count is recorded as absent, never as zero, because zero is a claim the
    artifact does not make. Only version-30 records are corrected; any other
    version falls back to the library's value.
    """
    if version != PREFETCH_VERSION_30:
        return None

    from windowsprefetch.utils import DecompressWin10

    try:
        raw = DecompressWin10().decompress(str(abs_path))
    except Exception:
        try:
            raw = abs_path.read_bytes()
        except OSError:
            return None

    if raw is None or len(raw) < RUN_COUNT_OFFSET_V30 + 4:
        return None
    return struct.unpack_from("<I", raw, RUN_COUNT_OFFSET_V30)[0]


def _records(abs_path: Path) -> Iterator[dict]:
    """Yield one normalised dict per .pf file. The only library-coupled code.

    Established by spike against windowsprefetch 4.0.3:
      - timestamps is a list of NAIVE STRINGS, 'YYYY-MM-DD HH:MM:SS.ffffff'
      - the volume serial attribute is volSerialNumber, NOT volumeSerialNumber
        (the latter does not exist and getattr would return None forever)
      - the run-time array holds at most eight slots; only populated ones are
        returned, so len(timestamps) <= runCount once runCount is read correctly

    Local import keeps the module importable, and the unit tests passing, on a
    machine where the library is not installed. Only parse() needs it.
    """
    from windowsprefetch import Prefetch

    if _is_unwritten(abs_path):
        return  # no evidence recorded, not a failure to read it

    pf = Prefetch(str(abs_path))

    run_times: list[datetime] = []
    for raw in getattr(pf, "timestamps", None) or []:
        if isinstance(raw, datetime):
            run_times.append(raw)
        elif isinstance(raw, str):
            try:
                run_times.append(datetime.fromisoformat(raw))
            except ValueError:
                continue  # unparseable slot is skipped, never guessed at

    version = getattr(pf, "version", None)
    run_count = _true_run_count(abs_path, version)
    if run_count is None:
        run_count = getattr(pf, "runCount", None)

    yield {
        "executable": getattr(pf, "executableName", "") or "",
        "run_count": run_count,
        "run_times": run_times,
        "volume_serial": getattr(pf, "volSerialNumber", None),
    }


def record_to_events(record: dict, relative_path: str) -> list[Event]:
    """Pure transform: dict in, Events out. No filesystem, no library type."""
    executable = (record.get("executable") or "").strip()
    if not executable:
        return []

    details_base = {
        "executable": executable,
        "path_source": "prefetch_executable_name",
    }
    if record.get("run_count") is not None:
        details_base["run_count"] = str(record["run_count"])
    if record.get("volume_serial") is not None:
        details_base["volume_serial"] = str(record["volume_serial"])

    events: list[Event] = []
    for slot, raw in enumerate(record.get("run_times") or []):
        if not isinstance(raw, datetime):
            continue
        run_time = normalise_run_time(raw)
        if run_time < EPOCH_SENTINEL:
            continue  # unused slot, not an execution
        events.append(
            Event(
                timestamp=run_time,
                source_artifact="prefetch",
                event_type="process_exec",          # CD-007, shared with EVTX
                action="program executed",
                source_file=relative_path,          # CD-003, passed through
                source_locator=f"run_slot={slot}",  # CD-004, unique in file
                host=None,
                user=None,
                path=executable,                    # CD-010, as recorded
                confidence="high",                  # CD-001
                timestamp_type="last_run",
                details=dict(details_base),
            )
        )
    return events


@register
class PrefetchParser:
    name = "prefetch"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        if "/windows/prefetch/" not in f"/{lowered}":
            return False
        if not lowered.endswith(".pf"):
            return False
        # Op-*.pf are SysMain operational files with a different internal
        # structure. The library parses them without raising and yields the
        # filename fragment as an executable name, so excluding them by name is
        # the only guard: accepting them emits a fabricated binary into the
        # timeline. See CD-020.
        return not lowered.rsplit("/", 1)[-1].startswith("op-")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        for record in _records(abs_path):
            yield from record_to_events(record, relative_path)
