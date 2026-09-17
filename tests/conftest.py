"""Shared builders for the Week 3 rule and engine tests (Person A)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from dfir_triage_pipeline.model import Event

# The scenario's own timestamps, so a test that drifts from the evidence fails.
#
# Two pairs here are easy to conflate, and conflating either one would make a
# fixture assert against the wrong record. Both are taken from
# groundtruth/scenario1-verification.md, not from a planning document.
#
#   OPERATOR LOG vs EVIDENCE. The operator's own log records the clear at
#   23:05:12.794670Z. The EID 1102 in the collected Security.evtx --
#   EventRecordID 28,201, the first record in the log -- is at
#   23:05:06.682356Z. The operator entry is 6.112314 s LATE. An engine fixture
#   must carry the evidence time, because that is what a parser emits.
#
#   HAND-READ vs PARSER-EMITTED. The raw FILETIME 134319994358327870 in the .pf
#   converts to 22:57:15.832787Z, and that is the figure every ground-truth
#   document quotes. windowsprefetch returns 22:57:15.832788Z, one microsecond
#   later, and that is what actually reaches the engine (D-013). The fixture
#   uses the parser-emitted value because the engine never sees the other one.

ARRIVAL = datetime(2026, 8, 23, 22, 20, 6, 710763, tzinfo=UTC)

#: What the parser emits, and therefore what the engine sees.
EXECUTION = datetime(2026, 8, 23, 22, 57, 15, 832788, tzinfo=UTC)
#: The raw FILETIME conversion, quoted by every ground-truth document.
EXECUTION_FILETIME = datetime(2026, 8, 23, 22, 57, 15, 832787, tzinfo=UTC)

#: EID 1102, EventRecordID 28,201 -- the evidence.
LOG_CLEAR = datetime(2026, 8, 23, 23, 5, 6, 682356, tzinfo=UTC)
#: The operator log's own entry for the same action, 6.112314 s late.
OPERATOR_LOG_CLEAR = datetime(2026, 8, 23, 23, 5, 12, 794670, tzinfo=UTC)

RUNKEY_WRITE = datetime(2026, 8, 21, 1, 34, 7, 976260, tzinfo=UTC)

#: 37m 09.122025s as the engine sees it; 37m 09.122024s from the raw FILETIME.
#: Every window test is anchored to this, not to a round number.
ARRIVAL_TO_EXECUTION = EXECUTION - ARRIVAL


def make_event(
    timestamp: datetime,
    source_artifact: str,
    event_type: str,
    timestamp_type: str,
    *,
    action: str = "test event",
    source_file: str = "C/test/source.evtx",
    source_locator: str | None = None,
    path: str | None = None,
    user: str | None = None,
    host: str | None = "windows10",
    details: dict[str, Any] | None = None,
) -> Event:
    """An Event with provenance filled in, since the model refuses one without."""
    return Event(
        timestamp=timestamp,
        timestamp_type=timestamp_type,
        source_artifact=source_artifact,
        event_type=event_type,
        action=action,
        source_file=source_file,
        source_locator=source_locator or f"EventRecordID={abs(hash(action)) % 100000}",
        path=path,
        user=user,
        host=host,
        details=details or {},
    )


def download(
    at: datetime = ARRIVAL,
    name: str = "invoice_scan.exe",
    total_bytes: str = "4608",
    url: str = "http://192.168.50.2:8000/invoice_scan.exe",
) -> Event:
    target = f"C:\\Users\\janed\\Downloads\\{name}"
    return make_event(
        at,
        "browser",
        "file_download",
        "recorded",
        action=f"downloaded {name}",
        source_file="C/Users/janed/AppData/Local/Microsoft/Edge/User Data/Default/History",
        source_locator=f"downloads.id={abs(hash((name, total_bytes, at))) % 1000}",
        path=target,
        user="janed",
        details={
            "url": url,
            "target_path": target,
            "bytes": total_bytes,
            "path_basename": name,
            "path_basename_canonical": name.lower(),
            "path_canonical": target.lower(),
        },
    )


def execution(at: datetime = EXECUTION, name: str = "INVOICE_SCAN.EXE") -> Event:
    return make_event(
        at,
        "prefetch",
        "process_exec",
        "last_run",
        action=f"executed {name}",
        source_file=f"C/Windows/prefetch/{name}-A345C2FE.pf",
        source_locator="run_slot=0",
        path=name,
        user=None,
        details={
            "executable": name,
            "run_count": "1",
            "path_basename_canonical": name.lower(),
            "path_source": "prefetch_executable_name",
        },
    )


def runkey(at: datetime = RUNKEY_WRITE, name: str = "invoice_scan.exe") -> Event:
    data = f"C:\\Users\\janed\\Downloads\\{name}"
    return make_event(
        at,
        "registry",
        "persistence_autorun",
        "presence",
        action=f"autorun value SecurityUpdate -> {data}",
        source_file="C/Users/janed/NTUSER.DAT",
        source_locator="hive_path=\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityUpdate",
        path=data,
        user="janed",
        details={
            "value_name": "SecurityUpdate",
            "value_data": data,
            "key_last_write": at.isoformat(timespec="microseconds"),
            "value_count_in_key": "3",
            "hive_type": "ntuser",
            "path_basename_canonical": name.lower(),
        },
    )


def log_cleared(at: datetime = LOG_CLEAR, user: str = "admin_local") -> Event:
    return make_event(
        at,
        "evtx.security",
        "log_cleared",
        "recorded",
        action="security event log cleared",
        source_file="C/Windows/System32/winevt/logs/Security.evtx",
        source_locator="EventRecordID=28201",
        user=user,
        details={"SubjectUserName": user, "SubjectLogonId": "0x3e7"},
    )


def service_install(
    at: datetime | None = None,
    user: str = "admin_local",
    image: str = '"C:\\Users\\admin_local\\tools\\svc.exe" -run',
    name: str = "TestSvc",
) -> Event:
    return make_event(
        at or (LOG_CLEAR - timedelta(minutes=5)),
        "evtx.system",
        "service_install",
        "recorded",
        action=f"service installed {name}",
        source_file="C/Windows/System32/winevt/logs/System.evtx",
        source_locator="EventRecordID=9001",
        path=image,
        user=user,
        details={"ServiceName": name, "ImagePath": image},
    )


# ---------------------------------------------------------------------------
# Cached collection ingest, added 2026-09-17.
#
# The suite calls `collect_events` 65 times across 22 test bodies, each walking
# a whole collection and opening every SQLite and ESE file in it. That
# exhausted the process's file-descriptor limit once enough parsers existed:
# the run died with `OSError: Too many open files`, and it surfaced in the USN
# journal parser -- which simply happened to be the next thing to open a file
# and holds no descriptors of its own. See D-050.
#
# Caching per collection fixes both the descriptors and the wall clock: five
# ingests instead of sixty-five.

_INGEST_CACHE: dict[str, Any] = {}


def cached_collect_events(root: Any) -> Any:
    """`collect_events(root)`, computed once per collection per session.

    Returns the SAME (events, stats) objects on every call, so a test must not
    mutate them. Nothing in the suite does -- every use is a read -- and the
    alternative is re-walking a collection for each assertion.
    """
    from dfir_triage_pipeline.ingest import collect_events

    key = str(root)
    if key not in _INGEST_CACHE:
        _INGEST_CACHE[key] = collect_events(root)
    return _INGEST_CACHE[key]
