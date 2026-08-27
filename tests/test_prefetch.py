import os
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.prefetch import (
    PrefetchParser,
    normalise_run_time,
    record_to_events,
)

REL = "C/Windows/prefetch/INVOICE_SCAN.EXE-ABCD1234.pf"


def _record(run_times, executable="INVOICE_SCAN.EXE", run_count=2):
    return {
        "executable": executable,
        "run_count": run_count,
        "run_times": run_times,
        "volume_serial": "a62af538",
    }


def test_naive_run_time_gets_utc_attached_not_converted():
    """A naive FILETIME-derived value is UTC by definition. astimezone() would
    treat it as local and shift it by the host offset -- silently, and the
    Event guard would still accept the result. D-013."""
    ts = normalise_run_time(datetime(2026, 8, 24, 10, 32, 7))
    assert ts.hour == 10
    assert ts.utcoffset() == timedelta(0)


def test_aware_run_time_is_converted_not_overwritten():
    ts = normalise_run_time(
        datetime(2026, 8, 24, 13, 32, 7, tzinfo=timezone(timedelta(hours=3)))
    )
    assert ts.hour == 10
    assert ts.utcoffset() == timedelta(0)


def test_unused_epoch_slots_produce_no_events():
    """windowsprefetch drops empty slots, but an unfiltered FILETIME 0 is a
    valid tz-aware UTC datetime the Event guard accepts, and it would sort
    above every real event in the timeline."""
    real = [datetime(2026, 8, 24, 10, 32, 7), datetime(2026, 8, 24, 10, 30, 1)]
    zeros = [datetime(1601, 1, 1, tzinfo=UTC)] * 6
    assert len(record_to_events(_record(real + zeros), REL)) == 2


def test_every_real_run_time_becomes_a_separate_event():
    times = [datetime(2026, 8, 24, 10, 32, 7 + i) for i in range(5)]
    assert len(record_to_events(_record(times), REL)) == 5


def test_source_locator_is_unique_within_the_file():
    times = [datetime(2026, 8, 24, 10, 32, 7 + i) for i in range(5)]
    locators = [e.source_locator for e in record_to_events(_record(times), REL)]
    assert len(set(locators)) == len(locators)


def test_contract_fields():
    e = record_to_events(_record([datetime(2026, 8, 24, 10, 32, 7)]), REL)[0]
    assert e.source_artifact == "prefetch"
    assert e.event_type == "process_exec"
    assert e.confidence == "high"
    assert e.timestamp_type == "last_run"
    assert e.source_file == REL
    assert e.path == "INVOICE_SCAN.EXE"
    assert e.details["volume_serial"] == "a62af538"


def test_event_count_may_be_fewer_than_run_count():
    """CD-018. The run-time array holds at most eight slots regardless of how
    many times the binary ran, so Event count is a lower bound on executions
    and must never be reported as a total."""
    events = record_to_events(
        _record([datetime(2026, 8, 24, 10, 32, 7)], run_count=3), REL
    )
    assert len(events) == 1
    assert events[0].details["run_count"] == "3"


def test_absent_run_count_is_omitted_not_zeroed():
    """A run count that cannot be read is recorded as absent. Emitting 0 would
    assert the binary never ran -- a claim the artifact does not make."""
    events = record_to_events(
        _record([datetime(2026, 8, 24, 10, 32, 7)], run_count=None), REL
    )
    assert "run_count" not in events[0].details


def test_missing_executable_name_yields_nothing():
    r = _record([datetime(2026, 8, 24, 10, 32, 7)], executable="")
    assert record_to_events(r, REL) == []


@pytest.mark.parametrize(
    "path,expected",
    [
        ("C/Windows/prefetch/A.pf", True),
        ("C/Windows/Prefetch/A.pf", True),
        ("Z/Windows/prefetch/A.pf", True),
        ("C/Windows/prefetch/Layout.ini", False),
        ("C/Windows/prefetch/AgAppLaunch.db", False),
        ("C/Windows/System32/winevt/logs/Security.evtx", False),
        # SysMain operational files: different internal structure. The library
        # parses them without raising and yields the filename fragment as an
        # executable, so they must be excluded by name. CD-020, D-025.
        ("C/Windows/prefetch/Op-EXPLORER.EXE-7A3328DA-000000F5.pf", False),
        ("C/Windows/Prefetch/OP-EXPLORER.EXE-7A3328DA-000000F5.pf", False),
    ],
)
def test_can_handle(path, expected):
    assert PrefetchParser().can_handle(path) is expected


def test_zero_filled_prefetch_yields_no_events_and_does_not_raise(tmp_path):
    """A .pf allocated but never flushed is collected as all zero bytes. Five
    exist across the collections and are present in their SHA-256 manifests, so
    they are intact evidence of an absence, not corruption. They must yield no
    events without raising -- a raise would count them as parser failures and
    misreport the run. D-024."""
    from dfir_triage_pipeline.parsers.prefetch import _records

    pf = tmp_path / "SVCHOST.EXE-CE29B0F4.pf"
    pf.write_bytes(b"\x00" * 5225)
    assert list(_records(pf)) == []


def test_malformed_non_zero_prefetch_still_raises(tmp_path):
    """The empty-file guard is narrow by design: only an all-zero header is
    treated as absence. Anything else must still raise and be counted."""
    from dfir_triage_pipeline.parsers.prefetch import _records

    pf = tmp_path / "GARBAGE.EXE-11112222.pf"
    pf.write_bytes(b"NOTAPREFETCHFILE" + b"\xff" * 512)
    with pytest.raises(AttributeError):
        list(_records(pf))


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_real_prefetch_yields_events():
    root = Path(COLLECTION)
    pfs = sorted(root.rglob("*.pf"))
    assert pfs, "no .pf files in the collection"
    parser = PrefetchParser()
    events = list(parser.parse(pfs[0], pfs[0].relative_to(root).as_posix()))
    assert events
    assert all(e.timestamp.year > 1601 for e in events)
    assert all(e.timestamp.utcoffset() == timedelta(0) for e in events)


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_real_run_count_is_never_below_event_count():
    """CD-018's invariant, against real evidence. windowsprefetch 4.0.3 reads
    runCount at the wrong offset for version-30 records and breaks this in
    610 of 835 collected files; the parser reads 0xC8 instead. D-023."""
    root = Path(COLLECTION)
    parser = PrefetchParser()
    checked = 0
    for pf in sorted(root.rglob("*.pf")):
        events = list(parser.parse(pf, pf.relative_to(root).as_posix()))
        if not events:
            continue
        raw = events[0].details.get("run_count")
        if raw is None:
            continue
        assert len(events) <= int(raw), f"{pf.name}: {len(events)} events > {raw} runs"
        checked += 1
    assert checked > 0, "no prefetch records carried a run count"
