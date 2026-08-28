import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.browser import (
    BrowserParser,
    record_to_event,
    webkit_to_utc,
)

REL = (
    "C/Users/janed/AppData/Local/Microsoft/Edge/User Data/Default/History"
)

# The scenario download, read by hand from the downloads table and independently
# recorded by Person A before this parser existed.
SCENARIO_START_TIME = 13431997206710763
SCENARIO_UTC = datetime(2026, 8, 23, 22, 20, 6, 710763, tzinfo=UTC)


def _record(**over):
    base = {
        "id": 13,
        "start_time": SCENARIO_START_TIME,
        "target_path": r"C:\Users\janed\Downloads\invoice_scan.exe",
        "url": "http://192.168.50.2:8000/invoice_scan.exe",
        "referrer": "",
        "total_bytes": 4608,
        "mime_type": "application/x-msdownload",
        "source_file": REL,
        "db_sha256": "0" * 64,
    }
    base.update(over)
    return base


def test_webkit_epoch_is_microseconds_since_1601_not_unix_seconds():
    """Chrome/Edge times are microseconds since 1601-01-01. Reading one as a
    Unix timestamp puts the download in the twenty-fourth century; dividing by
    the wrong factor puts it in 1601. The reference value is the scenario
    download, established independently of this parser."""
    assert webkit_to_utc(SCENARIO_START_TIME) == SCENARIO_UTC


def test_conversion_keeps_microsecond_precision():
    """Integer arithmetic throughout. The value is already microseconds, so no
    division occurs and no precision is lost -- the same concern that cost a
    microsecond in the registry parser's FILETIME conversion."""
    assert webkit_to_utc(SCENARIO_START_TIME).microsecond == 710763


def test_scenario_download_contract_fields():
    e = record_to_event(_record())
    assert e.timestamp == SCENARIO_UTC
    assert e.timestamp_type == "recorded"
    assert e.source_artifact == "browser"
    assert e.event_type == "file_download"
    assert e.path == r"C:\Users\janed\Downloads\invoice_scan.exe"
    assert e.source_locator == "downloads.id=13"
    assert e.details["bytes"] == "4608"


def test_incomplete_download_omits_bytes_rather_than_claiming_zero():
    """total_bytes is 0 for a download that never completed. Emitting "0" would
    assert a zero-length file; the artifact is saying it does not know the size."""
    e = record_to_event(_record(total_bytes=0))
    assert "bytes" not in e.details


def test_empty_optional_fields_are_omitted_not_emitted_blank():
    e = record_to_event(_record(referrer="", mime_type="", url=""))
    assert "referrer" not in e.details
    assert "mime_type" not in e.details
    assert "url" not in e.details


def test_target_path_is_verbatim():
    """CD-010. The browser recorded this path; the parser does not normalise
    case, resolve the profile directory, or strip the ' (1)' Chrome appends to
    a repeated filename -- that suffix is evidence of a repeated download."""
    raw = r"C:\Users\janed\Downloads\invoice_scan (1).exe"
    assert record_to_event(_record(target_path=raw)).path == raw


def test_db_sha256_is_carried_so_the_reading_is_auditable():
    e = record_to_event(_record(db_sha256="a" * 64))
    assert e.details["db_sha256"] == "a" * 64


@pytest.mark.parametrize(
    "path,expected",
    [
        (REL, True),
        (REL.replace("janed", "Youssef"), True),
        (REL.lower(), True),
        (REL + "-wal", False),
        (REL + "-journal", False),
        ("C/Users/janed/AppData/Local/Microsoft/Edge/User Data/Default/Cookies", False),
        ("C/Users/janed/AppData/Local/Google/Chrome/User Data/Default/History", False),
        ("C/Windows/prefetch/MSEDGE.EXE-1234ABCD.pf", False),
    ],
)
def test_can_handle(path, expected):
    assert BrowserParser().can_handle(path) is expected


def test_database_is_not_modified_by_reading_it(tmp_path):
    """immutable=1 with mode=ro prevents journal replay and lock creation, so the
    collected file is read exactly as collected. Verified by hashing before and
    after rather than by trusting the flag."""
    import hashlib
    import shutil

    from dfir_triage_pipeline.parsers.browser import _records

    src = tmp_path / "History"
    con = sqlite3.connect(src)
    con.execute(
        "CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid TEXT, current_path TEXT,"
        " target_path TEXT, start_time INTEGER, received_bytes INTEGER,"
        " total_bytes INTEGER, state INTEGER, danger_type INTEGER,"
        " interrupt_reason INTEGER, hash BLOB, end_time INTEGER, opened INTEGER,"
        " last_access_time INTEGER, transient INTEGER, referrer TEXT, site_url TEXT,"
        " embedder_download_data TEXT, tab_url TEXT, tab_referrer_url TEXT,"
        " http_method TEXT, by_ext_id TEXT, by_ext_name TEXT, by_web_app_id TEXT,"
        " etag TEXT, last_modified TEXT, mime_type TEXT, original_mime_type TEXT)"
    )
    con.execute(
        "INSERT INTO downloads (id, start_time, target_path, tab_url, referrer,"
        " total_bytes, mime_type) VALUES (13, ?, ?, '', '', 4608, '')",
        (SCENARIO_START_TIME, r"C:\Users\janed\Downloads\invoice_scan.exe"),
    )
    con.commit()
    con.close()

    dest = tmp_path / "copy" / "History"
    dest.parent.mkdir()
    shutil.copy2(src, dest)
    before = hashlib.sha256(dest.read_bytes()).hexdigest()
    events = list(_records(dest, REL))
    after = hashlib.sha256(dest.read_bytes()).hexdigest()

    assert before == after, "reading the database modified it"
    assert len(events) == 1
    assert events[0]["db_sha256"] == before


def test_non_database_file_raises_and_is_counted(tmp_path):
    """A readable database holding no downloads is silence; a file that is not a
    database at all is a failure to read evidence and must be counted."""
    from dfir_triage_pipeline.parsers.browser import _records

    fake = tmp_path / "History"
    fake.write_bytes(b"NOTASQLITEDB" + b"\x00" * 512)
    with pytest.raises(sqlite3.DatabaseError):
        list(_records(fake, REL))


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_real_history_reproduces_the_reference_download():
    """The check named in the step: the s1_v2 run must emit downloads.id=13 at
    2026-08-23T22:20:06.710763Z with total_bytes 4608. A parser disagreeing with
    those numbers is wrong against evidence read independently."""
    abs_path = Path(COLLECTION) / REL
    if not abs_path.exists():
        pytest.skip("janed Edge History not in this collection")
    events = list(BrowserParser().parse(abs_path, REL))
    match = [e for e in events if e.source_locator == "downloads.id=13"]
    if not match:
        pytest.skip("this collection carries no scenario download")
    assert match[0].timestamp == SCENARIO_UTC
    assert match[0].details["bytes"] == "4608"
    assert "invoice_scan.exe" in match[0].path
