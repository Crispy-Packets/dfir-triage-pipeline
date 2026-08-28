import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.amcache import (
    AmcacheParser,
    record_to_event,
    sha1_from_file_id,
)

REL = "C/Windows/AppCompat/Programs/Amcache.hve"


def _record(**over):
    base = {
        "container": "InventoryApplicationFile",
        "key_name": "3dviewer.exe|4bbba2169c0b42d3",
        "last_write": datetime(2026, 8, 21, 2, 51, 56, 879040, tzinfo=UTC),
        "path": r"c:\program files\windowsapps\3dviewer.exe",
        "values": {
            "Name": "3DViewer.exe",
            "FileId": "00003cae70a7440be29393c16c54a50057ceaa494d61",
            "Size": "12345",
            "Publisher": "microsoft corporation",
            "Version": "7.2602.8012.0",
            "BinaryType": "pe64_amd64",
        },
        "source_file": REL,
    }
    base.update(over)
    return base


def test_timestamp_type_is_presence_not_last_run():
    """Amcache is written by a scheduled maintenance task, not at execution. The
    key's last-write time is when the OS inventoried the binary, which may be
    hours from any execution and is sometimes unrelated to one. Treating it as
    an execution time is the classic Amcache misreading, and `presence` is what
    stops a correlation rule doing it."""
    assert record_to_event(_record()).timestamp_type == "presence"


def test_sha1_prefix_is_stripped():
    """FileId is a four-character field marker followed by the SHA-1. Carrying
    the prefix forward would break comparison against a hash computed anywhere
    else."""
    got = sha1_from_file_id("00003cae70a7440be29393c16c54a50057ceaa494d61")
    assert got == "3cae70a7440be29393c16c54a50057ceaa494d61"
    assert len(got) == 40


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "0000short",
        "0000" + "z" * 40,          # not hex
        "3cae70a7440be29393c16c54a50057ceaa494d61",  # already stripped, wrong length
    ],
)
def test_malformed_file_id_yields_no_hash_rather_than_a_wrong_one(value):
    """A reformatted or truncated identifier is not a hash. Emitting it as one
    would licence a false match against a hash from another source, which is
    worse than emitting nothing."""
    assert sha1_from_file_id(value) is None


def test_hash_is_omitted_when_file_id_is_unusable():
    e = record_to_event(_record(values={"Name": "x.exe", "FileId": "garbage"}))
    assert "sha1" not in e.details


def test_contract_fields():
    e = record_to_event(_record())
    assert e.source_artifact == "amcache"
    assert e.event_type == "program_inventoried"
    assert e.confidence == "high"
    assert e.source_file == REL
    assert e.details["sha1"] == "3cae70a7440be29393c16c54a50057ceaa494d61"
    assert e.details["name"] == "3DViewer.exe"


def test_locator_names_the_container_not_just_the_entry():
    """The same file can appear under InventoryApplicationFile and the legacy
    File layout. A locator carrying only the entry name would not be unique
    within the hive (CD-004)."""
    new = record_to_event(_record()).source_locator
    old = record_to_event(_record(container="File")).source_locator
    assert new.startswith("InventoryApplicationFile=")
    assert old.startswith("File=")
    assert new != old


def test_path_is_as_recorded():
    """Amcache lowercases paths itself. The parser does not re-case them, so the
    value stays what the artifact holds (CD-010)."""
    e = record_to_event(_record())
    assert e.path == r"c:\program files\windowsapps\3dviewer.exe"


@pytest.mark.parametrize(
    "path,expected",
    [
        (REL, True),
        (REL.lower(), True),
        ("C/Windows/AppCompat/Programs/Amcache.hve.LOG1", False),
        ("C/Windows/AppCompat/Programs/RecentFileCache.bcf", False),
        ("C/Users/janed/NTUSER.DAT", False),
        ("C/Windows/System32/config/SOFTWARE", False),
    ],
)
def test_can_handle(path, expected):
    assert AmcacheParser().can_handle(path) is expected


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_real_hive_parses_and_every_event_carries_a_path():
    abs_path = Path(COLLECTION) / REL
    if not abs_path.exists():
        pytest.skip("Amcache.hve not in this collection")
    events = list(AmcacheParser().parse(abs_path, REL))
    assert events
    assert all(e.path for e in events)
    assert all(e.timestamp_type == "presence" for e in events)


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_scenario_binary_is_absent_from_amcache():
    """A negative result, pinned so it is not mistaken for a parser fault.

    invoice_scan.exe executed at 2026-08-23T22:57:15Z and appears in Prefetch,
    but no Amcache entry exists for it in any subkey. The hive is current -- its
    newest entries are the Guest Additions binaries at 23:15:02, eighteen
    minutes after the execution -- so this is not a stale hive.

    Amcache is populated by the Microsoft Compatibility Appraiser scheduled
    task, which had not run between execution and collection. The consequence
    for Week 3 is that Amcache cannot corroborate this execution, and a rule
    requiring Prefetch and Amcache to agree would miss the one real detection in
    the corpus."""
    abs_path = Path(COLLECTION) / REL
    if not abs_path.exists():
        pytest.skip("Amcache.hve not in this collection")
    events = list(AmcacheParser().parse(abs_path, REL))
    hits = [e for e in events if "invoice" in e.path.lower()]
    if "s1_v2" not in str(COLLECTION):
        pytest.skip("assertion is about the scenario collection")
    assert hits == [], "Amcache unexpectedly carries the scenario binary"
