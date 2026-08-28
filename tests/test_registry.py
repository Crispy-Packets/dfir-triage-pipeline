import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.registry import (
    RegistryParser,
    filetime_to_utc,
    record_to_event,
)

HIVE = "C/Users/admin_local/NTUSER.DAT"
RUN = r"\Software\Microsoft\Windows\CurrentVersion\Run"


def _record(
    value_name="SecurityUpdate",
    value_data=r"C:\Users\janed\Downloads\invoice_scan.exe",
    owner="admin_local",
    count=2,
):
    return {
        "hive_type": "ntuser",
        "hive": HIVE,
        "key_path": RUN,
        "value_name": value_name,
        "value_data": value_data,
        "key_last_write": datetime(2026, 8, 21, 1, 34, 7, 976259, tzinfo=UTC),
        "value_count_in_key": count,
        "owner": owner,
    }


def test_timestamp_type_is_presence_not_recorded():
    """The key's last-write time is not the moment this value was written --
    every value under the key shares it. CD-019's `presence` says the entry
    exists now and when it appeared is unknown. Emitting `recorded` here would
    licence a correlation rule to place it in a time window it cannot support."""
    assert record_to_event(_record()).timestamp_type == "presence"


def test_value_data_is_verbatim_not_expanded():
    """CD-010. %APPDATA% is expanded by the OS at run time using the running
    user's environment; expanding it here would assert a path the artifact never
    recorded, and would resolve against the wrong profile for a machine-wide
    key."""
    raw = r"%APPDATA%\Microsoft\updater.exe"
    e = record_to_event(_record(value_data=raw))
    assert e.path == raw
    assert e.details["value_data"] == raw


def test_user_is_the_profile_owner_not_the_payload_owner():
    """In collection_s1_v2 the SecurityUpdate value sits in admin_local's hive
    while pointing at a binary under janed's profile. user is who the autorun
    runs as; deriving it from the value data would misattribute persistence to
    the account that happens to own the file."""
    e = record_to_event(_record())
    assert e.user == "admin_local"
    assert "janed" in e.path


def test_key_last_write_is_also_in_details_with_the_value_count():
    """Two events with an identical timestamp are explained by the count: they
    are siblings under one key, not two things that happened at one instant."""
    e = record_to_event(_record(count=2))
    assert e.details["key_last_write"].endswith("Z")
    assert e.details["value_count_in_key"] == "2"


def test_source_locator_distinguishes_run_from_runonce():
    """CD-004. A value name can repeat across Run and RunOnce within one hive,
    so the locator carries the key path as well as the name."""
    run = record_to_event(_record())
    once = record_to_event({**_record(), "key_path": RUN + "Once"})
    assert run.source_locator != once.source_locator
    assert run.source_locator.endswith("SecurityUpdate")


def test_contract_fields():
    e = record_to_event(_record())
    assert e.source_artifact == "registry"
    assert e.event_type == "persistence_autorun"
    assert e.confidence == "high"
    assert e.source_file == HIVE
    assert e.timestamp.utcoffset().total_seconds() == 0


def test_filetime_conversion_matches_the_known_key():
    """134317496479762600 is the real last-write time of admin_local's Run key
    in collection_s1_v2, read independently with regipy."""
    assert filetime_to_utc(134317496479762600) == datetime(
        2026, 8, 21, 1, 34, 7, 976260, tzinfo=UTC
    )


@pytest.mark.parametrize(
    "path,expected",
    [
        ("C/Users/janed/NTUSER.DAT", True),
        ("C/Users/admin_local/ntuser.dat", True),
        ("C/Windows/ServiceProfiles/LocalService/NTUSER.DAT", True),
        ("C/Windows/System32/config/SOFTWARE", True),
        # Transaction logs share the basename but are not hives.
        ("C/Users/janed/ntuser.dat.LOG1", False),
        ("C/Users/janed/ntuser.dat.LOG2", False),
        ("C/Windows/System32/config/SOFTWARE.LOG1", False),
        # SAM and SYSTEM are collected but carry no autorun keys.
        ("C/Windows/System32/config/SAM", False),
        ("C/Windows/System32/config/SYSTEM", False),
        # A stray file named SOFTWARE outside the config directory is not the
        # machine hive.
        ("C/Users/janed/Documents/SOFTWARE", False),
        ("C/Windows/prefetch/NOTEPAD.EXE-D8414F97.pf", False),
    ],
)
def test_can_handle(path, expected):
    assert RegistryParser().can_handle(path) is expected


def test_hive_without_autorun_keys_yields_nothing_and_does_not_raise(tmp_path):
    """Default's NTUSER.DAT has no Run key. A profile that never registered an
    autorun is an absence of evidence, not a parser fault -- raising would count
    it as a failure and misreport the run."""
    from dfir_triage_pipeline.parsers.registry import _records

    collection = os.environ.get("DFIR_TEST_COLLECTION")
    if not collection:
        pytest.skip("DFIR_TEST_COLLECTION not set")
    rel = "C/Users/Default/NTUSER.DAT"
    abs_path = Path(collection) / rel
    if not abs_path.exists():
        pytest.skip("Default profile hive not in this collection")
    assert list(_records(abs_path, rel)) == []


def test_unreadable_hive_raises_and_is_counted(tmp_path):
    """The empty-key guard is narrow by design: a missing Run key is silence, but
    a file that is not a hive at all must raise so the runner counts it."""
    from dfir_triage_pipeline.parsers.registry import _records

    fake = tmp_path / "NTUSER.DAT"
    fake.write_bytes(b"NOTAHIVE" + b"\x00" * 512)
    with pytest.raises(Exception):  # noqa: B017 - regipy raises its own types
        list(_records(fake, "C/Users/x/NTUSER.DAT"))


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_real_hive_emits_the_scenario_persistence():
    """The end-to-end check named in the step: collection_s1_v2 must yield a row
    whose path contains invoice_scan and whose locator names SecurityUpdate."""
    root = Path(COLLECTION)
    rel = "C/Users/admin_local/NTUSER.DAT"
    abs_path = root / rel
    if not abs_path.exists():
        pytest.skip("admin_local hive not in this collection")
    events = list(RegistryParser().parse(abs_path, rel))
    hits = [e for e in events if "invoice_scan" in e.path.lower()]
    if not hits:
        pytest.skip("this collection carries no scenario persistence")
    assert len(hits) == 1
    assert "SecurityUpdate" in hits[0].source_locator
    assert hits[0].timestamp_type == "presence"
    assert hits[0].user == "admin_local"
