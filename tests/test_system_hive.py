"""The SYSTEM hive parser: Shimcache, BAM and Services.

The properties pinned here are the ones that would let the parser return
plausible-looking output while being wrong -- which is what D-023 was (a library
read `runCount` at the wrong offset on all 835 Prefetch files and nothing
raised).
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.system_hive import (
    SystemHiveParser,
    filetime_to_utc,
    parse_shimcache,
)

EVIDENCE = Path.home() / "dfir-evidence"
SYSTEM_REL = "C/Windows/System32/config/SYSTEM"

needs_collection = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / SYSTEM_REL).is_file(),
    reason="collection_s1_v3 SYSTEM hive is required",
)


def _shimcache_blob(header_offset: int, entries: list[tuple[str, int]]) -> bytes:
    """Build a synthetic Windows 10/11 AppCompatCache blob.

    Synthetic because the property under test -- that the header offset is READ
    rather than assumed -- cannot be exercised by the corpus, which is Windows
    10 build 19045 with an offset of 52 in every collection.
    """
    body = b""
    for path, ticks in entries:
        encoded = path.encode("utf-16-le")
        # signature(4) crc(4) entry_length(4) path_length(2) path filetime(8)
        entry_length = 2 + len(encoded) + 8
        body += (
            b"10ts"
            + struct.pack("<I", 0)
            + struct.pack("<I", entry_length)
            + struct.pack("<H", len(encoded))
            + encoded
            + struct.pack("<Q", ticks)
        )
    head = struct.pack("<I", header_offset) + b"\x00" * (header_offset - 4)
    return head + body


class TestFiletime:
    def test_zero_is_not_a_time(self):
        """Zero means 'not recorded', not 1601. Emitting an epoch timestamp
        would put an event at the start of the timeline with no evidence."""
        assert filetime_to_utc(0) is None

    def test_below_epoch_is_rejected(self):
        assert filetime_to_utc(116444736000000000) is None

    def test_real_value_converts(self):
        # 2026-09-13T11:50:09Z
        ticks = 116444736000000000 + int(
            datetime(2026, 9, 13, 11, 50, 9, tzinfo=UTC).timestamp() * 10_000_000
        )
        result = filetime_to_utc(ticks)
        assert result is not None
        assert result.year == 2026 and result.month == 9

    def test_absurd_value_does_not_raise(self):
        assert filetime_to_utc(2**63 - 1) is None


class TestShimcacheFormat:
    def test_header_offset_is_read_not_assumed(self):
        """THE property that makes Windows 11 work. All five collections are
        Windows 10 19045 with an offset of 52; other builds use 48. A parser
        that hardcoded either would silently return nothing on the other."""
        for offset in (48, 52, 64):
            blob = _shimcache_blob(offset, [("C:\\Windows\\x.exe", 0)])
            entries = parse_shimcache(blob)
            assert len(entries) == 1, f"offset {offset} produced no entries"
            assert entries[0][0] == "C:\\Windows\\x.exe"

    def test_unknown_signature_yields_nothing(self):
        """A partially decoded cache is worse than none: entries are
        variable-length, so a wrong offset assembles plausible paths from the
        middle of other records."""
        blob = struct.pack("<I", 52) + b"\x00" * 48 + b"00ts" + b"\x00" * 40
        assert parse_shimcache(blob) == []

    def test_truncated_blob_stops_cleanly(self):
        blob = _shimcache_blob(52, [("C:\\a.exe", 0)])[:-4]
        parse_shimcache(blob)  # must not raise

    def test_empty_blob(self):
        assert parse_shimcache(b"") == []
        assert parse_shimcache(b"\x00\x00") == []

    def test_multiple_entries_in_order(self):
        """Position is meaningful -- entry 0 is the most recently inserted --
        and it is the only stable identifier the cache offers."""
        blob = _shimcache_blob(
            52, [("C:\\first.exe", 0), ("C:\\second.exe", 0), ("C:\\third.exe", 0)]
        )
        paths = [p for p, _ in parse_shimcache(blob)]
        assert paths == ["C:\\first.exe", "C:\\second.exe", "C:\\third.exe"]

    def test_path_length_zero_stops(self):
        """A zero-length path is a malformed entry, not an empty filename."""
        blob = struct.pack("<I", 52) + b"\x00" * 48
        blob += b"10ts" + struct.pack("<I", 0) + struct.pack("<I", 10)
        blob += struct.pack("<H", 0) + b"\x00" * 8
        assert parse_shimcache(blob) == []


class TestCanHandle:
    def test_accepts_the_system_hive(self):
        parser = SystemHiveParser()
        assert parser.can_handle("C/Windows/System32/config/SYSTEM")
        assert parser.can_handle("c/windows/system32/config/system")

    def test_rejects_transaction_logs(self):
        """They share the basename and hold no committed values."""
        parser = SystemHiveParser()
        for suffix in (".LOG", ".LOG1", ".LOG2"):
            assert not parser.can_handle(f"C/Windows/System32/config/SYSTEM{suffix}")

    def test_rejects_other_hives(self):
        parser = SystemHiveParser()
        assert not parser.can_handle("C/Windows/System32/config/SOFTWARE")
        assert not parser.can_handle("C/Users/x/NTUSER.DAT")


@needs_collection
class TestAgainstRealHive:
    @pytest.fixture(scope="class")
    def events(self):
        parser = SystemHiveParser()
        path = EVIDENCE / "collection_s1_v3" / SYSTEM_REL
        result = list(parser.parse(path, SYSTEM_REL))
        assert result, "parser produced no events; the tests would pass vacuously"
        return result

    def test_all_three_artifacts_are_emitted(self, events):
        families = {e.source_artifact for e in events}
        assert families == {"shimcache", "bam", "services"}

    def test_shimcache_carries_presence_not_execution(self, events):
        """Windows 10 populates entries on enumeration as well as on run, so
        the event type is program_shimcached and the claim is presence."""
        rows = [e for e in events if e.source_artifact == "shimcache"]
        assert rows
        assert all(e.event_type == "program_shimcached" for e in rows)
        assert all(e.timestamp_type == "presence" for e in rows)

    def test_bam_supplies_the_principal_prefetch_cannot(self, events):
        """The attestation matrix row this parser exists for: Prefetch records
        no user at all, and BAM re-attributes an execution to a SID."""
        rows = [e for e in events if e.source_artifact == "bam"]
        assert rows
        assert all(e.user and e.user.startswith("S-1-") for e in rows)
        assert all(e.timestamp_type == "last_run" for e in rows)

    def test_bam_bookkeeping_values_are_not_binaries(self, events):
        """Version and SequenceNumber sit alongside the paths and are not
        executables; emitting them would invent two binaries per SID."""
        paths = {e.path for e in events if e.source_artifact == "bam"}
        assert "Version" not in paths
        assert "SequenceNumber" not in paths

    def test_services_require_an_image_path(self, events):
        """A key without one is a driver stub or a configuration container,
        not an installed service with an executable."""
        rows = [e for e in events if e.source_artifact == "services"]
        assert rows
        assert all(e.path for e in rows)

    def test_every_event_carries_provenance(self, events):
        """CD-003/CD-004. A finding that cannot name its source is not
        acceptable output, and that starts here."""
        for event in events:
            assert event.source_file == SYSTEM_REL
            assert event.source_locator

    def test_locators_are_unique_within_the_hive(self, events):
        """CD-004: unique within the file. Shimcache has no id of its own, so
        position is the identifier -- and it must not collide."""
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_the_scenario_binary_is_attributed_to_a_sid(self, events):
        """s1_v3's 4688 was destroyed by the log clear. BAM re-attributes the
        execution regardless, which is the corroboration the matrix claims."""
        hits = [
            e
            for e in events
            if e.source_artifact == "bam"
            and "invoice_scan" in (e.details.get("path_basename_canonical") or "")
        ]
        assert hits, "invoice_scan.exe absent from BAM"
        assert hits[0].user.startswith("S-1-5-21-")
