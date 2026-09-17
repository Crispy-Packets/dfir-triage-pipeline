"""The USN change journal: creation, deletion and rename.

Two properties carry the weight here:

* the walk must RE-SYNCHRONISE rather than abort, because the journal is a
  sparse file whose head is zeroed as records age out -- aborting on the first
  zero length would discard all 169,000 records after it;
* one operation is one event. NTFS writes a record at each stage of an
  operation, and 43% of otherwise-emitted rows restate an earlier one.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.usn_journal import (
    UsnJournalParser,
    filetime_to_utc,
    iter_records,
)

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")
USN_REL = "C/$Extend/$J"

needs_s1v3 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / USN_REL).is_file(),
    reason="s1_v3 $J required",
)
needs_s1v2 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v2" / USN_REL).is_file(),
    reason="s1_v2 $J required",
)

CREATE = 0x00000100
DELETE = 0x00000200
RENAME_OLD = 0x00001000
RENAME_NEW = 0x00002000
CLOSE = 0x80000000


def _ticks(when: datetime) -> int:
    return 116444736000000000 + int(when.timestamp() * 10_000_000)


def _record(name: str, reason: int, when: datetime, *, major: int = 2) -> bytes:
    encoded = name.encode("utf-16-le")
    name_offset = 60
    length = name_offset + len(encoded)
    length += (-length) % 8  # 8-byte aligned
    blob = bytearray(length)
    struct.pack_into("<I", blob, 0, length)
    struct.pack_into("<HH", blob, 4, major, 0)
    struct.pack_into("<Q", blob, 32, _ticks(when))
    struct.pack_into("<I", blob, 40, reason)
    struct.pack_into("<HH", blob, 56, len(encoded), name_offset)
    blob[name_offset : name_offset + len(encoded)] = encoded
    return bytes(blob)


class TestFiletime:
    def test_real_value(self):
        when = datetime(2026, 9, 13, 11, 50, 10, tzinfo=UTC)
        assert filetime_to_utc(_ticks(when)).day == 13

    def test_zero_and_absurd(self):
        assert filetime_to_utc(0) is None
        assert filetime_to_utc(-1) is None
        assert filetime_to_utc(2**63 - 1) is None
        assert filetime_to_utc(True) is None


class TestIterRecords:
    def test_a_single_record(self):
        when = datetime(2026, 9, 13, 11, 50, 10, tzinfo=UTC)
        blob = _record("marker.txt", CREATE, when)
        found = list(iter_records(blob))
        assert len(found) == 1
        assert found[0][3] == "marker.txt"
        assert found[0][2] == CREATE

    def test_consecutive_records(self):
        when = datetime(2026, 9, 13, 11, 50, 10, tzinfo=UTC)
        blob = _record("a.txt", CREATE, when) + _record("b.txt", DELETE, when)
        assert [r[3] for r in iter_records(blob)] == ["a.txt", "b.txt"]

    def test_the_leading_sparse_region_is_skipped(self):
        """The journal's head is zeroed as records age out. A length of zero is
        unallocated space, not a malformed record."""
        when = datetime(2026, 9, 13, tzinfo=UTC)
        blob = b"\x00" * 4096 + _record("late.txt", CREATE, when)
        assert [r[3] for r in iter_records(blob)] == ["late.txt"]

    def test_a_torn_region_does_not_discard_what_follows(self):
        """THE property. Aborting on the first implausible length would throw
        away every record after a single damaged one."""
        when = datetime(2026, 9, 13, tzinfo=UTC)
        blob = (
            _record("before.txt", CREATE, when)
            + b"\xff" * 64
            + _record("after.txt", CREATE, when)
        )
        names = [r[3] for r in iter_records(blob)]
        assert "before.txt" in names
        assert "after.txt" in names

    def test_an_absurd_length_resynchronises(self):
        when = datetime(2026, 9, 13, tzinfo=UTC)
        bad = bytearray(_record("bad.txt", CREATE, when))
        struct.pack_into("<I", bad, 0, 0xFFFFFF)
        blob = bytes(bad) + _record("good.txt", CREATE, when)
        assert "good.txt" in [r[3] for r in iter_records(blob)]

    def test_unknown_major_versions_are_skipped(self):
        when = datetime(2026, 9, 13, tzinfo=UTC)
        blob = _record("x.txt", CREATE, when, major=9)
        assert list(iter_records(blob)) == []

    def test_version_three_is_accepted(self):
        when = datetime(2026, 9, 13, tzinfo=UTC)
        assert list(iter_records(_record("v3.txt", CREATE, when, major=3)))

    def test_a_name_running_past_the_record_is_skipped(self):
        when = datetime(2026, 9, 13, tzinfo=UTC)
        bad = bytearray(_record("x.txt", CREATE, when))
        struct.pack_into("<H", bad, 56, 9999)
        assert list(iter_records(bytes(bad))) == []

    def test_empty_input(self):
        assert list(iter_records(b"")) == []
        assert list(iter_records(b"\x00" * 100)) == []


class TestCanHandle:
    def test_accepts_the_journal(self):
        parser = UsnJournalParser()
        assert parser.can_handle("C/$Extend/$J")
        assert parser.can_handle("c\\$extend\\$j")

    def test_rejects_siblings(self):
        parser = UsnJournalParser()
        assert not parser.can_handle("C/$Extend/$Max")
        assert not parser.can_handle("C/$MFT")
        assert not parser.can_handle("C/$LogFile")


class TestDeduplication:
    def test_one_operation_yields_one_event(self, tmp_path):
        """NTFS writes create, create+extend, create+extend+close for a single
        file creation. Measured: invoice_scan_marker.txt produced three."""
        when = datetime(2026, 9, 13, 11, 50, 10, tzinfo=UTC)
        blob = (
            _record("marker.txt", CREATE, when)
            + _record("marker.txt", CREATE | 0x02, when)
            + _record("marker.txt", CREATE | 0x02 | CLOSE, when)
        )
        path = tmp_path / "J"
        path.write_bytes(blob)
        events = list(UsnJournalParser().parse(path, USN_REL))
        assert len(events) == 1
        assert events[0].event_type == "file_created"

    def test_the_same_name_at_a_different_time_is_a_different_event(self, tmp_path):
        blob = (
            _record("x.txt", CREATE, datetime(2026, 9, 13, 11, 0, tzinfo=UTC))
            + _record("x.txt", CREATE, datetime(2026, 9, 13, 12, 0, tzinfo=UTC))
        )
        path = tmp_path / "J"
        path.write_bytes(blob)
        assert len(list(UsnJournalParser().parse(path, USN_REL))) == 2

    def test_a_delete_outranks_a_close(self, tmp_path):
        """A record carrying several flags is named by its strongest claim."""
        when = datetime(2026, 9, 13, tzinfo=UTC)
        path = tmp_path / "J"
        path.write_bytes(_record("gone.txt", DELETE | CLOSE, when))
        events = list(UsnJournalParser().parse(path, USN_REL))
        assert [e.event_type for e in events] == ["file_deleted"]

    def test_non_lifecycle_reasons_yield_nothing(self, tmp_path):
        """A data overwrite says a file was touched -- extremely common, and
        the weakest claim the journal makes."""
        when = datetime(2026, 9, 13, tzinfo=UTC)
        path = tmp_path / "J"
        path.write_bytes(_record("touched.txt", 0x00000002 | CLOSE, when))
        assert list(UsnJournalParser().parse(path, USN_REL)) == []


@needs_s1v3
class TestTheScenarioSideEffect:
    def test_the_marker_file_creation_is_recorded(self):
        """The result this family exists for. Prefetch, Amcache, BAM and
        Shimcache all say the binary RAN; only the journal shows what it DID."""
        path = EVIDENCE / "collection_s1_v3" / USN_REL
        events = list(UsnJournalParser().parse(path, USN_REL))
        markers = [e for e in events if "invoice_scan_marker" in e.path.lower()]
        assert markers, "the payload's side effect is absent from the journal"
        assert markers[0].event_type == "file_created"
        assert markers[0].timestamp.hour == 11
        # Deduplicated: three records, one event.
        assert len(markers) == 1

    def test_the_marker_file_is_corroborated_only_by_the_operator_history(self):
        """What makes the journal necessary rather than redundant.

        WRITTEN AS "no other family records it" AND THAT WAS WRONG -- this
        test caught it. `ps_history` names the marker too, because the
        operator's own typed command creates it.

        The two are different claims and they corroborate each other: the
        history records the INSTRUCTION, and only in the account that typed it;
        the journal records the FILESYSTEM EFFECT, machine-wide, whether or not
        anyone typed anything. An attacker's dropper leaves the second and not
        the first.

        No execution-evidence family -- prefetch, amcache, bam, shimcache --
        names it at all. They say the binary RAN; only the journal shows what
        it DID.
        """
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        naming = {
            e.source_artifact
            for e in events
            if "invoice_scan_marker" in str(e.path or "").lower()
        }
        assert "usn" in naming
        assert not naming & {"prefetch", "amcache", "bam", "shimcache", "browser"}

    def test_timestamp_type_is_recorded(self):
        path = EVIDENCE / "collection_s1_v3" / USN_REL
        events = list(UsnJournalParser().parse(path, USN_REL))
        assert events
        assert all(e.timestamp_type == "recorded" for e in events)

    def test_locators_are_unique(self):
        path = EVIDENCE / "collection_s1_v3" / USN_REL
        locators = [e.source_locator for e in UsnJournalParser().parse(path, USN_REL)]
        assert len(locators) == len(set(locators))


@needs_s1v2
class TestTheRename:
    def test_the_payload_was_renamed(self):
        """s1_v2 holds a RENAME_OLD for invoice_scan.exe at 21:33 -- the
        operator swapping the binary between runs, which the $I records
        corroborate at three different sizes. No other family shows a rename
        at all."""
        path = EVIDENCE / "collection_s1_v2" / USN_REL
        events = list(UsnJournalParser().parse(path, USN_REL))
        renames = [
            e
            for e in events
            if "invoice_scan.exe" in e.path.lower()
            and e.event_type.startswith("file_renamed")
        ]
        assert renames

    def test_rename_is_unique_to_this_family(self):
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v2")
        renamers = {
            e.source_artifact
            for e in events
            if e.event_type.startswith("file_renamed")
        }
        assert renamers == {"usn"}
