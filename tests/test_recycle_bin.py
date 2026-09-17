"""`$I` records: a deletion, with the path the USN journal cannot supply.

The property that would silently produce a wrong path is the VERSION: v1 has a
fixed 260-character name field, v2 a length prefix. Applying the wrong layout
yields a path assembled from the length bytes onward -- plausible, and it does
not raise.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.recycle_bin import (
    RecycleBinParser,
    filetime_to_utc,
    parse_info_record,
)

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")

needs_s1v3 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3").is_dir(), reason="collection_s1_v3 required"
)
needs_s1v2 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v2").is_dir(), reason="collection_s1_v2 required"
)


def _ticks(when: datetime) -> int:
    return 116444736000000000 + int(when.timestamp() * 10_000_000)


def _v2(path: str, *, size: int = 4608, ticks: int = 0) -> bytes:
    encoded = path.encode("utf-16-le") + b"\x00\x00"
    chars = len(encoded) // 2
    return (
        struct.pack("<QQQ", 2, size, ticks) + struct.pack("<I", chars) + encoded
    )


def _v1(path: str, *, size: int = 4608, ticks: int = 0) -> bytes:
    name = path.encode("utf-16-le")
    name += b"\x00" * (260 * 2 - len(name))
    return struct.pack("<QQQ", 1, size, ticks) + name


class TestVersionHandling:
    def test_version_two_uses_the_length_prefix(self):
        record = parse_info_record(_v2("C:\\Users\\vboxuser\\Desktop\\invoice_scan.exe"))
        assert record["original_path"] == "C:\\Users\\vboxuser\\Desktop\\invoice_scan.exe"
        assert record["version"] == 2

    def test_version_one_uses_the_fixed_field(self):
        record = parse_info_record(_v1("C:\\Temp\\old.txt"))
        assert record["original_path"] == "C:\\Temp\\old.txt"
        assert record["version"] == 1

    def test_an_unknown_version_is_rejected(self):
        """Not decoded with a guessed layout. A version this parser has not
        seen is an absence, not an invitation to try v2's offsets."""
        blob = bytearray(_v2("C:\\x.txt"))
        struct.pack_into("<Q", blob, 0, 7)
        assert parse_info_record(bytes(blob)) is None

    def test_an_absurd_name_length_is_rejected(self):
        """A Windows path cannot exceed 32767 characters. A larger prefix means
        the record is not what it claims, and trusting it would read far past
        the buffer."""
        blob = bytearray(_v2("C:\\x.txt"))
        struct.pack_into("<I", blob, 24, 10**7)
        assert parse_info_record(bytes(blob)) is None

    def test_a_zero_name_length_is_rejected(self):
        blob = bytearray(_v2("C:\\x.txt"))
        struct.pack_into("<I", blob, 24, 0)
        assert parse_info_record(bytes(blob)) is None

    def test_a_truncated_name_yields_nothing(self):
        """A partial path is indistinguishable from a complete one and would be
        reported as the file's location."""
        full = _v2("C:\\Users\\vboxuser\\Desktop\\invoice_scan.exe")
        assert parse_info_record(full[:-10]) is None

    def test_short_and_non_bytes_input(self):
        assert parse_info_record(b"") is None
        assert parse_info_record(b"\x02" * 20) is None
        assert parse_info_record(None) is None


class TestFields:
    def test_size_and_time(self):
        when = datetime(2026, 9, 12, 10, 30, 38, tzinfo=UTC)
        record = parse_info_record(
            _v2("C:\\x.exe", size=201216, ticks=_ticks(when))
        )
        assert record["file_size"] == 201216
        assert record["deleted_at"].day == 12

    def test_zero_time_is_none_not_1601(self):
        assert parse_info_record(_v2("C:\\x.exe", ticks=0))["deleted_at"] is None

    def test_filetime_rejects_nonsense(self):
        assert filetime_to_utc(0) is None
        assert filetime_to_utc(-1) is None
        assert filetime_to_utc(True) is None
        assert filetime_to_utc(2**63 - 1) is None


class TestCanHandle:
    def test_accepts_info_records(self):
        parser = RecycleBinParser()
        base = "C/$Recycle.Bin/S-1-5-21-1591430865-807086247-2139423957-1000"
        assert parser.can_handle(f"{base}/$IA9EQBZ.exe")
        assert parser.can_handle(f"{base}/$ia9eqbz.txt")

    def test_rejects_the_content_file(self):
        """`$R` holds the deleted file itself and has no structure."""
        base = "C/$Recycle.Bin/S-1-5-21-1591430865-807086247-2139423957-1000"
        assert not RecycleBinParser().can_handle(f"{base}/$RA9EQBZ.exe")

    def test_rejects_files_outside_the_bin(self):
        parser = RecycleBinParser()
        assert not parser.can_handle("C/Users/vboxuser/Desktop/$IA9EQBZ.exe")
        assert not parser.can_handle("C/Windows/System32/config/SAM")


@needs_s1v3
class TestTheDeletedPayload:
    def test_the_scenario_binary_is_recorded_as_deleted(self):
        """The result this family exists for. Prefetch, Amcache, BAM and
        Shimcache all attest that invoice_scan.exe RAN; this is the only
        family that says it was removed afterwards."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        rows = [e for e in events if e.source_artifact == "recyclebin"]
        assert rows, "no $I records parsed"
        hits = [e for e in rows if "invoice_scan" in e.path.lower()]
        assert hits
        assert hits[0].path == "C:\\Users\\vboxuser\\Desktop\\invoice_scan.exe"
        assert hits[0].details["deleted_size"] == "4608"
        assert hits[0].event_type == "file_deleted"

    def test_the_sid_comes_from_the_path(self):
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        rows = [e for e in events if e.source_artifact == "recyclebin"]
        assert all(e.user and e.user.startswith("S-1-5-21-") for e in rows)

    def test_timestamp_type_is_recorded(self):
        """Windows wrote the FILETIME when it moved the file. Unlike `lnk`,
        this is an observation rather than a property copied from a target."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        rows = [e for e in events if e.source_artifact == "recyclebin"]
        assert all(e.timestamp_type == "recorded" for e in rows)


@needs_s1v2
class TestTheIterationHistory:
    def test_the_payload_was_deleted_repeatedly_at_changing_sizes(self):
        """s1_v2 holds nine deletions of the same name across four days at
        three sizes -- the operator iterating on the binary. No other family
        in the pipeline shows any of this."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v2")
        rows = [
            e
            for e in events
            if e.source_artifact == "recyclebin" and "invoice_scan" in e.path.lower()
        ]
        assert len(rows) >= 9
        assert len({e.details["deleted_size"] for e in rows}) >= 3

    def test_the_bin_records_what_the_journal_cannot(self):
        """AMENDED 2026-09-17. This asserted that `recyclebin` was the ONLY
        family recording a deletion, which was true when written and stopped
        being true when the USN journal landed the same day. The test caught
        that, so the claim is corrected rather than deleted.

        The two are not redundant and each holds what the other cannot:

          recyclebin  the ORIGINAL FULL PATH and the size at deletion, for
                      files that went to the bin
          usn         a NAME only -- the journal identifies the parent by MFT
                      reference, which resolving needs the $MFT -- but it sees
                      deletions that NEVER went to the bin: shift-delete, a
                      program removing its own temp files, an attacker
                      cleaning up

        Measured on s1_v2: the bin holds nine deletions of invoice_scan.exe
        with full paths and three distinct sizes; the journal holds the
        Prefetch file's deletion, which never went to the bin at all.
        """
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v2")
        deleters = {e.source_artifact for e in events if e.event_type == "file_deleted"}
        assert deleters == {"recyclebin", "usn"}

        bin_rows = [
            e
            for e in events
            if e.source_artifact == "recyclebin" and "invoice_scan" in e.path.lower()
        ]
        assert bin_rows
        # Only the bin carries a full path and a size.
        assert all(e.path.startswith("C:") for e in bin_rows)
        assert all("deleted_size" in e.details for e in bin_rows)


class TestAcrossCollections:
    @pytest.mark.parametrize(
        "collection,expected",
        [
            ("collection_clean_a", 0),
            ("collection_clean_b", 5),
            ("collection_s1_v2", 14),
            ("collection_clean_c", 0),
            ("collection_s1_v3", 1),
        ],
    )
    def test_measured_counts(self, collection, expected):
        """Measured 2026-09-17. Zero on two collections is a real result: the
        Recycle Bin was empty, not unparsed."""
        root = EVIDENCE / collection
        if not root.is_dir():
            pytest.skip(f"{collection} not present")
        parser = RecycleBinParser()
        count = 0
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if parser.can_handle(rel):
                count += len(list(parser.parse(path, rel)))
        assert count == expected
