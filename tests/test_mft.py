"""`$MFT`: every file on the volume, including deleted ones.

Two properties carry the weight:

* **the fixup array must be applied.** NTFS overwrites the last two bytes of
  every 512-byte sector with an update-sequence number. A parser that skips
  this reads two corrupted bytes per sector -- landing inside filenames and
  timestamps -- and produces plausible garbage without raising.
* **no timestomping verdict is derived from $SI vs $FN.** That comparison was
  implemented here and measured at a 27% base rate on a CLEAN collection
  (D-051). The test below pins its absence so it cannot be reintroduced
  without the measurement being redone.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline.parsers.mft import (
    MftParser,
    apply_fixup,
    filetime_to_utc,
    parse_record,
)

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")
MFT_REL = "C/$MFT"

needs_s1v3 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / MFT_REL).is_file(),
    reason="s1_v3 $MFT required",
)


def _record(
    name: str = "test.txt",
    *,
    in_use: bool = True,
    directory: bool = False,
    si_ticks: int = 133_000_000_000_000_000,
    fn_ticks: int = 133_000_000_000_000_000,
    usn: bytes = b"\x05\x00",
    tear: bool = False,
) -> bytes:
    """A 1024-byte MFT record with $SI and $FN, fixup applied as NTFS would."""
    record = bytearray(1024)
    record[0:4] = b"FILE"
    struct.pack_into("<HH", record, 4, 48, 3)  # usa offset, count
    flags = (1 if in_use else 0) | (2 if directory else 0)
    struct.pack_into("<H", record, 22, flags)
    struct.pack_into("<H", record, 20, 56)  # first attribute
    struct.pack_into("<I", record, 28, 1024)  # bytes allocated

    offset = 56
    # $STANDARD_INFORMATION: resident, four FILETIMEs at the body start.
    si_len = 24 + 48
    struct.pack_into("<II", record, offset, 0x10, si_len)
    record[offset + 8] = 0
    struct.pack_into("<H", record, offset + 20, 24)
    for i in range(4):
        struct.pack_into("<Q", record, offset + 24 + i * 8, si_ticks)
    offset += si_len

    # $FILE_NAME: parent ref(8) then four FILETIMEs, then sizes, then name.
    encoded = name.encode("utf-16-le")
    fn_body = 66 + len(encoded)
    fn_len = 24 + fn_body
    struct.pack_into("<II", record, offset, 0x30, fn_len)
    record[offset + 8] = 0
    struct.pack_into("<H", record, offset + 20, 24)
    body = offset + 24
    for i in range(4):
        struct.pack_into("<Q", record, body + 8 + i * 8, fn_ticks)
    record[body + 64] = len(name)
    record[body + 65] = 3  # namespace: win32+dos
    record[body + 66 : body + 66 + len(encoded)] = encoded
    offset += fn_len

    struct.pack_into("<I", record, offset, 0xFFFFFFFF)

    # The update sequence: array at 48, and each sector's last two bytes hold
    # the USN with the real bytes stashed in the array.
    record[48:50] = usn
    for i in (1, 2):
        end = i * 512 - 2
        record[50 + (i - 1) * 2 : 52 + (i - 1) * 2] = b"\xaa\xbb"
        record[end : end + 2] = b"\xff\xff" if tear else usn
    return bytes(record)


class TestFixup:
    def test_the_stashed_bytes_are_restored(self):
        """Without this, two bytes per sector are the USN rather than data."""
        fixed = apply_fixup(_record())
        assert fixed is not None
        assert fixed[510:512] == b"\xaa\xbb"
        assert fixed[1022:1024] == b"\xaa\xbb"

    def test_a_torn_record_is_rejected_not_repaired(self):
        """A sector whose trailing bytes do not carry the expected USN was
        captured mid-write. Its real contents are unknown, and guessing would
        fabricate a filename or a timestamp."""
        assert apply_fixup(_record(tear=True)) is None

    def test_a_short_or_absurd_header(self):
        assert apply_fixup(b"") is None
        assert apply_fixup(b"FILE" + b"\x00" * 4) is None


class TestParseRecord:
    def test_a_file_record(self):
        record = parse_record(_record("invoice_scan.exe"))
        assert record["name"] == "invoice_scan.exe"
        assert record["in_use"] is True
        assert record["is_directory"] is False
        assert record["si"][0] is not None

    def test_a_deleted_record_still_parses(self):
        """The reason this family matters: a deleted file's record survives
        with its name and times until the record is reused."""
        record = parse_record(_record("gone.txt", in_use=False))
        assert record["in_use"] is False
        assert record["name"] == "gone.txt"

    def test_a_directory_is_flagged(self):
        assert parse_record(_record("Downloads", directory=True))["is_directory"]

    def test_a_non_file_signature_is_rejected(self):
        blob = bytearray(_record())
        blob[0:4] = b"BAAD"
        assert parse_record(bytes(blob)) is None

    def test_a_record_with_no_name_yields_nothing(self):
        blob = bytearray(_record())
        # Truncate the attribute chain immediately: no $FILE_NAME.
        struct.pack_into("<I", blob, 56, 0xFFFFFFFF)
        assert parse_record(bytes(blob)) is None

    def test_short_input(self):
        assert parse_record(b"") is None
        assert parse_record(b"FILE") is None


class TestFiletime:
    def test_zero_and_absurd(self):
        assert filetime_to_utc(0) is None
        assert filetime_to_utc(-1) is None
        assert filetime_to_utc(True) is None
        assert filetime_to_utc(2**63 - 1) is None


class TestCanHandle:
    def test_accepts_the_mft(self):
        parser = MftParser()
        assert parser.can_handle("C/$MFT")
        assert parser.can_handle("c\\$mft")

    def test_rejects_other_metafiles(self):
        parser = MftParser()
        for name in ("C/$LogFile", "C/$Boot", "C/$Extend/$J", "C/$Secure_$SDS"):
            assert not parser.can_handle(name)


@needs_s1v3
class TestAgainstTheRealTable:
    @pytest.fixture(scope="class")
    def events(self):
        path = EVIDENCE / "collection_s1_v3" / MFT_REL
        result = list(MftParser().parse(path, MFT_REL))
        assert result, "parser produced no events"
        return result

    def test_deleted_records_are_recovered(self, events):
        """1,136 on s1_v3. No other family in the pipeline holds them."""
        deleted = [e for e in events if e.details["in_use"] == "false"]
        assert deleted
        assert all(e.path for e in deleted)

    def test_names_are_readable(self, events):
        """The fixup regression guard against real evidence: a skipped fixup
        corrupts two bytes per sector, which lands inside filenames."""
        sample = events[:5000]
        unreadable = [
            e for e in sample if "\ufffd" in e.path or not e.path.isprintable()
        ]
        assert not unreadable, f"corrupt names: {[e.path for e in unreadable[:5]]}"

    def test_no_timestomping_verdict_is_emitted(self, events):
        """D-051. The $SI-vs-$FN comparison fires on 27% of a CLEAN
        collection -- every file laid down from the Windows install image --
        so the pipeline emits both timestamps and makes no claim. This pins
        the absence so it cannot return without the measurement being redone.
        """
        for event in events[:20000]:
            assert "si_precedes_fn" not in event.details
            assert "timestomped" not in event.details

    def test_both_timestamp_sources_are_available(self, events):
        """The raw values stay, so an analyst can make the comparison on a
        specific file even though the pipeline will not make it wholesale."""
        with_both = [
            e
            for e in events[:20000]
            if "si_created" in e.details and "fn_created" in e.details
        ]
        assert with_both

    def test_metafiles_are_skipped(self, events):
        """Records 0-15 are NTFS's own structures, not files anyone created."""
        assert all(int(e.details["mft_record"]) >= 16 for e in events)

    def test_locators_are_unique(self, events):
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_timestamp_type_is_presence(self, events):
        """The record attests the file EXISTED with these times; it is not a
        log of an event occurring."""
        assert all(e.timestamp_type == "presence" for e in events[:5000])

    def test_the_scenario_files_are_present(self, events):
        names = {e.path.lower() for e in events}
        assert "invoice_scan.exe" in names
        assert "invoice_scan_marker.txt" in names


@needs_s1v3
class TestCorroboration:
    def test_the_mft_and_usn_agree_on_the_marker_file(self):
        """Two independent NTFS structures, one timestamp. The MFT records the
        file's creation time; the journal records the creation event."""
        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        marker = [
            e
            for e in events
            if "invoice_scan_marker" in str(e.path or "").lower()
            and e.source_artifact in ("mft", "usn")
        ]
        by_family = {e.source_artifact: e for e in marker}
        assert {"mft", "usn"} <= set(by_family)
        mft_created = by_family["mft"].details.get("si_created", "")
        assert mft_created.startswith("2026-09-13T11:50:10")
        assert by_family["usn"].timestamp.strftime("%H:%M:%S") == "11:50:10"
