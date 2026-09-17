"""`$MFT`: the record of every file on the volume, including deleted ones.

361 MB and 352,768 records on `s1_v3`. It is the artefact the attestation
matrix has cited as a missing corroborator more than any other, and it carries
two things no other family in this pipeline has:

* **timestamps a file's own entry declares**, from both `$STANDARD_INFORMATION`
  and `$FILE_NAME`. Both are emitted; **no timestomping verdict is derived from
  comparing them** -- that comparison was implemented, measured at a 27% base
  rate on a CLEAN host, and removed. See D-051 and the comment at the emission
  site;
* **records for files that no longer exist.** A deleted file's record stays
  until reused, with its name and times intact, so the MFT attests to a file
  the filesystem no longer lists.

**Streamed, never loaded.** Records are a fixed 1,024 bytes -- read from the
record's own `bytes_allocated` field rather than assumed -- so the file is
walked with a fixed-size read per record and the 361 MB never enters memory.

**The fixup array is applied, and that is not optional.** NTFS overwrites the
last two bytes of every 512-byte sector with an update-sequence number and
stores the real bytes in an array at the record's head. A parser that skips
this reads two corrupted bytes per sector -- which lands in the middle of
filenames and timestamps, and produces plausible garbage without raising. Where
the sector's stored USN does not match the record's, the record is **torn** and
is skipped rather than repaired: measured, zero torn records in 59,992 scanned.

**What is NOT decoded.** Data runs, resident file content, `$DATA` streams,
attribute lists and the directory index are all skipped. This parser answers
"what files existed, when, and are they still here" -- resolving a record to a
full path means walking parent references through the whole table, which needs
an index this does not build. `Event.path` therefore carries a NAME, the same
limitation `usn` has, and for the same reason.

**Only records with a name are emitted**, and `$MFT`'s own metafiles ($MFT,
$LogFile, $Bitmap and the rest, records 0-15) are skipped: they are volume
structures, not files anybody created.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..model import Event
from . import register

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

_SIGNATURE = b"FILE"

#: A record's size is read from its own header. This bounds a corrupt value.
_MIN_RECORD = 512
_MAX_RECORD = 8192
_DEFAULT_RECORD = 1024

#: NTFS applies the fixup per 512-byte sector.
_SECTOR = 512

#: Header offsets, all fixed.
_OFF_USA_OFFSET = 4
_OFF_USA_COUNT = 6
_OFF_FLAGS = 22
_OFF_ATTR_OFFSET = 20
_OFF_BYTES_ALLOCATED = 28

#: Record flags.
_FLAG_IN_USE = 0x0001
_FLAG_DIRECTORY = 0x0002

#: Attribute types this parser reads. Everything else is skipped by its
#: declared length.
_ATTR_STANDARD_INFORMATION = 0x10
_ATTR_FILE_NAME = 0x30
_ATTR_END = 0xFFFFFFFF

#: Records 0-15 are NTFS's own metafiles.
_FIRST_USER_RECORD = 16

#: $FILE_NAME namespaces. A file usually has both a long and an 8.3 entry; the
#: long one is preferred and the DOS one ignored when a longer exists.
_NAMESPACE_DOS = 2


def filetime_to_utc(ticks: int) -> datetime | None:
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except (OverflowError, ValueError):
        return None
    return converted if converted.year > 1601 else None


def apply_fixup(record: bytes) -> bytes | None:
    """Restore the bytes NTFS replaced with update-sequence numbers.

    Returns None for a TORN record -- one where a sector's trailing bytes do
    not carry the expected USN, meaning the record was captured mid-write. Such
    a record is skipped rather than repaired: the sector's real contents are
    genuinely unknown, and guessing would fabricate a filename or a timestamp.
    """
    if len(record) < 8:
        return None
    usa_offset = struct.unpack_from("<H", record, _OFF_USA_OFFSET)[0]
    usa_count = struct.unpack_from("<H", record, _OFF_USA_COUNT)[0]
    if usa_count < 1 or usa_offset + usa_count * 2 > len(record):
        return None

    expected = record[usa_offset : usa_offset + 2]
    patched = bytearray(record)
    for index in range(1, usa_count):
        end = index * _SECTOR - 2
        if end + 2 > len(patched):
            break
        if bytes(patched[end : end + 2]) != expected:
            return None
        source = usa_offset + index * 2
        patched[end : end + 2] = record[source : source + 2]
    return bytes(patched)


def _resident_attributes(record: bytes) -> Iterator[tuple[int, int]]:
    """(attribute type, offset of its resident body) for each attribute.

    Non-resident attributes are skipped: their content lives in data runs
    elsewhere on the volume, which a triage collection of `$MFT` alone does not
    have.
    """
    offset = struct.unpack_from("<H", record, _OFF_ATTR_OFFSET)[0]
    while offset + 24 <= len(record):
        attr_type = struct.unpack_from("<I", record, offset)[0]
        if attr_type == _ATTR_END:
            return
        length = struct.unpack_from("<I", record, offset + 4)[0]
        if length == 0 or offset + length > len(record):
            return
        if record[offset + 8] == 0:  # resident
            content = offset + struct.unpack_from("<H", record, offset + 20)[0]
            if content < len(record):
                yield attr_type, content
        offset += length


def parse_record(record: bytes) -> dict | None:
    """Decode one MFT record, or None when it is not a usable file record."""
    if len(record) < 48 or record[:4] != _SIGNATURE:
        return None
    fixed = apply_fixup(record)
    if fixed is None:
        return None

    flags = struct.unpack_from("<H", fixed, _OFF_FLAGS)[0]
    out: dict = {
        "in_use": bool(flags & _FLAG_IN_USE),
        "is_directory": bool(flags & _FLAG_DIRECTORY),
        "si": None,
        "fn": None,
        "name": None,
        "namespace": None,
    }

    for attr_type, content in _resident_attributes(fixed):
        if attr_type == _ATTR_STANDARD_INFORMATION and out["si"] is None:
            if content + 32 > len(fixed):
                continue
            out["si"] = tuple(
                filetime_to_utc(struct.unpack_from("<Q", fixed, content + shift)[0])
                for shift in (0, 8, 16, 24)
            )
        elif attr_type == _ATTR_FILE_NAME:
            if content + 66 > len(fixed):
                continue
            name_length = fixed[content + 64]
            namespace = fixed[content + 65]
            end = content + 66 + name_length * 2
            if name_length == 0 or end > len(fixed):
                continue
            try:
                name = fixed[content + 66 : end].decode("utf-16-le")
            except UnicodeDecodeError:
                continue
            # Prefer the long name: a file usually carries both a DOS 8.3
            # entry and a real one, and reporting `INVOIC~1.EXE` would lose
            # the name an analyst is looking for.
            if out["name"] is None or (
                out["namespace"] == _NAMESPACE_DOS and namespace != _NAMESPACE_DOS
            ):
                out["name"] = name
                out["namespace"] = namespace
                out["fn"] = tuple(
                    filetime_to_utc(
                        struct.unpack_from("<Q", fixed, content + shift)[0]
                    )
                    for shift in (8, 16, 24, 32)
                )

    return out if out["name"] else None


def _record_size(header: bytes) -> int:
    """The record size the file itself declares, bounded."""
    if len(header) < _OFF_BYTES_ALLOCATED + 4:
        return _DEFAULT_RECORD
    allocated = struct.unpack_from("<I", header, _OFF_BYTES_ALLOCATED)[0]
    return allocated if _MIN_RECORD <= allocated <= _MAX_RECORD else _DEFAULT_RECORD


class MftParser:
    name = "mft"

    def can_handle(self, relative_path: str) -> bool:
        return relative_path.replace("\\", "/").lower().endswith("/$mft")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        with abs_path.open("rb") as handle:
            first = handle.read(_DEFAULT_RECORD)
            if len(first) < 48 or first[:4] != _SIGNATURE:
                return
            size = _record_size(first)
            handle.seek(0)

            index = -1
            while True:
                raw = handle.read(size)
                if len(raw) < size:
                    return
                index += 1
                if index < _FIRST_USER_RECORD:
                    continue

                record = parse_record(raw)
                if record is None:
                    continue

                details: dict[str, str] = {
                    "mft_record": str(index),
                    "file_name": record["name"],
                    "in_use": str(record["in_use"]).lower(),
                    "is_directory": str(record["is_directory"]).lower(),
                }

                si, fn = record["si"], record["fn"]
                if si:
                    for label, value in zip(
                        ("si_created", "si_modified", "si_mft_modified", "si_accessed"),
                        si,
                        strict=False,
                    ):
                        if value:
                            details[label] = value.isoformat().replace("+00:00", "Z")
                if fn and fn[0]:
                    details["fn_created"] = fn[0].isoformat().replace("+00:00", "Z")

                # NO si_precedes_fn FLAG IS EMITTED, and the omission is the
                # decision. `$SI` earlier than `$FN` is the textbook
                # timestomping indicator, it was implemented here, and
                # measuring it disqualified it: 94,262 of 351,088 records on
                # s1_v3 and 99,955 of 287,983 on clean_c -- 27% of both, with
                # the same files leading each list ($Recycle.Bin, PerfLogs,
                # Program Files).
                #
                # The cause is ordinary: a file laid down from a Windows
                # install image keeps the image's `$SI` and gets a fresh `$FN`
                # when it is written to this volume. That is every OS file.
                # An indicator with a 27% base rate on a clean host is not an
                # indicator, and shipping it would have put a `timestomped`
                # detail on a third of the filesystem.
                #
                # Both timestamps are emitted as details, so an analyst can
                # make the comparison against a specific file. The pipeline
                # does not make the CLAIM. See D-051.

                created = si[0] if si else None
                yield Event(
                    timestamp=created or (fn[0] if fn else _FILETIME_EPOCH),
                    source_artifact="mft",
                    event_type="file_record",
                    action=(
                        "file record present in the MFT"
                        if record["in_use"]
                        else "deleted file record still in the MFT"
                    ),
                    source_file=relative_path,
                    # The record number: unique within the table and the only
                    # identifier it carries (CD-004).
                    source_locator=f"record/{index}",
                    # The record attests that the file EXISTED with these
                    # times. It is not a log of an event occurring.
                    timestamp_type="presence",
                    # A NAME, never a path: resolving the parent reference
                    # needs a full-table index this parser does not build. Same
                    # limitation as `usn`, for the same reason (CD-010).
                    path=record["name"],
                    user=None,
                    details=details,
                )


register(MftParser)
