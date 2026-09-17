"""The USN change journal (`$Extend\\$J`): file creation, deletion and rename.

NTFS appends a record here for every change to every file on the volume. It is
the only family in this pipeline that records a **rename**, and the only one
besides `recyclebin` that records a **deletion** -- and unlike the Recycle Bin
it sees deletions that never went to the bin at all (shift-delete, a program
removing its own temp files, an attacker cleaning up).

**Measured on `s1_v3`, it caught what nothing else did:**

    11:50:09  invoice_scan.exe            data overwrite
    11:50:10  invoice_scan_marker.txt     CREATE   <- the payload's side effect
    11:50:25  INVOICE_SCAN.EXE-...pf      CREATE   <- Prefetch being written

The marker file appears in no other family. Amcache, Prefetch, BAM and
Shimcache all say the binary RAN; only the journal shows what it DID.

On `s1_v2` the journal also holds a RENAME_OLD for `invoice_scan.exe` at
21:33:04 -- the operator swapping the binary between runs, which the `$I`
records corroborate at three different sizes.

**Volume is the problem this parser exists to solve.** The journal holds
169,304 records on `s1_v3` and 328,156 on `s1_v2`, five times the rest of the
pipeline combined, and the overwhelming majority are Windows servicing writing
`.mui` resource files. Emitting them all would drown every other family in the
timeline and in the anomaly layer's per-family models.

So **only lifecycle reasons are emitted**: create, delete, and the two halves of
a rename. Data overwrites, attribute changes, security changes and stream
changes are counted but not emitted -- they say a file was touched, which is
both extremely common and the weakest claim the journal makes.

**Records are located by walking declared lengths, with re-synchronisation.**
The journal is a sparse file: its head is zeroed as records age out, and a
length of zero means unallocated space rather than a malformed record. A record
whose declared length is implausible advances the cursor by 8 bytes and the walk
resumes, rather than aborting -- a torn region in the middle must not discard
the 169,000 records after it.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..model import Event
from . import register

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: USN_RECORD_V2/V3 header fields, at fixed offsets from the record start.
_OFF_LENGTH = 0
_OFF_MAJOR = 4
_OFF_TIMESTAMP = 32
_OFF_REASON = 40
_OFF_NAME_LENGTH = 56
_OFF_NAME_OFFSET = 58

#: A record is at least a header and at most this; anything else is not a
#: record and the walk re-synchronises rather than trusting the length.
_MIN_RECORD = 60
_MAX_RECORD = 1024

#: Re-synchronisation step. Records are 8-byte aligned.
_ALIGN = 8

#: Reason flags. Only these four are emitted -- see the module docstring.
_REASON_FILE_CREATE = 0x00000100
_REASON_FILE_DELETE = 0x00000200
_REASON_RENAME_OLD_NAME = 0x00001000
_REASON_RENAME_NEW_NAME = 0x00002000

#: Emitted in this order, so a record carrying several flags is named by its
#: strongest claim. A delete-and-close is a deletion; a create-and-write is a
#: creation.
_EMITTED = (
    (_REASON_FILE_DELETE, "file_deleted", "file deleted"),
    (_REASON_RENAME_OLD_NAME, "file_renamed_from", "file renamed, old name"),
    (_REASON_RENAME_NEW_NAME, "file_renamed_to", "file renamed, new name"),
    (_REASON_FILE_CREATE, "file_created", "file created"),
)

#: A cap on how many records are read from one journal. The journals here hold
#: up to 328,156 records and the walk is linear, but an unbounded loop over a
#: corrupt file is not something a triage tool should do.
_MAX_RECORDS = 2_000_000


def filetime_to_utc(ticks: int) -> datetime | None:
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except (OverflowError, ValueError):
        return None
    return converted if converted.year > 1601 else None


def iter_records(blob: bytes) -> Iterator[tuple[int, datetime | None, int, str]]:
    """(offset, timestamp, reason, name) for each record in the journal.

    Walks by declared length and re-synchronises on anything implausible. The
    leading sparse region is skipped by the same mechanism: a length of zero is
    unallocated space, not a record.
    """
    position = 0
    emitted = 0
    limit = len(blob)

    while position + _MIN_RECORD <= limit and emitted < _MAX_RECORDS:
        length = struct.unpack_from("<I", blob, position + _OFF_LENGTH)[0]

        if not _MIN_RECORD <= length <= _MAX_RECORD or position + length > limit:
            position += _ALIGN
            continue

        major = struct.unpack_from("<H", blob, position + _OFF_MAJOR)[0]
        if major not in (2, 3):
            position += _ALIGN
            continue

        name_length = struct.unpack_from("<H", blob, position + _OFF_NAME_LENGTH)[0]
        name_offset = struct.unpack_from("<H", blob, position + _OFF_NAME_OFFSET)[0]

        if not name_length or name_offset + name_length > length:
            position += length
            continue

        start = position + name_offset
        name = blob[start : start + name_length].decode("utf-16-le", errors="replace")
        if name:
            reason = struct.unpack_from("<I", blob, position + _OFF_REASON)[0]
            ticks = struct.unpack_from("<Q", blob, position + _OFF_TIMESTAMP)[0]
            yield position, filetime_to_utc(ticks), reason, name
            emitted += 1

        position += length


class UsnJournalParser:
    name = "usn_journal"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.replace("\\", "/").lower()
        return lowered.endswith("/$extend/$j")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        blob = abs_path.read_bytes()

        # NTFS writes a record at each STAGE of one operation: create, then
        # create+extend, then create+extend+close, all carrying the same
        # timestamp and name. Measured on s1_v3: 43% of otherwise-emitted rows
        # are such restatements, and `invoice_scan_marker.txt` alone produced
        # three identical creations. One operation is one event, so the first
        # record for a (name, type, timestamp) wins and the rest are dropped.
        #
        # The set is bounded by the journal's own record count, and the
        # alternative -- emitting all three -- would treble this family's
        # already dominant share of the timeline.
        seen: set[tuple[str, str, datetime]] = set()

        for offset, timestamp, reason, name in iter_records(blob):
            if timestamp is None:
                continue

            for flag, event_type, action in _EMITTED:
                if not reason & flag:
                    continue
                key = (name, event_type, timestamp)
                if key in seen:
                    break
                seen.add(key)
                yield Event(
                    # NTFS appends the record as the change happens, so this is
                    # an observation -- among the strongest in the pipeline.
                    timestamp=timestamp,
                    source_artifact="usn",
                    event_type=event_type,
                    action=action,
                    source_file=relative_path,
                    # The record's byte offset: unique within the journal, and
                    # the only identifier it carries (CD-004).
                    source_locator=f"usn@{offset}",
                    timestamp_type="recorded",
                    # The journal records a NAME, never a path: it names the
                    # file and its parent by reference number, which resolving
                    # would need the $MFT. Recorded as it stands (CD-010).
                    path=name,
                    user=None,
                    details={
                        "usn_reason": f"0x{reason:08x}",
                        "file_name": name,
                    },
                )
                break


register(UsnJournalParser)
