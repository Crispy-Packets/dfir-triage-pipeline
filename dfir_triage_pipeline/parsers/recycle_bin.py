"""`$Recycle.Bin` `$I` records: a file's original path and its deletion time.

When a file is sent to the Recycle Bin, Windows writes two files: `$R...` holds
the content, `$I...` holds the metadata. The `$I` record is the **only artefact
in this pipeline that attests to a deletion** -- every other family records that
a file existed, ran, or was opened.

It carries three things nothing else does:

* the file's **original full path**, which the `$R` name destroys;
* the **size it had when deleted**;
* **when it was deleted**, as a FILETIME.

**Measured on `s1_v3`:** one record, and it names the scenario payload --
`C:\\Users\\vboxuser\\Desktop\\invoice_scan.exe`, 4,608 bytes. The binary was
executed, established persistence, and was then deleted; Prefetch, Amcache, BAM
and Shimcache all attest that it RAN, and this is the only family that says it
was removed afterwards.

**The record is per-SID by location.** `$Recycle.Bin\\<SID>\\$I...` puts the
deleting account in the path, so the principal needs no inference -- the same
property that makes the NTUSER Explorer keys worth parsing.

**Two versions exist and the length differs.** Version 1 (Vista through 8) has
a fixed 260-character name field; version 2 (8.1 and later) writes a name LENGTH
at offset 24 followed by that many UTF-16 units. Reading a version 2 record with
the version 1 layout yields a path assembled from the length prefix onward --
plausible, wrong, and it does not raise. The version field is read, not assumed.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: Header: version(8) file_size(8) deleted_filetime(8) = 24 bytes, then the
#: name, whose encoding depends on the version.
_HEADER_BYTES = 24

#: Version 1 writes a fixed 260-CHARACTER name field with no length prefix.
_V1_NAME_CHARS = 260

#: A sanity bound on the version 2 length prefix. A Windows path cannot exceed
#: 32767 characters, and a larger value means the record is not what it claims.
_MAX_NAME_CHARS = 32767


def filetime_to_utc(ticks: Any) -> datetime | None:
    """FILETIME to aware UTC, or None when the value is not a real time."""
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except (OverflowError, ValueError):
        return None
    return converted if converted.year > 1601 else None


def parse_info_record(blob: bytes) -> dict[str, Any] | None:
    """Decode an `$I` record, or None when it is not one.

    The VERSION decides the name layout, so it is read rather than assumed:
    applying the version 1 layout to a version 2 record produces a path
    assembled from the length prefix onward, which looks like a real path.
    """
    if not isinstance(blob, bytes) or len(blob) < _HEADER_BYTES:
        return None

    version, file_size, deleted = struct.unpack_from("<QQQ", blob, 0)
    if version not in (1, 2):
        return None

    if version == 2:
        if len(blob) < _HEADER_BYTES + 4:
            return None
        name_chars = struct.unpack_from("<I", blob, _HEADER_BYTES)[0]
        if not 0 < name_chars <= _MAX_NAME_CHARS:
            return None
        start = _HEADER_BYTES + 4
    else:
        name_chars = _V1_NAME_CHARS
        start = _HEADER_BYTES

    end = start + name_chars * 2
    if end > len(blob):
        # A truncated name is not decoded from what is present: a partial path
        # is indistinguishable from a complete one and would be reported as
        # the file's location.
        return None

    path = blob[start:end].decode("utf-16-le", errors="replace").rstrip("\x00").strip()
    if not path:
        return None

    return {
        "version": version,
        "original_path": path,
        "file_size": file_size,
        "deleted_at": filetime_to_utc(deleted),
    }


def _sid_from_path(relative_path: str) -> str | None:
    """The deleting account's SID, from the `$Recycle.Bin\\<SID>\\` segment."""
    for part in relative_path.replace("\\", "/").split("/"):
        if part.upper().startswith("S-1-"):
            return part
    return None


class RecycleBinParser:
    name = "recycle_bin"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.replace("\\", "/").lower()
        if "/$recycle.bin/" not in f"/{lowered}":
            return False
        # `$I` holds the metadata; `$R` holds the content and is not parsed --
        # it is the deleted file itself, with no structure of its own.
        return lowered.rsplit("/", 1)[-1].startswith("$i")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        record = parse_info_record(abs_path.read_bytes())
        if record is None:
            return

        details: dict[str, str] = {
            "original_path": record["original_path"],
            "deleted_size": str(record["file_size"]),
            "info_version": str(record["version"]),
        }
        sid = _sid_from_path(relative_path)
        if sid:
            details["sid"] = sid

        deleted_at = record["deleted_at"]
        yield Event(
            # A real deletion time when the record carries one. Unlike the
            # presence families this IS an observation: Windows wrote the
            # FILETIME at the moment it moved the file.
            timestamp=deleted_at or _FILETIME_EPOCH,
            source_artifact="recyclebin",
            event_type="file_deleted",
            action="file sent to the Recycle Bin",
            source_file=relative_path,
            # One record per file, so the file is the locator.
            source_locator="InfoRecord",
            timestamp_type="recorded" if deleted_at else "presence",
            path=record["original_path"],
            user=sid,
            details=details,
        )


register(RecycleBinParser)
