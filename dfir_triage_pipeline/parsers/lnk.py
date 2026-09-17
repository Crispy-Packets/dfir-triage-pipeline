"""Shell link files: a path, a volume, and the target's own timestamps.

A `.lnk` in `AppData\\Roaming\\Microsoft\\Windows\\Recent` is written by Explorer
when a file is opened. It is the corroborator `recentdocs` cannot be: RecentDocs
holds a NAME and the containing key's last-write time, shared by every sibling
(D-027). A LNK holds the **full path**, the **volume serial**, the target's
**size**, and **three FILETIMEs copied from the target file itself**.

Those timestamps are the point. They describe the target, not the link, so they
survive the target's deletion -- a LNK is a record of a file that may no longer
exist, written by the OS at a moment the user opened it.

**Removable media is the case this reopens (CD-013).** The volume serial and
drive type come from the volume the target lived on, so a LNK attests that a
file was opened from a drive that is not present now and may never be seen
again. Measured on `s1_v2`: four Recent links name `Z:\\` with serial
`5659C38D`, distinct from the system disk's `A62AF538` -- the transfer volume
used to move the scenario files, recorded by nothing else in this pipeline.

**Why the parsing is written out rather than taken from a library.** Every
section after the 76-byte header is length-prefixed and positioned relative to
the one before it, so a single mis-sized field shifts everything after it and
the parser emits plausible strings read out of the middle of other structures --
without raising. Two specific traps:

* **StringData counts CHARACTERS, not bytes.** A Unicode link (all 256 in this
  corpus) stores `count` UTF-16 units, so the byte length is `count * 2`. Read
  as bytes, every subsequent section lands mid-string.
* **LinkInfo offsets are relative to the START of the LinkInfo structure**, not
  to the file. Treating them as absolute reads from the header instead.

Both are bounds-checked here, and a section that would run past the end of the
file stops the parse rather than decoding whatever follows. Measured: 256 files
across five collections, 0 raised, 0 overran.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

#: The ShellLinkHeader is a fixed 76 bytes, and its first field says so.
_HEADER_BYTES = 76
_HEADER_SIGNATURE = 0x4C

#: The link CLSID, constant for every shell link ever written. A file whose
#: header size is 76 but whose CLSID differs is not a shell link.
_LINK_CLSID = bytes(
    (
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    )
)

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

# LinkFlags bits, in the order StringData sections appear on disk. The ORDER is
# load-bearing: each section follows the previous one, so reading them out of
# order desynchronises every field after the first.
_HAS_TARGET_ID_LIST = 0x01
_HAS_LINK_INFO = 0x02
_STRING_DATA = (
    (0x04, "name"),
    (0x08, "relative_path"),
    (0x10, "working_dir"),
    (0x20, "arguments"),
    (0x40, "icon_location"),
)
_IS_UNICODE = 0x80

#: LinkInfoFlags: whether the volume and local-path fields are present.
_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x01

_DRIVE_TYPES = {
    0: "unknown",
    1: "no_root_directory",
    2: "removable",
    3: "fixed",
    4: "remote",
    5: "cdrom",
    6: "ramdisk",
}

#: Recent-folder links are the ones a user's activity produced. Links under
#: Start Menu and Desktop are installed by software and describe the machine's
#: configuration rather than anything anyone did.
_RECENT_MARKER = "/microsoft/windows/recent/"


def filetime_to_utc(ticks: Any) -> datetime | None:
    """FILETIME to aware UTC, or None when the value is not a real time.

    A LNK writes zero for "not recorded" -- measured on several Recent links
    whose targets no longer existed when the link was written.
    """
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except (OverflowError, ValueError):
        return None
    return converted if converted.year > 1601 else None


def _cstring(blob: bytes, offset: int, *, wide: bool = False) -> str | None:
    """A null-terminated string at `offset`, or None."""
    if offset < 0 or offset >= len(blob):
        return None
    if wide:
        end = offset
        while end + 1 < len(blob) and blob[end : end + 2] != b"\x00\x00":
            end += 2
        text = blob[offset:end].decode("utf-16-le", errors="replace")
    else:
        end = blob.find(b"\x00", offset)
        end = len(blob) if end == -1 else end
        text = blob[offset:end].decode("latin-1", errors="replace")
    return text or None


def is_shell_link(blob: bytes) -> bool:
    """Does this file's header identify it as a shell link?"""
    if len(blob) < _HEADER_BYTES:
        return False
    if struct.unpack_from("<I", blob, 0)[0] != _HEADER_SIGNATURE:
        return False
    return blob[4:20] == _LINK_CLSID


def parse_lnk(blob: bytes) -> dict[str, Any] | None:
    """Decode a shell link, or None when it is not one.

    Returns what could be read. A section that would run past the end of the
    file ends the parse and the fields gathered so far are kept: a truncated
    link still attests to its header, and the alternative is discarding a real
    record because its tail is damaged.
    """
    if not is_shell_link(blob):
        return None

    flags, attributes = struct.unpack_from("<II", blob, 20)
    created, accessed, modified = struct.unpack_from("<QQQ", blob, 28)
    target_size = struct.unpack_from("<I", blob, 52)[0]

    out: dict[str, Any] = {
        "flags": flags,
        "attributes": attributes,
        "target_created": filetime_to_utc(created),
        "target_accessed": filetime_to_utc(accessed),
        "target_modified": filetime_to_utc(modified),
        "target_size": target_size,
    }

    position = _HEADER_BYTES

    if flags & _HAS_TARGET_ID_LIST:
        if position + 2 > len(blob):
            return out
        # The id list is a shell-namespace structure this parser does not
        # decode; it is skipped by its declared size.
        position += 2 + struct.unpack_from("<H", blob, position)[0]

    if flags & _HAS_LINK_INFO and position + 16 <= len(blob):
        position = _read_link_info(blob, position, out)

    # StringData. Each is a CHARACTER count followed by that many UTF-16 units
    # on a Unicode link -- the single most common way to mis-parse a LNK.
    wide = bool(flags & _IS_UNICODE)
    for bit, name in _STRING_DATA:
        if not flags & bit:
            continue
        if position + 2 > len(blob):
            break
        count = struct.unpack_from("<H", blob, position)[0]
        position += 2
        width = 2 if wide else 1
        end = position + count * width
        if end > len(blob):
            break
        raw = blob[position:end]
        position = end
        text = raw.decode("utf-16-le" if wide else "latin-1", errors="replace")
        if text:
            out[name] = text

    return out


def _read_link_info(blob: bytes, start: int, out: dict[str, Any]) -> int:
    """Read the LinkInfo structure; return the offset just past it.

    **Every offset in here is relative to `start`, not to the file.** Treating
    them as absolute reads from inside the header and yields paths assembled
    from unrelated bytes.
    """
    size = struct.unpack_from("<I", blob, start)[0]
    info_flags = struct.unpack_from("<I", blob, start + 8)[0]
    volume_offset, base_path_offset = struct.unpack_from("<II", blob, start + 12)

    if info_flags & _VOLUME_ID_AND_LOCAL_BASE_PATH:
        if volume_offset and start + volume_offset + 16 <= len(blob):
            volume = start + volume_offset
            drive_type = struct.unpack_from("<I", blob, volume + 4)[0]
            serial = struct.unpack_from("<I", blob, volume + 8)[0]
            label_offset = struct.unpack_from("<I", blob, volume + 12)[0]
            out["drive_type"] = _DRIVE_TYPES.get(drive_type, str(drive_type))
            out["volume_serial"] = f"{serial:08X}"
            # 0x14 is the sentinel meaning "the label is Unicode and lives at
            # the offset in the NEXT field"; a plain offset points at ASCII.
            if label_offset and label_offset != 0x14:
                label = _cstring(blob, volume + label_offset)
                if label:
                    out["volume_label"] = label

        if base_path_offset:
            path = _cstring(blob, start + base_path_offset)
            if path:
                out["local_path"] = path

    end = start + size
    return end if 0 < size and end <= len(blob) else len(blob)


def _is_recent(relative_path: str) -> bool:
    return _RECENT_MARKER in f"/{relative_path.lower().replace(chr(92), '/')}/"


def _hive_user(relative_path: str) -> str | None:
    parts = relative_path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return None


class LnkParser:
    name = "lnk"

    def can_handle(self, relative_path: str) -> bool:
        return relative_path.lower().endswith(".lnk")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        record = parse_lnk(abs_path.read_bytes())
        if record is None:
            # Not a shell link despite the extension. Yielding nothing rather
            # than raising: a mislabelled file is not a parser fault, and
            # raising would inflate the failure count (D-024's reasoning).
            return

        target = record.get("local_path") or record.get("relative_path")
        if not target:
            # A link with no path at all -- measured on the `ms-settings:` and
            # `ms-gamingoverlay:` protocol links, which name a URI handler
            # rather than a file. Nothing to attribute, so nothing is emitted.
            return

        details: dict[str, str] = {
            "lnk_location": "recent" if _is_recent(relative_path) else "installed",
            "target_size": str(record["target_size"]),
        }
        for key in ("drive_type", "volume_serial", "volume_label", "arguments",
                    "working_dir", "relative_path"):
            value = record.get(key)
            if value:
                details[key] = str(value)
        for key in ("target_created", "target_accessed", "target_modified"):
            value = record.get(key)
            if value:
                details[key] = value.isoformat().replace("+00:00", "Z")

        # The target's modification time is the strongest claim the link makes
        # about WHEN: it is copied from the file itself. Falling back to
        # creation, then to the epoch sentinel the presence families use.
        modified = record.get("target_modified")
        created = record.get("target_created")
        timestamp = modified or created

        yield Event(
            timestamp=timestamp or _FILETIME_EPOCH,
            source_artifact="lnk",
            event_type="file_opened",
            action="shell link recorded a file",
            source_file=relative_path,
            # One event per file, so the file itself is the locator. CD-004
            # requires uniqueness within the file, which is trivially met.
            source_locator="ShellLinkHeader",
            # The timestamps describe the TARGET, not the link. `recorded` would
            # claim the OS logged an event at this instant; it did not -- it
            # copied a property of a file. `presence` is the honest label: this
            # file existed, with this timestamp, when the link was written.
            timestamp_type="presence",
            path=target,
            user=_hive_user(relative_path),
            details=details,
        )


register(LnkParser)
