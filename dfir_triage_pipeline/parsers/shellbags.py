"""Shellbags: folders a user browsed, including ones that no longer exist.
`UsrClass.dat`'s `BagMRU` tree records every folder Explorer has displayed, as a
tree mirroring the filesystem. It is the corroborator for a directory that was
opened and then removed -- the folder's own metadata is gone, the parent
directory shows nothing, and the shellbag still names it.
It also survives the target volume being detached: a bag for `E:\\Camera` stays
in the hive after the drive is unplugged, which is the same CD-013 property the
`lnk` family has, reached independently.
**What is decoded, and what is not.** A shell item's layout depends on its type
byte, and the types are not a documented contract -- they are what Explorer
happens to write. Two are decoded here:
    0x31  a folder
    0x32  a file
Both carry a short (8.3) name in ASCII at a fixed offset, and most carry a long
name in UTF-16 in an extension block after it. **The long name is anchored to
the 0xBEEF extension signature, at signature + 40** -- measured on every item in
the corpus. It is NOT computed from the end of the short name, which varies in
length, and it is NOT found by scanning: a scan sweeps up the DOS timestamps
sitting before it, which decode as printable CJK, and yields names like
`詆eKapeFiles-master`. See D-049.
Types `0x1f` (root/desktop), `0x2e` and `0x2f` (volume and GUID entries) are
**not** decoded into names. `0x2f` holds a bare drive letter, which the tree
position already gives; `0x1f` and `0x2e` hold CLSIDs naming virtual folders
like "This PC". Emitting them would put `耮⮒팖鍥` -- the UTF-16 misreading of a
GUID -- into a path field.
**The timestamp is the containing key's last write**, shared by every bag under
it, so this family is `presence` for D-027's reason. The DOS timestamps embedded
in each item describe the TARGET folder, not when it was browsed, and are
recorded as details rather than as the event time.
"""


from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

_BAGMRU = r"\Local Settings\Software\Microsoft\Windows\Shell\BagMRU"


_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


#: Shell item types whose layout this parser knows. Anything else is counted
#: but not named -- see the module docstring.
_FOLDER = 0x31
_FILE = 0x32


#: Offset of the 8.3 short name within a 0x31/0x32 item, established from the
#: bytes: size(2) type(1) unknown(1) file_size(4) dos_date(2) dos_time(2)
#: attributes(2) then the name.
_SHORT_NAME_OFFSET = 14
#: The extension block's signature, and the long name's offset from it.
#:
#: 40 bytes past the signature, measured on EVERY item in the corpus --
#: KAPE, Users, vboxuser, Downloads, Desktop, TCPView, SysinternalsSuite,
#: montague -- regardless of how long the 8.3 short name is. See D-049.
_EXTENSION_SIGNATURE = b"\xef\xbe"
_LONG_NAME_OFFSET = 40
_UTF16_TERMINATOR = b"\x00\x00"


#: Bookkeeping values that order the MRU rather than naming anything.
_NOT_AN_ITEM = frozenset({"MRUListEx", "NodeSlot", "NodeSlots"})


#: A guard on tree depth. The BagMRU tree mirrors a filesystem and cannot
#: legitimately nest this far; a cycle or a corrupt hive would otherwise recurse
#: without end.
_MAX_DEPTH = 32


def dos_datetime(date_word: int, time_word: int) -> datetime | None:
    """A DOS date/time pair to aware UTC, or None when it is not a time.


    DOS times are LOCAL to the machine that wrote them and carry no zone, so
    UTC is attached rather than converted -- D-013's rule. Two-second
    resolution is all the format has.
    """
    if not date_word:
        return None
    year = 1980 + ((date_word >> 9) & 0x7F)
    month = (date_word >> 5) & 0x0F
    day = date_word & 0x1F
    hour = (time_word >> 11) & 0x1F
    minute = (time_word >> 5) & 0x3F
    second = (time_word & 0x1F) * 2
    try:
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        return None


def _ascii_until_null(blob: bytes, start: int) -> str:
    end = blob.find(b"\x00", start)
    end = len(blob) if end == -1 else end
    return blob[start:end].decode("latin-1", errors="replace")


def _long_name(blob: bytes) -> str | None:
    r"""The UTF-16 long name, anchored to the 0xBEEF extension signature.


    **The offset is `signature + 40`, measured on every item in the corpus** --
    KAPE, Users, vboxuser, Downloads, Desktop, TCPView, SysinternalsSuite and
    the rest, all at exactly that distance regardless of how long the 8.3 short
    name is.


    Anchoring to the SIGNATURE rather than to the end of the short name is the
    whole point. The first version of this function scanned for the longest
    printable UTF-16 run after the short name, and produced names like
    `詆eKapeFiles-master` and `剼Ùvboxuser`: the scan started inside the DOS
    timestamps, which decode as printable CJK, and swept them up as part of the
    name. Every one of those was well-formed, plausible at a glance, and wrong.


    Explorer appends a resource reference to shell-provided names --
    `Downloads@shell32.dll,-21798` -- which is stripped.
    """
    signature = blob.find(_EXTENSION_SIGNATURE)
    if signature == -1:
        return None
    start = signature + _LONG_NAME_OFFSET
    if start >= len(blob):
        return None


    end = start
    while end + 1 < len(blob) and blob[end : end + 2] != _UTF16_TERMINATOR:
        end += 2
    if end <= start:
        return None


    try:
        text = blob[start:end].decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    if not all(character.isprintable() for character in text):
        return None


    cleaned = text.split("@")[0].strip()
    return cleaned or None


def parse_shell_item(blob: Any) -> dict[str, Any] | None:
    """Decode a 0x31/0x32 shell item, or None for any other type."""
    if not isinstance(blob, bytes) or len(blob) < _SHORT_NAME_OFFSET + 1:
        return None
    item_type = blob[2]
    if item_type not in (_FOLDER, _FILE):
        return None


    short_name = _ascii_until_null(blob, _SHORT_NAME_OFFSET)
    if not short_name:
        return None


    modified = dos_datetime(
        int.from_bytes(blob[8:10], "little"), int.from_bytes(blob[10:12], "little")
    )
    return {
        "kind": "folder" if item_type == _FOLDER else "file",
        "short_name": short_name,
        "long_name": _long_name(blob),
        "target_modified": modified,
    }


def _key(hive: Any, path: str) -> Any:
    try:
        return hive.get_key(path)
    except Exception:
        return None


def _key_timestamp(key: Any) -> datetime:
    raw = getattr(key, "header", None)
    ticks = getattr(raw, "last_modified", None) if raw is not None else None
    if isinstance(ticks, int) and ticks > 0:
        try:
            return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
        except (OverflowError, ValueError):
            pass
    return _FILETIME_EPOCH


def _hive_user(relative_path: str) -> str | None:
    parts = relative_path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _walk(
    hive: Any, key_path: str, ancestry: tuple[str, ...], depth: int
) -> Iterator[tuple[str, tuple[str, ...], dict, datetime]]:
    """Every decodable shell item under `key_path`, with its path so far."""
    if depth > _MAX_DEPTH:
        return
    key = _key(hive, key_path)
    if key is None:
        return


    timestamp = _key_timestamp(key)
    slots: dict[str, tuple[str, ...]] = {}


    for value in key.get_values():
        if value.name in _NOT_AN_ITEM:
            continue
        record = parse_shell_item(value.value)
        if record is None:
            # An undecoded type still holds a tree position, so its children
            # are walked -- they may be ordinary folders under a virtual root.
            slots[value.name] = ancestry
            continue
        name = record["long_name"] or record["short_name"]
        slots[value.name] = (*ancestry, name)
        yield f"{key_path}\\{value.name}", slots[value.name], record, timestamp


    for sub in key.iter_subkeys():
        yield from _walk(
            hive, f"{key_path}\\{sub.name}", slots.get(sub.name, ancestry), depth + 1
        )


class ShellbagsParser:
    name = "shellbags"


    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.replace("\\", "/").lower()
        if lowered.endswith((".log", ".log1", ".log2")):
            return False
        return lowered.endswith("/usrclass.dat")


    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        from regipy.registry import RegistryHive


        hive = RegistryHive(str(abs_path))
        user = _hive_user(relative_path)


        for locator, ancestry, record, timestamp in _walk(hive, _BAGMRU, (), 0):
            if not ancestry:
                continue


            details: dict[str, str] = {
                "bag_kind": record["kind"],
                "short_name": record["short_name"],
                "bag_depth": str(len(ancestry)),
            }
            if record["long_name"]:
                details["long_name"] = record["long_name"]
            modified = record["target_modified"]
            if modified:
                # A property of the TARGET folder, not of when it was browsed.
                details["target_modified"] = modified.isoformat().replace(
                    "+00:00", "Z"
                )


            yield Event(
                # The containing key's last write, shared by every bag under
                # it. D-027 exactly.
                timestamp=timestamp,
                source_artifact="shellbags",
                event_type="folder_browsed",
                action="folder displayed in Explorer",
                source_file=relative_path,
                source_locator=locator[len(_BAGMRU) :].lstrip("\\") or "root",
                timestamp_type="presence",
                path="\\".join(ancestry),
                user=user,
                details=details,
            )


register(ShellbagsParser)

