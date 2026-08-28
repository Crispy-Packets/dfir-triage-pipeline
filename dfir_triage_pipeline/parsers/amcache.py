from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..model import Event
from . import register
from .registry import filetime_to_utc

# Amcache records applications the OS has inventoried. The subkey carrying file
# entries is InventoryApplicationFile on Windows 8.1 and later; the older `File`
# layout is read too so a collection from an earlier build still parses.
FILE_KEYS = (
    r"\Root\InventoryApplicationFile",
    r"\Root\File",
)

# Values read from each entry. Everything here is declared in
# docs/details-schema.md before emission, per CD-012.
_WANTED = (
    "LowerCaseLongPath",
    "Name",
    "FileId",
    "Size",
    "ProgramId",
    "Publisher",
    "Version",
    "BinaryType",
    "LinkDate",
)

# FileId is a SHA-1 with a four-zero prefix: 4 + 40 hex characters. The prefix
# is a field marker, not part of the digest, and carrying it forward would break
# any comparison against a hash computed elsewhere.
_FILEID_PREFIX_LEN = 4
_SHA1_HEX_LEN = 40


def sha1_from_file_id(file_id: str | None) -> str | None:
    """Strip Amcache's four-character prefix from FileId to get the SHA-1.

    Returns None rather than guessing when the value is not the expected shape:
    a truncated or reformatted identifier is not a hash, and emitting it as one
    would licence a false match against a hash from another source.
    """
    if not file_id:
        return None
    text = str(file_id).strip()
    if len(text) != _FILEID_PREFIX_LEN + _SHA1_HEX_LEN:
        return None
    digest = text[_FILEID_PREFIX_LEN:].lower()
    if not all(c in "0123456789abcdef" for c in digest):
        return None
    return digest


def _records(abs_path: Path, relative_path: str) -> Iterator[dict]:
    """Yield one normalised dict per inventoried file. The only regipy-coupled code."""
    from regipy.registry import RegistryHive

    hive = RegistryHive(str(abs_path))

    for key_path in FILE_KEYS:
        try:
            container = hive.get_key(key_path)
        except Exception:
            continue  # layout absent on this Windows build

        for entry in container.iter_subkeys():
            try:
                values = {v.name: v.value for v in entry.get_values()}
            except Exception:
                continue  # one unreadable entry does not abort the hive

            path = values.get("LowerCaseLongPath") or values.get("FullPath")
            if not path:
                continue  # an entry with no path identifies no file

            yield {
                "container": key_path.rsplit("\\", 1)[-1],
                "key_name": entry.name,
                "last_write": filetime_to_utc(entry.header.last_modified),
                "path": str(path),
                "values": {
                    k: str(values[k]) for k in _WANTED if values.get(k) not in (None, "")
                },
                "source_file": relative_path,
            }


def record_to_event(record: dict) -> Event:
    """Pure transform: dict in, Event out. No filesystem, no regipy type."""
    values = record["values"]
    details = {"amcache_key": record["key_name"]}

    for source, target in (
        ("Name", "name"),
        ("Publisher", "publisher"),
        ("Version", "version"),
        ("BinaryType", "binary_type"),
        ("Size", "size"),
        ("ProgramId", "program_id"),
    ):
        if source in values:
            details[target] = values[source]

    sha1 = sha1_from_file_id(values.get("FileId"))
    if sha1:
        details["sha1"] = sha1

    return Event(
        timestamp=record["last_write"],
        source_artifact="amcache",
        event_type="program_inventoried",       # CD-007
        action="binary recorded in application inventory",
        source_file=record["source_file"],      # CD-003
        # Names the container as well as the entry: the same file can appear
        # under InventoryApplicationFile and the legacy File layout, and a
        # locator that did not distinguish them would not be unique (CD-004).
        source_locator=f"{record['container']}={record['key_name']}",
        # Amcache is written by a scheduled maintenance task, not at execution
        # time, so the key's last-write time is when the OS inventoried the
        # binary -- not when it ran, and not necessarily near it. "presence"
        # says the entry exists and when it appeared is not what this timestamp
        # means. Treating it as an execution time is the classic Amcache error.
        timestamp_type="presence",
        host=None,
        user=None,
        path=record["path"],                    # CD-010, as recorded (lowercased
                                                # by the artifact itself)
        confidence="high",
        details=details,
    )


@register
class AmcacheParser:
    name = "amcache"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        if not lowered.endswith("/amcache.hve"):
            return False
        return "/appcompat/programs/" in f"/{lowered}"

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        for record in _records(abs_path, relative_path):
            yield record_to_event(record)
