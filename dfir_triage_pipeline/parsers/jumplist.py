"""JumpLists: which application opened a file.

A `.lnk` in `Recent` says a file was opened. A JumpList says **which program
opened it**, because the file is named after that program: the hex stem is the
application's AppID, a hash Windows assigns per executable. That is the row the
attestation matrix marks as carried by no family.

**Two formats sit in the same tree and only one is OLE.** Measured on `s1_v3`:

    *.automaticDestinations-ms   7 files   OLE compound, 512-byte sectors
    *.customDestinations-ms      6 files   NOT OLE -- concatenated LNK blobs

The `custom` files begin `02 00 00 00` and hold shell links one after another
with no container structure at all. Treating them as OLE, which their extension
and their neighbours both suggest, finds no header and yields nothing -- a
silent empty family rather than an error.

**The embedded records are ordinary shell links**, so `parsers/lnk.py` decodes
them. This parser's whole job is to find where each one starts and hand it over;
none of the LNK offset arithmetic is repeated here.

**Both formats are scanned for the link signature rather than walked
structurally.** For the `custom` files that is the format. For the OLE files it
is a deliberate simplification: a full compound-file implementation -- FAT,
miniFAT, directory tree, sector chains -- is a large amount of code whose only
purpose here is locating streams that the signature already locates, and a bug
in it would produce plausible wrong output. The cost is that a link fragmented
across non-contiguous sectors is not recovered; measured, every link in these
files is contiguous, and one that is not simply yields no event rather than a
wrong one, because `parse_lnk` bounds-checks every field it reads.

**The DestList stream is not read.** It holds access counts and a most-recently-
used ordering, which would be worth having; it is a separate binary structure
whose entry size varies by Windows version, and inventing a version-dependent
layout is how D-023 and D-045 happened. Omitted rather than guessed.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from ..model import Event
from . import register
from .lnk import parse_lnk

#: The shell-link header signature: a 4-byte header size of 0x4C. Every embedded
#: record starts with it, in both container formats.
_LNK_SIGNATURE = b"\x4c\x00\x00\x00"

#: The OLE compound-file magic. Present on automaticDestinations only.
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: A guard against a pathological file: a JumpList holding more links than this
#: is not something these collections contain, and the cap bounds the scan.
_MAX_LINKS = 2000


def _embedded_links(blob: bytes) -> Iterator[tuple[int, dict]]:
    """(offset, decoded link) for every shell link found in the container.

    The signature alone is not enough to accept a candidate -- four bytes of
    `4C 00 00 00` occur in ordinary data -- so each is handed to `parse_lnk`,
    which verifies the 16-byte link CLSID immediately after it. A candidate
    that fails that check is skipped rather than decoded.
    """
    position = 0
    found = 0
    while found < _MAX_LINKS:
        index = blob.find(_LNK_SIGNATURE, position)
        if index == -1:
            return
        position = index + 4
        record = parse_lnk(blob[index:])
        if record is None:
            continue
        found += 1
        yield index, record


def _hive_user(relative_path: str) -> str | None:
    parts = relative_path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def app_id_of(relative_path: str) -> str:
    """The application id: the filename stem, which is Windows' per-app hash."""
    name = relative_path.replace("\\", "/").rsplit("/", 1)[-1]
    return name.split(".")[0]


class JumpListParser:
    name = "jumplist"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        return lowered.endswith(
            (".automaticdestinations-ms", ".customdestinations-ms")
        )

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        blob = abs_path.read_bytes()
        user = _hive_user(relative_path)
        app_id = app_id_of(relative_path)
        kind = "automatic" if blob[:8] == _OLE_MAGIC else "custom"

        for offset, record in _embedded_links(blob):
            target = record.get("local_path") or record.get("relative_path")
            if not target:
                continue

            details: dict[str, str] = {
                "app_id": app_id,
                "jumplist_type": kind,
                "target_size": str(record["target_size"]),
            }
            for key in ("drive_type", "volume_serial", "volume_label",
                        "arguments", "working_dir"):
                value = record.get(key)
                if value:
                    details[key] = str(value)
            for key in ("target_created", "target_accessed", "target_modified"):
                value = record.get(key)
                if value:
                    details[key] = value.isoformat().replace("+00:00", "Z")

            modified = record.get("target_modified")
            created = record.get("target_created")

            yield Event(
                timestamp=modified or created or _FILETIME_EPOCH,
                source_artifact="jumplist",
                event_type="file_opened",
                action="application recorded a file in its jump list",
                source_file=relative_path,
                # The byte offset of the embedded link. There is no id inside
                # the container, and offset is unique within the file (CD-004).
                source_locator=f"link@{offset}",
                # Same reasoning as `lnk`: the times describe the TARGET file,
                # copied into the link. The OS logged no event at that instant.
                timestamp_type="presence",
                path=target,
                user=user,
                details=details,
            )


register(JumpListParser)
