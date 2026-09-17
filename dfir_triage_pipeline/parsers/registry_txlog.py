"""Registry transaction logs: pending writes not yet in the hive.

`NTUSER.DAT.LOG1`, `SYSTEM.LOG2` and their siblings are the registry's
write-ahead logs. Windows writes a change here first and flushes it into the
hive later, so **a log can hold a value the hive itself does not**.

This matters for a collection taken from a live machine, which all five here
were: KAPE copies the hive and the logs separately, and anything written after
the hive was flushed exists only in the log.

**These were classified as "no committed values" earlier in this project and
that was wrong.** Measured -- every one carries a valid `regf` header and an
`HvLE` log entry with real dirty-page data:

    ntuser.dat.LOG1   378,880 bytes   seq 428   entry 32,256 bytes
    SYSTEM.LOG1       425,984 bytes   seq 901   entry 52,736 bytes
    SAM.LOG1           32,768 bytes   seq  38   entry 15,872 bytes

**What this parser does, and what it does not.** It does NOT replay the log
into the hive. Replay means applying dirty pages at their recorded offsets and
re-parsing the result, and a mistake there produces a hive that parses cleanly
and contains fabricated keys -- the worst failure mode this pipeline has. That
is a larger piece of work than the rest of this file and it is not attempted.

What it does is report **that pending writes exist, how many bytes, and whether
the log is AHEAD of its hive** -- which is the actionable part. A log whose
sequence number exceeds the hive's is holding changes the hive has never seen,
and an analyst who sees that knows the hive alone is an incomplete answer.

The sequence comparison is the reason both files are read together rather than
the log alone: `seq1` in the log header against `seq1` in the hive it belongs
to. A log at sequence 901 beside a hive at 899 is two flushes behind.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..model import Event
from . import register

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: Both hives and their logs start with this; `file_type` at offset 28 tells
#: them apart -- 0 is a primary hive, 6 is a transaction log.
_REGF = b"regf"
_FILE_TYPE_LOG = 6

#: The base block is 4096 bytes; log entries begin immediately after it.
_BASE_BLOCK = 512
_HVLE = b"HvLE"

_LOG_SUFFIXES = (".log1", ".log2")


def parse_log_header(blob: bytes) -> dict | None:
    """The log's base block, or None when this is not a transaction log."""
    if len(blob) < _BASE_BLOCK + 16 or blob[:4] != _REGF:
        return None
    try:
        primary_sequence, secondary_sequence = struct.unpack_from("<II", blob, 4)
        modified = struct.unpack_from("<Q", blob, 12)[0]
        major, minor = struct.unpack_from("<II", blob, 20)
        file_type = struct.unpack_from("<I", blob, 28)[0]
    except struct.error:
        return None

    if file_type != _FILE_TYPE_LOG:
        return None

    entry_size = 0
    entry_sequence = None
    if blob[_BASE_BLOCK : _BASE_BLOCK + 4] == _HVLE:
        try:
            entry_size, _flags, entry_sequence = struct.unpack_from(
                "<III", blob, _BASE_BLOCK + 4
            )
        except struct.error:
            entry_size = 0

    converted = None
    if modified > 0:
        try:
            converted = _FILETIME_EPOCH + timedelta(microseconds=modified // 10)
        except (OverflowError, ValueError):
            converted = None

    return {
        "primary_sequence": primary_sequence,
        "secondary_sequence": secondary_sequence,
        "version": f"{major}.{minor}",
        "entry_size": entry_size,
        "entry_sequence": entry_sequence,
        "modified": converted if converted and converted.year > 1601 else None,
    }


def hive_sequence(hive_path: Path) -> int | None:
    """The primary sequence number of the hive this log belongs to.

    Read from the hive's own base block rather than by parsing it, so a hive
    regipy cannot open still yields the comparison.
    """
    try:
        with hive_path.open("rb") as handle:
            head = handle.read(12)
    except OSError:
        return None
    if len(head) < 12 or head[:4] != _REGF:
        return None
    try:
        return struct.unpack_from("<I", head, 4)[0]
    except struct.error:
        return None


class RegistryTxLogParser:
    name = "registry_txlog"

    def can_handle(self, relative_path: str) -> bool:
        return relative_path.lower().endswith(_LOG_SUFFIXES)

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        try:
            blob = abs_path.read_bytes()
        except OSError:
            return

        header = parse_log_header(blob)
        if header is None:
            # Not a transaction log despite the extension, or truncated before
            # the base block. Nothing to report rather than a guess.
            return

        # The hive is the same path with the .LOGn suffix removed.
        hive_path = abs_path.with_suffix("")
        hive_seq = hive_sequence(hive_path)

        details: dict[str, str] = {
            "log_sequence": str(header["primary_sequence"]),
            "log_version": header["version"],
            "pending_bytes": str(header["entry_size"]),
            "hive_name": hive_path.name,
        }
        if header["entry_sequence"] is not None:
            details["entry_sequence"] = str(header["entry_sequence"])
        if hive_seq is not None:
            details["hive_sequence"] = str(hive_seq)
            # THE actionable field: a log ahead of its hive holds changes the
            # hive has never seen, so the hive alone is an incomplete answer.
            details["log_ahead_of_hive"] = str(
                header["primary_sequence"] > hive_seq
            ).lower()

        if not header["entry_size"]:
            # A log with no dirty pages is fully flushed and asserts nothing.
            return

        yield Event(
            timestamp=header["modified"] or _FILETIME_EPOCH,
            source_artifact="registry_txlog",
            event_type="pending_registry_write",
            action="registry transaction log holds unflushed changes",
            source_file=relative_path,
            source_locator="BaseBlock",
            # The base block's own last-write time. It says the log EXISTS with
            # pending data, not when any particular value was written -- the
            # log is not replayed, so no individual change is claimed.
            timestamp_type="presence",
            path=None,
            user=None,
            details=details,
        )


register(RegistryTxLogParser)
