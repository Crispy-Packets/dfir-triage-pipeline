"""NTUSER.DAT beyond the Run keys: what a user ran, and what they opened.

`parsers/registry.py` already reads the Run/RunOnce values out of this hive.
This parser reads the Explorer keys beside them, which answer a different
question: not "what persists" but **"what did this specific person do"**.

    UserAssist   a GUI-launched program, with a run count and a last-run time
    RecentDocs   a file opened through the shell, per extension
    TypedPaths   a path typed into the Explorer address bar
    RunMRU       a command typed into the Run dialog

**Every one is per-user by construction.** Prefetch and Shimcache are
machine-wide and name no principal; BAM supplies a SID but only for what its
service observed. These keys sit inside one user's hive, so the principal is the
hive's owner and needs no inference -- which makes them the corroborator for
"which of the three accounts did this", a question the others cannot answer.

**Three encodings, each established by reading the bytes:**

1. **UserAssist value names are ROT13.** `HRZR_PGYFRFFVBA` is `UEME_CTLSESSION`.
   Not encryption and not obfuscation worth respecting -- it is a trivial
   substitution Windows applies -- but a parser that skips it emits garbage
   paths that look like data.

2. **The UserAssist record is 72 bytes**, and the fields that matter are not at
   the front: run count at offset 4, focus count at 8, focus milliseconds at 12,
   and the last-run FILETIME at **offset 60**. Measured on `clean_b`: 57 records
   of 72 bytes and 2 of 1612 (the `UEME_CTLSESSION` aggregates, which are not
   programs and are skipped).

3. **RecentDocs values are UTF-16LE up to a null, then a shell-link tail.** The
   readable name is the prefix; the remainder is a binary structure this parser
   does not decode. Splitting on a single null byte rather than on a UTF-16 code
   unit truncates mid-character -- `test_doc` came back as `test_doc�`.

**What these keys do NOT attest.** UserAssist counts GUI launches only: a
program started from a command line, a script, or a service leaves no entry, so
a zero count is not evidence of no execution. RecentDocs records that a name was
opened through the shell, not that the file still exists or ever did -- entry 15
on `clean_b` decodes to a URL query string rather than a filename, which is why
the parser reports the recorded string without asserting it is a path.
"""

from __future__ import annotations

import codecs
import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..model import Event

_EXPLORER = r"\Software\Microsoft\Windows\CurrentVersion\Explorer"
_USERASSIST = _EXPLORER + r"\UserAssist"
_RECENTDOCS = _EXPLORER + r"\RecentDocs"
_TYPEDPATHS = _EXPLORER + r"\TypedPaths"
_RUNMRU = _EXPLORER + r"\RunMRU"

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: The modern UserAssist record. Anything else is a different structure and is
#: skipped rather than decoded from what happens to be there.
_USERASSIST_RECORD_BYTES = 72

#: Offsets within that record, read out of the bytes rather than assumed.
_OFF_RUN_COUNT = 4
_OFF_FOCUS_COUNT = 8
_OFF_FOCUS_MS = 12
_OFF_LAST_RUN = 60

#: Session aggregates, not programs. They are 1612 bytes and carry a roll-up of
#: the whole session; emitting one would invent a binary called
#: `UEME_CTLSESSION` with a run count of several hundred.
_NOT_A_PROGRAM = ("UEME_CTLSESSION", "UEME_CTLCUACount:ctor")

#: Bookkeeping values that order an MRU list rather than naming anything.
_MRU_ORDERING = frozenset({"MRUList", "MRUListEx"})


def rot13(text: str) -> str:
    """UserAssist value names are ROT13. Digits and punctuation pass through."""
    return codecs.decode(text, "rot13")


def filetime_to_utc(ticks: int) -> datetime | None:
    """FILETIME to aware UTC, or None when the value is not a real time."""
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=ticks / 10)
    except (OverflowError, ValueError):
        return None
    return converted if converted.year > 1601 else None


def parse_userassist_record(blob: Any) -> dict[str, Any] | None:
    """Decode a 72-byte UserAssist record, or None.

    A shorter blob is not decoded from what is present: the FILETIME lives at
    offset 60, so a truncated record would yield a run count with no time, or a
    time read from the wrong bytes.
    """
    if not isinstance(blob, bytes) or len(blob) < _USERASSIST_RECORD_BYTES:
        return None
    try:
        run_count = struct.unpack_from("<I", blob, _OFF_RUN_COUNT)[0]
        focus_count = struct.unpack_from("<I", blob, _OFF_FOCUS_COUNT)[0]
        focus_ms = struct.unpack_from("<I", blob, _OFF_FOCUS_MS)[0]
        ticks = struct.unpack_from("<Q", blob, _OFF_LAST_RUN)[0]
    except struct.error:
        return None
    return {
        "run_count": run_count,
        "focus_count": focus_count,
        "focus_ms": focus_ms,
        "last_run": filetime_to_utc(ticks),
    }


def decode_mru_name(blob: Any) -> str | None:
    """The readable name from a RecentDocs value.

    The value is UTF-16LE terminated by a null CODE UNIT, followed by a shell
    link structure this parser does not decode. Splitting on a single null
    BYTE truncates mid-character, which is how `test_doc` became
    `test_doc\\ufffd`.
    """
    if not isinstance(blob, bytes) or len(blob) < 2:
        return None
    # Work in code units so the terminator is found on an even boundary.
    limit = len(blob) - (len(blob) % 2)
    text = blob[:limit].decode("utf-16-le", errors="replace")
    name = text.split("\x00", 1)[0].strip()
    return name or None


def _hive_user(relative_path: str) -> str | None:
    """The account name, from the hive's own location under Users\\."""
    parts = relative_path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return None


def _key(hive: Any, path: str) -> Any:
    try:
        return hive.get_key(path)
    except Exception:
        return None


def _key_timestamp(key: Any) -> datetime:
    raw = getattr(key, "header", None)
    ticks = getattr(raw, "last_modified", None) if raw is not None else None
    if isinstance(ticks, int):
        converted = filetime_to_utc(ticks)
        if converted is not None:
            return converted
    return _FILETIME_EPOCH


def _userassist_events(hive: Any, relative_path: str, user: str | None) -> Iterator[Event]:
    root = _key(hive, _USERASSIST)
    if root is None:
        return

    for guid in root.iter_subkeys():
        count = _key(hive, f"{_USERASSIST}\\{guid.name}\\Count")
        if count is None:
            continue

        for value in count.get_values():
            name = rot13(value.name)
            if name.startswith(_NOT_A_PROGRAM):
                continue
            record = parse_userassist_record(value.value)
            if record is None:
                continue

            details: dict[str, str] = {
                "run_count": str(record["run_count"]),
                "focus_count": str(record["focus_count"]),
                "focus_seconds": str(record["focus_ms"] // 1000),
                "userassist_guid": guid.name,
            }

            yield Event(
                # A real last-run FILETIME when the record carries one. This is
                # `last_run` for the same reason Prefetch is: one overwritten
                # slot behind a count.
                timestamp=record["last_run"] or _key_timestamp(count),
                source_artifact="userassist",
                event_type="process_exec",
                action="program launched through the shell",
                source_file=relative_path,
                source_locator=f"UserAssist\\{guid.name}\\{value.name}",
                timestamp_type="last_run" if record["last_run"] else "presence",
                path=name,
                user=user,
                details=details,
            )


def _mru_events(
    hive: Any,
    relative_path: str,
    user: str | None,
    *,
    key_path: str,
    family: str,
    event_type: str,
    action: str,
    decode: Any,
) -> Iterator[Event]:
    """Shared shape for the three MRU-style keys.

    All three are a list of values under one key whose last-write time is the
    only time available, shared by every sibling -- D-027's problem exactly, so
    they are all `presence` and carry `value_count_in_key` to say how many
    entries share the timestamp.
    """
    roots = [(_key(hive, key_path), key_path)]
    root = roots[0][0]
    if root is None:
        return

    # RecentDocs nests one subkey per extension beside its root values.
    if family == "recentdocs":
        roots.extend(
            (_key(hive, f"{key_path}\\{sub.name}"), f"{key_path}\\{sub.name}")
            for sub in root.iter_subkeys()
        )

    for node, node_path in roots:
        if node is None:
            continue
        values = [v for v in node.get_values() if v.name not in _MRU_ORDERING]
        if not values:
            continue
        timestamp = _key_timestamp(node)
        suffix = node_path[len(key_path) :].lstrip("\\")

        for value in values:
            name = decode(value.value)
            if not name:
                continue
            details = {
                "value_name": value.name,
                "value_count_in_key": str(len(values)),
            }
            if suffix:
                details["recentdocs_extension"] = suffix

            yield Event(
                timestamp=timestamp,
                source_artifact=family,
                event_type=event_type,
                action=action,
                source_file=relative_path,
                source_locator=f"{node_path.lstrip(chr(92))}\\{value.name}",
                # The containing key's last write, shared by every sibling
                # value. D-027: it says the entry EXISTS, not when it was made.
                timestamp_type="presence",
                path=name,
                user=user,
                details=details,
            )


def explorer_events(abs_path: Path, relative_path: str) -> Iterator[Event]:
    """Every Explorer-key event in one NTUSER.DAT.

    **Called by `registry.RegistryParser.parse`, not registered separately.**
    `find_parser` returns the first parser whose `can_handle` matches, and
    `registry` already claims `NTUSER.DAT`; a second registration against the
    same file would never run. A SOFTWARE hive reaches this function too and
    simply yields nothing, because none of these keys exist there.
    """
    if not relative_path.lower().replace("\\", "/").endswith("/ntuser.dat"):
        return

    from regipy.registry import RegistryHive

    hive = RegistryHive(str(abs_path))
    user = _hive_user(relative_path)


    yield from _userassist_events(hive, relative_path, user)
    yield from _mru_events(
        hive,
        relative_path,
        user,
        key_path=_RECENTDOCS,
        family="recentdocs",
        event_type="file_opened",
        action="file opened through the shell",
        decode=decode_mru_name,
    )
    yield from _mru_events(
        hive,
        relative_path,
        user,
        key_path=_TYPEDPATHS,
        family="typedpaths",
        event_type="path_typed",
        action="path typed into the Explorer address bar",
        decode=lambda v: v.strip() if isinstance(v, str) and v.strip() else None,
    )
    yield from _mru_events(
        hive,
        relative_path,
        user,
        key_path=_RUNMRU,
        family="runmru",
        event_type="command_typed",
        action="command typed into the Run dialog",
        # RunMRU values end with a literal `\1` ordering suffix.
        decode=lambda v: (
            v.rsplit("\\1", 1)[0].strip()
            if isinstance(v, str) and v.strip()
            else None
        ),
    )
