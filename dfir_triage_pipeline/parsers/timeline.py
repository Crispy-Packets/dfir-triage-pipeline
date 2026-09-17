"""Windows Timeline (`ActivitiesCache.db`): what the user had open, and for how long.

The Activity Feed records an application the user interacted with, when it
started, and -- for engagement records -- **how many seconds they actively used
it**. No other family in this pipeline carries a duration: Prefetch counts runs,
BAM names a SID, SRUM samples resource use at intervals, and none of them says
a person sat in front of a program for seventeen seconds.

**Four ActivityTypes appear; two are parsed.** Measured on `s1_v3`:

    type  5   41 rows   an application was opened
    type  6  102 rows   UserEngaged, carrying activeDurationSeconds
    type 11    2 rows   settings sync (bluelight, pen input) -- not activity
    type 16   37 rows   clipboard/copy notifications -- no application

Types 11 and 16 are skipped. A settings-sync row names
`windows.data.bluelightreduction.settings` rather than a program, and emitting
it would put a configuration blob into a family whose other rows are things a
person did.

**`AppId` is a JSON array of platform/application pairs**, not a string. The
useful member is whichever platform is present, in this order of specificity:

    x_exe_path        a full path, sometimes on another drive
    windows_win32     a program identifier
    packageId         an AppX package
    alternateId       a fallback the OS fills in

Taking the first array member blindly yields `data_boundary` entries whose
application is `microsoft.default.default` -- a constant that names nothing.

**Times are Unix epoch seconds**, not FILETIME and not OLE. A parser that
applies either of the other two conventions used elsewhere in this pipeline
places the events decades away without raising.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

#: The two types that record something a person did.
_APP_OPENED = 5
_USER_ENGAGED = 6
_PARSED_TYPES = (_APP_OPENED, _USER_ENGAGED)

#: AppId platforms, most specific first. `data_boundary` is deliberately absent:
#: its application is the constant `microsoft.default.default`.
_PLATFORM_PRIORITY = ("x_exe_path", "windows_win32", "packageId", "alternateId")

#: Timeline timestamps are Unix seconds. Anything outside this band is a decode
#: failure rather than a time.
_EARLIEST = datetime(2015, 1, 1, tzinfo=UTC)
_LATEST = datetime(2100, 1, 1, tzinfo=UTC)


def unix_to_utc(seconds: Any) -> datetime | None:
    """Unix epoch seconds to aware UTC, or None when it is not a time."""
    if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
        return None
    try:
        converted = datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return converted if _EARLIEST <= converted <= _LATEST else None


def _as_text(value: Any) -> str | None:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def decode_app_id(raw: Any) -> str | None:
    """The application, from the JSON platform array.

    Returns the most specific platform present. A bare string is accepted too:
    the column is JSON on every row in this corpus, but the value is
    application-written and a future build could change it.
    """
    text = _as_text(raw)
    if not text:
        return None
    try:
        entries = json.loads(text)
    except (ValueError, TypeError):
        return text

    if not isinstance(entries, list):
        return text

    found: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        platform = entry.get("platform")
        application = entry.get("application")
        if isinstance(platform, str) and isinstance(application, str) and application:
            found.setdefault(platform, application)

    for platform in _PLATFORM_PRIORITY:
        if platform in found:
            return found[platform]
    return None


def decode_payload(raw: Any) -> dict[str, Any]:
    """The payload JSON, or {} when it is not JSON.

    Type 11 rows carry base64 protobuf here rather than JSON; those rows are
    not parsed at all, but the guard stays so a malformed payload on a parsed
    row cannot take the parser down.
    """
    text = _as_text(raw)
    if not text:
        return {}
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _rows(abs_path: Path) -> list[sqlite3.Row]:
    r"""Activity rows, INCLUDING those still in the write-ahead log.

    **The database and its `-wal` are copied to a temporary directory and
    opened normally there**, which lets SQLite replay the log and recover rows
    that were never checkpointed into the `.db`. The originals are only ever
    read (CD-016); the replay happens on the copy.

    This parser used `immutable=1` on the evidence in place, which is safe --
    it prevents replay and touches no sibling file -- but `immutable=1`
    IGNORES THE WAL ENTIRELY. Measured on `s1_v3`:

        rows with the WAL ignored   182
        rows with the WAL replayed  205

    **23 activities existed only in the log**, and the most recent of them are
    PowerShell. A parser that silently drops the newest evidence in a database
    is worse than one that drops the oldest, because an incident's tail is
    where the activity is. See D-053.

    A collection with no `-wal` beside the database behaves exactly as before.

    **Rows are fetched EAGERLY and the connection closed before returning.**
    This was a generator with `yield from` inside `try/finally`, which holds
    the descriptor open for as long as the caller takes to consume it -- and
    the caller is itself a generator feeding a whole ingest run. Across a
    collection that exhausted the process's file-descriptor limit, and the
    resulting `OSError: Too many open files` surfaced in a DIFFERENT parser
    (the USN journal, which simply happened to open a file next). See D-050.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        staged = Path(tmpdir) / abs_path.name
        try:
            shutil.copy2(abs_path, staged)
        except OSError:
            return []
        # The journal files must keep their exact names beside the copy, or
        # SQLite will not find them and the replay silently yields nothing.
        for suffix in ("-wal", "-shm"):
            sibling = Path(str(abs_path) + suffix)
            if sibling.is_file():
                try:
                    shutil.copy2(sibling, Path(str(staged) + suffix))
                except OSError:
                    pass
        return _read_staged(staged)


def _read_staged(staged: Path) -> list[sqlite3.Row]:
    """Read the staged copy, letting SQLite recover the WAL into it."""
    connection = sqlite3.connect(str(staged))
    connection.row_factory = sqlite3.Row
    try:
        # An initialised-but-unused database has no Activity table at all --
        # measured on host 1's `admin_local`, an account that logged on but
        # never used the Activity Feed. That is an absence of evidence, not a
        # parser fault, so it yields nothing rather than raising and inflating
        # the failure count (D-024's reasoning).
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='Activity'"
        ).fetchone()
        if not exists:
            return []
        return connection.execute(
            "SELECT Id, AppId, ActivityType, Payload, StartTime, EndTime, "
            "LastModifiedTime FROM Activity"
        ).fetchall()
    finally:
        connection.close()


def _hive_user(relative_path: str) -> str | None:
    parts = relative_path.replace("\\", "/").split("/")
    for index, part in enumerate(parts):
        if part.lower() == "users" and index + 1 < len(parts):
            return parts[index + 1]
    return None


class TimelineParser:
    name = "timeline"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.replace("\\", "/").lower()
        # The -wal and -shm files beside it are SQLite's own journals and hold
        # no rows this parser can read on their own.
        return lowered.endswith("/activitiescache.db")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        user = _hive_user(relative_path)

        for row in _rows(abs_path):
            activity_type = row["ActivityType"]
            if activity_type not in _PARSED_TYPES:
                continue

            application = decode_app_id(row["AppId"])
            if not application:
                continue

            started = unix_to_utc(row["StartTime"])
            timestamp = started or unix_to_utc(row["LastModifiedTime"])
            if timestamp is None:
                continue

            payload = decode_payload(row["Payload"])
            details: dict[str, str] = {"activity_type": str(activity_type)}

            display = payload.get("displayText") or payload.get("appDisplayName")
            if isinstance(display, str) and display.strip():
                details["display_text"] = display.strip()

            duration = payload.get("activeDurationSeconds")
            if isinstance(duration, int) and not isinstance(duration, bool):
                # The value no other family carries: how long a person was
                # actually engaged, as opposed to how long a process lived.
                details["active_seconds"] = str(duration)

            ended = unix_to_utc(row["EndTime"])
            if ended:
                details["end_time"] = ended.isoformat().replace("+00:00", "Z")

            identifier = row["Id"]
            locator = (
                identifier.hex()
                if isinstance(identifier, bytes)
                else str(identifier)
            )

            yield Event(
                timestamp=timestamp,
                source_artifact="timeline",
                event_type=(
                    "app_engaged" if activity_type == _USER_ENGAGED else "app_opened"
                ),
                action=(
                    "user interacted with an application"
                    if activity_type == _USER_ENGAGED
                    else "application opened"
                ),
                source_file=relative_path,
                source_locator=f"Activity/{locator}",
                # The Activity Feed writes the row when the activity happens,
                # so this is an observation rather than a copied property.
                timestamp_type="recorded",
                path=application,
                user=user,
                details=details,
            )


register(TimelineParser)
