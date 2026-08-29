from __future__ import annotations

import hashlib
import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..model import Event
from ..paths import derive as derive_path
from . import register

# Chrome/Edge store times as microseconds since 1601-01-01 UTC -- the FILETIME
# epoch, but in microseconds rather than 100-nanosecond ticks. Treating one as a
# Unix timestamp puts every download in 1601 or in the twenty-fourth century.
_WEBKIT_EPOCH_OFFSET_US = 11644473600 * 1_000_000

# Read only what is declared in docs/details-schema.md. Selecting * would pull
# 28 columns and invite emitting an undeclared key by accident (CD-012).
_DOWNLOADS_QUERY = """
    SELECT id, start_time, target_path, tab_url, referrer, total_bytes, mime_type
    FROM downloads
    ORDER BY id
"""

_EDGE_HISTORY_SUFFIX = "/appdata/local/microsoft/edge/user data/default/history"


def webkit_to_utc(value: int) -> datetime:
    """Convert a WebKit/Chrome timestamp to timezone-aware UTC.

    Integer arithmetic throughout: the value is already microseconds, so no
    division is needed and no precision is lost. The scenario download reads
    13431997206710763 -> 2026-08-23T22:20:06.710763Z, which matches the value
    Person A recovered by hand from this same row.
    """
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
        microseconds=value - _WEBKIT_EPOCH_OFFSET_US
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _records(abs_path: Path, relative_path: str) -> Iterator[dict]:
    """Yield one normalised dict per download row. The only sqlite-coupled code.

    The database is copied to a temporary file before it is opened, and the copy
    is hashed. Two reasons, both established in Week 1:

      - The file sits deep in the collection tree and the reading toolchain hit
        a path-length limit opening it in place; Person A recorded the same
        workaround with the copy's SHA-256 as provenance.
      - Opening a SQLite database read-write replays any journal, which modifies
        the file. `immutable=1` with `mode=ro` prevents both the replay and any
        lock file, so the copy is read exactly as collected.

    Recording the hash of what was actually read is what makes the reading
    auditable: a later reader can confirm the bytes this parser saw.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        copy = Path(tmpdir) / "History"
        shutil.copy2(abs_path, copy)
        db_sha256 = _sha256(copy)

        uri = f"file:{copy.as_posix()}?immutable=1&mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            rows = list(connection.execute(_DOWNLOADS_QUERY))
        except sqlite3.DatabaseError:
            # Not a readable History database. Raised rather than swallowed so
            # the runner counts it: an unreadable database is a failure to read
            # evidence, unlike a readable one holding no downloads.
            raise
        finally:
            connection.close()

    for row in rows:
        row_id, start_time, target_path, tab_url, referrer, total_bytes, mime = row
        if not start_time or not target_path:
            continue  # a row with no time or no destination records no download
        yield {
            "id": row_id,
            "start_time": start_time,
            "target_path": target_path,
            "url": tab_url or "",
            "referrer": referrer or "",
            "total_bytes": total_bytes,
            "mime_type": mime or "",
            "source_file": relative_path,
            "db_sha256": db_sha256,
        }


def record_to_event(record: dict) -> Event:
    """Pure transform: dict in, Event out. No filesystem, no sqlite type."""
    details = {
        "target_path": record["target_path"],
        "db_sha256": record["db_sha256"],
    }
    if record.get("url"):
        details["url"] = record["url"]
    if record.get("referrer"):
        details["referrer"] = record["referrer"]
    if record.get("mime_type"):
        details["mime_type"] = record["mime_type"]
    # total_bytes is 0 for a download that never completed. Emitting "0" would
    # assert a zero-length file; the artifact is instead saying it does not know
    # the size, so the key is omitted (CD-012's absent-is-not-zero rule).
    if record.get("total_bytes"):
        details["bytes"] = str(record["total_bytes"])

    # B-9. The download target is the strongest link between a browser record
    # and a later execution: it is how invoice_scan.exe in Edge history joins to
    # INVOICE_SCAN.EXE in Prefetch, which carries no path at all.
    details.update(derive_path(record["target_path"]))

    return Event(
        timestamp=webkit_to_utc(record["start_time"]),
        source_artifact="browser",
        event_type="file_download",              # CD-007
        action="file downloaded",
        source_file=record["source_file"],       # CD-003
        source_locator=f"downloads.id={record['id']}",  # CD-004, unique in db
        # The browser wrote this row as the download began, so the timestamp is
        # the event itself -- unlike a registry autorun, whose time is a key's
        # last write. CD-019.
        timestamp_type="recorded",
        host=None,
        user=None,
        path=record["target_path"],              # CD-010, verbatim
        confidence="high",
        details=details,
    )


@register
class BrowserParser:
    name = "browser"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        if not lowered.endswith(_EDGE_HISTORY_SUFFIX):
            return False
        # History-journal and cache siblings share the stem but are not the
        # database; endswith already excludes them, and this guards the case
        # where a collection carries History-wal alongside History.
        return not lowered.endswith(("-wal", "-shm", "-journal"))

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        for record in _records(abs_path, relative_path):
            yield record_to_event(record)
