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

#: Chromium-family history databases. Edge and Chrome ship the IDENTICAL
#: `downloads` schema -- verified on both collections' files, every column this
#: parser reads present in each -- so one query serves both and the browser is
#: recorded as a detail rather than forked into two parsers.
#:
#: Chrome yields ZERO downloads on this corpus (both hosts used Edge). The
#: suffix is carried anyway: a collection where Chrome WAS used would otherwise
#: be silently unparsed, and an empty family is a measured absence rather than
#: a gap.
_HISTORY_SUFFIXES = {
    "edge": "/appdata/local/microsoft/edge/user data/default/history",
    "chrome": "/appdata/local/google/chrome/user data/default/history",
}


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


#: Page visits joined to their URL, and the search terms typed into the
#: address bar. Read alongside `downloads`, which this parser read alone until
#: 2026-09-17 -- measured on s1_v3, that was hiding 610 visits and 65 search
#: terms behind 86 downloads.
_VISITS_QUERY = """
    SELECT v.id, v.visit_time, u.url, u.title, v.transition
    FROM visits v JOIN urls u ON u.id = v.url
    ORDER BY v.id
"""

#: `keyword_search_terms` has NO unique key of its own -- keyword_id is the
#: search ENGINE, so every term typed into Bing shares one. Using it as the
#: locator produced 61 duplicates on s1_v3 and violated CD-004. The row is
#: identified by (keyword_id, url_id) instead, which is the table's real
#: primary key.
_SEARCH_QUERY = """
    SELECT k.keyword_id, k.url_id, k.term, u.url, u.last_visit_time
    FROM keyword_search_terms k JOIN urls u ON u.id = k.url_id
    ORDER BY k.keyword_id, k.url_id
"""

#: Chromium's transition mask. The low byte is the core type; only the values
#: that say something about HOW the user arrived are named, and the raw mask is
#: always kept so nothing is lost to this table being incomplete.
_TRANSITIONS = {
    0: "link",
    1: "typed",
    2: "auto_bookmark",
    3: "auto_subframe",
    4: "manual_subframe",
    5: "generated",
    6: "start_page",
    7: "form_submit",
    8: "reload",
    9: "keyword",
    10: "keyword_generated",
}


def _query(abs_path: Path, query: str) -> list[tuple]:
    """Rows from a copy of the database, or [] when the table is absent.

    Copied and opened `immutable=1` for the same reasons `_records` does it:
    opening read-write replays the journal and modifies the evidence.

    Rows are fetched eagerly and the connection closed before returning --
    holding it open across a `yield` exhausted the process descriptor limit
    once (D-050).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        copy = Path(tmpdir) / "History"
        try:
            shutil.copy2(abs_path, copy)
        except OSError:
            return []
        uri = f"file:{copy.as_posix()}?immutable=1&mode=ro"
        connection = sqlite3.connect(uri, uri=True)
        try:
            return list(connection.execute(query))
        except sqlite3.DatabaseError:
            # A schema this browser version does not have. An absence, not a
            # failure to read evidence (D-024's reasoning).
            return []
        finally:
            connection.close()


def _visit_events(
    abs_path: Path, relative_path: str, browser: str
) -> Iterator[Event]:
    """One event per page visit, and one per search term."""
    for row in _query(abs_path, _VISITS_QUERY):
        visit_id, visit_time, url, title, transition = row
        if not visit_time or not url:
            continue
        details = {"browser": browser, "url": url}
        if title:
            details["page_title"] = title
        if isinstance(transition, int):
            details["transition_raw"] = str(transition)
            core = transition & 0xFF
            if core in _TRANSITIONS:
                # `typed` is the discriminating value: it means the user wrote
                # the address rather than following a link to it.
                details["transition"] = _TRANSITIONS[core]
        yield Event(
            timestamp=webkit_to_utc(visit_time),
            source_artifact="browser",
            event_type="page_visited",
            action="page visited in the browser",
            source_file=relative_path,
            source_locator=f"visits.id={visit_id}",
            # The browser wrote the row as the visit happened.
            timestamp_type="recorded",
            host=None,
            user=None,
            path=url,
            confidence="high",
            details=details,
        )

    for row in _query(abs_path, _SEARCH_QUERY):
        keyword_id, url_id, term, url, last_visit = row
        if not term:
            continue
        timestamp = webkit_to_utc(last_visit) if last_visit else None
        yield Event(
            # `keyword_search_terms` carries no time of its own; the URL row's
            # last-visit time is the closest the artefact offers, and when it
            # has none the event is presence-typed rather than invented.
            timestamp=timestamp or datetime(1601, 1, 1, tzinfo=UTC),
            source_artifact="browser",
            event_type="search_term",
            action="search term entered in the browser",
            source_file=relative_path,
            source_locator=(
                f"keyword_search_terms.{keyword_id}.{url_id}"
            ),
            timestamp_type="recorded" if timestamp else "presence",
            host=None,
            user=None,
            path=term,
            confidence="high",
            details={"browser": browser, "search_term": term, "url": url or ""},
        )


def browser_of(relative_path: str) -> str | None:
    """Which Chromium browser this path is the history database of, or None.

    Journal and cache siblings share the stem but are not the database;
    `endswith` already excludes them, and the explicit check guards the case
    where a collection carries `History-wal` alongside `History`.
    """
    lowered = relative_path.lower().replace("\\", "/")
    if lowered.endswith(("-wal", "-shm", "-journal")):
        return None
    for browser, suffix in _HISTORY_SUFFIXES.items():
        if lowered.endswith(suffix):
            return browser
    return None


@register
class BrowserParser:
    name = "browser"

    def can_handle(self, relative_path: str) -> bool:
        return browser_of(relative_path) is not None

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        browser = browser_of(relative_path) or "unknown"
        for record in _records(abs_path, relative_path):
            event = record_to_event(record)
            # Which browser recorded the download, so a consumer is not left
            # inferring it from the path. Set here rather than in
            # record_to_event because the record carries no such field.
            event.details["browser"] = browser
            yield event

        # Page visits and search terms, added 2026-09-17.
        #
        # This parser read `downloads` alone for most of the project, and
        # docs/artifact-attestation-matrix.md recorded that as a stated limit:
        # "page visits -- the parser reads FROM downloads only". Measured on
        # s1_v3 that limit was hiding 610 visit rows and 65 search terms
        # against 86 downloads. A stated gap is still a gap.
        yield from _visit_events(abs_path, relative_path, browser)
