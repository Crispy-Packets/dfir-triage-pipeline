"""Chromium profile databases beside `History`: typed queries, sites, autofill.

`parsers/browser.py` reads the `downloads` table of `History`. A Chromium
profile holds a dozen further SQLite databases, and four of them record what a
person did rather than what the browser cached:

    Shortcuts                 omni_box_shortcuts -- **text typed into the
                              address bar**, with the URL it resolved to and
                              how many times it was used
    Top Sites                 top_sites -- the most-visited list
    Favicons                  icon_mapping -- **every page an icon was fetched
                              for**, which is a visit record that SURVIVES
                              clearing History
    Web Data                  autofill -- form values the user typed, with
                              first- and last-used times

**The Favicons point is the forensic one.** `History` is the file a person
clears; `Favicons` is not, and its `icon_mapping` table names 374 page URLs on
`s1_v3`. A browsing record that outlives the deletion of browsing records is
worth having.

**These are read-only and copied before opening**, for the same two reasons
`browser.py` copies `History`: opening a SQLite database read-write replays any
journal and modifies the file, and the collection path can exceed what the
sqlite driver will open in place. `immutable=1` prevents both.

**`Login Data` is deliberately not read.** Its `logins` table holds saved
credentials, encrypted under DPAPI. Measured, it is empty on these collections
anyway -- but the parser does not look, for the same reason `sam_hive.py` does
not read the `V` value.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..model import Event
from . import register

#: Chrome/Edge store times as microseconds since 1601-01-01 UTC. Same epoch as
#: FILETIME but a different unit -- treating one as the other puts every row in
#: 1601 or in the twenty-fourth century. Shared with browser.py's reasoning.
_WEBKIT_EPOCH_OFFSET_US = 11644473600 * 1_000_000

#: (basename, table, query, event_type, action, path column). Only tables whose
#: rows record a person's action are read; caches and metadata are not.
_SOURCES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "shortcuts",
        "SELECT text, url, last_access_time, number_of_hits FROM omni_box_shortcuts",
        "url_typed",
        "text typed into the browser address bar",
        "shortcuts",
    ),
    (
        "top sites",
        "SELECT url, title, url_rank FROM top_sites",
        "site_frequent",
        "site in the browser's most-visited list",
        "top_sites",
    ),
    (
        "favicons",
        "SELECT page_url, icon_id FROM icon_mapping",
        "page_visited",
        "browser fetched an icon for a page",
        "favicons",
    ),
    (
        "web data",
        "SELECT name, value, date_created, date_last_used, count FROM autofill",
        "form_autofill",
        "value typed into a web form",
        "autofill",
    ),
)

#: Journals and siblings share the stem but are not the database.
_NOT_A_DATABASE = ("-wal", "-shm", "-journal")


def webkit_to_utc(value: object) -> datetime | None:
    """A Chromium timestamp to aware UTC, or None when it is not a time."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None
    try:
        return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
            microseconds=value - _WEBKIT_EPOCH_OFFSET_US
        )
    except (OverflowError, ValueError):
        return None


def profile_database(relative_path: str) -> str | None:
    """Which profile database this is, or None.

    Matched on the basename under a `User Data/<profile>/` path, so a file
    called `Shortcuts` elsewhere on the disk is not opened as one.
    """
    lowered = relative_path.replace("\\", "/").lower()
    if "/user data/" not in lowered or lowered.endswith(_NOT_A_DATABASE):
        return None
    name = lowered.rsplit("/", 1)[-1]
    return name if any(name == source[0] for source in _SOURCES) else None


def _rows(abs_path: Path, query: str) -> list[tuple]:
    """Query a copy of the database, or [] when it cannot be read."""
    with tempfile.TemporaryDirectory() as tmpdir:
        copy = Path(tmpdir) / "db"
        try:
            shutil.copy2(abs_path, copy)
        except OSError:
            return []
        connection = sqlite3.connect(f"file:{copy.as_posix()}?immutable=1&mode=ro", uri=True)
        try:
            return list(connection.execute(query))
        except sqlite3.DatabaseError:
            # A profile database whose schema differs by browser version. The
            # table is absent rather than the file being unreadable, so this is
            # an absence of evidence, not a failure (D-024's reasoning).
            return []
        finally:
            connection.close()


class BrowserProfileParser:
    name = "browser_profile"

    def can_handle(self, relative_path: str) -> bool:
        return profile_database(relative_path) is not None

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        database = profile_database(relative_path)
        source = next((s for s in _SOURCES if s[0] == database), None)
        if source is None:
            return
        _, query, event_type, action, table = source

        lowered = relative_path.replace("\\", "/").lower()
        browser = "chrome" if "/google/chrome/" in lowered else "edge"

        for index, row in enumerate(_rows(abs_path, query)):
            event = self._row_to_event(
                row, table, event_type, action, relative_path, index, browser
            )
            if event is not None:
                yield event

    @staticmethod
    def _row_to_event(
        row: tuple,
        table: str,
        event_type: str,
        action: str,
        relative_path: str,
        index: int,
        browser: str,
    ) -> Event | None:
        details: dict[str, str] = {"browser": browser, "profile_table": table}
        timestamp: datetime | None = None
        path: str | None = None

        if table == "shortcuts":
            text, url, last_access, hits = row
            path = url or text
            if text:
                details["typed_text"] = str(text)
            if hits:
                details["use_count"] = str(hits)
            timestamp = webkit_to_utc(last_access)
        elif table == "top_sites":
            url, title, rank = row
            path = url
            if title:
                details["page_title"] = str(title)
            if rank is not None:
                details["site_rank"] = str(rank)
        elif table == "favicons":
            page_url, icon_id = row
            path = page_url
            if icon_id is not None:
                details["icon_id"] = str(icon_id)
        elif table == "autofill":
            name, value, created, last_used, count = row
            path = name
            if value:
                details["field_value"] = str(value)
            if count:
                details["use_count"] = str(count)
            created_at = webkit_to_utc(created)
            if created_at:
                details["first_used"] = created_at.isoformat().replace("+00:00", "Z")
            timestamp = webkit_to_utc(last_used) or created_at

        if not path:
            return None

        return Event(
            # A row with no usable time carries the epoch sentinel and
            # `presence`: Top Sites and icon_mapping record no time at all, so
            # claiming one would invent it.
            timestamp=timestamp or datetime(1601, 1, 1, tzinfo=UTC),
            source_artifact="browser_profile",
            event_type=event_type,
            action=action,
            source_file=relative_path,
            source_locator=f"{table}/{index}",
            timestamp_type="recorded" if timestamp else "presence",
            path=str(path),
            user=None,
            details=details,
        )


register(BrowserProfileParser)
