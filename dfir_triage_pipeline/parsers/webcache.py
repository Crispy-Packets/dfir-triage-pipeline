r"""`WebCacheV01.dat`: the WinINet history, cache and download index.

The ESE database behind Internet Explorer, the legacy Edge, and **every
component that uses WinINet** -- which on a modern machine still includes the
Windows Store, Office, and background transfer jobs. It is a different record
from the Chromium `History` database `browser.py` reads, not a duplicate of it.

**What it carries that Chromium's history does not:**

* **`Visited:` entries naming the USER** -- `Visited: vboxuser@https://...`.
  The account is inside the record, so a visit is attributed without inferring
  it from the file's location;
* **per-day history containers** (`MSHist012026091020260911`), which bound a
  visit to a date range even when its own timestamps are gone;
* **`BackgroundTransferApi`** rows -- downloads performed by the OS rather than
  by a browser, which leave no Chromium history at all;
* **`DOMStore`** -- sites that wrote local storage, evidence of interaction
  beyond a page load.

**The `Containers` table is the index and must be read first.** Rows live in
`Container_<n>` tables whose number means nothing on its own; `Containers` maps
each id to a name (`History`, `Content`, `DOMStore`, …) and a directory.
Reading `Container_5` without that mapping would report cache entries as
history.

**Timestamps are FILETIME**, despite the surrounding browser conventions --
`AccessedTime` on `s1_v3` reads `134336824935732258`, which is 2026-09-13. Not
the WebKit microseconds `browser.py` handles, and not the OLE dates `srum.py`
handles. Three time formats in one pipeline is why each parser states its own.

**Cache content is not extracted.** `Content` containers index files on disk
under `INetCache`; this parser records that the entry EXISTS with its URL and
size, and does not read the cached response body.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

#: Container names worth emitting, and the event_type each earns. A container
#: whose name is not here is skipped: `Content` is 40,000 cache-file entries
#: describing what a page loaded, not what a person did.
#:
#: `MSHist01...` names are per-day history and are matched by prefix.
_HISTORY = "History"
_DAILY_HISTORY_PREFIX = "MSHist01"
_DOM_STORE = "DOMStore"
_BACKGROUND_TRANSFER = "BackgroundTransferApi"

_EMITTED = {
    _HISTORY: ("page_visited", "page visited, recorded by WinINet"),
    _DOM_STORE: ("dom_storage", "site wrote local storage"),
    _BACKGROUND_TRANSFER: (
        "background_transfer",
        "background transfer performed by the OS",
    ),
}

#: A guard on a hostile file. The real database is 25 MB.
_MAX_ROWS_PER_CONTAINER = 200_000


def filetime_to_utc(ticks: Any) -> datetime | None:
    """FILETIME to aware UTC, or None when the value is not a real time."""
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except (OverflowError, ValueError):
        return None
    return converted if converted.year > 1601 else None


def _text(value: Any) -> str | None:
    """A column value as text, whichever encoding the database used."""
    if isinstance(value, bytes):
        # URLs are UTF-8; container names and directories are UTF-16.
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            decoded = value.decode("utf-16-le", errors="replace")
        value = decoded
    if isinstance(value, str):
        value = value.rstrip("\x00").strip()
        return value or None
    return None


def split_visited(url: str) -> tuple[str | None, str]:
    r"""`Visited: user@https://...` into (user, url).

    The account is INSIDE the record, which is what makes this family able to
    attribute a visit without inferring the user from the file's path. The
    daily containers prefix a date range as well:
    `:2026091020260911: vboxuser@https://...`.

    A record that does not carry the marker is returned unchanged with no user,
    rather than having one guessed from the surrounding text.
    """
    remainder = url
    if remainder.startswith(":"):
        # Strip the leading `:<daterange>: ` the daily containers add.
        closing = remainder.find(":", 1)
        if closing != -1:
            remainder = remainder[closing + 1 :].lstrip()

    for marker in ("Visited: ", "DOMStore:", ":BackgroundTransferApi:"):
        if remainder.startswith(marker):
            remainder = remainder[len(marker) :].lstrip()
            break

    if "@" in remainder:
        candidate, _, rest = remainder.partition("@")
        # A user name has no scheme and no dots-as-domain; anything longer is
        # an email address in a URL and must not be mistaken for an account.
        if candidate and "/" not in candidate and ":" not in candidate:
            return candidate, rest or remainder
    return None, remainder


def _containers(db: Any) -> dict[int, tuple[str, str | None]]:
    """Container id -> (name, directory).

    Read FIRST and always: a `Container_<n>` number means nothing on its own,
    and reading one without this mapping would report cache entries as history.
    """
    mapping: dict[int, tuple[str, str | None]] = {}
    try:
        table = db.table("Containers")
    except Exception:
        return mapping

    for record in table.records():
        container_id = record.get("ContainerId")
        name = _text(record.get("Name"))
        if isinstance(container_id, int) and name:
            mapping[container_id] = (name, _text(record.get("Directory")))
    return mapping


def _event_kind(name: str) -> tuple[str, str] | None:
    if name.startswith(_DAILY_HISTORY_PREFIX):
        return _EMITTED[_HISTORY]
    return _EMITTED.get(name)


class WebCacheParser:
    name = "webcache"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.replace("\\", "/").lower()
        # V01.log, V01.chk and WebCacheV01.jfm are the ESE journal and
        # checkpoint; they hold no committed rows of their own.
        return lowered.endswith("/webcachev01.dat")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        from dissect.esedb import EseDB

        # The handle must outlive the reading, and events are collected rather
        # than yielded from inside the with-block: holding a descriptor across
        # a yield exhausted the process limit once (D-050).
        events: list[Event] = []
        with abs_path.open("rb") as handle:
            db = EseDB(handle)
            containers = _containers(db)

            for container_id, (container_name, directory) in containers.items():
                kind = _event_kind(container_name)
                if kind is None:
                    continue
                event_type, action = kind

                try:
                    table = db.table(f"Container_{container_id}")
                    rows = list(table.records())
                except Exception:
                    # A container named in the index whose table is absent or
                    # unreadable. An absence, not a parser fault (D-024).
                    continue

                for index, record in enumerate(rows[:_MAX_ROWS_PER_CONTAINER]):
                    url = _text(record.get("Url"))
                    if not url:
                        continue
                    user, cleaned = split_visited(url)

                    details: dict[str, str] = {
                        "url": cleaned,
                        "container": container_name,
                        "container_id": str(container_id),
                    }
                    if directory:
                        details["cache_directory"] = directory
                    count = record.get("AccessCount")
                    if isinstance(count, int) and count:
                        details["access_count"] = str(count)
                    size = record.get("FileSize")
                    if isinstance(size, int) and size:
                        details["cached_bytes"] = str(size)
                    for label, column in (
                        ("created", "CreationTime"),
                        ("modified", "ModifiedTime"),
                        ("expires", "ExpiryTime"),
                    ):
                        when = filetime_to_utc(record.get(column))
                        if when:
                            details[label] = when.isoformat().replace("+00:00", "Z")

                    accessed = filetime_to_utc(record.get("AccessedTime"))
                    events.append(
                        Event(
                            timestamp=accessed or _FILETIME_EPOCH,
                            source_artifact="webcache",
                            event_type=event_type,
                            action=action,
                            source_file=relative_path,
                            # Container plus row index: the EntryId is unique
                            # only within a container, so both are needed
                            # (CD-004).
                            source_locator=f"Container_{container_id}/{index}",
                            timestamp_type="recorded" if accessed else "presence",
                            path=cleaned,
                            # The account from inside the record, never
                            # inferred from the file's location.
                            user=user,
                            details=details,
                        )
                    )

        yield from events


register(WebCacheParser)
