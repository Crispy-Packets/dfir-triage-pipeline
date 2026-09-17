"""SRUM: per-application network bytes and resource usage.

`SRUDB.dat` is the System Resource Usage Monitor's ESE database. It is the only
artefact in this pipeline that attests to **how much data an application moved**
-- Prefetch says a binary ran, BAM says which SID ran it, and neither says a
program sent 90 MB anywhere. For an exfiltration question that is the record.

**Two providers are read**, both keyed by an application and a user:

    {973F5D5C-...}  Network Data Usage      BytesSent / BytesRecvd
    {D10CA2FE-...}  Application Resource    CPU cycles, bytes read/written

The other providers are energy estimation, push notifications and connectivity
timelines; they describe the machine's power and radio state rather than what a
program did, and are not read.

**Three things here were established by reading the bytes, and all three would
have produced confident wrong output if taken from a format description.**

1. **`IdType=3` is the SID.** The application identity is `IdType` 0, 1 or 2 --
   three different forms, all of them applications (a device path, a service
   name, an AppX package identity). A parser that assumed the common numbering
   attributes every row to the wrong party.

2. **`TimeStamp` is an OLE automation date whose float64 bits arrive as an
   int.** `dissect` declares the column `JET_coltyp.DateTime` and hands back
   `4676592689485971456`. That is not a scale factor away from a real time: the
   BITS must be reinterpreted as a float64 (46274.1875 days since 1899-12-30 =
   2026-09-09T04:30Z). Treating it as ticks puts the event ~148 million years
   out, and nothing raises.

3. **`AppId=1` resolves under no IdType at all.** It is SRUM's sentinel for
   unattributed traffic, 31 of 334 rows on `s1_v3`. Those rows are emitted with
   the application named as unattributed rather than dropped -- the bytes were
   still moved -- and rather than invented, which is what a `f"<id {n}>"`
   fallback would amount to.

**What SRUM did NOT record here, measured.** `invoice_scan.exe` appears nowhere
in `s1_v3`: not in the id map, not in either provider. The reason is in the
data rather than in the artefact's design -- SRUM's last flush on that host was
**11:48:00** and the payload ran at **11:50:09**, so there are zero rows at or
after the execution for ANY program. The horizon is a measurable boundary, and
`docs/evidence/srum-parser-2026-09-17.md` records it. This is the D-028 shape:
an artefact that could have corroborated, and on this evidence did not.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

#: OLE automation dates count days from this epoch.
_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=UTC)

#: Anything outside this band is a decode failure rather than a timestamp. SRUM
#: cannot hold an entry from before Windows shipped, and one from the far future
#: means the float64 reinterpretation did not apply to that value.
_EARLIEST = datetime(1995, 1, 1, tzinfo=UTC)
_LATEST = datetime(2100, 1, 1, tzinfo=UTC)

NETWORK_TABLE = "{973F5D5C-1D90-4944-BE8E-24B94231A174}"
RESOURCE_TABLE = "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}"

#: IdType 3 holds a binary SID; every other type holds an application identity.
_SID_ID_TYPE = 3

#: SRUM's own sentinel for traffic it could not attribute. It is not in the id
#: map under any type, so it is named rather than left as a bare integer.
_UNATTRIBUTED_APP_ID = 1
_UNATTRIBUTED = "<unattributed>"


def ole_timestamp(raw: Any) -> datetime | None:
    """An ESE DateTime column to aware UTC, or None when it is not a time.

    The value arrives as the raw 8 bytes of a float64 presented as an int, so
    the bits are reinterpreted rather than scaled. See the module docstring.
    """
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if not isinstance(raw, int) or isinstance(raw, bool):
        return None
    try:
        days = struct.unpack("<d", struct.pack("<Q", raw))[0]
    except (struct.error, OverflowError):
        return None
    if days != days or days in (float("inf"), float("-inf")):  # NaN / infinity
        return None
    try:
        converted = _OLE_EPOCH + timedelta(days=days)
    except (OverflowError, ValueError):
        return None
    return converted if _EARLIEST <= converted <= _LATEST else None


def decode_sid(blob: bytes | None) -> str | None:
    """A binary SID to its S-1-... text form, or None when it is not one."""
    if not isinstance(blob, bytes) or len(blob) < 8:
        return None
    revision = blob[0]
    sub_count = blob[1]
    if revision != 1 or sub_count > 15 or len(blob) < 8 + 4 * sub_count:
        return None
    authority = int.from_bytes(blob[2:8], "big")
    subs = struct.unpack_from(f"<{sub_count}I", blob, 8)
    return "-".join(["S", str(revision), str(authority), *(str(s) for s in subs)])


def decode_app(blob: bytes | None) -> str | None:
    """An application identity blob to text.

    Three shapes share this column -- a device path, a bare service name, and an
    AppX package identity -- and all three are UTF-16LE. They are returned as
    recorded (CD-010) rather than normalised into a common form, because which
    shape SRUM used is itself information about how the program was launched.
    """
    if not isinstance(blob, bytes) or not blob:
        return None
    text = blob.decode("utf-16-le", errors="replace").rstrip("\x00").strip()
    return text or None


def _build_id_map(db: Any) -> tuple[dict[int, str], dict[int, str]]:
    """(applications, sids), both keyed by the integer index rows reference."""
    applications: dict[int, str] = {}
    sids: dict[int, str] = {}

    try:
        table = db.table("SruDbIdMapTable")
    except Exception:
        return applications, sids

    for record in table.records():
        blob = record.get("IdBlob")
        index = record.get("IdIndex")
        if blob is None or not isinstance(index, int):
            # A null blob is a real row in this table; it carries no identity
            # and there is nothing to map.
            continue
        if record.get("IdType") == _SID_ID_TYPE:
            sid = decode_sid(blob)
            if sid:
                sids[index] = sid
        else:
            name = decode_app(blob)
            if name:
                applications[index] = name

    return applications, sids


def _resolve_app(app_id: Any, applications: dict[int, str]) -> str | None:
    """The application name, or the sentinel, or None when unknown.

    A bare integer is never returned as a name: an unresolvable id is an
    absence, and `f"<id 37>"` would put a fabricated identifier into a field a
    rule may join on.
    """
    if not isinstance(app_id, int):
        return None
    if app_id in applications:
        return applications[app_id]
    return _UNATTRIBUTED if app_id == _UNATTRIBUTED_APP_ID else None


def _network_events(
    db: Any, relative_path: str, applications: dict[int, str], sids: dict[int, str]
) -> Iterator[Event]:
    try:
        table = db.table(NETWORK_TABLE)
    except Exception:
        return

    for record in table.records():
        timestamp = ole_timestamp(record.get("TimeStamp"))
        if timestamp is None:
            continue
        application = _resolve_app(record.get("AppId"), applications)
        if application is None:
            continue

        sent = record.get("BytesSent") or 0
        received = record.get("BytesRecvd") or 0
        if not sent and not received:
            # A row recording no traffic asserts nothing about the network.
            continue

        row_id = record.get("AutoIncId")
        yield Event(
            timestamp=timestamp,
            source_artifact="srum",
            event_type="network_usage",
            action="application transferred data over the network",
            source_file=relative_path,
            # AutoIncId is the table's own primary key and is unique within it.
            source_locator=f"network/{row_id}",
            # SRUM writes a row per application per hour-ish interval, stamped
            # when the provider flushed. It is a recorded observation of that
            # interval, not a presence claim about the program.
            timestamp_type="recorded",
            path=application,
            user=sids.get(record.get("UserId")),
            details={
                "bytes_sent": str(sent),
                "bytes_received": str(received),
                "srum_provider": "network_data_usage",
            },
        )


def _resource_events(
    db: Any, relative_path: str, applications: dict[int, str], sids: dict[int, str]
) -> Iterator[Event]:
    try:
        table = db.table(RESOURCE_TABLE)
    except Exception:
        return

    for record in table.records():
        timestamp = ole_timestamp(record.get("TimeStamp"))
        if timestamp is None:
            continue
        application = _resolve_app(record.get("AppId"), applications)
        if application is None:
            continue

        bytes_read = (record.get("ForegroundBytesRead") or 0) + (
            record.get("BackgroundBytesRead") or 0
        )
        bytes_written = (record.get("ForegroundBytesWritten") or 0) + (
            record.get("BackgroundBytesWritten") or 0
        )
        cycles = (record.get("ForegroundCycleTime") or 0) + (
            record.get("BackgroundCycleTime") or 0
        )

        row_id = record.get("AutoIncId")
        yield Event(
            timestamp=timestamp,
            source_artifact="srum",
            event_type="resource_usage",
            action="application consumed CPU and disk",
            source_file=relative_path,
            source_locator=f"resource/{row_id}",
            timestamp_type="recorded",
            path=application,
            user=sids.get(record.get("UserId")),
            details={
                "bytes_read": str(bytes_read),
                "bytes_written": str(bytes_written),
                "cpu_cycles": str(cycles),
                "srum_provider": "application_resource_usage",
            },
        )


class SrumParser:
    name = "srum"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower().replace("\\", "/")
        return lowered.endswith("/sru/srudb.dat")

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        from dissect.esedb import EseDB

        # The file handle must outlive the generator, so the whole parse runs
        # inside the with-block rather than returning a lazy iterator over a
        # closed file.
        with abs_path.open("rb") as handle:
            db = EseDB(handle)
            applications, sids = _build_id_map(db)
            yield from _network_events(db, relative_path, applications, sids)
            yield from _resource_events(db, relative_path, applications, sids)


register(SrumParser)
