"""The SAM hive: local accounts, independent of the Security event log.

`docs/artifact-attestation-matrix.md` names this as the corroborator for two
claims the Security log cannot support once it has been cleared:

* **An account EXISTS.** A 4720 records a creation event; SAM records the
  account itself. An account present in SAM with no 4720 in the log was created
  before the log's retention window, before auditing was enabled, or after a
  clear -- and only SAM says it is there at all.
* **An account was USED.** The `F` value carries a last-logon FILETIME and a
  logon count maintained by the SAM itself. A non-zero count with no 4624 in
  the log is authentication the log no longer holds.

Neither is a log, so `wevtutil cl security` leaves both intact.

**The `F` value layout**, established against the bytes in these collections
rather than from a specification (D-023 is what happens otherwise):

    offset  8  FILETIME  last logon
    offset 24  FILETIME  password last set
    offset 32  FILETIME  account expires
    offset 40  FILETIME  password last failed
    offset 48  DWORD     RID
    offset 56  WORD      account control flags
    offset 66  WORD      logon count

Every field is bounds-checked and a short blob yields no event: a partially
decoded account record would carry plausible times read from the wrong offsets.

**What this parser does NOT do:** it reads no password hash and decrypts
nothing. The `V` value holds the NT hash and `SupplementalCredentials` holds
more; neither is touched. The artefact is read for account metadata only, and a
triage pipeline that extracted credential material would be a different tool
with different handling requirements.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

_FILETIME_EPOCH = 116444736000000000

#: `F` is a fixed 80-byte structure. Anything shorter is truncated or is not
#: an F value, and is skipped rather than decoded from what is there.
_F_MINIMUM_BYTES = 80

#: Account control flags, from the WORD at offset 56. Only the ones that change
#: what an account IS are decoded; the rest are password-policy detail.
_ACCOUNT_FLAGS = {
    0x0001: "disabled",
    0x0002: "home_directory_required",
    0x0004: "password_not_required",
    0x0008: "temporary_duplicate",
    0x0010: "normal_account",
    0x0080: "workstation_trust",
    0x0100: "server_trust",
    0x0200: "password_never_expires",
    0x0400: "account_auto_locked",
}

#: Well-known RIDs. Named rather than suppressed: a rule may want to know that
#: an account is built-in, and hiding them would remove evidence.
_WELL_KNOWN_RIDS = {
    500: "administrator",
    501: "guest",
    503: "default_account",
    504: "wdag_utility",
}


def filetime_to_utc(ticks: int) -> datetime | None:
    """FILETIME to aware UTC, or None when the value is not a real time.

    SAM writes zero for "never" -- never logged on, password never set -- and
    that is information rather than a timestamp. Returning None lets the caller
    record the absence instead of placing an event in 1601.
    """
    if ticks <= _FILETIME_EPOCH:
        return None
    try:
        return datetime.fromtimestamp((ticks - _FILETIME_EPOCH) / 10_000_000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def parse_f_value(blob: bytes) -> dict[str, Any]:
    """Decode the SAM `F` value into account metadata.

    Returns {} for any blob shorter than the fixed structure. A partial decode
    would emit plausible FILETIMEs read from the wrong offsets, which is worse
    than no account record at all.
    """
    if not isinstance(blob, bytes) or len(blob) < _F_MINIMUM_BYTES:
        return {}

    try:
        last_logon = struct.unpack_from("<Q", blob, 8)[0]
        password_set = struct.unpack_from("<Q", blob, 24)[0]
        password_failed = struct.unpack_from("<Q", blob, 40)[0]
        rid = struct.unpack_from("<I", blob, 48)[0]
        flags = struct.unpack_from("<H", blob, 56)[0]
        logon_count = struct.unpack_from("<H", blob, 66)[0]
    except struct.error:
        return {}

    return {
        "rid": rid,
        "last_logon": filetime_to_utc(last_logon),
        "password_last_set": filetime_to_utc(password_set),
        "password_last_failed": filetime_to_utc(password_failed),
        "flags": flags,
        "logon_count": logon_count,
    }


def _names_to_rid(hive: Any) -> dict[int, str]:
    """RID -> account name, from the `Names` subkey.

    An unusual layout worth stating: each account is a SUBKEY named after the
    account, and its default value's TYPE field holds the RID. The value's data
    is unrelated bytes. Reading the data would resolve no account at all.

    regipy hands the type back as a DECIMAL STRING, because the RID is not one
    of the REG_* constants it knows how to name, so it falls back to `str()`.
    An `isinstance(rid, int)` check silently mapped nothing and every account
    came out as `RID-1000` -- true, but useless to a rule that wants a name.
    Both forms are accepted here: which one arrives is a library detail.
    """
    mapping: dict[int, str] = {}
    try:
        names = hive.get_key("\\SAM\\Domains\\Account\\Users\\Names")
    except Exception:
        return mapping

    for key in names.iter_subkeys():
        for value in key.get_values():
            rid = _coerce_rid(getattr(value, "value_type", None))
            if rid:
                mapping[rid] = key.name
            break
    return mapping


def _coerce_rid(raw: Any) -> int | None:
    """The RID as an int, whether it arrives as one or as its decimal text."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw or None
    if isinstance(raw, str):
        text = raw.strip()
        if text.isdigit():
            return int(text) or None
    return None


def _hive_last_write(key: Any) -> datetime:
    raw = getattr(key, "header", None)
    ticks = getattr(raw, "last_modified", None) if raw is not None else None
    if isinstance(ticks, int):
        converted = filetime_to_utc(ticks)
        if converted is not None:
            return converted
    timestamp = getattr(key, "timestamp", None)
    if isinstance(timestamp, str):
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    if isinstance(timestamp, datetime):
        return timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)
    return datetime(1601, 1, 1, tzinfo=UTC)


def _account_events(hive: Any, relative_path: str) -> Iterator[Event]:
    try:
        users = hive.get_key("\\SAM\\Domains\\Account\\Users")
    except Exception:
        return

    names = _names_to_rid(hive)

    for key in users.iter_subkeys():
        if key.name == "Names":
            continue
        blob = next((v.value for v in key.get_values() if v.name == "F"), None)
        record = parse_f_value(blob)
        if not record:
            continue

        rid = record["rid"]
        account = names.get(rid) or f"RID-{rid}"
        flags = record["flags"]

        details: dict[str, str] = {
            "rid": str(rid),
            "logon_count": str(record["logon_count"]),
        }
        decoded = [name for bit, name in _ACCOUNT_FLAGS.items() if flags & bit]
        if decoded:
            details["account_flags"] = ",".join(sorted(decoded))
        if rid in _WELL_KNOWN_RIDS:
            details["well_known"] = _WELL_KNOWN_RIDS[rid]

        # Times are recorded as details rather than as the event timestamp,
        # because one account carries several and the event is the account's
        # EXISTENCE. `never` is written explicitly: SAM's zero means the thing
        # never happened, which a missing key could not distinguish from a
        # field this parser failed to read.
        for field in ("last_logon", "password_last_set", "password_last_failed"):
            value = record[field]
            details[field] = (
                value.isoformat().replace("+00:00", "Z") if value else "never"
            )

        # WHICH time this event carries, and the honest label for it.
        #
        # Measured across all five collections: the user key's last-write time
        # is EXACTLY the last-logon FILETIME on every account with a non-zero
        # logon count, because Windows rewrites the key on each logon. So the
        # key write is not independent corroboration -- it is the same fact
        # arriving twice, and an event timestamped by it whilst labelled
        # `presence` would understate what the artefact actually knows.
        #
        # An account that has never logged on has no such time. There the key
        # write is genuinely all SAM offers, and `presence` is then correct.
        # `last_run` rather than a new `last_logon` term. CD-019 defines the
        # vocabulary by SHAPE -- "the artifact records only the most recent
        # occurrence" -- and SAM's single overwritten slot behind a count of 13
        # is precisely that shape. A separate term would split one concept in
        # two and break every rule that reasons over recency.
        last_logon = record["last_logon"]
        if last_logon is not None:
            timestamp, timestamp_type = last_logon, "last_run"
            action = "local account last logged on"
        else:
            timestamp, timestamp_type = _hive_last_write(key), "presence"
            action = "local account present in the SAM, never logged on"

        yield Event(
            timestamp=timestamp,
            source_artifact="sam",
            event_type="local_account",
            action=action,
            source_file=relative_path,
            # RID is unique within the hive and stable across renames, which a
            # name is not.
            source_locator=f"Users\\{key.name}",
            timestamp_type=timestamp_type,
            user=account,
            details=details,
        )


class SamHiveParser:
    name = "sam_hive"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        if lowered.endswith((".log", ".log1", ".log2")):
            return False
        return lowered.endswith("/sam") and "/config/" in f"/{lowered}"

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        from regipy.registry import RegistryHive

        yield from _account_events(RegistryHive(str(abs_path)), relative_path)


register(SamHiveParser)
