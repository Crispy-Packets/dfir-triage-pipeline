from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ..model import Event
from ..paths import derive as derive_path
from . import register

# Autorun locations. Machine-wide keys live in SOFTWARE and run for every user;
# the per-user keys live in each profile's NTUSER.DAT and run only for that
# profile's owner. Both are collected by KapeTriage, and the distinction is
# recorded in details["hive_type"] because it changes who the persistence
# affects, not merely where it was found.
SOFTWARE_KEYS = (
    r"\Microsoft\Windows\CurrentVersion\Run",
    r"\Microsoft\Windows\CurrentVersion\RunOnce",
)
NTUSER_KEYS = (
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
)

def filetime_to_utc(value: int) -> datetime:
    """Convert a Windows FILETIME to a timezone-aware UTC datetime.

    regipy returns the key's last-write time as a raw FILETIME integer:
    100-nanosecond intervals since 1601-01-01 UTC. The value is UTC by
    definition, so it is constructed as UTC rather than converted -- the same
    rule the Prefetch parser follows for run times (D-013, CD-006).

    Converted with integer arithmetic, not float seconds. A FILETIME in 2026 is
    around 1.34e17; dividing it by 1e7 exhausts double precision and loses the
    last microsecond -- the known key at 134317496479762600 comes back as
    ...976259 instead of ...976260. One microsecond is immaterial to a rule but
    not to a provenance check, which compares a timeline row against a value
    read independently from the hive.
    """
    micros = (value - 116444736000000000) // 10
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=micros)


def _hive_type(relative_path: str) -> str | None:
    """Which of the two hive families this file is, or None if neither."""
    name = relative_path.rsplit("/", 1)[-1].lower()
    if name == "software":
        return "software"
    if name == "ntuser.dat":
        return "ntuser"
    return None


def _profile_owner(relative_path: str) -> str | None:
    """Profile directory name for an NTUSER hive, used as Event.user.

    C/Users/<name>/NTUSER.DAT               -> <name>
    C/Windows/ServiceProfiles/<n>/NTUSER.DAT -> <n>

    The owner is who the autorun runs *as*. It is deliberately not derived from
    the value data: in collection_s1_v2 the SecurityUpdate value sits in
    admin_local's hive while pointing at a binary under janed's profile, so
    conflating the two would misattribute the persistence.
    """
    parts = relative_path.split("/")
    if len(parts) < 2:
        return None
    return parts[-2] or None


def _records(abs_path: Path, relative_path: str) -> Iterator[dict]:
    """Yield one normalised dict per autorun value. The only regipy-coupled code.

    A hive with no autorun key yields nothing and does not raise: a profile that
    has never had a Run entry is an absence of evidence, not a read failure. A
    hive that cannot be opened at all does raise, and is counted by the runner.
    """
    from regipy.registry import RegistryHive

    hive_type = _hive_type(relative_path)
    if hive_type is None:
        return

    hive = RegistryHive(str(abs_path))
    key_paths = SOFTWARE_KEYS if hive_type == "software" else NTUSER_KEYS
    owner = _profile_owner(relative_path) if hive_type == "ntuser" else None

    for key_path in key_paths:
        try:
            key = hive.get_key(key_path)
        except Exception:
            continue  # key absent from this hive: nothing was ever registered

        values = list(key.get_values())
        if not values:
            continue

        last_write = filetime_to_utc(key.header.last_modified)
        for value in values:
            data = value.value
            if data is None or not isinstance(data, str) or not data.strip():
                continue  # a name with no command registers no autorun
            yield {
                "hive_type": hive_type,
                "hive": relative_path,
                "key_path": key_path,
                "value_name": value.name or "",
                "value_data": data,
                "key_last_write": last_write,
                "value_count_in_key": len(values),
                "owner": owner,
            }


def record_to_event(record: dict) -> Event:
    """Pure transform: dict in, Event out. No filesystem, no regipy type."""
    details = {
        "hive": record["hive"],
        "hive_type": record["hive_type"],
        "key_path": record["key_path"],
        "value_name": record["value_name"],
        "value_data": record["value_data"],
        "key_last_write": record["key_last_write"].isoformat().replace("+00:00", "Z"),
        "value_count_in_key": str(record["value_count_in_key"]),
    }

    # B-9. Most autorun values are command lines rather than paths, and derive()
    # returns nothing for those by design -- a canonical form built from a
    # command line would join two unrelated records (CD-021, D-032).
    details.update(derive_path(record["value_data"]))
    return Event(
        timestamp=record["key_last_write"],
        source_artifact="registry",
        event_type="persistence_autorun",       # CD-007
        action="autorun entry present",
        source_file=record["hive"],             # CD-003, collection-relative
        # Unique within the hive: one value name cannot repeat under one key,
        # and the key path disambiguates Run from RunOnce (CD-004).
        source_locator=f"{record['key_path']}\\{record['value_name']}",
        # The key's last-write time is the only time the artifact offers, and it
        # belongs to the key: every value under it shares this timestamp, and it
        # is not when this value was written. "presence" is CD-019's third value
        # for exactly this -- the entry exists now; when it appeared is unknown.
        timestamp_type="presence",
        host=None,
        user=record["owner"],
        path=record["value_data"],              # CD-010, verbatim, unexpanded
        confidence="high",                      # presence is certain
        details=details,
    )


@register
class RegistryParser:
    name = "registry"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        if _hive_type(lowered) is None:
            return False
        # Transaction logs carry the same basename plus a suffix and are not
        # hives; regipy cannot parse them and they hold no committed values.
        if lowered.endswith((".log", ".log1", ".log2")):
            return False
        if _hive_type(lowered) == "software":
            return "/windows/system32/config/" in f"/{lowered}"
        return True

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        for record in _records(abs_path, relative_path):
            yield record_to_event(record)
