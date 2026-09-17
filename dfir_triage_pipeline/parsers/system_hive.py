"""The SYSTEM hive: Shimcache, BAM, and installed services.

Three artefacts, one hive, and each answers a question no currently parsed
family can (`docs/artifact-attestation-matrix.md`):

**Shimcache** (`AppCompatCache`) records that a binary was *present and seen by
the application-compatibility engine*. It survives when Prefetch does not --
Prefetch is disabled by default on Server and capped at 1024 entries -- so it is
often the last execution-adjacent evidence on a server. It is NOT proof of
execution: Windows 10 populates entries on enumeration as well as on run, which
is why the event type below is `program_shimcached` and not `process_exec`.

**BAM** (Background Activity Moderator) records the last time a binary ran,
**keyed by SID**. Prefetch carries no principal at all, so BAM is the artefact
that re-attributes an execution to a user after a 4688 is wiped.

**Services** records every installed service with its ImagePath, start type and
service type. The registry is authoritative where System 7045 is not: a service
installed before the log's retention window, or after a System-log clear,
exists here and nowhere else.

Two format notes, both established against the bytes in these collections
rather than from a specification, because D-023 is what happens otherwise (a
library read `runCount` at the wrong offset on all 835 Prefetch files).

* Shimcache uses the **`10ts` entry layout**, which Windows 10 and Windows 11
  share -- the format did not change at that boundary. What varies between
  builds is the HEADER OFFSET, so it is read from the blob's first four bytes
  rather than hardcoded. All five collections here are Windows 10 build 19045
  with an offset of 52; Windows 11 builds report 52 or 48 depending on build,
  and both are handled because neither is assumed.

  **No Windows 11 evidence was available to test against**, and that is stated
  rather than implied: the parser is written to the format and the format is
  shared, but the claim is untested on 11. `tests/test_system_hive.py` pins the
  offset-independence with a synthetic blob at a non-52 offset, which is the
  property that makes 11 work if the format holds.

  The signature is checked rather than assumed, and an unrecognised one yields
  no events rather than a guess. Pre-Windows-10 layouts (`00ts`, Win8's `00ts`
  variant, XP's flat array) carry different field offsets and are NOT parsed --
  guessing at one would fabricate paths rather than fail.
* BAM values are 24-byte blobs whose first 8 bytes are a FILETIME. The
  remaining 16 are not documented as stable and are not read.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..model import Event
from ..paths import derive as derive_path
from . import register

#: Shimcache entry signature for the Windows 10 AND 11 layout -- the format is
#: shared, and the header offset (read from the blob, not hardcoded) is what
#: differs between builds. Earlier layouts are not parsed: they carry different
#: field offsets, and guessing at one would fabricate paths rather than fail.
_MODERN_SIGNATURE = b"10ts"

#: FILETIME epoch offset in 100ns ticks.
_FILETIME_EPOCH = 116444736000000000

#: BAM stores a 24-byte blob per binary; only the leading FILETIME is read.
_BAM_BLOB_BYTES = 24


def filetime_to_utc(ticks: int) -> datetime | None:
    """FILETIME to aware UTC, or None when the value is not a real time.

    Zero and obviously out-of-range values appear in both artefacts and mean
    "not recorded" rather than 1601. Returning None lets the caller omit the
    event instead of emitting a timestamp the artefact never carried.
    """
    if ticks <= _FILETIME_EPOCH:
        return None
    seconds = (ticks - _FILETIME_EPOCH) / 10_000_000
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _current_control_set(hive: Any) -> int:
    """Which ControlSet is current, per `\\Select\\Current`.

    A hive collected from a live system can carry two or three control sets,
    and the others are stale. Reading ControlSet001 unconditionally would
    silently report a previous boot's configuration on any machine where the
    current set is not 1.
    """
    try:
        for value in hive.get_key("\\Select").get_values():
            if value.name == "Current":
                return int(value.value)
    except Exception:
        pass
    return 1


# --------------------------------------------------------------------------- #
# Shimcache
# --------------------------------------------------------------------------- #


def parse_shimcache(blob: bytes) -> list[tuple[str, datetime | None]]:
    """Decode a Windows 10/11 AppCompatCache blob into (path, last_modified).

    The header offset is READ FROM THE BLOB rather than hardcoded, which is what
    makes this work across builds: Windows 10 19045 uses 52, other builds use
    48, and a parser that assumed either would silently return nothing on the
    other.

    Returns an empty list for any blob whose signature is not recognised. A
    partially decoded cache is worse than none: the entries are variable-length
    and a wrong offset produces plausible-looking paths assembled from the
    middle of other records.
    """
    if len(blob) < 8:
        return []

    header_offset = struct.unpack_from("<I", blob, 0)[0]
    if header_offset >= len(blob) or blob[header_offset:header_offset + 4] != _MODERN_SIGNATURE:
        return []

    entries: list[tuple[str, datetime | None]] = []
    offset = header_offset
    while offset + 12 <= len(blob):
        if blob[offset:offset + 4] != _MODERN_SIGNATURE:
            break
        try:
            # signature(4) crc(4) entry_length(4) path_length(2) path ...
            entry_length = struct.unpack_from("<I", blob, offset + 8)[0]
            path_length = struct.unpack_from("<H", blob, offset + 12)[0]
            path_start = offset + 14
            path_end = path_start + path_length
            if path_end > len(blob) or path_length == 0:
                break
            path = blob[path_start:path_end].decode("utf-16-le", errors="replace")
            ticks = struct.unpack_from("<Q", blob, path_end)[0]
            entries.append((path, filetime_to_utc(ticks)))
            offset += 12 + entry_length
        except (struct.error, IndexError):
            break
    return entries


def _shimcache_events(hive: Any, control_set: int, relative_path: str) -> Iterator[Event]:
    key_path = f"\\ControlSet{control_set:03d}\\Control\\Session Manager\\AppCompatCache"
    try:
        key = hive.get_key(key_path)
    except Exception:
        return
    blob = next(
        (v.value for v in key.get_values() if v.name == "AppCompatCache"), None
    )
    if not isinstance(blob, bytes):
        return

    for index, (path, modified) in enumerate(parse_shimcache(blob)):
        details = {"shimcache_position": str(index)}
        if modified is not None:
            details["file_modified"] = modified.isoformat().replace("+00:00", "Z")
        details.update(derive_path(path))
        yield Event(
            # The key's last-write time, not the entry's. Shimcache records a
            # file's MODIFICATION time, which is a property of the file rather
            # than of when it was seen -- so the event carries presence, and
            # file_modified carries what the artefact actually said.
            timestamp=hive_last_write(key),
            source_artifact="shimcache",
            event_type="program_shimcached",
            action="binary recorded in the application compatibility cache",
            source_file=relative_path,
            # Position is the ONLY stable identifier: the cache holds no id, and
            # one path can appear once. Order is meaningful -- entry 0 is most
            # recently inserted -- so position is both unique and informative.
            source_locator=f"AppCompatCache[{index}]",
            timestamp_type="presence",
            path=path,
            details=details,
        )


def hive_last_write(key: Any) -> datetime:
    """A key's last-write time as aware UTC.

    regipy exposes this as a naive ISO string or a timestamp depending on
    version; both are normalised here rather than at four call sites.
    """
    raw = getattr(key, "header", None)
    ticks = getattr(raw, "last_modified", None) if raw is not None else None
    if isinstance(ticks, int):
        converted = filetime_to_utc(ticks)
        if converted is not None:
            return converted
    timestamp = getattr(key, "timestamp", None)
    if isinstance(timestamp, str):
        text = timestamp.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            pass
    if isinstance(timestamp, datetime):
        return timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)
    return datetime(1601, 1, 1, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# BAM
# --------------------------------------------------------------------------- #


def _bam_events(hive: Any, control_set: int, relative_path: str) -> Iterator[Event]:
    """Last-run time per binary, per SID.

    This is the only artefact in the pipeline that ties an execution to a
    principal without an event log. Prefetch records that a binary ran and
    carries no user at all.
    """
    for service in ("bam", "dam"):
        for suffix in ("State\\UserSettings", "UserSettings"):
            key_path = f"\\ControlSet{control_set:03d}\\Services\\{service}\\{suffix}"
            try:
                root = hive.get_key(key_path)
            except Exception:
                continue

            for sid_key in root.iter_subkeys():
                sid = sid_key.name
                for value in sid_key.get_values():
                    # Version and SequenceNumber are bookkeeping, not binaries.
                    if value.name in ("Version", "SequenceNumber"):
                        continue
                    blob = value.value
                    if not isinstance(blob, bytes) or len(blob) < 8:
                        continue
                    last_run = filetime_to_utc(struct.unpack_from("<Q", blob, 0)[0])
                    if last_run is None:
                        continue

                    path = value.name
                    details = {"sid": sid, "bam_service": service}
                    details.update(derive_path(path))
                    yield Event(
                        timestamp=last_run,
                        source_artifact="bam",
                        event_type="process_exec",
                        action="binary last run, per background activity moderator",
                        source_file=relative_path,
                        # SID plus path is unique within the hive: one SID
                        # records one entry per binary.
                        source_locator=f"{service}\\{sid}\\{path}",
                        # A real last-run time, unlike Shimcache's presence.
                        timestamp_type="last_run",
                        user=sid,
                        path=path,
                        details=details,
                    )
            break


# --------------------------------------------------------------------------- #
# Services
# --------------------------------------------------------------------------- #

#: Start types worth carrying. 0 boot, 1 system, 2 auto, 3 manual, 4 disabled.
_START_TYPES = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}

#: Service types. 0x10 own process, 0x20 shared, 0x1 kernel driver.
_SERVICE_TYPES = {1: "kernel_driver", 2: "fs_driver", 16: "own_process", 32: "shared_process"}


def _service_events(hive: Any, control_set: int, relative_path: str) -> Iterator[Event]:
    """Installed services, from the registry rather than from System 7045.

    The registry is authoritative where the log is not: a service installed
    before the log's retention window, or after a System-log clear, exists here
    and nowhere else.
    """
    try:
        services = hive.get_key(f"\\ControlSet{control_set:03d}\\Services")
    except Exception:
        return

    for service in services.iter_subkeys():
        values = {v.name: v.value for v in service.get_values()}
        image = values.get("ImagePath")
        if not isinstance(image, str) or not image.strip():
            # A key with no ImagePath is a driver stub or a configuration
            # container, not an installed service with an executable.
            continue

        start = values.get("Start")
        details = {
            "service_name": service.name,
            "image_path": image,
        }
        if isinstance(start, int):
            details["start_type"] = _START_TYPES.get(start, str(start))
        service_type = values.get("Type")
        if isinstance(service_type, int):
            details["service_type"] = _SERVICE_TYPES.get(service_type, str(service_type))
        account = values.get("ObjectName")
        if isinstance(account, str) and account.strip():
            details["account"] = account

        # CD-021: an ImagePath is frequently a command line, and derive_path
        # declines those by design rather than joining two unrelated records.
        details.update(derive_path(image))

        yield Event(
            timestamp=hive_last_write(service),
            source_artifact="services",
            event_type="service_registered",
            action="service present in the registry",
            source_file=relative_path,
            source_locator=f"Services\\{service.name}",
            # The key's last write is shared by every value under it, exactly as
            # D-027 records for Run keys. It says when the service entry was
            # last touched, not when the service was installed.
            timestamp_type="presence",
            user=account if isinstance(account, str) and account.strip() else None,
            path=image,
            details=details,
        )


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def _records(abs_path: Path, relative_path: str) -> Iterator[Event]:
    from regipy.registry import RegistryHive

    hive = RegistryHive(str(abs_path))
    control_set = _current_control_set(hive)
    yield from _shimcache_events(hive, control_set, relative_path)
    yield from _bam_events(hive, control_set, relative_path)
    yield from _service_events(hive, control_set, relative_path)


class SystemHiveParser:
    name = "system_hive"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        if lowered.endswith((".log", ".log1", ".log2")):
            # Transaction logs share the basename and hold no committed values.
            return False
        return lowered.endswith("/system") and "/config/" in f"/{lowered}"

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        yield from _records(abs_path, relative_path)


register(SystemHiveParser)
