"""The SECURITY and DEFAULT hives: privilege holders and the system profile.

Two hives KAPE collects that nothing else in this pipeline reads.

**SECURITY** holds the Local Security Authority's policy database. One subtree
is both readable without decryption and forensically meaningful:

    \\Policy\\Accounts   one subkey per SID that has been GRANTED A PRIVILEGE

Measured on `s1_v3`: 13 SIDs, including `S-1-5-32-544` (Administrators),
`S-1-5-80-*` (service accounts) and the built-in Guest. An account appearing
here has been given a right beyond its group membership -- which is how
`SeDebugPrivilege` or `SeBackupPrivilege` is handed to something that should
not have it, and it leaves no event when the Security log has been cleared.

**DEFAULT** is the NTUSER hive of the SYSTEM profile: the per-user settings
that apply to services and to a brand-new account. A Run value here executes
**as SYSTEM at boot**, which is a stronger persistence than a per-user Run key,
and `parsers/registry.py` does not reach it -- that parser's NTUSER paths are
matched under `Users\\`, and this hive lives in `System32\\config`.

**What is deliberately NOT read.** `\\Policy\\Secrets` holds LSA secrets --
service account passwords and cached credentials -- encrypted under the boot
key. `PolEKList` is that boot key material. Neither is touched, for the same
reason `sam_hive.py` does not read the `V` value: a triage pipeline that
extracted credential material would be a different tool with different handling
requirements.

**The privilege NAMES are not decoded.** Each `\\Policy\\Accounts\\<SID>` key
carries a binary `Privilgs` value listing LUIDs, and mapping a LUID to
`SeDebugPrivilege` needs a table that varies by Windows version. Inventing that
mapping is how D-023 and D-045 happened, so the event records THAT a SID holds
privileges and leaves naming them to an analyst.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..model import Event
from . import register

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

_ACCOUNTS = r"\Policy\Accounts"

#: Run keys in the SYSTEM profile's hive. Same locations registry.py reads in a
#: user's NTUSER.DAT, but this hive is not under `Users\` so that parser's
#: matching never reaches it.
_DEFAULT_RUN_KEYS = (
    r"\Software\Microsoft\Windows\CurrentVersion\Run",
    r"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
)

#: Well-known SIDs, named so a finding is readable without a lookup. Only the
#: unambiguous ones; a domain SID is left as recorded.
_WELL_KNOWN = {
    "S-1-1-0": "Everyone",
    "S-1-5-6": "Service",
    "S-1-5-19": "Local Service",
    "S-1-5-20": "Network Service",
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-545": "Users",
    "S-1-5-32-551": "Backup Operators",
    "S-1-5-32-555": "Remote Desktop Users",
    "S-1-5-32-559": "Performance Log Users",
    "S-1-5-80-0": "All Services",
    "S-1-5-90-0": "Window Manager Group",
}


def filetime_to_utc(ticks: Any) -> datetime | None:
    if not isinstance(ticks, int) or isinstance(ticks, bool) or ticks <= 0:
        return None
    try:
        converted = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except (OverflowError, ValueError):
        return None
    return converted if converted.year > 1601 else None


def _key(hive: Any, path: str) -> Any:
    try:
        return hive.get_key(path)
    except Exception:
        return None


def _key_timestamp(key: Any) -> datetime:
    raw = getattr(key, "header", None)
    ticks = getattr(raw, "last_modified", None) if raw is not None else None
    converted = filetime_to_utc(ticks) if isinstance(ticks, int) else None
    return converted or _FILETIME_EPOCH


def hive_kind(relative_path: str) -> str | None:
    """`security`, `default`, or None when this is neither."""
    lowered = relative_path.replace("\\", "/").lower()
    if lowered.endswith((".log", ".log1", ".log2", ".regtrans-ms")):
        return None
    if "/system32/config/" not in f"/{lowered}":
        return None
    name = lowered.rsplit("/", 1)[-1]
    return name if name in ("security", "default") else None


def _privilege_events(hive: Any, relative_path: str) -> Iterator[Event]:
    accounts = _key(hive, _ACCOUNTS)
    if accounts is None:
        return

    for sub in accounts.iter_subkeys():
        sid = sub.name
        if not sid.upper().startswith("S-1-"):
            continue
        details = {"sid": sid}
        friendly = _WELL_KNOWN.get(sid.upper())
        if friendly:
            details["well_known"] = friendly
        # The privilege LUIDs are present but not decoded -- see the module
        # docstring. Recording how many were granted is honest and useful; a
        # name would be invented.
        values = [v for v in sub.get_values() if v.name and v.name != "(default)"]
        if values:
            details["privilege_values"] = ",".join(sorted(v.name for v in values))

        yield Event(
            timestamp=_key_timestamp(sub),
            source_artifact="lsa_policy",
            event_type="privilege_granted",
            action="SID holds an LSA privilege assignment",
            source_file=relative_path,
            source_locator=f"Policy\\Accounts\\{sid}",
            # The key's last write. It says the assignment EXISTS, not when it
            # was made -- D-027's limit, shared by every registry family here.
            timestamp_type="presence",
            path=None,
            user=sid,
            details=details,
        )


def _default_profile_events(hive: Any, relative_path: str) -> Iterator[Event]:
    for key_path in _DEFAULT_RUN_KEYS:
        key = _key(hive, key_path)
        if key is None:
            continue
        values = [v for v in key.get_values() if v.name and v.name != "(default)"]
        if not values:
            continue
        timestamp = _key_timestamp(key)

        for value in values:
            data = value.value
            if not isinstance(data, str) or not data.strip():
                continue
            yield Event(
                timestamp=timestamp,
                source_artifact="registry",
                # Shared with parsers/registry.py deliberately: this IS an
                # autorun, and a second spelling would break any chain joined
                # on event_type.
                event_type="persistence_autorun",
                action="autorun value in the SYSTEM profile hive",
                source_file=relative_path,
                source_locator=f"{key_path.lstrip(chr(92))}\\{value.name}",
                timestamp_type="presence",
                path=data.strip(),
                user=None,
                details={
                    "value_name": value.name,
                    "value_count_in_key": str(len(values)),
                    "hive_type": "default",
                    # The distinction that makes this worth parsing separately.
                    "runs_as": "SYSTEM",
                },
            )


class SecurityHiveParser:
    name = "security_hive"

    def can_handle(self, relative_path: str) -> bool:
        return hive_kind(relative_path) is not None

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        from regipy.registry import RegistryHive

        kind = hive_kind(relative_path)
        hive = RegistryHive(str(abs_path))

        if kind == "security":
            yield from _privilege_events(hive, relative_path)
        elif kind == "default":
            yield from _default_profile_events(hive, relative_path)


register(SecurityHiveParser)
