from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from evtx import PyEvtxParser

from ..model import Event
from . import register

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# CD-007. event_type strings are shared with the Prefetch parser by contract.
SECURITY_EIDS: dict[int, tuple[str, str]] = {
    4624: ("logon", "successful logon"),
    4625: ("logon_failed", "failed logon"),
    4688: ("process_exec", "process created"),
    4720: ("account_created", "user account created"),
    1102: ("log_cleared", "security event log cleared"),
}
SYSTEM_EIDS: dict[int, tuple[str, str]] = {
    7045: ("service_install", "service installed"),
}
# Script-block logging. 4104 is the only EID taken from this channel: 4103 is
# pipeline execution detail and 40961/40962/53504 are engine lifecycle, none of
# which carry the script text a rule needs.
POWERSHELL_EIDS: dict[int, tuple[str, str]] = {
    4104: ("script_block", "powershell script block logged"),
}


def _records(abs_path: Path) -> Iterator[str]:
    for record in PyEvtxParser(str(abs_path)).records():
        xml_text = record.get("data") if isinstance(record, dict) else None
        if xml_text:
            yield xml_text


def parse_systemtime(value: str) -> datetime:
    # CD-006. Truncate 100ns fraction; convert aware offsets with astimezone(UTC).
    text = value
    if "." in text:
        head, rest = text.split(".", 1)
        frac = ""
        suffix = ""
        for ch in rest:
            if ch.isdigit() and not suffix:
                frac += ch
            else:
                suffix += ch
        text = f"{head}.{frac[:6]}{suffix}"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _event_data(root: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in root.findall("e:EventData/e:Data", NS):
        name = node.get("Name")
        if name:
            out[name] = node.text or ""
    return out


def _user_data(root: ET.Element) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in root.iter():
        if node.tag.endswith("}LogFileCleared"):
            for child in node:
                tag = child.tag.split("}")[-1]
                out[tag] = child.text or ""
    return out


def _user_for(eid: int, data: dict[str, str]) -> str | None:
    if eid in (4624, 4625, 4720):
        return data.get("TargetUserName") or None
    if eid == 4688:
        return data.get("SubjectUserName") or None
    if eid == 1102:
        return data.get("SubjectUserName") or None
    if eid == 7045:
        return data.get("AccountName") or None
    return None


def _path_for(eid: int, data: dict[str, str]) -> str | None:
    if eid == 4688:
        return data.get("NewProcessName") or None
    if eid == 7045:
        return data.get("ImagePath") or None
    return None


def _details_for(eid: int, data: dict[str, str]) -> dict[str, str]:
    keep: tuple[str, ...]
    if eid in (4624, 4625):
        keep = ("LogonType", "IpAddress", "WorkstationName", "LogonProcessName", "SubStatus")
    elif eid == 4688:
        keep = ("CommandLine", "ParentProcessName", "NewProcessId", "SubjectDomainName")
    elif eid == 4720:
        # TargetUserName is the account that was CREATED; SubjectUserName is the
        # account that created it. Keeping only the subject was a defect: it
        # left every account-creation row naming the operator and never the new
        # account, so a base rate could be counted but its members could not be
        # told apart. Distinguishing four standing lab accounts from one staged
        # testuser is exactly what A-4 needs. See D-029.
        keep = ("TargetUserName", "TargetDomainName", "SubjectUserName", "SubjectDomainName")
    elif eid == 1102:
        keep = ("SubjectUserName", "SubjectDomainName", "SubjectLogonId")
    elif eid == 7045:
        keep = ("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName")
    elif eid == 4104:
        # ScriptBlockText is deliberately NOT kept: a single block can run to
        # tens of kilobytes, details is carried in every timeline row, and the
        # text is recoverable from the source record via source_locator. The
        # fragment identifiers are kept because without them a consumer cannot
        # tell a whole script from one third of one.
        keep = ("ScriptBlockId", "MessageNumber", "MessageTotal", "Path")
    else:
        keep = ()
    return {k: data[k] for k in keep if k in data and data[k] != ""}


# Channel filename -> source_artifact. The PowerShell operational channel is
# written by the OS as "Microsoft-Windows-PowerShell%4Operational.evtx": %4 is
# an escaped forward slash from the channel name "Microsoft-Windows-PowerShell/
# Operational". Matching on the escaped literal is what the collected filename
# actually is.
#
# The other two PowerShell logs are excluded deliberately. "Windows
# PowerShell.evtx" is the legacy classic log and carries no script blocks, and
# the Admin channel carries only engine errors.
_CHANNELS: tuple[tuple[str, str], ...] = (
    ("/security.evtx", "evtx.security"),
    ("/system.evtx", "evtx.system"),
    ("/microsoft-windows-powershell%4operational.evtx", "evtx.powershell"),
)


def _artifact_for(lowered_path: str) -> str | None:
    for suffix, artifact in _CHANNELS:
        if lowered_path.endswith(suffix):
            return artifact
    return None


def record_to_event(xml_text: str, artifact: str, relative_path: str) -> Event | None:
    root = ET.fromstring(xml_text)
    system = root.find("e:System", NS)
    if system is None:
        return None

    eid_text = system.findtext("e:EventID", default="", namespaces=NS)
    if not eid_text.isdigit():
        return None
    eid = int(eid_text)

    table = {
        "evtx.security": SECURITY_EIDS,
        "evtx.system": SYSTEM_EIDS,
        "evtx.powershell": POWERSHELL_EIDS,
    }[artifact]
    if eid not in table:
        return None

    event_type, action = table[eid]

    time_node = system.find("e:TimeCreated", NS)
    system_time = time_node.get("SystemTime") if time_node is not None else None
    if not system_time:
        return None

    record_id = system.findtext("e:EventRecordID", default="", namespaces=NS)
    if not record_id:
        return None

    data = _event_data(root)
    if eid == 1102:
        data = _user_data(root)

    return Event(
        timestamp=parse_systemtime(system_time),
        source_artifact=artifact,
        event_type=event_type,
        action=action,
        source_file=relative_path,
        source_locator=f"EventRecordID={record_id}",
        # Every EID in the vocabulary is written by the log at the moment the
        # event occurs, so the timestamp is the event itself -- unlike Prefetch,
        # whose slot 0 is a last-run summary. CD-019.
        timestamp_type="recorded",
        host=system.findtext("e:Computer", default=None, namespaces=NS) or None,
        user=_user_for(eid, data),
        path=_path_for(eid, data),
        confidence="high",
        details=_details_for(eid, data),
    )


@register
class EvtxWindowsParser:
    name = "evtx_windows"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.lower()
        if "/winevt/logs/" not in f"/{lowered}":
            return False
        return _artifact_for(lowered) is not None

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        artifact = _artifact_for(relative_path.lower())
        if artifact is None:
            return
        for xml_text in _records(abs_path):
            try:
                event = record_to_event(xml_text, artifact, relative_path)
            except ET.ParseError:
                continue
            if event is not None:
                yield event
