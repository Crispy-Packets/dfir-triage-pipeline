from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from evtx import PyEvtxParser

from ..model import Event
from ..paths import derive as derive_path
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

# WMI-Activity/Operational. 5861 is the only EID taken: it records a PERMANENT
# event subscription being registered -- filter, consumer and the WQL query that
# triggers it -- which is the artifact fileless WMI persistence leaves
# (T1546.003). 5857-5860 are provider lifecycle and query telemetry, written
# constantly by normal Windows operation, and a rule reading them would fire on
# background noise.
WMI_EIDS: dict[int, tuple[str, str]] = {
    5861: ("wmi_subscription", "wmi permanent event subscription registered"),
}

# TerminalServices-LocalSessionManager/Operational. 21 is a session logon and
# 25 a reconnection; both carry the `Address` field, which is what separates a
# remote session from a local console one. 22/23/24/39/40 are shell start,
# logoff and disconnect -- present, but they describe the end of a session
# rather than its origin.
RDP_EIDS: dict[int, tuple[str, str]] = {
    21: ("rdp_session", "terminal services session logon"),
    25: ("rdp_session", "terminal services session reconnection"),
}


# Added 2026-09-17, after surveying every channel KAPE collected: 100 were
# unparsed, 93 of them holding records. These five were selected by what they
# ATTEST, not by volume -- the largest unparsed channel is Store telemetry with
# 21,068 rows and nothing forensic in any of them.

# The LEGACY PowerShell channel, which docs/artifact-attestation-matrix.md has
# carried as a stated gap since it was written. 600 is provider lifecycle and
# carries HostApplication -- the full command line of the process that started
# PowerShell -- which survives when script-block logging is off and 4104 holds
# nothing. 400/403 bracket an engine session. 500/501 are pipeline detail and
# are not taken.
PS_CLASSIC_EIDS: dict[int, tuple[str, str]] = {
    400: ("ps_engine_start", "powershell engine started"),
    403: ("ps_engine_stop", "powershell engine stopped"),
    600: ("ps_provider_start", "powershell provider lifecycle"),
    # Added 2026-09-18 by the curated-channel audit (D-059). 800 is pipeline
    # execution detail and is the ONLY record in this pipeline carrying a
    # PowerShell command line when script-block logging is off: 4104 exists
    # only with that logging enabled, and 600 -- the EID this channel was
    # taken for -- carries HostApplication that nothing extracted (D-055).
    #
    # Shares `script_block` with 4104 deliberately: both record that
    # PowerShell executed a command and carry its text, and a second spelling
    # would break any chain joined on event_type.
    #
    # Measured 10/10/10/0/0. Flat on host 1, absent on host 2 -- it does NOT
    # discriminate by volume and is taken for the field, not the count.
    800: ("script_block", "powershell pipeline executed a command"),
}

#: Fields read out of a legacy-PowerShell detail block, mapped to the
#: `details` keys declared in docs/details-schema.md (CD-012).
_PS_CLASSIC_FIELDS = {
    "HostApplication": "host_application",
    "CommandLine": "ps_command_line",
    "ScriptName": "ps_script_name",
    "UserId": "ps_user_id",
    "SequenceNumber": "ps_sequence_number",
}


def parse_ps_detail_block(data: dict[str, str]) -> dict[str, str]:
    r"""Fields from a legacy-PowerShell record's `key=value` detail block.

    The classic channel does NOT use `<Data Name="...">`. It writes unnamed
    `<Data>` elements whose text is a tab-indented block:

        DetailSequence=1
        SequenceNumber=18
        UserId=WINDOWS10\Youssef
        HostApplication=powershell.exe -ExecutionPolicy Bypass -File C:\...

    `_event_data` keys on the `Name` attribute and therefore returns NOTHING
    for these records -- which is why every 400/403/600 row carries empty
    details (D-055) and why this needs its own reader rather than a `keep`
    tuple like every other EID in this module.

    A value may contain `=` (a command line usually does), so each line is
    split on the FIRST `=` only. Lines without one are continuations of the
    previous value and are appended to it, because a command line wrapped
    across lines would otherwise be truncated at the wrap.
    """
    out: dict[str, str] = {}
    for blob in data.values():
        current: str | None = None
        for line in blob.splitlines():
            stripped = line.strip()
            if not stripped:
                current = None
                continue
            key, sep, value = stripped.partition("=")
            key = key.strip()
            if sep and key in _PS_CLASSIC_FIELDS:
                current = _PS_CLASSIC_FIELDS[key]
                out[current] = value.strip()
            elif sep and key and key[0].isalpha() and " " not in key:
                # A field this parser does not keep; stop appending to the
                # previous one rather than folding an unrelated value into it.
                current = None
            elif current:
                out[current] = f"{out[current]} {stripped}".strip()
    return {k: v for k, v in out.items() if v}

# Defender. 1116/1117 are a detection and its remediation -- the only family in
# this pipeline that records an AV verdict at all. 5001 is real-time protection
# being DISABLED, which is a defence-evasion artifact (T1562.001); 5007 is a
# configuration change, 334 of them on s1_v3, and is taken because a
# configuration change is how protection gets turned off quietly.
DEFENDER_EIDS: dict[int, tuple[str, str]] = {
    1116: ("malware_detected", "defender detected malware"),
    1117: ("malware_remediated", "defender acted on malware"),
    5001: ("defense_disabled", "defender real-time protection disabled"),
    5007: ("defense_configured", "defender configuration changed"),
}

# Winlogon. 811/812 are logon-UI notifications that survive a Security-log
# clear -- 645 rows on s1_v3 against 12 surviving Security records. They do not
# name a principal, so they corroborate that SOMEONE logged on when 4624 is
# gone, which is weaker than a logon record and stronger than nothing.
WINLOGON_EIDS: dict[int, tuple[str, str]] = {
    811: ("logon_ui", "logon user interface notification"),
    812: ("logon_ui", "logon user interface notification"),
}

# Windows Firewall. 2004/2005/2006/2033 are a rule added, changed, deleted, and
# all rules deleted -- the artifact of an attacker opening a port or clearing a
# policy. 2097 is a settings-restore notice, 518 rows, and is NOT taken: it
# fires on ordinary profile switches.
FIREWALL_EIDS: dict[int, tuple[str, str]] = {
    2004: ("firewall_rule_added", "firewall rule added"),
    2005: ("firewall_rule_changed", "firewall rule changed"),
    2006: ("firewall_rule_deleted", "firewall rule deleted"),
    2033: ("firewall_rules_deleted", "all firewall rules deleted"),
}

# BITS. A background transfer is a download that leaves no browser history at
# all, which is why it is a favoured delivery mechanism. 3 is a job created, 59
# a transfer started, 60 a transfer completed, 4 the JOB completion summary and
# 5 the job cancellation.
#
# 4 was labelled "bits_job_cancelled" until D-066. Measured across the corpus:
# no job carries both a 4 and a 5 (0 of 117 on clean_a, 0 of 51 on s1_v3), every
# job with a 4 has hr=0 on its own EID 60, and the 4's bytesTransferred equals
# that 60's bytesTotal exactly. A cancellation does not transfer every byte it
# asked for. EID 5 -- which carries jobTitle, jobId, jobOwner and fileCount but
# NO bytesTransferred -- is the cancellation, and it was not mapped at all.
BITS_EIDS: dict[int, tuple[str, str]] = {
    3: ("bits_job_created", "bits transfer job created"),
    4: ("bits_job_completed", "bits transfer job completed"),
    5: ("bits_job_cancelled", "bits transfer job cancelled"),
    59: ("bits_transfer_started", "bits transfer started"),
    60: ("bits_transfer_completed", "bits transfer completed"),
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
    r"""Named `EventData/Data` fields, with a positional fallback.

    Most channels write `<Data Name="ImagePath">...</Data>` and the name is
    the key. **The legacy `Windows PowerShell` channel does not**: it writes
    unnamed `<Data>` elements whose text is a tab-indented `key=value` block.

    Keying only on the `Name` attribute returned an EMPTY DICT for every
    record of that channel, which is the root cause of D-055 -- 400/403/600
    emitting no details at all while CD-007 cited a field inside them as the
    reason the channel was taken. Unnamed elements are therefore kept under
    positional keys `0`, `1`, ... and `parse_ps_detail_block` reads them.

    Named entries keep their name, so nothing that already worked changes.
    """
    out: dict[str, str] = {}
    position = 0
    for node in root.findall("e:EventData/e:Data", NS):
        name = node.get("Name")
        if name:
            out[name] = node.text or ""
        else:
            out[str(position)] = node.text or ""
            position += 1
    return out


#: `UserData` wrapper elements this parser reads, each holding one child level
#: of named fields. Listed explicitly rather than descended blindly: a schema
#: that nests deeper would silently flatten two different fields onto one key.
_USER_DATA_WRAPPERS = (
    "LogFileCleared",
    # WMI-Activity 5861. The element name is the operation, and its children
    # carry Namespace, ESS (the event filter), CONSUMER and the WQL query.
    "Operation_ESStoConsumerBinding",
    # TerminalServices-LocalSessionManager 21/25, whose fields sit under
    # EventXML rather than under an operation-named element.
    "EventXML",
)


def _user_data(root: ET.Element) -> dict[str, str]:
    """Named fields from a `UserData` record.

    Several channels carry their payload under `UserData` rather than
    `EventData` -- WMI-Activity and TerminalServices among them -- and reading
    only `EventData` returns an empty dict for those records. They then parse
    without raising and produce an event with no fields, which is the silent
    failure this project keeps meeting rather than an error anyone would notice.
    """
    out: dict[str, str] = {}
    for node in root.iter():
        tag = node.tag.split("}")[-1]
        if tag in _USER_DATA_WRAPPERS:
            for child in node:
                name = child.tag.split("}")[-1]
                out[name] = (child.text or "").strip()
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
    if eid in (21, 25):
        # DOMAIN\user as the channel records it. Not split: CD-010's principle
        # is that a parser records what the artifact wrote, and entity.user
        # normalisation happens in core/entity.py where it is visible.
        return data.get("User") or None
    if eid in (3, 4, 5):
        # The BITS job owner, DOMAIN\user verbatim per CD-010, exactly as the
        # 21/25 branch records User. Present on 100% of EID 3/4/5 records in all
        # five collections; without it the family is joinable only on exe_name
        # and only on EID 3.
        #
        # core/entity.py folds NT AUTHORITY\LOCAL SERVICE to None through
        # SYSTEM_CONTEXTS, so OS-owned jobs contribute no principal and only a
        # real account becomes an entity.user. That is the correct outcome here:
        # a font download owned by LOCAL SERVICE should not create an entity.
        return data.get("jobOwner") or None
    if eid == 800:
        # The legacy channel's UserId, out of its key=value detail block. This
        # is what makes ps_classic joinable on entity.user, which 811/812
        # cannot be -- the only principal on those is S-1-5-18 (D-057).
        return parse_ps_detail_block(data).get("ps_user_id") or None
    return None


def _path_for(eid: int, data: dict[str, str]) -> str | None:
    if eid == 4688:
        return data.get("NewProcessName") or None
    if eid == 7045:
        return data.get("ImagePath") or None
    if eid == 3:
        # BITS job created: the process that created the job. This is what makes
        # a background transfer joinable to an execution on entity.exe_name
        # (D-065). EIDs 4/5/59/60 carry no process path -- only the job id links
        # them back to the EID 3, and a job id is not a path.
        return data.get("processPath") or None
    return None


# Cap on the script text carried in details, in UTF-8 bytes.
#
# Chosen by measuring the corpus rather than picked round: the 3,249 script
# blocks across the three collections are bimodally distributed, with a median
# of 339 bytes and a p90 of about 15 KB. The large blocks are VS Code and
# PowerShell profile initialisation; the attack-relevant blocks in s1_v2 -- the
# WebClient DownloadFile calls that fetch invoice_scan.exe -- are 112 and 113
# bytes. A 4 KB cap therefore keeps every block a rule needs to read intact and
# truncates only benign initialisation noise.
#
# Truncation is recorded, never silent: script_block_text_bytes always carries
# the FULL byte length and script_block_truncated appears when the cap was hit.
# A rule may only read the capped text with positive operators -- see
# rules/schema.md. Asserting `not_contains` against the first 4 KB of a 20 KB
# script claims something the evidence does not support.
SCRIPT_BLOCK_TEXT_CAP = 4096


def _truncate_utf8(text: str, cap: int) -> tuple[str, int, bool]:
    """Cut text to at most cap UTF-8 bytes without splitting a character.

    Returns (text, full_byte_length, was_truncated). The length is of the
    ORIGINAL, so a consumer can always tell how much was not recorded.
    """
    raw = text.encode("utf-8")
    if len(raw) <= cap:
        return text, len(raw), False
    # errors="ignore" drops a partial character at the boundary rather than
    # emitting a replacement character that was never in the evidence.
    return raw[:cap].decode("utf-8", errors="ignore"), len(raw), True


def _details_for(eid: int, data: dict[str, str]) -> dict[str, str]:
    keep: tuple[str, ...]
    if eid in (400, 403, 600, 800):
        # The legacy channel writes a key=value block in unnamed <Data>
        # elements rather than Name-keyed ones, so it needs its own reader
        # instead of a `keep` tuple. See parse_ps_detail_block and D-059.
        #
        # 400/403/600 were left out until D-055 was fixed on 2026-09-19, so
        # every engine-lifecycle row carried details == {} while the record
        # held HostApplication -- the full command line of the process that
        # started PowerShell, which is the field this channel was ADDED for
        # (CD-007) and the only record of a PowerShell command line when
        # script-block logging is off. Measured before widening: present on
        # 100% of rows on all three EIDs in all five collections
        # (400: 93/94/91/17/26, 403: 82/82/62/13/17, 600: 578/584/563/104/160).
        fields = parse_ps_detail_block(data)
        # Both of these are command lines and are capped identically: the byte
        # length is always the REAL one, so truncation is measurable rather
        # than silent, and a rule may only read a capped value with positive
        # operators. ps_command_line is what the pipeline invoked;
        # host_application is what launched the host, including the
        # -ExecutionPolicy Bypass and -File arguments a rule looks for.
        for key in ("ps_command_line", "host_application"):
            value = fields.pop(key, None)
            if not value:
                continue
            text, full_len, truncated = _truncate_utf8(
                value, SCRIPT_BLOCK_TEXT_CAP
            )
            fields[key] = text
            fields[f"{key}_bytes"] = str(full_len)
            if truncated:
                fields[f"{key}_truncated"] = "true"
        return fields
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
        # ScriptBlockText is carried, but capped -- see SCRIPT_BLOCK_TEXT_CAP.
        # It was originally dropped entirely on the grounds that a block can run
        # to tens of kilobytes. Measuring the corpus showed the objection holds
        # only for benign initialisation blocks: the script text a detection
        # rule needs is around 112 bytes. Dropping it blocked R-ATOMIC-0003
        # outright, because no Event field carried what the script said.
        #
        # The fragment identifiers are kept because without them a consumer
        # cannot tell a whole script from one third of one.
        keep = ("ScriptBlockId", "MessageNumber", "MessageTotal", "Path")
    elif eid == 5861:
        # The WQL query is the discriminating field: `Namespace` and `ESS` name
        # the subscription, but the query says what triggers it. A subscription
        # on Win32_LogonSession or a timer is how fileless persistence survives
        # a reboot, and only the query shows which.
        keep = ("Namespace", "ESS", "CONSUMER", "PossibleCause")
    elif eid in (3, 4, 5):
        # BITS job lifecycle (D-065). processPath on EID 3 is the process that
        # CREATED the job, which is the field that makes a background transfer
        # attributable to a binary at all -- it is also read by _path_for, so an
        # EID 3 row carries entity.exe_name and can be joined to an execution.
        # jobOwner is DOMAIN\user verbatim, per CD-010: the parser records what
        # the artefact wrote and entity normalisation happens in core/entity.py.
        keep = ("jobTitle", "jobId", "jobOwner", "processPath", "fileCount",
                "bytesTransferred")
    elif eid in (59, 60):
        # BITS transfer lifecycle (D-065). `url` is the source address, which no
        # other family records for a background transfer -- the browser family
        # cannot see these at all.
        #
        # `name` is the job's DISPLAY NAME, not a destination path. Measured
        # across five collections it is a title ("Font Download") on 252/286/
        # 349/89/105 rows and a filesystem path on only 2/2/2/6/6, all of them
        # Edge Updater, which happens to name its jobs after the target file.
        # It is the same value as EID 3's jobTitle for the same jobId. The local
        # destination is NOT in this channel; see details-schema.md.
        #
        # bytesTotal/fileLength are excluded on EID 59 and kept on 60: at
        # transfer START the size is frequently unknown and the record carries
        # the UINT64_MAX sentinel 18446744073709551615 (10/9/9/7/7 rows). A
        # numeric predicate against that value matches everything.
        keep = ("transferId", "Id", "url", "name", "fileTime")
        if eid == 60:
            # hr is the result code -- non-zero is a failed transfer, and this
            # is the only field that says so.
            keep += ("hr", "bytesTotal", "bytesTransferred")
    elif eid in (21, 25):
        # Address separates a remote session from a local console one: it holds
        # "LOCAL" for a console logon and an IP for a remote desktop. Without it
        # a rule could not tell the two apart, and every console logon on the
        # machine would read as remote access.
        keep = ("User", "SessionID", "Address")
    elif eid in (2004, 2005, 2006, 2033):
        # Windows Firewall. Added for D-073: the channel was typed but had no
        # branch here, so 983 rows asserted `firewall_rules_deleted` -- a
        # DESTROY-phase defence-evasion event type -- while carrying nothing
        # that said WHICH rule, by whom, or with what binary. The event type
        # made a claim the payload could not substantiate.
        #
        # Measured over all five collections before writing this: 2006 carries
        # RuleName/RuleId/ModifyingUser/ModifyingApplication on 936 of 936
        # rows; 2033 carries no rule identity at all, only Store Type and the
        # two modifying fields, because deleting every rule names none.
        #
        # ModifyingApplication is the field that makes the family worth
        # reading. It is the Windows svchost.exe path on every row in this
        # corpus -- which is the base rate, not a detection: an attacker's
        # netsh.exe or a script host is what would differ. ModifyingUser is
        # always a service SID here for the same reason.
        keep = ("RuleName", "RuleId", "ModifyingUser", "ModifyingApplication", "Store Type")
    elif eid == 5007:
        # Defender configuration change (D-069). `New Value` and `Old Value`
        # are the registry path and value, and are the entire content of the
        # record -- without them the row says only that some Defender setting
        # changed at some time. Product Name is a resource string (%%827 on
        # every row) and Product Version is the engine build; both are kept
        # because they are what distinguishes a servicing change from a policy
        # one when the values themselves are ambiguous.
        #
        # This channel is 5007-only in this corpus: 1116/1117/5001 are declared
        # in DEFENDER_EIDS but measured at zero rows across all five
        # collections. Nothing was detected and real-time protection was never
        # disabled, so the branch covers what exists.
        keep = ("New Value", "Old Value", "Product Name", "Product Version")
    else:
        keep = ()
    details = {k: data[k] for k in keep if k in data and data[k] != ""}

    if eid == 4104 and data.get("ScriptBlockText"):
        text, full_len, truncated = _truncate_utf8(
            data["ScriptBlockText"], SCRIPT_BLOCK_TEXT_CAP
        )
        details["script_block_text"] = text
        # Always the full length, so truncation is measurable rather than
        # inferred from whether the text happens to look cut off.
        details["script_block_text_bytes"] = str(full_len)
        if truncated:
            details["script_block_truncated"] = "true"

    return details


def _path_details(eid: int, data: dict[str, str]) -> dict[str, str]:
    """B-9 derived fields for the path this record carries, if any.

    Kept separate from _details_for because the path is read by _path_for and
    the two would otherwise duplicate the per-EID knowledge of where it lives.
    """
    return derive_path(_path_for(eid, data))


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
    # Added 2026-09-15. Both carry their payload under UserData rather than
    # EventData, which is why _user_data had to be generalised first: a record
    # read with the wrong extractor parses without raising and yields an event
    # with no fields.
    ("/microsoft-windows-wmi-activity%4operational.evtx", "evtx.wmi"),
    (
        "/microsoft-windows-terminalservices-localsessionmanager%4operational.evtx",
        "evtx.rdp",
    ),
    # Added 2026-09-17. See the EID maps above for why each was selected.
    ("/windows powershell.evtx", "evtx.ps_classic"),
    ("/microsoft-windows-windows defender%4operational.evtx", "evtx.defender"),
    ("/microsoft-windows-winlogon%4operational.evtx", "evtx.winlogon"),
    (
        "/microsoft-windows-windows firewall with advanced security"
        "%4firewall.evtx",
        "evtx.firewall",
    ),
    ("/microsoft-windows-bits-client%4operational.evtx", "evtx.bits"),
)


#: Channels whose records this pipeline reads but does not interpret.
#:
#: Ten channels above have a curated EID map: a named event_type per EID,
#: chosen because the EID means something specific. The other 95 channels KAPE
#: collects hold 46,464 records between them, and reading NONE of them was a
#: judgement call that hid evidence behind an opinion.
#:
#: These are read generically instead. Every record becomes a `log_record` with
#: its EventData intact, timestamped and attributed to its channel, but with no
#: claim about what the EID MEANS. That is the honest middle position: the
#: evidence is in the timeline and searchable, and the pipeline does not invent
#: semantics for 3,000 EIDs it has not studied.
#:
#: A channel that later earns a curated map simply moves into _CHANNELS above.
_GENERIC_CHANNEL_PREFIX = "evtx.x."

#: Channel file names are `Provider%4Channel.evtx`; KAPE writes them verbatim.
_EVTX_SUFFIX = ".evtx"


def generic_artifact(lowered_path: str) -> str:
    """A stable family name for an uncurated channel, from its file name.

    `Microsoft-Windows-Bits-Client%4Operational.evtx` becomes
    `evtx.x.microsoft-windows-bits-client.operational`. The name is derived
    from the file rather than assigned, so a channel this pipeline has never
    seen still lands in a predictable family.
    """
    name = lowered_path.rsplit("/", 1)[-1]
    if name.endswith(_EVTX_SUFFIX):
        name = name[: -len(_EVTX_SUFFIX)]
    # %4 is the collector's encoding of the backslash between provider and
    # channel; a space appears in a few legacy names.
    cleaned = name.replace("%4", ".").replace(" ", "-")
    return _GENERIC_CHANNEL_PREFIX + cleaned


def _artifact_for(lowered_path: str) -> str | None:
    for suffix, artifact in _CHANNELS:
        if lowered_path.endswith(suffix):
            return artifact
    # Every other .evtx file is read generically rather than skipped.
    if lowered_path.endswith(_EVTX_SUFFIX):
        return generic_artifact(lowered_path)
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
        "evtx.wmi": WMI_EIDS,
        "evtx.rdp": RDP_EIDS,
        "evtx.ps_classic": PS_CLASSIC_EIDS,
        "evtx.defender": DEFENDER_EIDS,
        "evtx.winlogon": WINLOGON_EIDS,
        "evtx.firewall": FIREWALL_EIDS,
        "evtx.bits": BITS_EIDS,
    }.get(artifact)

    if table is None:
        # A channel with no curated EID map: every remaining EVTX file KAPE
        # collected. See _GENERIC_CHANNEL_PREFIX and CD-007.
        event_type, action = "log_record", f"{artifact.split('.', 1)[-1]} log record"
        # _details_for and _user_for dispatch on the EID ALONE, so on a generic
        # channel they would answer for whichever curated channel happens to use
        # that number. The BITS additions make this concrete: EIDs 3, 4 and 5 are
        # among the most reused numbers in the Windows log estate. Measured over
        # all five collections, no generic channel currently carries the field
        # NAMES a curated branch keeps, so this fires on nothing today (D-067) --
        # it is fixed because the next collection is not bound by that, not
        # because it was observed breaking.
    elif eid not in table:
        return None
    else:
        event_type, action = table[eid]

    time_node = system.find("e:TimeCreated", NS)
    system_time = time_node.get("SystemTime") if time_node is not None else None
    if not system_time:
        return None

    record_id = system.findtext("e:EventRecordID", default="", namespaces=NS)
    if not record_id:
        return None

    data = _event_data(root)
    if eid == 1102 or artifact in ("evtx.wmi", "evtx.rdp"):
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
        user=_user_for(eid, data) if table is not None else None,
        path=_path_for(eid, data) if table is not None else None,
        confidence="high",
        # Curated channels only: on a generic channel the EID is not evidence
        # of which record shape this is (D-067, above).
        details=(
            {**_details_for(eid, data), **_path_details(eid, data)}
            if table is not None
            else {}
        ),
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
