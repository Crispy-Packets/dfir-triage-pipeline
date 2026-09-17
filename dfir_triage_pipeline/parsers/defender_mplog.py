"""Defender's `MPLog`: processes the AV engine saw, and files it reported on.

`MPLog-*.log` is the Defender engine's own operational log, written as UTF-16
text under `ProgramData\\Microsoft\\Windows Defender\\Support`. It is not an
event channel and nothing in the Windows event log duplicates it.

**It names the scenario payload on `s1_v3` and on no clean collection.**
Measured through the parser: one `ReportLowfi` for the payload under
`Downloads` at 2026-09-13T12:16:11, and zero rows naming it on `clean_a`,
`clean_b` or `clean_c`. `s1_v2` shows none either -- an earlier raw grep that
suggested twelve was matching `MPDetection`, a different file in the same
directory that this parser does not read.

**Two line shapes are taken**, out of the twenty-odd the engine writes:

    ProcessImageName:  every process the real-time engine observed, with its
                       PID and accumulated scan time -- 2,538 lines on s1_v2.
                       This is execution evidence from a source completely
                       independent of Prefetch, Amcache, BAM and the event log.

    ReportLowfi(path)  a LOW-FIDELITY detection: the engine noticed something
                       about a file and reported it for cloud evaluation. It is
                       NOT a verdict -- see below.

Everything else is engine lifecycle, signature updates, cloud heartbeats and
configuration, none of which says anything about what ran on the machine.

**`ReportLowfi` is not a detection, and the event type says so.** The name is
Defender's own: *low fidelity*. The engine reports a file it wants a second
opinion on; a real verdict is a 1116 in `evtx.defender`. Spelling this
`malware_detected` would claim Defender identified the payload as malicious,
which it did not: measured across all five collections, `evtx.defender` holds
**zero** 1116 and 1117 verdicts, while `s1_v3`'s MPLog holds a `ReportLowfi`
for the payload. The engine looked and did not conclude.

**The file is UTF-16LE with a BOM**, and lines are timestamped
`2026-09-13T12:16:11.890` with no zone. Those are local machine time, so UTC is
attached rather than converted (D-013).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from ..model import Event
from . import register

#: `2026-09-13T12:16:11.890 ` then the message. Some lines carry a trailing Z
#: on the timestamp and some do not; both appear in one file.
_LINE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)Z?\s+(?P<body>.+)$"
)

#: `ProcessImageName: setup.exe, Pid: 4980, TotalTime: 8129, Count: 427, ...`
_PROCESS = re.compile(
    r"^ProcessImageName:\s*(?P<name>[^,]+?)\s*,\s*Pid:\s*(?P<pid>\d+)"
    r"(?:\s*,\s*TotalTime:\s*(?P<total>\d+))?"
    r"(?:\s*,\s*Count:\s*(?P<count>\d+))?"
)

#: `ReportLowfi(c:\users\x\downloads\invoice_scan.exe, 0x437a0835) from 0x...`
_LOWFI = re.compile(r"^ReportLowfi\((?P<path>[^,)]+)")

#: `OnDemandScan skipped or partial scan for [pid:6652,ProcessStart:1343...]`
#: A process the engine did NOT fully scan. Worth recording for the same reason
#: an absent Amcache entry is (D-028): the artefact saying it did not look is
#: different from the artefact not existing.
_SCAN_SKIP = re.compile(
    r"^OnDemandScan skipped or partial scan for \[pid:(?P<pid>\d+)"
)

#: `Service started - Microsoft Defender Antivirus (77BDAF73-...)`
_SERVICE_START = re.compile(r"^Service started\b")

#: The text log families under Support/. All four share the same
#: `<ISO timestamp> <message>` line format -- verified on each -- so one parser
#: reads them and `log_family` records which file a row came from.
#:
#: MpWppCoreTracing, MpWppTracing and MpWppUpdateLogging are NOT here: they are
#: binary ETW traces (`.bin`), not text, and decoding them needs a TMF schema
#: this pipeline does not have.
_TEXT_LOG_PREFIXES = ("mplog", "mpdetection", "mpscanskip", "mpdevicecontrol")

#: A pathological or truncated file must not spin. The largest here is 9,552
#: lines; this bounds a corrupt one.
_MAX_LINES = 500_000


def parse_timestamp(raw: str) -> datetime | None:
    """`2026-09-13T12:16:11.890` to aware UTC, or None.

    No zone is written, so UTC is ATTACHED rather than converted -- the value
    is the subject machine's wall clock, and converting would apply the
    analyst's zone to it (D-013).
    """
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _read_text(abs_path: Path) -> str:
    """The log as text.

    Written UTF-16LE with a BOM. `errors="replace"` rather than raising: a
    single bad byte must not discard 9,000 lines, and a log that is not UTF-16
    at all simply yields no matching lines.
    """
    try:
        return abs_path.read_text(encoding="utf-16", errors="replace")
    except (UnicodeError, OSError):
        try:
            return abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


class DefenderMpLogParser:
    name = "defender_mplog"

    def can_handle(self, relative_path: str) -> bool:
        lowered = relative_path.replace("\\", "/").lower()
        if "/windows defender/support/" not in f"/{lowered}":
            return False
        name = lowered.rsplit("/", 1)[-1]
        if name.endswith(".bin"):
            return False
        return name.startswith(_TEXT_LOG_PREFIXES)

    def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
        text = _read_text(abs_path)
        # Which of the four logs this row came from. They share a line format
        # but not a subject, and a consumer should not have to parse the
        # filename to tell a scan-skip log from the engine log.
        family = abs_path.name.split("-", 1)[0].lower()

        for number, raw in enumerate(text.splitlines(), start=1):
            if number > _MAX_LINES:
                return
            line = raw.lstrip("\ufeff").strip()
            if not line:
                continue
            match = _LINE.match(line)
            if match is None:
                continue
            timestamp = parse_timestamp(match.group("stamp"))
            if timestamp is None:
                continue
            body = match.group("body")

            process = _PROCESS.match(body)
            if process is not None:
                details = {
                    "process_name": process.group("name"),
                    "pid": process.group("pid"),
                    "mplog_line": str(number),
                    "log_family": family,
                }
                if process.group("total"):
                    details["scan_time_ms"] = process.group("total")
                if process.group("count"):
                    details["scan_count"] = process.group("count")
                yield Event(
                    timestamp=timestamp,
                    source_artifact="defender_mplog",
                    # The engine observed this process running. It shares the
                    # string with prefetch, bam and 4688 by the same contract
                    # that governs every shared event_type.
                    event_type="process_exec",
                    action="defender engine observed a running process",
                    source_file=relative_path,
                    source_locator=f"line/{number}",
                    timestamp_type="recorded",
                    path=process.group("name"),
                    user=None,
                    details=details,
                )
                continue

            lowfi = _LOWFI.match(body)
            if lowfi is not None:
                path = lowfi.group("path").strip()
                if not path:
                    continue
                yield Event(
                    timestamp=timestamp,
                    source_artifact="defender_mplog",
                    # NOT malware_detected. `Lowfi` is Defender's own word for
                    # low fidelity: the engine wanted a second opinion, it did
                    # not reach a verdict. A verdict is a 1116 in evtx.defender.
                    event_type="file_reported",
                    action="defender reported a file for evaluation",
                    source_file=relative_path,
                    source_locator=f"line/{number}",
                    timestamp_type="recorded",
                    path=path,
                    user=None,
                    details={
                        "reported_path": path,
                        "mplog_line": str(number),
                        "log_family": family,
                    },
                )
                continue

            skipped = _SCAN_SKIP.match(body)
            if skipped is not None:
                yield Event(
                    timestamp=timestamp,
                    source_artifact="defender_mplog",
                    # The engine declining to scan something is evidence in the
                    # same way an absent Amcache entry is (D-028): "it did not
                    # look" differs from "it looked and found nothing".
                    event_type="scan_skipped",
                    action="defender skipped or partially scanned a process",
                    source_file=relative_path,
                    source_locator=f"line/{number}",
                    timestamp_type="recorded",
                    path=None,
                    user=None,
                    details={
                        "pid": skipped.group("pid"),
                        "mplog_line": str(number),
                        "log_family": family,
                    },
                )
                continue

            if _SERVICE_START.match(body):
                yield Event(
                    timestamp=timestamp,
                    source_artifact="defender_mplog",
                    event_type="av_service_started",
                    action="defender antivirus service started",
                    source_file=relative_path,
                    source_locator=f"line/{number}",
                    timestamp_type="recorded",
                    path=None,
                    user=None,
                    details={"mplog_line": str(number), "log_family": family},
                )


register(DefenderMpLogParser)
