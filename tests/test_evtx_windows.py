from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.evtx_windows import (
    EvtxWindowsParser,
    parse_systemtime,
    record_to_event,
)

REL = "C/Windows/System32/winevt/Logs/Security.evtx"
_REPO = Path(__file__).resolve().parents[1]
_COLLECTIONS = _REPO / "collections"
_CLEAN_B_SECURITY = (
    _COLLECTIONS
    / "collection_clean_b"
    / "C"
    / "Windows"
    / "System32"
    / "winevt"
    / "logs"
    / "Security.evtx"
)
_CLEAN_B_SYSTEM = (
    _COLLECTIONS
    / "collection_clean_b"
    / "C"
    / "Windows"
    / "System32"
    / "winevt"
    / "logs"
    / "System.evtx"
)
_S1_SECURITY = (
    _COLLECTIONS
    / "collection_s1_v2"
    / "C"
    / "Windows"
    / "System32"
    / "winevt"
    / "logs"
    / "Security.evtx"
)

_LOCATOR_RE = re.compile(r"^EventRecordID=\d+$")

requires_collections = pytest.mark.skipif(
    not _COLLECTIONS.is_dir(),
    reason="collections/ evidence directory not present",
)
requires_clean_b_security = pytest.mark.skipif(
    not _CLEAN_B_SECURITY.is_file(),
    reason="collections/ clean_b Security.evtx not present",
)
requires_clean_b_system = pytest.mark.skipif(
    not _CLEAN_B_SYSTEM.is_file(),
    reason="collections/ clean_b System.evtx not present",
)
requires_s1_security = pytest.mark.skipif(
    not _S1_SECURITY.is_file(),
    reason="collections/ scenario1 Security.evtx not present",
)

RECORD_1102 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2026-08-11T10:35:02.1234567Z"/>
    <EventRecordID>4711</EventRecordID>
    <Computer>WIN-VICTIM</Computer>
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserName>admin_local</SubjectUserName>
      <SubjectDomainName>WIN-VICTIM</SubjectDomainName>
    </LogFileCleared>
  </UserData>
</Event>"""

RECORD_4624 = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-08-11T09:00:00.000000Z"/>
    <EventRecordID>12</EventRecordID>
    <Computer>WIN-VICTIM</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">janed</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">192.168.56.1</Data>
  </EventData>
</Event>"""

RECORD_UNSUPPORTED = RECORD_4624.replace("<EventID>4624</EventID>", "<EventID>5379</EventID>")


def _assert_contract_shape(event) -> None:
    assert _LOCATOR_RE.match(event.source_locator)
    assert event.timestamp.tzinfo is not None
    assert event.timestamp.utcoffset() == timedelta(0)
    assert event.confidence == "high"


def test_seven_digit_fractional_seconds_parse():
    """Windows emits 100ns resolution; we truncate to microseconds explicitly."""
    ts = parse_systemtime("2026-08-11T10:35:02.1234567Z")
    assert ts.utcoffset() == timedelta(0)
    assert ts.microsecond == 123456


def test_explicit_offset_is_converted_not_overwritten():
    ts = parse_systemtime("2026-08-11T13:35:02.1234567+03:00")
    assert ts.hour == 10
    assert ts.utcoffset() == timedelta(0)


def test_1102_reads_user_from_userdata_not_eventdata():
    event = record_to_event(RECORD_1102, "evtx.security", REL)
    assert event.event_type == "log_cleared"
    assert event.user == "admin_local"


def test_locator_is_event_record_id():
    assert record_to_event(RECORD_1102, "evtx.security", REL).source_locator == "EventRecordID=4711"


def test_logon_type_is_preserved_for_week3_rules():
    event = record_to_event(RECORD_4624, "evtx.security", REL)
    assert event.details["LogonType"] == "10"


def test_unsupported_eid_returns_none_rather_than_raising():
    assert record_to_event(RECORD_UNSUPPORTED, "evtx.security", REL) is None


def test_source_file_is_passed_through_unchanged():
    assert record_to_event(RECORD_4624, "evtx.security", REL).source_file == REL


def test_can_handle_matches_real_path_shape():
    p = EvtxWindowsParser()
    assert p.can_handle("C/Windows/System32/winevt/Logs/Security.evtx")
    assert p.can_handle("C/Windows/System32/winevt/logs/System.evtx")
    # Amended 2026-09-17: every channel in the log directory is now read, the
    # uncurated ones into generic families. See test_powershell_4104.py.
    assert p.can_handle("C/Windows/System32/winevt/Logs/Application.evtx")
    # The directory anchor still holds: a .evtx sitting in Downloads is a file
    # somebody copied, not this machine's event log.
    assert not p.can_handle("C/Users/janed/Downloads/Security.evtx")


def test_malformed_xml_is_skipped_without_aborting(monkeypatch, tmp_path):
    """Defect 4: ET.ParseError on one record must not abort the file."""
    import dfir_triage_pipeline.parsers.evtx_windows as mod

    def fake_records(_path):
        yield RECORD_4624
        yield "<Event><broken"
        yield RECORD_1102

    monkeypatch.setattr(mod, "_records", fake_records)
    events = list(EvtxWindowsParser().parse(tmp_path / "dummy.evtx", REL))
    assert len(events) == 2
    assert events[0].event_type == "logon"
    assert events[1].event_type == "log_cleared"


@requires_collections
@requires_s1_security
def test_scenario1_contains_the_log_clear():
    relative = "C/Windows/System32/winevt/logs/Security.evtx"
    events = list(EvtxWindowsParser().parse(_S1_SECURITY, relative))
    cleared = [e for e in events if e.event_type == "log_cleared"]
    assert len(cleared) >= 1
    for event in cleared:
        _assert_contract_shape(event)
        assert event.user


@requires_collections
@requires_clean_b_security
def test_clean_b_contains_logons():
    relative = "C/Windows/System32/winevt/logs/Security.evtx"
    events = list(EvtxWindowsParser().parse(_CLEAN_B_SECURITY, relative))
    logons = [e for e in events if e.event_type == "logon"]
    assert len(logons) >= 1
    for event in logons[:5]:
        _assert_contract_shape(event)


@requires_collections
@requires_clean_b_security
def test_clean_b_contains_process_exec():
    relative = "C/Windows/System32/winevt/logs/Security.evtx"
    events = list(EvtxWindowsParser().parse(_CLEAN_B_SECURITY, relative))
    execs = [e for e in events if e.event_type == "process_exec"]
    assert len(execs) >= 1
    _assert_contract_shape(execs[0])


@requires_collections
@requires_clean_b_security
def test_clean_b_contains_account_created():
    relative = "C/Windows/System32/winevt/logs/Security.evtx"
    events = list(EvtxWindowsParser().parse(_CLEAN_B_SECURITY, relative))
    created = [e for e in events if e.event_type == "account_created"]
    assert len(created) >= 1
    _assert_contract_shape(created[0])


@requires_collections
@requires_clean_b_system
def test_clean_b_contains_service_install():
    relative = "C/Windows/System32/winevt/logs/System.evtx"
    events = list(EvtxWindowsParser().parse(_CLEAN_B_SYSTEM, relative))
    installs = [e for e in events if e.event_type == "service_install"]
    assert len(installs) >= 1
    _assert_contract_shape(installs[0])


class TestUserDataChannels:
    """WMI-Activity and TerminalServices (2026-09-15).

    Both carry their payload under `UserData` rather than `EventData`. Reading
    only `EventData` returns an empty dict for these records, and they then
    parse WITHOUT RAISING and produce an event with no fields -- the silent
    failure this project keeps meeting rather than an error anyone would see.
    """

    def _parse(self, xml, artifact, rel):
        from dfir_triage_pipeline.parsers import evtx_windows

        return evtx_windows.record_to_event(xml, artifact, rel)

    def test_wmi_subscription_fields_are_extracted(self):
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>5861</EventID>"
            '<TimeCreated SystemTime="2026-09-09T11:03:59.225087Z"/>'
            "<EventRecordID>1</EventRecordID><Computer>WINVM</Computer></System>"
            "<UserData>"
            '<Operation_ESStoConsumerBinding xmlns="http://manifests.microsoft.com/win/2006/windows/WMI">'
            "<Namespace>//./root/subscription</Namespace>"
            "<ESS>SCM Event Log Filter</ESS>"
            '<CONSUMER>NTEventLogEventConsumer="SCM Event Log Consumer"</CONSUMER>'
            "<PossibleCause>Query = &quot;select * from MSFT_SCMEventLogEvent&quot;</PossibleCause>"
            "</Operation_ESStoConsumerBinding></UserData></Event>"
        )
        event = self._parse(xml, "evtx.wmi", "C/Windows/x/wmi.evtx")
        assert event is not None
        assert event.event_type == "wmi_subscription"
        assert event.details["Namespace"] == "//./root/subscription"
        assert event.details["ESS"] == "SCM Event Log Filter"
        assert "NTEventLogEventConsumer" in event.details["CONSUMER"]
        # The query is the discriminating field: Namespace and ESS name the
        # subscription, only the query says what triggers it.
        assert "MSFT_SCMEventLogEvent" in event.details["PossibleCause"]

    def test_rdp_session_carries_the_address(self):
        """`Address` is what separates a remote session from a console one.
        Without it every local sign-in would read as remote access."""
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>21</EventID>"
            '<TimeCreated SystemTime="2026-09-09T01:07:45.016888Z"/>'
            "<EventRecordID>31</EventRecordID><Computer>WINVM</Computer></System>"
            '<UserData><EventXML xmlns="Event_NS">'
            "<User>WINVM" + chr(92) + "vboxuser</User><SessionID>1</SessionID>"
            "<Address>LOCAL</Address>"
            "</EventXML></UserData></Event>"
        )
        event = self._parse(xml, "evtx.rdp", "C/Windows/x/rdp.evtx")
        assert event is not None
        assert event.event_type == "rdp_session"
        assert event.details["Address"] == "LOCAL"
        assert event.user == "WINVM" + chr(92) + "vboxuser"

    def test_remote_address_is_preserved_verbatim(self):
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>25</EventID>"
            '<TimeCreated SystemTime="2026-09-09T01:07:45.016888Z"/>'
            "<EventRecordID>32</EventRecordID></System>"
            '<UserData><EventXML xmlns="Event_NS">'
            "<User>CORP" + chr(92) + "admin</User><SessionID>2</SessionID>"
            "<Address>10.0.0.5</Address>"
            "</EventXML></UserData></Event>"
        )
        event = self._parse(xml, "evtx.rdp", "C/Windows/x/rdp.evtx")
        assert event.details["Address"] == "10.0.0.5"

    def test_unlisted_eid_on_a_new_channel_is_dropped(self):
        """5857-5860 are WMI provider lifecycle, written constantly by normal
        operation. Only 5861 is in the vocabulary."""
        xml = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            "<System><EventID>5857</EventID>"
            '<TimeCreated SystemTime="2026-09-09T11:03:59.225087Z"/>'
            "<EventRecordID>2</EventRecordID></System>"
            "<UserData></UserData></Event>"
        )
        assert self._parse(xml, "evtx.wmi", "C/Windows/x/wmi.evtx") is None

    def test_both_channels_are_registered(self):
        from dfir_triage_pipeline.parsers.evtx_windows import _artifact_for

        assert _artifact_for(
            "c/windows/system32/winevt/logs/microsoft-windows-wmi-activity%4operational.evtx"
        ) == "evtx.wmi"
        assert _artifact_for(
            "c/windows/system32/winevt/logs/"
            "microsoft-windows-terminalservices-localsessionmanager%4operational.evtx"
        ) == "evtx.rdp"


class TestBitsCarriesTransferDetail:
    """D-065/D-066/D-067.

    Every `evtx.bits` row carried `details == {}` until 2026-09-19, while the
    raw records held a source URL, a byte count, a result code and the process
    that created the job. These assert the extraction AND the three things the
    measurement said must not be assumed: that EID 4 is a completion rather
    than a cancellation, that `name` is a job title rather than a destination
    path, and that the EID-59 size sentinel never reaches a rule.
    """

    BITS_REL = (
        "C/Windows/System32/winevt/Logs/"
        "Microsoft-Windows-Bits-Client%4Operational.evtx"
    )

    def _parse(self, xml, artifact="evtx.bits", rel=None):
        from dfir_triage_pipeline.parsers import evtx_windows

        return evtx_windows.record_to_event(xml, artifact, rel or self.BITS_REL)

    def _record(self, eid, fields, record_id=1):
        data = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in fields.items())
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f"<System><EventID>{eid}</EventID>"
            '<TimeCreated SystemTime="2026-08-28T17:51:09.000000Z"/>'
            f"<EventRecordID>{record_id}</EventRecordID>"
            "<Computer>WINVM</Computer></System>"
            f"<EventData>{data}</EventData></Event>"
        )

    def test_job_created_carries_the_creating_process_as_path(self):
        """processPath is the whole point of EID 3: it is the only field in the
        channel that attributes a background transfer to a binary, and it must
        reach Event.path so the row joins on entity.exe_name."""
        event = self._parse(
            self._record(
                3,
                {
                    "jobTitle": "Edge Component Updater",
                    "jobId": "0075B139-B255-4551-8A00-7ED06A777B2D",
                    "jobOwner": "WINVM\\vboxuser",
                    "processPath": "C:\\Program Files (x86)\\Microsoft\\Edge\\"
                    "Application\\msedge.exe",
                    "processId": "2500",
                },
            )
        )
        assert event is not None
        assert event.event_type == "bits_job_created"
        assert event.path == (
            "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
        )
        assert event.details["path_basename"] == "msedge.exe"
        assert event.details["jobOwner"] == "WINVM\\vboxuser"
        # Transport tuning carries no forensic claim and is dropped.
        assert "processId" not in event.details

    def test_eid_4_is_a_completion_not_a_cancellation(self):
        """D-066. EID 4 was mapped to bits_job_cancelled. Measured: no job
        carries both a 4 and a 5, and a 4's bytesTransferred equals its own
        transfer's bytesTotal -- a cancellation does not move every byte."""
        event = self._parse(
            self._record(
                4,
                {
                    "User": "WINVM\\vboxuser",
                    "jobId": "3774B14B-2230-4179-AC4F-DFBA52571B60",
                    "jobOwner": "WINVM\\vboxuser",
                    "fileCount": "1",
                    "bytesTransferred": "17514013",
                },
            )
        )
        assert event is not None
        assert event.event_type == "bits_job_completed"
        assert event.details["bytesTransferred"] == "17514013"

    def test_eid_5_is_the_cancellation_and_is_parsed_at_all(self):
        """EID 5 was not in BITS_EIDS, so every cancellation in the corpus was
        discarded unseen -- 7 rows on clean_a, 6 on s1_v3."""
        event = self._parse(
            self._record(
                5,
                {
                    "User": "WINVM\\vboxuser",
                    "jobTitle": "PreSignInSettingsConfigJSON",
                    "jobId": "B609655F-72EA-40E6-81AC-40AE1FAF7A30",
                    "jobOwner": "WINVM\\vboxuser",
                    "fileCount": "1",
                },
            )
        )
        assert event is not None
        assert event.event_type == "bits_job_cancelled"
        # A cancellation carries no byte count. That absence is the shape.
        assert "bytesTransferred" not in event.details

    def test_transfer_started_carries_the_url(self):
        """The source address, which no other family records for a background
        transfer: the browser family cannot see these at all."""
        event = self._parse(
            self._record(
                59,
                {
                    "transferId": "816ECD77-6E6E-4CBE-B854-0381CF61B58A",
                    "Id": "4314B58C-BF32-4388-973F-E047BFF0A93F",
                    "url": "http://example.invalid/filestreamingservice/files/x",
                    "name": "Edge Component Updater",
                    "fileTime": "2026-08-06T02:52:36.000000Z",
                    "bytesTotal": "18446744073709551615",
                },
            )
        )
        assert event is not None
        assert event.event_type == "bits_transfer_started"
        assert event.details["url"] == (
            "http://example.invalid/filestreamingservice/files/x"
        )

    def test_the_eid_59_size_sentinel_never_reaches_a_rule(self):
        """At transfer START the size is frequently unknown and the record
        carries UINT64_MAX (10/9/9/7/7 rows across five collections). A numeric
        predicate against that value matches everything, so bytesTotal is not
        kept on 59 at all -- excluded rather than filtered, so the key can never
        carry a sentinel."""
        event = self._parse(
            self._record(
                59,
                {
                    "Id": "4314B58C-BF32-4388-973F-E047BFF0A93F",
                    "url": "http://example.invalid/x",
                    "name": "Font Download",
                    "bytesTotal": "18446744073709551615",
                    "fileLength": "18446744073709551615",
                },
            )
        )
        assert event is not None
        assert "bytesTotal" not in event.details
        assert "fileLength" not in event.details

    def test_transfer_completed_carries_size_and_result_code(self):
        """hr is the only field that distinguishes a failed transfer from a
        successful one, and on EID 60 the size is real rather than a sentinel."""
        event = self._parse(
            self._record(
                60,
                {
                    "Id": "4314B58C-BF32-4388-973F-E047BFF0A93F",
                    "url": "http://example.invalid/x",
                    "name": "Edge Component Updater",
                    "hr": "0",
                    "bytesTotal": "116698",
                    "bytesTransferred": "116698",
                },
            )
        )
        assert event is not None
        assert event.event_type == "bits_transfer_completed"
        assert event.details["hr"] == "0"
        assert event.details["bytesTotal"] == "116698"

    def test_name_is_a_job_title_and_is_not_treated_as_a_destination_path(self):
        """Measured: `name` is a title on 252/286/349/89/105 rows and a path on
        only 2/2/2/6/6. It is NOT the destination, and nothing derives a path
        from it -- only EID 3's processPath reaches Event.path."""
        event = self._parse(
            self._record(
                60,
                {
                    "Id": "x",
                    "url": "http://example.invalid/x",
                    "name": "Font Download",
                    "hr": "0",
                },
            )
        )
        assert event is not None
        assert event.details["name"] == "Font Download"
        assert event.path is None
        assert "path_basename" not in event.details

    def test_a_generic_channel_does_not_borrow_bits_keys(self):
        """D-067. _details_for and _user_for dispatch on the EID alone, so on an
        uncurated channel they would answer for whichever curated channel uses
        that number -- and 3, 4 and 5 are among the most reused numbers in the
        Windows log estate. Measured over five collections this fires on
        nothing today; it is asserted because the next collection is not bound
        by that.
        """
        xml = self._record(
            3,
            {
                "jobTitle": "not a bits job",
                "processPath": "C:\\Windows\\System32\\svchost.exe",
                "jobOwner": "WINVM\\vboxuser",
            },
        )
        event = self._parse(
            xml,
            artifact="evtx.x.some-provider.operational",
            rel="C/Windows/System32/winevt/Logs/Some-Provider%4Operational.evtx",
        )
        assert event is not None
        assert event.event_type == "log_record"
        assert event.details == {}
        assert event.path is None
        assert event.user is None


class TestPsClassicLifecycleCarriesHostApplication:
    """D-055.

    `evtx.ps_classic` was added to close a stated gap: EID 600 holds
    `HostApplication`, the full command line of the process that started
    PowerShell, present when script-block logging is off and 4104 holds
    nothing (CD-007). `_details_for` had a branch only for 800, so every
    400/403/600 row was emitted with `details == {}` and the field the channel
    was taken for reached no Event at all.
    """

    PS_REL = "C/Windows/System32/winevt/Logs/Windows PowerShell.evtx"

    def _parse(self, xml, artifact="evtx.ps_classic", rel=None):
        from dfir_triage_pipeline.parsers import evtx_windows

        return evtx_windows.record_to_event(xml, artifact, rel or self.PS_REL)

    def _record(self, eid, block, record_id=1):
        return (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            f"<System><EventID>{eid}</EventID>"
            '<TimeCreated SystemTime="2026-08-28T17:51:09.000000Z"/>'
            f"<EventRecordID>{record_id}</EventRecordID>"
            "<Computer>WINVM</Computer></System>"
            f"<EventData><Data>{block}</Data></EventData></Event>"
        )

    BLOCK = (
        "DetailSequence=1\n\tSequenceNumber=13\n\t"
        "HostApplication=powershell.exe -ExecutionPolicy Bypass "
        "-File C:\\Users\\janed\\Downloads\\stage.ps1\n"
    )

    @pytest.mark.parametrize(
        ("eid", "event_type"),
        [
            (400, "ps_engine_start"),
            (403, "ps_engine_stop"),
            (600, "ps_provider_start"),
        ],
    )
    def test_lifecycle_eids_carry_the_launching_command_line(self, eid, event_type):
        event = self._parse(self._record(eid, self.BLOCK))
        assert event is not None
        assert event.event_type == event_type
        assert event.details["host_application"] == (
            "powershell.exe -ExecutionPolicy Bypass "
            "-File C:\\Users\\janed\\Downloads\\stage.ps1"
        )
        assert event.details["ps_sequence_number"] == "13"
        # The real length is always recorded, so truncation is measurable.
        assert int(event.details["host_application_bytes"]) == len(
            event.details["host_application"].encode("utf-8")
        )
        assert "host_application_truncated" not in event.details

    def test_a_long_command_line_is_capped_and_says_so(self):
        """Same contract as script_block_text: the byte count is of the
        ORIGINAL, and the truncation marker is present rather than inferred."""
        from dfir_triage_pipeline.parsers.evtx_windows import SCRIPT_BLOCK_TEXT_CAP

        payload = "A" * (SCRIPT_BLOCK_TEXT_CAP + 500)
        block = f"DetailSequence=1\n\tHostApplication=powershell.exe -Command {payload}\n"
        event = self._parse(self._record(600, block))
        assert event is not None
        assert event.details["host_application_truncated"] == "true"
        assert len(event.details["host_application"].encode("utf-8")) <= (
            SCRIPT_BLOCK_TEXT_CAP
        )
        # The FULL length, not the truncated one.
        assert int(event.details["host_application_bytes"]) > SCRIPT_BLOCK_TEXT_CAP

    def test_eid_800_still_separates_the_two_command_lines(self):
        """Regression guard for the D-055 widening: 800 carried
        ps_command_line before this change and must still distinguish it from
        host_application. They are different facts -- what was invoked versus
        what launched the host."""
        block = (
            "DetailSequence=1\n\tSequenceNumber=18\n\t"
            "UserId=WINVM\\vboxuser\n\t"
            "HostApplication=powershell.exe -ExecutionPolicy Bypass -File x.ps1\n\t"
            "CommandLine=Add-Type -AssemblyName System.IO.Compression\n"
        )
        event = self._parse(self._record(800, block))
        assert event is not None
        assert event.event_type == "script_block"
        assert event.details["ps_command_line"] == (
            "Add-Type -AssemblyName System.IO.Compression"
        )
        assert event.details["host_application"] == (
            "powershell.exe -ExecutionPolicy Bypass -File x.ps1"
        )
        assert event.details["ps_command_line_bytes"] == "44"
        # 800 is the only ps_classic EID carrying a joinable principal.
        assert event.user == "WINVM\\vboxuser"
