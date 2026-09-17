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
