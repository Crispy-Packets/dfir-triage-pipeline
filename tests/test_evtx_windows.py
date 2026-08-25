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
    assert not p.can_handle("C/Windows/System32/winevt/Logs/Application.evtx")
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
