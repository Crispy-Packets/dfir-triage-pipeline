"""Tests for the PowerShell script-block channel added to evtx_windows.

Kept in their own file rather than added to Person A's test_evtx_windows.py, so
the ownership split stays clean.
"""

import os
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.evtx_windows import (
    EvtxWindowsParser,
    _artifact_for,
    record_to_event,
)

PS_REL = (
    "C/Windows/System32/winevt/logs/Microsoft-Windows-PowerShell%4Operational.evtx"
)

XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2026-08-23T22:57:20.123456Z"/>
    <EventRecordID>9001</EventRecordID>
    <Computer>WINDOWS10</Computer>
  </System>
  <EventData>
    <Data Name="MessageNumber">2</Data>
    <Data Name="MessageTotal">3</Data>
    <Data Name="ScriptBlockText">{text}</Data>
    <Data Name="ScriptBlockId">455024bc-f82c-40a9-b4e3-a16247618cc0</Data>
    <Data Name="Path">{path}</Data>
  </EventData>
</Event>"""


def _event(text="Invoke-WebRequest http://192.168.50.2:8000/x", path=""):
    return record_to_event(
        XML.format(text=text, path=path), "evtx.powershell", PS_REL
    )


def test_4104_is_recognised_on_the_powershell_channel():
    e = _event()
    assert e is not None
    assert e.source_artifact == "evtx.powershell"
    assert e.event_type == "script_block"
    assert e.timestamp_type == "recorded"


def test_fragment_identifiers_are_kept():
    """A script block arrives as N records sharing a ScriptBlockId. Without
    MessageNumber and MessageTotal a consumer cannot tell a whole script from
    one third of one, and would report a fragment as the script that ran."""
    d = _event().details
    assert d["ScriptBlockId"] == "455024bc-f82c-40a9-b4e3-a16247618cc0"
    assert d["MessageNumber"] == "2"
    assert d["MessageTotal"] == "3"


def test_script_text_is_carried_under_a_declared_cap():
    """Superseded the original assertion that the text is dropped entirely.

    Dropping it blocked R-ATOMIC-0003 outright: no Event field said what a
    script did, so the rule could not be written. It is now carried under
    SCRIPT_BLOCK_TEXT_CAP with the truncation declared. The raw key name is
    still absent -- the value is emitted as script_block_text, because it is
    not the verbatim field once a cap can apply to it.

    Cap behaviour itself is pinned in tests/test_script_block_text.py; this
    test guards the boundary between the two designs. See D-031."""
    from dfir_triage_pipeline.parsers.evtx_windows import SCRIPT_BLOCK_TEXT_CAP

    long_text = "Write-Output 'x'; " * 500
    d = _event(text=long_text).details
    assert "ScriptBlockText" not in d
    assert len(d["script_block_text"].encode()) <= SCRIPT_BLOCK_TEXT_CAP
    assert d["script_block_text_bytes"] == str(len(long_text.encode()))


def test_fragments_are_emitted_separately_not_reassembled():
    """Each record is one Event. Reassembly is a consumer's decision -- joining
    on ScriptBlockId -- and doing it in the parser would invent an event that no
    single record attests to, and would need a locator no record carries."""
    first = record_to_event(
        XML.format(text="part one", path=""), "evtx.powershell", PS_REL
    )
    second = record_to_event(
        XML.format(text="part two", path=""), "evtx.powershell", PS_REL
    )
    assert first.source_locator == second.source_locator == "EventRecordID=9001"
    assert first.details["ScriptBlockId"] == second.details["ScriptBlockId"]


def test_empty_path_is_omitted_not_emitted_blank():
    """An absent Path means the block did not come from a file -- an interactive
    or in-memory block. That is meaningful, and an empty string would flatten it
    into 'a file whose name we do not know'."""
    assert "Path" not in _event(path="").details
    assert _event(path=r"C:\tmp\s.ps1").details["Path"] == r"C:\tmp\s.ps1"


def test_other_powershell_eids_are_ignored():
    """4103 is pipeline detail; 40961/40962/53504 are engine lifecycle. None
    carry script text, and the s1_v2 channel holds 169 of them."""
    for eid in (4103, 4100, 40961, 40962, 53504):
        xml = XML.replace("<EventID>4104</EventID>", f"<EventID>{eid}</EventID>")
        assert record_to_event(xml, "evtx.powershell", PS_REL) is None


@pytest.mark.parametrize(
    "path,expected",
    [
        (PS_REL, "evtx.powershell"),
        (PS_REL.lower(), "evtx.powershell"),
        ("C/Windows/System32/winevt/logs/Security.evtx", "evtx.security"),
        ("C/Windows/System32/winevt/logs/System.evtx", "evtx.system"),
        # The legacy classic log carries no script blocks, which is why it is
        # NOT evtx.powershell. It was unmapped entirely until 2026-09-17 and is
        # now its own family: EID 600 holds HostApplication, the full command
        # line of the process that started PowerShell, and that is present when
        # script-block logging is off and 4104 holds nothing at all.
        ("C/Windows/System32/winevt/logs/Windows PowerShell.evtx", "evtx.ps_classic"),
        # The Admin channel carries engine errors only.
        (
            "C/Windows/System32/winevt/logs/Microsoft-Windows-PowerShell%4Admin.evtx",
            None,
        ),
        ("C/Windows/System32/winevt/logs/Application.evtx", None),
    ],
)
def test_artifact_for(path, expected):
    assert _artifact_for(path.lower()) == expected


def test_can_handle_accepts_the_operational_channel():
    p = EvtxWindowsParser()
    assert p.can_handle(PS_REL) is True
    assert p.can_handle("C/Windows/System32/winevt/logs/Application.evtx") is False


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_real_channel_yields_only_4104():
    """The channel holds 4104 alongside 4103, 4100, 40961, 40962 and 53504.
    Only 4104 is in the vocabulary, so the parser must be selective rather than
    emitting everything it can read."""
    abs_path = Path(COLLECTION) / PS_REL
    if not abs_path.exists():
        pytest.skip("PowerShell operational channel not in this collection")
    events = list(EvtxWindowsParser().parse(abs_path, PS_REL))
    if not events:
        pytest.skip("channel carries no script blocks")
    assert all(e.event_type == "script_block" for e in events)
    assert all(e.source_artifact == "evtx.powershell" for e in events)
    assert all("ScriptBlockId" in e.details for e in events)
