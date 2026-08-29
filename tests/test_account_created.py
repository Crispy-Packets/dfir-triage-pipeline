"""EID 4720 account creation: the created account must be named.

Written for A-4, which requires the account-creation base rate to be measured
rather than assumed. A count alone does not satisfy that: telling four standing
lab accounts apart from one deliberately staged testuser needs the account
names, and those live in TargetUserName.
"""

import os
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.evtx_windows import EvtxWindowsParser, record_to_event

SEC_REL = "C/Windows/System32/winevt/logs/Security.evtx"

XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4720</EventID>
    <TimeCreated SystemTime="2026-08-24T18:44:37.368349Z"/>
    <EventRecordID>15707</EventRecordID>
    <Computer>WINDOWS10</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">testuser</Data>
    <Data Name="TargetDomainName">WINDOWS10</Data>
    <Data Name="SubjectUserName">admin_local</Data>
    <Data Name="SubjectDomainName">WINDOWS10</Data>
  </EventData>
</Event>"""


def test_created_account_is_recorded():
    """D-029: the parser previously kept only SubjectUserName, so every
    account-creation row named the operator and never the new account. A base
    rate could be counted but its members could not be told apart."""
    e = record_to_event(XML, "evtx.security", SEC_REL)
    assert e.event_type == "account_created"
    assert e.details["TargetUserName"] == "testuser"


def test_creator_and_created_are_both_kept_and_distinct():
    """These are different accounts and conflating them inverts the finding:
    admin_local created testuser, not the other way round."""
    d = record_to_event(XML, "evtx.security", SEC_REL).details
    assert d["TargetUserName"] == "testuser"
    assert d["SubjectUserName"] == "admin_local"


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_measured_base_rate_on_the_real_collection():
    """A-4: account creation is noisy, and this is the proof rather than the
    assertion.

    clean_a carries 4 and clean_b 5. Three are lab accounts created on
    2026-08-12 (Youssef, janed, admin_local), one is the built-in
    WDAGUtilityAccount created by Windows at install, and the fifth -- present
    only in clean_b -- is testuser, staged at 2026-08-24T18:44:37Z, thirteen
    minutes before that collection was acquired at 18:58:05Z.

    Week 4 must not read an account-creation event as a detection on this
    corpus: every one of them is benign, and the scenario collection contains
    none at all.
    """
    abs_path = Path(COLLECTION) / SEC_REL
    if not abs_path.exists():
        pytest.skip("Security.evtx not in this collection")

    created = [
        e
        for e in EvtxWindowsParser().parse(abs_path, SEC_REL)
        if e.event_type == "account_created"
    ]
    names = {e.details.get("TargetUserName") for e in created}
    assert all(n for n in names), "every 4720 must name the account it created"

    name = str(COLLECTION)
    if "clean_a" in name:
        assert len(created) == 4
        assert names == {"WDAGUtilityAccount", "Youssef", "janed", "admin_local"}
    elif "clean_b" in name:
        assert len(created) == 5
        assert "testuser" in names
    elif "s1_v2" in name:
        # The Security log was cleared at 23:05:06; nothing before it survives,
        # and no account was created after it.
        assert created == []
