"""Every collected EVTX channel is read; every History table that carries
user activity is read.

Both of these were previously bounded by judgement rather than by evidence:
95 of 100 channels went unparsed because I decided they added nothing, and
`History` was read for `downloads` alone with the omission documented as a
stated limit. A stated limit is still a limit.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline.parsers.evtx_windows import (
    EvtxWindowsParser,
    _artifact_for,
    generic_artifact,
)

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")
LOGS = "C/Windows/System32/winevt/logs"

needs_s1v3 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3").is_dir(), reason="s1_v3 required"
)


class TestGenericChannelNaming:
    def test_the_name_comes_from_the_file(self):
        """Derived, not assigned, so a channel this pipeline has never seen
        still lands in a predictable family."""
        assert generic_artifact(
            f"{LOGS}/microsoft-windows-bits-client%4operational.evtx".lower()
        ) == "evtx.x.microsoft-windows-bits-client.operational"

    def test_the_collector_encoding_is_decoded(self):
        """%4 is the backslash between provider and channel."""
        assert "%4" not in generic_artifact(f"{LOGS}/a%4b.evtx")

    def test_spaces_survive_as_hyphens(self):
        """`Windows PowerShell.evtx` is curated, but other legacy names carry
        spaces and a family name with one would be awkward downstream."""
        assert " " not in generic_artifact(f"{LOGS}/some legacy name.evtx")

    def test_every_generic_name_is_prefixed(self):
        """So a consumer can tell an interpreted family from a raw one at a
        glance, and the validator can accept them as a class."""
        assert generic_artifact(f"{LOGS}/anything.evtx").startswith("evtx.x.")


class TestCuratedChannelsWin:
    @pytest.mark.parametrize(
        "name,expected",
        [
            ("security.evtx", "evtx.security"),
            ("system.evtx", "evtx.system"),
            ("microsoft-windows-powershell%4operational.evtx", "evtx.powershell"),
            ("microsoft-windows-windows defender%4operational.evtx", "evtx.defender"),
            ("windows powershell.evtx", "evtx.ps_classic"),
        ],
    )
    def test_a_curated_channel_keeps_its_family(self, name, expected):
        """If a curated channel fell through to the generic branch its EIDs
        would stop being interpreted, and every rule joined on `logon` or
        `process_exec` would silently match nothing."""
        assert _artifact_for(f"{LOGS}/{name}".lower()) == expected


class TestDirectoryAnchor:
    def test_an_evtx_outside_the_log_directory_is_not_handled(self):
        """A .evtx in Downloads is a file somebody copied, not this machine's
        event log. Reading it would attribute another host's events here."""
        parser = EvtxWindowsParser()
        assert not parser.can_handle("C/Users/janed/Downloads/Security.evtx")
        assert not parser.can_handle("C/Temp/Application.evtx")


@needs_s1v3
class TestEveryChannelIsRead:
    def test_no_collected_channel_is_skipped(self):
        """THE property. 95 of 100 channels were unparsed by judgement; that
        is now zero."""
        parser = EvtxWindowsParser()
        root = EVIDENCE / "collection_s1_v3"
        skipped = [
            p.relative_to(root).as_posix()
            for p in root.rglob("*.evtx")
            if not parser.can_handle(p.relative_to(root).as_posix())
        ]
        assert skipped == [], f"unhandled channels: {skipped[:5]}"

    def test_the_generic_families_carry_real_records(self):
        """Measured: 46,464 records across 88 generic families on s1_v3."""
        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        generic = [e for e in events if e.source_artifact.startswith("evtx.x.")]
        assert len(generic) > 40000
        assert len({e.source_artifact for e in generic}) > 50

    def test_generic_records_are_log_records_not_interpreted(self, ):
        """The honest position: the evidence is in the timeline and
        searchable, and the pipeline invents no semantics for EIDs it has not
        studied."""
        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        generic = [e for e in events if e.source_artifact.startswith("evtx.x.")]
        assert {e.event_type for e in generic} == {"log_record"}
        assert all(e.timestamp_type == "recorded" for e in generic[:2000])

    def test_no_evtx_parse_failures(self):
        _, stats = collect_events(EVIDENCE / "collection_s1_v3")
        assert [f for f in stats.failures if f[0] == "evtx_windows"] == []


@needs_s1v3
class TestBrowserVisitsAndSearches:
    @pytest.fixture(scope="class")
    def browser(self):
        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        rows = [e for e in events if e.source_artifact == "browser"]
        assert rows
        return rows

    def test_visits_are_read_not_only_downloads(self, browser):
        """Measured on s1_v3: 613 visits and 65 search terms against 86
        downloads. The parser read the 86 alone for most of the project."""
        kinds = {e.event_type for e in browser}
        assert {"file_download", "page_visited", "search_term"} <= kinds
        visits = [e for e in browser if e.event_type == "page_visited"]
        assert len(visits) > 500

    def test_typed_visits_are_distinguished(self, browser):
        """`typed` means the user wrote the address rather than following a
        link -- the discriminating value in the transition mask."""
        typed = [e for e in browser if e.details.get("transition") == "typed"]
        assert typed

    def test_the_raw_transition_is_always_kept(self, browser):
        """The name table is incomplete by design; the mask must survive it."""
        visits = [e for e in browser if e.event_type == "page_visited"]
        assert all("transition_raw" in e.details for e in visits)

    def test_search_terms_carry_the_term(self, browser):
        terms = [e for e in browser if e.event_type == "search_term"]
        assert terms
        assert all(e.details["search_term"] for e in terms)

    def test_locators_stay_unique_across_the_three_tables(self, browser):
        by_file: dict[str, list[str]] = {}
        for event in browser:
            by_file.setdefault(event.source_file, []).append(event.source_locator)
        for locators in by_file.values():
            assert len(locators) == len(set(locators))


class TestTheDeliveryUrlOnHost1:
    def test_the_operator_typed_the_payload_url(self):
        """s1_v2's search terms hold the attacker infrastructure directly --
        `http://192.168.50.5:8000/invoice_scan.exe` typed into the address
        bar. The downloads table alone did not carry this."""
        root = EVIDENCE / "collection_s1_v2"
        if not root.is_dir():
            pytest.skip("collection_s1_v2 not present")
        events, _ = collect_events(root)
        terms = [
            e
            for e in events
            if e.source_artifact == "browser" and e.event_type == "search_term"
        ]
        assert terms
        assert any("invoice_scan.exe" in str(e.path).lower() for e in terms)
