"""The correlation engine (Person A, Week 3, A-8 and A-9).

A-8 requires six categories: positive, negative, boundary-window, ordering,
duplicate, missing-field. Missing-field lives in test_engine_conditions.py; the
other five are here, plus A-9's fabricated-join test, which is the one the
acceptance gate turns on.
"""

from __future__ import annotations

import dataclasses
import random
from datetime import timedelta
from pathlib import Path

import pytest
from conftest import (
    ARRIVAL,
    ARRIVAL_TO_EXECUTION,
    EXECUTION,
    LOG_CLEAR,
    download,
    execution,
    log_cleared,
    runkey,
    service_install,
)

from dfir_triage_pipeline.core import engine
from dfir_triage_pipeline.core.ruleset import Window, load_rules, parse_duration

RULES_ROOT = Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture(scope="module")
def rules():
    return {r.rule_id: r for r in load_rules(RULES_ROOT)}


def run_one(rule, events):
    return engine.run([rule], events)[0]


class TestPositive:
    """Category 1. The chain the acceptance gate names."""

    def test_download_to_execution_is_reconstructed(self, rules):
        findings = run_one(rules["R-CORR-0001"], [download(), execution()])
        assert len(findings) == 1
        f = findings[0]
        assert f.time_claim == "observed_interval"
        assert f.window_observed_seconds == pytest.approx(2229.122025, abs=1e-6)

    def test_every_matched_event_names_its_source(self, rules):
        """Schema section 7: a finding that cannot name the source_file and
        source_locator of every event it matched is not acceptable output."""
        f = run_one(rules["R-CORR-0001"], [download(), execution()])[0]
        for matched in f.matched:
            assert matched.source_file and matched.source_locator
        assert len(f.provenance_lines()) == 2

    def test_finding_id_is_deterministic(self, rules):
        a = run_one(rules["R-CORR-0001"], [download(), execution()])[0]
        b = run_one(rules["R-CORR-0001"], [execution(), download()])[0]
        assert a.finding_id == b.finding_id


class TestNegative:
    """Category 2."""

    def test_a_download_alone_produces_nothing(self, rules):
        assert run_one(rules["R-CORR-0001"], [download()]) == []

    def test_different_executables_do_not_join(self, rules):
        events = [download(name="report.pdf.exe"), execution(name="INVOICE_SCAN.EXE")]
        assert run_one(rules["R-CORR-0001"], events) == []

    def test_system_accounts_are_not_a_shared_principal(self, rules):
        """R-CORR-0004 joins on entity.user. LocalSystem is excluded, so the
        VirtualBox services drop out before the rule evaluates anything."""
        events = [service_install(user="LocalSystem"), log_cleared(user="LocalSystem")]
        assert run_one(rules["R-CORR-0004"], events) == []


class TestBoundaryWindow:
    """Category 3 -- the one A-8 says catches real bugs.

    The window is PT45M. The measured interval is 37m 09.122025s as the engine
    sees it -- 37m 09.122024s from the raw FILETIME, one microsecond earlier,
    because windowsprefetch and the FILETIME conversion disagree by that much
    (D-013). Both window edges are tested at one microsecond, not at a
    comfortable margin, so the distinction is not academic here.
    """

    def test_exactly_at_the_edge_matches(self, rules):
        at_edge = ARRIVAL + timedelta(minutes=45)
        findings = run_one(rules["R-CORR-0001"], [download(), execution(at=at_edge)])
        assert len(findings) == 1

    def test_one_microsecond_outside_does_not(self, rules):
        past_edge = ARRIVAL + timedelta(minutes=45, microseconds=1)
        assert run_one(rules["R-CORR-0001"], [download(), execution(at=past_edge)]) == []

    def test_the_real_interval_sits_inside_with_headroom(self, rules):
        assert ARRIVAL_TO_EXECUTION < timedelta(minutes=45)
        assert ARRIVAL_TO_EXECUTION.total_seconds() == pytest.approx(2229.122025, abs=1e-6)

    def test_a_thirty_minute_window_would_have_missed_the_only_chain(self):
        """Stated as a test so the justification in the rule file cannot quietly
        stop being true."""
        assert ARRIVAL_TO_EXECUTION > timedelta(minutes=30)


class TestOrdering:
    """Category 4."""

    def test_execution_before_download_is_not_a_chain(self, rules):
        early = ARRIVAL - timedelta(minutes=5)
        assert run_one(rules["R-CORR-0001"], [download(), execution(at=early)]) == []

    def test_input_order_does_not_change_the_result(self, rules):
        forward = run_one(rules["R-CORR-0001"], [download(), execution()])
        reversed_ = run_one(rules["R-CORR-0001"], [execution(), download()])
        assert [f.finding_id for f in forward] == [f.finding_id for f in reversed_]


class TestDuplicate:
    """Category 5."""

    def test_repeated_downloads_yield_one_chain_not_many(self, rules):
        """Nine earlier invoice_scan.exe downloads precede the real one (D-027).
        One chain observed once is the honest shape, not nine chains."""
        earlier = [
            download(at=ARRIVAL - timedelta(days=3), total_bytes="201216"),
            download(at=ARRIVAL - timedelta(days=2), total_bytes="360448"),
        ]
        findings = run_one(rules["R-CORR-0001"], [*earlier, download(), execution()])
        assert len(findings) == 1

    def test_the_matched_download_is_the_one_inside_the_window(self, rules):
        stale = download(at=ARRIVAL - timedelta(days=3), total_bytes="201216")
        findings = run_one(rules["R-CORR-0001"], [stale, download(), execution()])
        matched_ids = {m.event_id for m in findings[0].matched}
        assert stale.event_id not in matched_ids
        assert download().event_id in matched_ids


class TestPresenceNeverEntersAWindow:
    """Schema 5.2 and 5.4, and the reason D-027 exists."""

    def test_runkey_chain_reports_no_interval(self, rules):
        findings = run_one(rules["R-CORR-0003"], [execution(), runkey()])
        assert len(findings) == 1
        f = findings[0]
        assert f.window_observed_seconds is None
        assert f.time_claim != "observed_interval"

    def test_it_matches_despite_the_persistence_being_two_days_older(self, rules):
        """The measured trap: the Run key's last-write is 2026-08-21T01:34:07Z
        and the download it points at is 2026-08-23T22:20:06Z. Any window over
        that pair either finds nothing or inverts the chain."""
        assert runkey().timestamp < ARRIVAL
        assert len(run_one(rules["R-CORR-0003"], [execution(), runkey()])) == 1

    def test_the_finding_says_why_it_carries_no_time(self, rules):
        f = run_one(rules["R-CORR-0003"], [execution(), runkey()])[0]
        assert any("presence" in note for note in f.notes)


class TestFabricatedJoin:
    """A-9. The gate says Scenario 1 produces its chain WITHOUT fabricated
    joins. This is the test that proves it, and a correlation engine that joins
    on proximity alone fails it -- which is the point."""

    def test_two_events_sharing_no_entity_produce_nothing(self, rules):
        """Perfectly adjacent in time, and completely unrelated.

        Asserted as an explicit count rather than a loop over whatever came
        back: a loop body that never runs proves nothing, which is how this
        test passed a deliberate mutation before being rewritten.
        """
        clear = log_cleared(at=EXECUTION + timedelta(seconds=1), user="janed")
        events = [execution(), clear]
        correlated = [
            f
            for rule in rules.values()
            if rule.kind == "correlation"
            for f in run_one(rule, events)
        ]
        assert correlated == [], (
            "a correlation rule joined two events that share no entity key: "
            f"{[(f.rule_id, f.entity_keys) for f in correlated]}"
        )

    def test_events_with_no_derivable_principal_do_not_group_together(self, rules):
        """The absent-key path directly.

        Both events yield no entity.user -- CD-022's recorded "-" is not a
        principal -- and they sit one second apart. An engine that let an absent
        key fall back to the empty string would group them and report a chain.
        """
        service = service_install(user="-", at=LOG_CLEAR - timedelta(seconds=1))
        clear = log_cleared(user="-")
        findings = run_one(rules["R-CORR-0004"], [service, clear])
        assert findings == [], (
            "two events with no derivable principal were joined as though they "
            "shared one; an absent key must never join, not even to another absent key"
        )

    def test_proximity_alone_never_correlates(self, rules):
        """One second apart, different executables, no shared principal."""
        a = download(name="alpha.exe")
        b = execution(at=ARRIVAL + timedelta(seconds=1), name="BETA.EXE")
        assert run_one(rules["R-CORR-0001"], [a, b]) == []

    def test_an_absent_entity_key_does_not_join_to_another_absent_one(self, rules):
        """Two events that both fail to yield an exe_name must not become one
        group keyed on nothing."""
        a = service_install(image="run this thing please", user="janed")
        b = service_install(image="also not a path", user="janed")
        findings = run_one(rules["R-CORR-0004"], [a, b, log_cleared(user="janed")])
        for f in findings:
            assert all(v for _, v in f.entity_keys)


class TestWindowSearch:
    """A non-zero window.min must not cause a valid chain to be missed.

    All four current rules use min: PT0S, where the earliest ordered candidate
    is always the best one. The schema permits a non-zero minimum, and an
    earlier engine took the first ordered candidate, tested the window once and
    abandoned the anchor if it failed -- so a candidate that violated the
    minimum hid a valid one behind it. A miss with no error is the worst
    failure this engine can produce, which is why it is pinned here.
    """

    def _with_min(self, rule, minimum: str):
        return dataclasses.replace(
            rule,
            window=Window("download", "execution", parse_duration(minimum),
                          parse_duration("PT45M"), "probe: minimum enforced"),
        )

    def test_a_candidate_failing_the_minimum_does_not_hide_a_valid_one(self, rules):
        tightened = self._with_min(rules["R-CORR-0001"], "PT10M")
        events = [
            download(),
            execution(at=ARRIVAL + timedelta(minutes=2)),   # violates min
            execution(at=ARRIVAL + timedelta(minutes=20)),  # valid
        ]
        findings = run_one(tightened, events)
        assert len(findings) == 1
        assert findings[0].window_observed_seconds == pytest.approx(1200.0)

    def test_no_valid_candidate_still_produces_nothing(self, rules):
        tightened = self._with_min(rules["R-CORR-0001"], "PT10M")
        events = [download(), execution(at=ARRIVAL + timedelta(minutes=2))]
        assert run_one(tightened, events) == []

    def test_a_truncated_search_is_reported_rather_than_silent(self, rules, monkeypatch):
        """If the search budget is ever reached the engine stops looking, which
        is a possible miss. It has to say so."""
        monkeypatch.setattr(engine, "SEARCH_BUDGET", 1)
        events = [download(at=ARRIVAL - timedelta(days=d)) for d in range(4)]
        events += [download(), execution()]
        _, stats = engine.run([rules["R-CORR-0001"]], events)
        assert "R-CORR-0001" in stats.search_truncated


class TestDeterminism:
    """Schema section 9."""

    def test_same_input_same_findings_same_order(self, rules):
        events = [download(), execution(), runkey(), log_cleared(),
                  service_install(user="admin_local", at=LOG_CLEAR - timedelta(minutes=3))]
        first, _ = engine.run(list(rules.values()), events)
        second, _ = engine.run(list(rules.values()), list(reversed(events)))
        assert [f.finding_id for f in first] == [f.finding_id for f in second]

    def test_thirty_shuffles_produce_identical_output(self, rules):
        """Reversing the input is a weak shuffle. Random orderings are the test
        that actually exercises the sort's tie-breakers."""
        events = [download(), execution(), runkey(), log_cleared(),
                  service_install(user="admin_local", at=LOG_CLEAR - timedelta(minutes=3)),
                  download(at=ARRIVAL - timedelta(days=2), total_bytes="360448")]
        reference = [f.finding_id for f in engine.run(list(rules.values()), events)[0]]
        rng = random.Random(20260830)
        for _ in range(30):
            shuffled = events[:]
            rng.shuffle(shuffled)
            produced, _ = engine.run(list(rules.values()), shuffled)
            assert [f.finding_id for f in produced] == reference

    def test_findings_sort_by_time_then_rule(self, rules):
        events = [download(), execution(), runkey(), log_cleared()]
        findings, _ = engine.run(list(rules.values()), events)
        keys = [(f.first_timestamp, f.rule_id) for f in findings]
        assert keys == sorted(keys)
