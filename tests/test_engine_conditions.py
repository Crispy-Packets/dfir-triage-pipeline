"""Condition semantics (Person A, Week 3, A-8).

The clause under test throughout is schema section 3.4: an unknown field is a
load-time error, a declared-but-absent value makes a condition FALSE, and a
negative operator is false on an absent field too. If a negative operator were
true on absence, every event from a parser that does not emit the key would
match, and absence would become evidence.
"""

from __future__ import annotations

import pytest
from conftest import EXECUTION, download, execution, make_event

from dfir_triage_pipeline.core.engine import EngineStats, evaluate_condition, read_field
from dfir_triage_pipeline.core.ruleset import Condition


def cond(field: str, op: str, value=None, ci: bool = False) -> Condition:
    return Condition(field=field, op=op, value=value, ci=ci, has_value=value is not None)


class TestFieldAddressing:
    def test_event_attribute_by_bare_name(self):
        assert read_field(execution(), "source_artifact") == "prefetch"

    def test_details_key_needs_its_prefix(self):
        assert read_field(execution(), "details.executable") == "INVOICE_SCAN.EXE"

    def test_a_bare_unknown_name_raises_rather_than_missing_quietly(self):
        """A typo must not silently resolve to a details lookup that finds
        nothing -- that is the failure the prefix rule exists to prevent."""
        with pytest.raises(KeyError):
            read_field(execution(), "executable")


class TestMissingField:
    """Category 6 of A-8: missing-field."""

    def test_absent_details_key_makes_the_condition_false(self):
        assert evaluate_condition(execution(), cond("details.nope", "equals", "x")) is False

    def test_absent_is_counted_so_a_dead_rule_is_visible(self):
        stats = EngineStats()
        evaluate_condition(execution(), cond("details.nope", "equals", "x"), stats)
        assert stats.absent_field_skips["details.nope"] == 1

    @pytest.mark.parametrize("op", ["not_equals", "not_contains", "not_in"])
    def test_negative_operators_are_false_on_an_absent_field(self, op):
        """The clause that matters most. If these were true, absence would be
        evidence and every parser that omits the key would match."""
        value = ["x"] if op == "not_in" else "x"
        assert evaluate_condition(execution(), cond("details.nope", op, value)) is False

    def test_absence_is_asserted_explicitly_or_not_at_all(self):
        assert evaluate_condition(execution(), cond("details.nope", "absent")) is True
        assert evaluate_condition(execution(), cond("details.executable", "present")) is True

    def test_a_recorded_dash_is_not_an_absent_field(self):
        """CD-022: '-' is a value the log wrote; empty is a field the parser did
        not find. A rule can still tell them apart."""
        event = make_event(EXECUTION, "evtx.security", "logon", "recorded",
                           details={"IpAddress": "-"})
        assert evaluate_condition(event, cond("details.IpAddress", "equals", "-")) is True
        assert evaluate_condition(event, cond("details.IpAddress", "absent")) is False


class TestOperators:
    def test_case_sensitivity_is_opt_in(self):
        event = execution()
        assert evaluate_condition(event, cond("details.executable", "equals",
                                              "invoice_scan.exe")) is False
        assert evaluate_condition(event, cond("details.executable", "equals",
                                              "invoice_scan.exe", ci=True)) is True

    def test_matches_uses_the_pattern_verbatim(self):
        assert evaluate_condition(download(), cond("path", "matches",
                                                   r"(?i)\\users\\[^\\]+\\downloads\\")) is True

    def test_numeric_comparison_across_string_values(self):
        """details values are serialised as strings; a size comparison still
        has to work without the rule author casting anything."""
        assert evaluate_condition(download(), cond("details.bytes", "gt", 1000)) is True
        assert evaluate_condition(download(), cond("details.bytes", "gt", 99999)) is False

    def test_unknown_operator_raises(self):
        with pytest.raises(KeyError):
            evaluate_condition(execution(), cond("path", "sounds_like", "x"))
