"""The seven schema-2.0.0 capabilities (2026-09-14).

Each closes a gap found by writing rules against the 1.x grammar. Four of them
have no evidence in this corpus to exercise -- there is no failed-logon burst,
no multi-user chain, no repeated step -- so they are tested against synthetic
events and are declared as such in `docs/schema-v2-gaps.md`. That is the honest
shape: the capability exists and is pinned, and the record says it has not been
seen against real evidence.

The properties asserted are the ones that would let a feature return a plausible
answer while being wrong: a burst reported once per position rather than once per
group, an absent step that matches everything, a join override that correlates
unrelated events.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dfir_triage_pipeline.core import engine, entity_score
from dfir_triage_pipeline.core.findings import Finding, MatchedEvent
from dfir_triage_pipeline.core.ruleset import (
    Aggregate,
    Condition,
    Conditions,
    Rule,
    RuleError,
    Select,
    Step,
    Window,
)
from dfir_triage_pipeline.model import Event

REPO_ROOT = Path(__file__).resolve().parent.parent

BASE = datetime(2026, 9, 14, 10, 0, tzinfo=UTC)


def _ev(offset_s, event_type="logon_failed", user="janed", artifact="evtx.security",
        leaf=None, **details):
    d = dict(details)
    if leaf:
        d["path_basename_canonical"] = leaf
    return Event(
        timestamp=BASE + timedelta(seconds=offset_s),
        source_artifact=artifact,
        event_type=event_type,
        action="acted",
        source_file="f",
        source_locator=f"L{offset_s}",
        timestamp_type="recorded",
        user=user,
        details=d,
    )


def _conds(field="event_type", op="equals", value="logon_failed", **kw):
    return Conditions(all_of=(Condition(field=field, op=op, value=value, has_value=True, **kw),))


# --------------------------------------------------------------------------- #
# Gap 3 -- cross-field comparison
# --------------------------------------------------------------------------- #


class TestCrossFieldComparison:
    def test_equal_fields_match(self):
        event = _ev(0, a="x", b="x")
        cond = Condition(field="details.a", op="equals", value_field="details.b")
        assert engine.evaluate_condition(event, cond) is True

    def test_unequal_fields_do_not(self):
        event = _ev(0, a="x", b="y")
        cond = Condition(field="details.a", op="equals", value_field="details.b")
        assert engine.evaluate_condition(event, cond) is False

    def test_absent_right_hand_side_is_false(self):
        """Consistent with an absent left-hand side. If this matched, a parser
        that does not emit the key would satisfy every comparison against it."""
        event = _ev(0, a="x")
        cond = Condition(field="details.a", op="equals", value_field="details.missing")
        assert engine.evaluate_condition(event, cond) is False

    def test_numeric_comparison_across_fields(self):
        event = _ev(0, small="5", large="50")
        cond = Condition(field="details.small", op="lt", value_field="details.large")
        assert engine.evaluate_condition(event, cond) is True

    def test_contains_across_fields(self):
        event = _ev(0, haystack="abcdef", needle="cde")
        cond = Condition(field="details.haystack", op="contains", value_field="details.needle")
        assert engine.evaluate_condition(event, cond) is True

    def test_value_and_value_field_are_mutually_exclusive(self, tmp_path):
        """Two right-hand sides have no defined precedence, so either resolution
        would make half of all such rules silently mean the other thing."""
        from dfir_triage_pipeline.core.ruleset import _conditions

        with pytest.raises(RuleError, match="mutually exclusive"):
            _conditions(
                {"all": [{"field": "path", "op": "equals", "value": "x", "value_field": "user"}]},
                "where",
            )


# --------------------------------------------------------------------------- #
# Gap 4 -- rarity
# --------------------------------------------------------------------------- #


class TestRarityConditions:
    def _ctx(self, *names):
        events = [_ev(i, leaf=n) for i, n in enumerate(names)]
        return engine.RunContext.build(events)

    def test_rare_entity_matches_lte(self):
        ctx = self._ctx("rare.exe", "common.exe", "common.exe", "common.exe")
        cond = Condition(field="path", op="entity_count_lte", value=1, has_value=True)
        assert engine.evaluate_condition(_ev(0, leaf="rare.exe"), cond, None, ctx) is True

    def test_common_entity_does_not(self):
        ctx = self._ctx("rare.exe", "common.exe", "common.exe", "common.exe")
        cond = Condition(field="path", op="entity_count_lte", value=1, has_value=True)
        assert engine.evaluate_condition(_ev(0, leaf="common.exe"), cond, None, ctx) is False

    def test_gte_is_the_inverse(self):
        ctx = self._ctx("rare.exe", "common.exe", "common.exe", "common.exe")
        cond = Condition(field="path", op="entity_count_gte", value=3, has_value=True)
        assert engine.evaluate_condition(_ev(0, leaf="common.exe"), cond, None, ctx) is True
        assert engine.evaluate_condition(_ev(0, leaf="rare.exe"), cond, None, ctx) is False

    def test_event_with_no_entity_is_false_not_maximally_rare(self):
        """A count of zero would read as 'rarest thing in the collection' and
        would make every EVTX log-on record match a rarity rule."""
        ctx = self._ctx("a.exe", "b.exe")
        cond = Condition(field="path", op="entity_count_lte", value=1, has_value=True)
        assert engine.evaluate_condition(_ev(0), cond, None, ctx) is False

    def test_missing_context_does_not_raise(self):
        """A caller that builds findings by hand gets False, not an exception."""
        cond = Condition(field="path", op="entity_count_lte", value=1, has_value=True)
        assert engine.evaluate_condition(_ev(0, leaf="a.exe"), cond) is False

    def test_non_integer_threshold_is_rejected(self):
        ctx = self._ctx("a.exe")
        cond = Condition(field="path", op="entity_count_lte", value="1", has_value=True)
        with pytest.raises(ValueError, match="requires an integer"):
            engine.evaluate_condition(_ev(0, leaf="a.exe"), cond, None, ctx)


# --------------------------------------------------------------------------- #
# Gap 1 -- aggregation
# --------------------------------------------------------------------------- #


def _burst_rule(count=5, within_s=600, group_by="entity.user"):
    return Rule(
        rule_id="R-TEST-0001",
        kind="atomic",
        title="Failed logon burst",
        description="d",
        severity="high",
        weight=50,
        attack_technique="T1110",
        attack_name="Brute Force",
        enabled=True,
        schema_version="2.0.0",
        select=Select(event_types=("logon_failed",)),
        conditions=_conds(),
        source_path="x",
        aggregate=Aggregate(
            count=count, within=timedelta(seconds=within_s), group_by=group_by
        ),
    )


class TestAggregation:
    def test_burst_inside_window_fires_once(self):
        events = [_ev(i * 60) for i in range(6)]
        found = engine.evaluate_atomic(_burst_rule(), events, engine.EngineStats())
        assert len(found) == 1
        assert len(found[0].matched) == 5

    def test_events_spread_beyond_the_window_do_not_fire(self):
        events = [_ev(i * 600) for i in range(6)]
        assert engine.evaluate_atomic(_burst_rule(), events, engine.EngineStats()) == []

    def test_one_finding_per_group_not_per_position(self):
        """Fifty failures in a minute is one spray observed once. A sliding
        window that emitted at every position would report it 46 times."""
        events = [_ev(i * 6) for i in range(20)]
        found = engine.evaluate_atomic(_burst_rule(), events, engine.EngineStats())
        assert len(found) == 1

    def test_groups_are_independent(self):
        events = [_ev(i * 60) for i in range(6)] + [_ev(i * 60, user="admin") for i in range(2)]
        found = engine.evaluate_atomic(_burst_rule(), events, engine.EngineStats())
        assert [f.entity_keys for f in found] == [(("entity.user", "janed"),)]

    def test_events_without_the_group_key_are_dropped_not_pooled(self):
        """A shared 'unknown' bucket would manufacture a burst from unrelated
        events -- the fabricated join the engine exists to prevent."""
        events = [_ev(i * 60, user=None) for i in range(6)]
        assert engine.evaluate_atomic(_burst_rule(), events, engine.EngineStats()) == []

    def test_finding_claims_an_interval(self):
        events = [_ev(i * 60) for i in range(6)]
        found = engine.evaluate_atomic(_burst_rule(), events, engine.EngineStats())
        assert found[0].time_claim == "observed_interval"
        assert found[0].window_observed_seconds == pytest.approx(240.0)

    def test_count_below_two_is_rejected(self):
        from dfir_triage_pipeline.core.ruleset import _aggregate

        with pytest.raises(RuleError, match="2 or more"):
            _aggregate({"count": 1, "within": "PT10M", "group_by": "entity.user"}, "w")

    def test_ungroupable_key_is_rejected(self):
        """Grouping on `path` would burst on events sharing only a filename."""
        from dfir_triage_pipeline.core.ruleset import _aggregate

        with pytest.raises(RuleError, match="not groupable"):
            _aggregate({"count": 5, "within": "PT10M", "group_by": "path"}, "w")


# --------------------------------------------------------------------------- #
# Gap 9 -- entity aggregation
# --------------------------------------------------------------------------- #


def _finding(rule_id, weight, severity="high", entity_value="a.exe", technique="T1000"):
    return Finding(
        rule_id=rule_id,
        rule_version="1",
        schema_version="1",
        title=rule_id,
        severity=severity,
        weight=weight,
        attack_technique=technique,
        matched=(
            MatchedEvent(
                event_id="e",
                timestamp=BASE,
                timestamp_type="recorded",
                source_artifact="prefetch",
                event_type="process_exec",
                source_file="f",
                source_locator="l",
            ),
        ),
        entity_keys=(("entity.exe_name", entity_value),),
        time_claim="observed_occurrence",
        reason="r",
    )


class TestEntityAggregation:
    def test_combining_is_monotonic(self):
        """An extra rule must never lower a score."""
        assert entity_score.combine_weights([85]) == 85
        assert entity_score.combine_weights([85, 60]) > 85
        assert entity_score.combine_weights([85, 60, 40]) > entity_score.combine_weights([85, 60])

    def test_combining_stays_below_100_without_a_100_rule(self):
        """A plain sum capped at 100 made invoice_scan.exe and onedrive.exe
        indistinguishable -- both 145 clamped to 100, ordering destroyed at the
        top of the list. The combination must leave headroom."""
        assert entity_score.combine_weights([85, 60]) == 94
        assert entity_score.combine_weights([90] * 10) < 100

    def test_a_100_weight_reaches_100(self):
        assert entity_score.combine_weights([100]) == 100

    def test_negative_weight_cannot_invert_the_scale(self):
        assert entity_score.combine_weights([50, -80]) == 50

    def test_distinct_rules_not_distinct_findings(self):
        """A rule firing five times contributes its weight once, or the score
        would measure how many registry values a program registered."""
        findings = [_finding("R-A", 60) for _ in range(5)]
        entity = entity_score.aggregate(findings)[0]
        assert entity.score == 60
        assert entity.finding_count == 5
        assert entity.rule_ids == ("R-A",)

    def test_worst_severity_wins(self):
        findings = [_finding("R-A", 10, "low"), _finding("R-B", 20, "critical")]
        assert entity_score.aggregate(findings)[0].severity == "critical"

    def test_findings_with_no_entity_are_dropped(self):
        finding = _finding("R-A", 50)
        object.__setattr__(finding, "entity_keys", ())
        assert entity_score.aggregate([finding]) == []

    def test_order_is_deterministic_on_ties(self):
        a = [_finding("R-A", 50, entity_value="z.exe"), _finding("R-A", 50, entity_value="a.exe")]
        assert [e.value for e in entity_score.aggregate(a)] == ["a.exe", "z.exe"]
        assert [e.value for e in entity_score.aggregate(list(reversed(a)))] == ["a.exe", "z.exe"]


# --------------------------------------------------------------------------- #
# Gaps 2, 6, 7 -- negative steps, join overrides, repetition
# --------------------------------------------------------------------------- #


class TestStepValidation:
    def _step(self, **kw):
        from dfir_triage_pipeline.core.ruleset import load_rule

        return load_rule, kw

    def test_absent_with_in_window_is_rejected(self, tmp_path):
        rule = _rule_yaml(steps_extra="    absent: true\n", in_window="true")
        path = tmp_path / "R-TEST-0002-x.yml"
        path.write_text(rule, encoding="utf-8")
        from dfir_triage_pipeline.core.ruleset import load_rule

        with pytest.raises(RuleError, match="absent and in_window"):
            load_rule(path)

    def test_absent_with_optional_is_rejected(self, tmp_path):
        rule = _rule_yaml(steps_extra="    absent: true\n", optional="true")
        path = tmp_path / "R-TEST-0003-x.yml"
        path.write_text(rule, encoding="utf-8")
        from dfir_triage_pipeline.core.ruleset import load_rule

        with pytest.raises(RuleError, match="absent and optional"):
            load_rule(path)

    def test_max_below_min_is_rejected(self, tmp_path):
        rule = _rule_yaml(steps_extra="    min_count: 5\n    max_count: 2\n")
        path = tmp_path / "R-TEST-0004-x.yml"
        path.write_text(rule, encoding="utf-8")
        from dfir_triage_pipeline.core.ruleset import load_rule

        with pytest.raises(RuleError, match="below min_count"):
            load_rule(path)

    def test_join_override_sharing_no_key_is_rejected(self, tmp_path):
        """Two steps joining on unrelated keys correlate unrelated events."""
        rule = _rule_yaml(steps_extra="    join_override: [entity.host]\n")
        path = tmp_path / "R-TEST-0005-x.yml"
        path.write_text(rule, encoding="utf-8")
        from dfir_triage_pipeline.core.ruleset import load_rule

        with pytest.raises(RuleError, match="shares no key"):
            load_rule(path)


def _rule_yaml(steps_extra="", in_window="false", optional="false"):
    return f"""schema_version: "1.5.0"
id: R-TEST-0009
type: correlation
title: t
description: d
severity: high
weight: 50
enabled: true
attack:
  technique: T1000
  name: n
select:
  event_type: [process_exec]
conditions:
  all:
    - field: event_type
      op: equals
      value: process_exec
steps:
  - name: first
    select:
      event_type: [process_exec]
    conditions:
      all:
        - field: event_type
          op: equals
          value: process_exec
    in_window: true
    optional: false
  - name: second
    select:
      event_type: [file_download]
    conditions:
      all:
        - field: event_type
          op: equals
          value: file_download
    in_window: {in_window}
    optional: {optional}
{steps_extra}join:
  on: [entity.exe_name]
window:
  from: first
  to: first
  min: PT0S
  max: PT1S
  justification: j
expected:
  clean_a: 0
  clean_b: 0
  s1_v2: 0
  clean_c: 0
  s1_v3: 0
order: any
"""


class TestNegativeAndRepeatedSteps:
    def _rule(self, second_step):
        return Rule(
            rule_id="R-TEST-0010",
            kind="correlation",
            title="t",
            description="d",
            severity="high",
            weight=50,
            attack_technique="T1000",
            attack_name="n",
            enabled=True,
            schema_version="2.0.0",
            select=Select(event_types=("process_exec",)),
            conditions=_conds(value="process_exec"),
            source_path="x",
            steps=(
                Step(
                    name="execution",
                    select=Select(event_types=("process_exec",)),
                    conditions=_conds(value="process_exec"),
                    in_window=True,
                    optional=False,
                ),
                second_step,
            ),
            join_on=("entity.exe_name",),
            window=Window("execution", "execution", timedelta(0), timedelta(seconds=1), "j"),
        )

    def test_absent_step_fires_when_nothing_matches(self):
        """'Executed with no arrival record' -- the shape that catches a tool
        which did not come through the download path."""
        rule = self._rule(
            Step(
                name="arrival",
                select=Select(event_types=("file_download",)),
                conditions=_conds(value="file_download"),
                in_window=False,
                optional=False,
                absent=True,
            )
        )
        events = [_ev(0, "process_exec", artifact="prefetch", leaf="tool.exe")]
        found = engine.evaluate_correlation(rule, events, engine.EngineStats())
        assert len(found) == 1

    def test_absent_step_suppresses_when_something_matches(self):
        rule = self._rule(
            Step(
                name="arrival",
                select=Select(event_types=("file_download",)),
                conditions=_conds(value="file_download"),
                in_window=False,
                optional=False,
                absent=True,
            )
        )
        events = [
            _ev(0, "process_exec", artifact="prefetch", leaf="tool.exe"),
            _ev(10, "file_download", artifact="browser", leaf="tool.exe"),
        ]
        assert engine.evaluate_correlation(rule, events, engine.EngineStats()) == []

    def test_min_count_requires_repetition(self):
        rule = self._rule(
            Step(
                name="writes",
                select=Select(event_types=("persistence_autorun",)),
                conditions=_conds(value="persistence_autorun"),
                in_window=False,
                optional=False,
                min_count=3,
            )
        )
        one = [
            _ev(0, "process_exec", artifact="prefetch", leaf="tool.exe"),
            _ev(5, "persistence_autorun", artifact="registry", leaf="tool.exe"),
        ]
        assert engine.evaluate_correlation(rule, one, engine.EngineStats()) == []

        many = one + [
            _ev(6, "persistence_autorun", artifact="registry", leaf="tool.exe"),
            _ev(7, "persistence_autorun", artifact="registry", leaf="tool.exe"),
        ]
        assert len(engine.evaluate_correlation(rule, many, engine.EngineStats())) == 1


class TestValidatorAgreesWithEngine:
    """The validator and the loader are deliberately separate implementations,
    so a bug in one does not pass both. That only helps if they agree about
    which grammar is legal -- a capability the engine supports and the
    validator rejects is unreachable from a rule file.
    """

    def _validator(self):
        import importlib.util
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "validate_rules",
            Path(__file__).resolve().parent.parent / "rules" / "validate_rules.py",
        )
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return mod

    def test_rarity_operators_are_declared(self):
        mod = self._validator()
        assert engine._RARITY_OPS <= mod.OPERATORS
        assert engine._RARITY_OPS == mod.RARITY_OPS

    def test_groupable_keys_agree(self):
        """The engine and the validator must permit the same group_by set, or a
        rule passes one and fails the other."""
        from dfir_triage_pipeline.core import ruleset

        assert ruleset._GROUPABLE == self._validator().GROUPABLE

    def test_validator_accepts_every_new_step_key(self):
        mod = self._validator()
        source = (
            __import__("pathlib").Path(mod.__file__).read_text(encoding="utf-8")
        )
        for key in ("absent", "min_count", "max_count", "join_override"):
            assert f'"{key}"' in source, f"{key} is not in the validator's allowed step keys"

    def test_validator_has_an_aggregate_check(self):
        assert hasattr(self._validator(), "check_aggregate")


def _finding_keys(rule_id, weight, keys, severity="high", technique="T1000"):
    """Like `_finding`, but the caller chooses the entity keys. D-058 is about
    which KINDS are scored, so the keys cannot be hardcoded."""
    return Finding(
        rule_id=rule_id,
        rule_version="1",
        schema_version="1",
        title=rule_id,
        severity=severity,
        weight=weight,
        attack_technique=technique,
        matched=(
            MatchedEvent(
                event_id="e",
                timestamp=BASE,
                timestamp_type="recorded",
                source_artifact="prefetch",
                event_type="process_exec",
                source_file="f",
                source_locator="l",
            ),
        ),
        entity_keys=tuple(keys),
        time_claim="observed_occurrence",
        reason="r",
    )


class TestEntityKindsAreRankedSeparately:
    """D-058.

    `entity.user=youssef` scored 97 on a collection containing no attack, two
    points below the payload's 99, on a scale that mixed entity kinds. A user's
    97 and a binary's 99 do not measure the same thing, and one table invited
    exactly that comparison -- while concealing that binaries separate cleanly
    on their own (clean 86/86/75 high, scenario 99/99 critical).
    """

    def test_host_entities_are_not_scored_at_all(self):
        """One host per collection, so a host ranking is a table of one row;
        and a host aggregates every finding in the run. It was already excluded
        from JOINS, and nothing stated why scoring should differ."""
        findings = [
            _finding_keys("R-A", 60, [("entity.host", "windows10")]),
            _finding_keys("R-B", 70, [("entity.host", "windows10")]),
        ]
        assert entity_score.aggregate(findings) == []
        tables = entity_score.aggregate_by_kind(findings)
        assert "entity.host" not in tables
        assert all(not rows for rows in tables.values())

    def test_a_finding_naming_a_host_and_a_binary_keeps_the_binary(self):
        """Excluding the host must not discard a finding's other entities."""
        findings = [
            _finding_keys(
                "R-A",
                90,
                [("entity.host", "windows10"), ("entity.exe_name", "payload.exe")],
            )
        ]
        scored = entity_score.aggregate(findings)
        assert [(e.key, e.value) for e in scored] == [
            ("entity.exe_name", "payload.exe")
        ]

    def test_each_kind_gets_its_own_worst_first_table(self):
        findings = [
            _finding_keys("R-A", 40, [("entity.exe_name", "low.exe")]),
            _finding_keys("R-B", 90, [("entity.exe_name", "high.exe")]),
            _finding_keys("R-C", 70, [("entity.user", "someone")]),
        ]
        tables = entity_score.aggregate_by_kind(findings)
        assert [e.value for e in tables["entity.exe_name"]] == ["high.exe", "low.exe"]
        assert [e.value for e in tables["entity.user"]] == ["someone"]

    def test_every_scored_kind_is_present_even_when_empty(self):
        """A consumer must never have to tell 'no such kind' from 'none found'."""
        tables = entity_score.aggregate_by_kind([])
        assert set(tables) == set(entity_score.KIND_ORDER)
        assert all(rows == [] for rows in tables.values())

    def test_a_user_and_a_binary_no_longer_share_a_ranking(self):
        """The defect in one assertion. Separating the kinds does not make the
        user score meaningful -- it stops it contaminating the binary table."""
        findings = [
            _finding_keys("R-1", 85, [("entity.user", "youssef")]),
            _finding_keys("R-2", 60, [("entity.user", "youssef")]),
            _finding_keys("R-3", 40, [("entity.user", "youssef")]),
            _finding_keys(
                "R-4", 95, [("entity.exe_name", "payload.exe")], severity="critical"
            ),
        ]
        tables = entity_score.aggregate_by_kind(findings)
        users, exes = tables["entity.user"], tables["entity.exe_name"]
        assert len(users) == 1 and len(exes) == 1
        assert users[0].score > 90
        assert all(e.key == "entity.user" for e in users)
        assert all(e.key == "entity.exe_name" for e in exes)

    def test_run_json_carries_both_views_and_no_host(self):
        """The shape Person A's report consumes. `entities` keeps its name,
        shape and ordering; `entities_by_kind` is additive."""
        from pathlib import Path

        from dfir_triage_pipeline.core import run_json

        findings = [
            _finding_keys(
                "R-A",
                95,
                [("entity.exe_name", "payload.exe"), ("entity.host", "windows10")],
                severity="critical",
            ),
            _finding_keys("R-B", 70, [("entity.user", "janed")]),
        ]
        doc = run_json.build(
            collection=Path("collection_x"),
            events=[],
            findings=findings,
            entities=entity_score.aggregate(findings),
        )
        # Pinned to the constant, not to a literal: this test is about D-058's
        # two entity views, and it failed on the additive 1.2.0 bump (D-072)
        # without either view having changed. A version literal here asserts
        # "nothing was ever added", which is not the claim.
        assert doc["run_json_version"] == run_json.RUN_JSON_VERSION
        kinds = doc["entities_by_kind"]
        assert set(kinds) == set(entity_score.KIND_ORDER)
        assert [e["value"] for e in kinds["entity.exe_name"]] == ["payload.exe"]
        assert [e["value"] for e in kinds["entity.user"]] == ["janed"]
        assert all(e["key"] != "entity.host" for e in doc["entities"])
        assert "entity.host" not in kinds
        # The flat view is exactly the union of the per-kind tables.
        assert sum(len(v) for v in kinds.values()) == len(doc["entities"])


def _load_all_rules():
    """Every rule in the repository, loaded the way the pipeline loads them."""
    from pathlib import Path

    from dfir_triage_pipeline.core.ruleset import load_rules

    return load_rules(Path(__file__).resolve().parent.parent / "rules")


class TestKnownBehaviorRulesDoNotScore:
    """Class 2 rules produce findings but must never move the entity ranking.

    A `known-behavior` rule expresses a real intrusion behaviour that THIS
    corpus does not exercise, so it has no measured true positive anywhere.
    Letting its weight into `entity_score` would move the clean ceiling
    (86/86/75) toward the payload's 99 with no evidence that the movement is
    correct -- and that separation is the project's headline result.

    Excluded in `aggregate`, beside the entity-kind filter, for the same
    reason D-058 excludes `entity.host` there: once, where no consumer can
    reintroduce it.
    """

    def test_a_known_behavior_finding_adds_no_weight(self):
        """The whole point. Same entity, two rules, only Class 1 counts."""
        c1 = _finding_keys("R-A", 40, [("entity.exe_name", "setup.exe")])
        c2 = _finding_keys("R-B", 60, [("entity.exe_name", "setup.exe")])
        c2 = dataclasses.replace(c2, rule_class="known-behavior")

        scored = entity_score.aggregate([c1, c2])

        assert len(scored) == 1
        assert scored[0].score == entity_score.combine_weights([40])
        assert scored[0].rule_ids == ("R-A",)

    def test_an_entity_named_only_by_class_2_is_not_scored_at_all(self):
        """Not "scored at zero" -- absent. A zero-scored entity would still
        appear in the table and in run.json, implying it was ranked."""
        c2 = dataclasses.replace(
            _finding_keys("R-B", 99, [("entity.exe_name", "onlyclass2.exe")]),
            rule_class="known-behavior",
        )
        assert entity_score.aggregate([c2]) == []

    def test_the_default_is_corpus_validated(self):
        """Every Finding built by hand -- and every rule written before the
        class existed -- must behave exactly as it did before."""
        f = _finding_keys("R-A", 40, [("entity.exe_name", "setup.exe")])
        assert f.rule_class == "corpus-validated"
        assert len(entity_score.aggregate([f])) == 1

    def test_every_rule_declares_a_known_class(self):
        """A closed set, so `known-behaviour` (British spelling) or any other
        typo fails here rather than silently scoring."""
        rules = _load_all_rules()
        allowed = {"corpus-validated", "known-behavior"}
        bad = {r.rule_id: r.rule_class for r in rules
               if r.rule_class not in allowed}
        assert bad == {}, f"unknown rule_class: {bad}"

    def test_a_rule_with_unmeasured_expectations_is_class_2(self):
        """The guard against forgetting `class:` on a new Class 2 rule.

        `validate_rules.py` cannot catch this -- it is Person A's file and does
        not know the key -- so this is the only check that will. A rule
        declaring `unmeasured` for any collection has, by definition, no
        measured base rate there, and must not contribute to the ranking.
        """
        rules = _load_all_rules()
        offenders = []
        for rule in rules:
            values = [v for _, v in rule.expected]
            if "unmeasured" in values and rule.rule_class != "known-behavior":
                offenders.append(rule.rule_id)
        assert offenders == [], (
            "rules carry `unmeasured` expectations but are not marked "
            f"`class: known-behavior`: {offenders}"
        )


class TestEveryRuleDeclaresAPhase:
    """`phase:` is metadata -- nothing in matching or scoring reads it, so a
    wrong value cannot be caught by a result changing. These checks are the
    only thing standing between the field and silent drift.

    The agreement check is the point of the field: where the event_type -> phase
    map in docs/evidence/phase-span-2026-09-20.md and the rule schema are
    naming the same stage, an atomic rule's phase must match the map. Drift
    between the two layers is the failure this catches.

    They are no longer the same taxonomy -- the map has four stages taken from
    the scenario's steps, the schema has five -- so the check covers the types
    where both speak, and names the exception rather than hiding it.
    """

    # docs/evidence/phase-span-2026-09-20.md, the adopted mapping table.
    # Only the types the 24 rules actually select on; the table is larger.
    #
    # `network_usage` is deliberately absent. That document maps it to EXECUTE
    # because its four stages are the scenario's own steps and it has no exfil
    # bucket; schema 2.1.0 has `exfiltrate` and R-ATOMIC-0014 (T1041) uses it.
    # The two layers disagree about that one event type on purpose, so it is
    # not checked here. Flipping the table value instead would assert the
    # measured document says something it does not.
    EVENT_TYPE_PHASE = {
        "file_download": "delivery",
        "process_exec": "execute",
        "script_block": "execute",
        "program_inventoried": "execute",
        "persistence_autorun": "persist",
        "service_install": "persist",
        "service_registered": "persist",
        "wmi_subscription": "persist",
        "account_created": "persist",
        "file_deleted": "destroy",
        "log_cleared": "destroy",
    }

    def _rules(self):
        from dfir_triage_pipeline.core.ruleset import load_rules

        return load_rules(REPO_ROOT / "rules", include_disabled=True)

    def test_every_rule_on_disk_carries_a_phase_in_the_closed_set(self):
        phases = {"delivery", "execute", "persist", "destroy", "exfiltrate"}
        offenders = [r.rule_id for r in self._rules() if r.phase not in phases]
        assert offenders == [], f"rules with no phase or a phase outside the set: {offenders}"

    def test_atomic_phases_agree_with_the_event_type_map(self):
        """Where the phase-span map assigns the selected event type a stage,
        the rule must name the same stage. Types the map deliberately leaves
        unmapped (the record-keeping group, `file_opened` among them) are
        skipped -- the rule's phase there is a judgement, not a lookup.
        """
        disagreements = []
        for rule in self._rules():
            if rule.kind != "atomic":
                continue
            types = list(rule.select.event_types)
            if len(types) != 1:
                continue
            expected = self.EVENT_TYPE_PHASE.get(types[0])
            if expected is None:
                continue
            if rule.phase != expected:
                disagreements.append(
                    f"{rule.rule_id}: {types[0]} maps to {expected}, "
                    f"rule says {rule.phase}"
                )
        assert disagreements == [], disagreements

    def test_the_validator_declares_the_same_closed_set(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "validate_rules", REPO_ROOT / "rules" / "validate_rules.py"
        )
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        assert mod.PHASES == frozenset(
            {"delivery", "execute", "persist", "destroy", "exfiltrate"}
        )
        assert "phase" in mod.REQUIRED_TOP
