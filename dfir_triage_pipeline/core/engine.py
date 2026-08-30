"""The correlation engine.

Deterministic and time-sorted: the same input gives the same findings in the
same order, every run (schema section 9).

Two properties matter more than any other, and both are enforced here rather
than left to the rule author:

* **No fabricated joins.** Every correlation rule joins on a derived entity key.
  Two events that share no entity are never correlated, however close together
  they are. `ruleset.load_rule` refuses a rule with an empty `join.on`; this
  module never falls back to proximity when a key is absent.
* **`presence` events carry no time claim.** A step whose events are
  `presence`-typed is joined on entity and excluded from the interval
  arithmetic. D-027 is why: the scenario's Run-key persistence carries a
  timestamp two days BEFORE the download it points at, because the value was
  written during an earlier attempt. A window over that pair either finds
  nothing or reports persistence preceding its own delivery.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from . import entity
from .findings import Finding, MatchedEvent, sort_findings
from .ruleset import Condition, Conditions, Rule, Select, Step

#: Static map, load-time only. At run time `Event.timestamp_type` is
#: authoritative and nothing here derives it (schema section 5.3).
PRESENCE_ARTIFACTS = frozenset({"registry", "amcache"})

_NEGATIVE_OPS = frozenset({"not_equals", "not_in", "not_contains"})


@dataclass
class EngineStats:
    """What the run summary reports. A rule whose skip count equals the number
    of events it selected is doing nothing, and this is where that shows."""

    events_seen: int = 0
    rules_evaluated: int = 0
    absent_field_skips: dict[str, int] = None  # type: ignore[assignment]
    findings_by_rule: dict[str, int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.absent_field_skips is None:
            self.absent_field_skips = {}
        if self.findings_by_rule is None:
            self.findings_by_rule = {}


# --------------------------------------------------------------------------- #
# Field access
# --------------------------------------------------------------------------- #

_SENTINEL = object()

_EVENT_ATTRS = frozenset(
    {
        "timestamp",
        "timestamp_type",
        "source_artifact",
        "event_type",
        "action",
        "source_file",
        "source_locator",
        "host",
        "user",
        "path",
        "confidence",
    }
)


def read_field(event: Any, field: str) -> Any:
    """The value a condition addresses, or `_SENTINEL` when it is absent.

    Absent means the artifact did not record it. It is never coerced to "" or 0
    (CONTRACT-RULES section 3), and it is distinguishable from a recorded empty
    string so that a rule can tell a written "-" from a missing field (CD-022).
    """
    if field.startswith("details."):
        key = field[len("details.") :]
        details = getattr(event, "details", None) or {}
        value = details.get(key, _SENTINEL)
        return value if value is not _SENTINEL else _SENTINEL
    if field not in _EVENT_ATTRS:
        # Unknown names are a load-time error in the validator; reaching one here
        # means a rule bypassed validation, so fail loudly rather than not match.
        raise KeyError(
            f"{field!r} is not an Event attribute and has no details. prefix "
            "(schema section 3.2)"
        )
    value = getattr(event, field, None)
    return _SENTINEL if value is None else value


# --------------------------------------------------------------------------- #
# Operators
# --------------------------------------------------------------------------- #


def _fold(value: Any, ci: bool) -> Any:
    if ci and isinstance(value, str):
        return value.casefold()
    return value


def evaluate_condition(event: Any, cond: Condition, stats: EngineStats | None = None) -> bool:
    """One condition against one event.

    The clause that matters: **a negative operator is false on an absent
    field.** `not_equals`, `not_contains` and `not_in` all evaluate false when
    the field is absent, exactly as their positive forms do. If they were true,
    every event from a parser that does not emit the key would match, and
    absence would become evidence. `op: absent` is how absence is asserted.
    """
    value = read_field(event, cond.field)
    absent = value is _SENTINEL

    if cond.op == "present":
        return not absent
    if cond.op == "absent":
        return absent

    if absent:
        if stats is not None:
            stats.absent_field_skips[cond.field] = stats.absent_field_skips.get(cond.field, 0) + 1
        return False

    left = _fold(value, cond.ci)
    right = _fold(cond.value, cond.ci)

    if cond.op == "equals":
        return left == right
    if cond.op == "not_equals":
        return left != right
    if cond.op == "in":
        return left in [_fold(v, cond.ci) for v in (right or [])]
    if cond.op == "not_in":
        return left not in [_fold(v, cond.ci) for v in (right or [])]
    if cond.op == "contains":
        return isinstance(left, str) and str(right) in left
    if cond.op == "not_contains":
        return isinstance(left, str) and str(right) not in left
    if cond.op == "starts_with":
        return isinstance(left, str) and left.startswith(str(right))
    if cond.op == "ends_with":
        return isinstance(left, str) and left.endswith(str(right))
    if cond.op == "matches":
        return bool(re.search(str(cond.value), str(value)))
    if cond.op in ("gt", "gte", "lt", "lte"):
        return _compare(value, cond.value, cond.op)
    raise KeyError(f"unknown operator {cond.op!r}; the set is closed (schema section 3.3)")


def _compare(left: Any, right: Any, op: str) -> bool:
    try:
        if isinstance(left, str) and isinstance(right, int | float):
            left = float(left)
        elif isinstance(right, str) and isinstance(left, int | float):
            right = float(right)
    except ValueError:
        return False
    try:
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right
    except TypeError:
        return False


def evaluate_conditions(
    event: Any, conditions: Conditions, stats: EngineStats | None = None
) -> bool:
    for cond in conditions.all_of:
        if not evaluate_condition(event, cond, stats):
            return False
    if conditions.any_of and not any(
        evaluate_condition(event, c, stats) for c in conditions.any_of
    ):
        return False
    for cond in conditions.none_of:
        if evaluate_condition(event, cond, stats):
            return False
    return True


def matches_select(event: Any, select: Select) -> bool:
    if event.event_type not in select.event_types:
        return False
    if select.source_artifacts and event.source_artifact not in select.source_artifacts:
        return False
    return True


# --------------------------------------------------------------------------- #
# Atomic rules
# --------------------------------------------------------------------------- #


def _time_claim_for(event: Any) -> str:
    if event.timestamp_type == "presence":
        return "none"
    if event.timestamp_type == "last_run":
        return "observed_occurrence"
    return "observed_interval"


def evaluate_atomic(rule: Rule, events: Sequence[Any], stats: EngineStats) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if not matches_select(event, rule.select):
            continue
        if not evaluate_conditions(event, rule.conditions, stats):
            continue
        keys = entity.keys_for(event)
        claim = "none" if event.timestamp_type == "presence" else "observed_occurrence"
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                rule_version=rule.schema_version,
                schema_version=rule.schema_version,
                title=rule.title,
                severity=rule.severity,
                weight=rule.weight,
                attack_technique=rule.attack_technique,
                matched=(MatchedEvent.of(event),),
                entity_keys=tuple(sorted(keys.items())),
                time_claim=claim,
                reason=(
                    f"{rule.title}: {event.action} "
                    f"({event.source_file} :: {event.source_locator})"
                ),
                notes=(
                    ("this event records existence, not when it happened",)
                    if claim == "none"
                    else ()
                ),
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Correlation rules
# --------------------------------------------------------------------------- #


def _join_key(event: Any, join_on: Sequence[str]) -> tuple[str, ...] | None:
    """The entity tuple this event joins on, or None when any part is absent.

    An absent entity key never joins -- not to another absent key, and not to
    the empty string. That is what stops proximity standing in for identity.
    """
    values: list[str] = []
    for name in join_on:
        value = entity.resolve(event, name)
        if not value:
            return None
        values.append(value)
    return tuple(values)


def _candidates(
    step: Step, events: Sequence[Any], join_on: Sequence[str], stats: EngineStats
) -> dict[tuple[str, ...], list[Any]]:
    grouped: dict[tuple[str, ...], list[Any]] = {}
    for event in events:
        if not matches_select(event, step.select):
            continue
        if not evaluate_conditions(event, step.conditions, stats):
            continue
        key = _join_key(event, join_on)
        if key is None:
            continue
        grouped.setdefault(key, []).append(event)
    for bucket in grouped.values():
        bucket.sort(key=lambda e: (e.timestamp, e.source_file, e.source_locator, e.event_id))
    return grouped


def evaluate_correlation(rule: Rule, events: Sequence[Any], stats: EngineStats) -> list[Finding]:
    if rule.window is None:
        # ruleset.load_rule guarantees this, so reaching it means a rule was
        # built by hand and bypassed the loader. Fail loudly, never silently.
        raise ValueError(f"{rule.rule_id}: a correlation rule must carry a window")
    per_step = {
        step.name: _candidates(step, events, rule.join_on, stats) for step in rule.steps
    }
    windowed = [s for s in rule.steps if s.in_window]
    unwindowed = [s for s in rule.steps if not s.in_window]

    required_keys = [
        set(per_step[s.name]) for s in rule.steps if not s.optional
    ]
    if not required_keys:
        return []
    shared = set.intersection(*required_keys)

    findings: list[Finding] = []
    for key in sorted(shared):
        combination = _first_valid_combination(rule, per_step, key, windowed)
        if combination is None:
            continue
        matched = list(combination)

        for step in unwindowed:
            bucket = per_step[step.name].get(key, [])
            if bucket:
                matched.append((step, bucket[0]))
            elif not step.optional:
                matched = []
                break
        if not matched:
            continue

        findings.append(_build_finding(rule, key, matched))
    return findings


def _first_valid_combination(
    rule: Rule,
    per_step: dict[str, dict[tuple[str, ...], list[Any]]],
    key: tuple[str, ...],
    windowed: Sequence[Step],
) -> list[tuple[Step, Any]] | None:
    """Earliest combination of windowed steps satisfying order and window.

    Earliest rather than every combination, for two reasons: it is bounded, and
    it is deterministic. Reporting one finding per entity per rule is also the
    honest shape -- five downloads of the same binary followed by one execution
    is one chain observed once, not five chains.
    """
    if rule.window is None:
        raise ValueError(f"{rule.rule_id}: a correlation rule must carry a window")
    if not windowed:
        return []
    first = windowed[0]
    for anchor in per_step[first.name].get(key, []):
        chain: list[tuple[Step, Any]] = [(first, anchor)]
        previous = anchor
        ok = True
        for step in windowed[1:]:
            picked = None
            for candidate in per_step[step.name].get(key, []):
                if rule.order == "strict" and candidate.timestamp < previous.timestamp:
                    continue
                picked = candidate
                break
            if picked is None:
                if step.optional:
                    continue
                ok = False
                break
            chain.append((step, picked))
            previous = picked
        if not ok:
            continue
        if _window_holds(rule, chain):
            return chain
    return None


def _window_holds(rule: Rule, chain: Sequence[tuple[Step, Any]]) -> bool:
    if rule.window is None:
        return False
    by_name = {step.name: event for step, event in chain}
    start = by_name.get(rule.window.from_step)
    end = by_name.get(rule.window.to_step)
    if start is None or end is None:
        return False
    delta = end.timestamp - start.timestamp
    if rule.order == "strict" and delta < timedelta(0):
        return False
    return rule.window.minimum <= abs(delta) <= rule.window.maximum


def _build_finding(
    rule: Rule, key: tuple[str, ...], matched: Sequence[tuple[Step, Any]]
) -> Finding:
    if rule.window is None:
        raise ValueError(f"{rule.rule_id}: a correlation rule must carry a window")
    by_name = {step.name: event for step, event in matched}
    windowed_present = [e for s, e in matched if s.in_window]
    has_presence = any(e.timestamp_type == "presence" for s, e in matched)

    start = by_name.get(rule.window.from_step)
    end = by_name.get(rule.window.to_step)
    if start is not None and end is not None and len(windowed_present) >= 2:
        observed: float | None = (end.timestamp - start.timestamp).total_seconds()
        claim = "observed_interval"
    else:
        observed = None
        claim = "none" if has_presence and not windowed_present else "observed_occurrence"

    notes: list[str] = []
    if has_presence:
        notes.append(
            "a presence-typed member carries no time of its own: its timestamp is the "
            "containing key's last-write time, shared with its sibling values, and it is "
            "excluded from the interval (schema 5.2, D-027)"
        )
        if claim == "observed_interval":
            claim = "observed_occurrence"

    parts = [f"{step.name}={event.action}" for step, event in matched]
    reason = f"{rule.title}: " + " -> ".join(parts) + f" [{', '.join(key)}]"

    return Finding(
        rule_id=rule.rule_id,
        rule_version=rule.schema_version,
        schema_version=rule.schema_version,
        title=rule.title,
        severity=rule.severity,
        weight=rule.weight,
        attack_technique=rule.attack_technique,
        matched=tuple(MatchedEvent.of(event, step.name) for step, event in matched),
        entity_keys=tuple(zip(rule.join_on, key, strict=True)),
        time_claim=claim,
        reason=reason,
        window_observed_seconds=observed if claim == "observed_interval" else None,
        notes=tuple(notes),
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def run(rules: Iterable[Rule], events: Sequence[Any]) -> tuple[list[Finding], EngineStats]:
    """Evaluate every enabled rule. Findings come back in deterministic order."""
    stats = EngineStats(events_seen=len(events))
    findings: list[Finding] = []
    for rule in sorted(rules, key=lambda r: r.rule_id):
        if not rule.enabled:
            continue
        stats.rules_evaluated += 1
        produced = (
            evaluate_atomic(rule, events, stats)
            if rule.kind == "atomic"
            else evaluate_correlation(rule, events, stats)
        )
        stats.findings_by_rule[rule.rule_id] = len(produced)
        findings.extend(produced)
    return sort_findings(findings), stats
