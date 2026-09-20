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

#: Candidate examinations allowed per rule, per entity group. Generous: the real
#: groups are single digits, because they are keyed on one executable name. If it
#: is ever reached the search stops, which is a possible MISSED, so the rule is
#: recorded in `search_truncated` and the run summary prints it. A truncated
#: search that says nothing would be the same silent miss in a new costume.
SEARCH_BUDGET = 100_000


@dataclass
class EngineStats:
    """What the run summary reports. A rule whose skip count equals the number
    of events it selected is doing nothing, and this is where that shows."""

    events_seen: int = 0
    rules_evaluated: int = 0
    absent_field_skips: dict[str, int] = None  # type: ignore[assignment]
    findings_by_rule: dict[str, int] = None  # type: ignore[assignment]
    search_truncated: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.absent_field_skips is None:
            self.absent_field_skips = {}
        if self.findings_by_rule is None:
            self.findings_by_rule = {}
        if self.search_truncated is None:
            self.search_truncated = set()


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


#: Directories an unprivileged user can write to, as a path SHAPE rather than
#: as a list of names. Deliberately the same markers `features._USER_WRITABLE`
#: uses, so the rule layer and the anomaly layer cannot disagree about what
#: "user-writable" means for the same path.
_USER_WRITABLE_MARKERS = (
    r"\users" + "\\",
    r"\appdata" + "\\",
    r"\temp" + "\\",
    r"\programdata" + "\\",
    r"\downloads" + "\\",
    r"\public" + "\\",
)

#: Environment variables that expand into a user-writable location. An autorun
#: value often stores the unexpanded form, and %APPDATA% is as user-writable as
#: the path it expands to.
_USER_WRITABLE_VARS = ("%appdata%", "%localappdata%", "%temp%", "%tmp%", "%userprofile%")

#: Locations only an administrator can write to. Checked FIRST, because
#: `C:\Program Files\Common Files\...\Users Guide\` would otherwise
#: match on the substring and a system path would be called user-writable.
_SYSTEM_MARKERS = (
    r"\program files" + "\\",
    r"\program files (x86)" + "\\",
    r"\windows" + "\\",
    r"\programw6432" + "\\",
    "%programfiles%",
    "%systemroot%",
    "%windir%",
)


def _is_user_writable(raw: str) -> bool:
    """Whether a path sits somewhere an unprivileged user can write.

    A SHAPE predicate, not a name list. `docs/per-family-features.md` and the
    `expected:` notes on R-ATOMIC-0006 and R-CORR-0003 both record why this
    distinction matters: suppressing `onedrive.exe` or `msedge.exe` by name
    would improve the base rates on this corpus and would not survive contact
    with a different estate. Asking where the binary lives is a property of the
    finding rather than of this lab.

    System locations are tested first and win. A path under Program Files that
    happens to contain the substring "users" is not user-writable, and the
    ordering is what makes that true rather than a longer regex.
    """
    text = raw.replace("/", "\\").lower()
    if not text:
        return False
    if any(m in text for m in _SYSTEM_MARKERS):
        return False
    if any(v in text for v in _USER_WRITABLE_VARS):
        return True
    return any(m in text for m in _USER_WRITABLE_MARKERS)


@dataclass(frozen=True, slots=True)
class RunContext:
    """Corpus-level facts a condition may ask about, computed once per run.

    Only `entity_counts` for now: how many events in the whole run name each
    executable, keyed by `entity.exe_name`. It is what `op: rarity_*` reads.

    Computed over the events being SCORED, not over a training baseline, and
    the difference matters for what a rule may claim. `features.build_rarity_index`
    fits a profile on a training collection and applies it unchanged, so it can
    say "unseen in the baseline". A rule can only say "rare within this
    collection". The weaker claim is the honest one for a layer that receives no
    training set, and a rule's description must not imply the stronger one.
    """

    entity_counts: dict[str, int]

    @classmethod
    def build(cls, events: Sequence[Any]) -> RunContext:
        counts: dict[str, int] = {}
        for event in events:
            name = entity.exe_name(event)
            if name:
                counts[name] = counts.get(name, 0) + 1
        return cls(entity_counts=counts)


#: An empty context. Conditions that need corpus facts evaluate false against it
#: rather than raising, so a caller that builds a Finding by hand -- every unit
#: test that does not go through `run()` -- still works.
EMPTY_CONTEXT = RunContext(entity_counts={})


def evaluate_condition(
    event: Any,
    cond: Condition,
    stats: EngineStats | None = None,
    context: RunContext | None = None,
) -> bool:
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

    if cond.op in _RARITY_OPS:
        return _evaluate_rarity(event, cond, context or EMPTY_CONTEXT)

    if absent:
        if stats is not None:
            stats.absent_field_skips[cond.field] = stats.absent_field_skips.get(cond.field, 0) + 1
        return False

    # Cross-field comparison (schema 2.0.0, gap 3). The right-hand side is read
    # from the same event, and an absent right-hand side is false for the same
    # reason an absent left-hand side is: a comparison against nothing is not a
    # match, and treating it as one would make a missing field into evidence.
    if cond.value_field is not None:
        raw_right = read_field(event, cond.value_field)
        if raw_right is _SENTINEL:
            if stats is not None:
                stats.absent_field_skips[cond.value_field] = (
                    stats.absent_field_skips.get(cond.value_field, 0) + 1
                )
            return False
        left = _fold(value, cond.ci)
        right = _fold(raw_right, cond.ci)
        return _apply(left, right, value, raw_right, cond)

    left = _fold(value, cond.ci)
    right = _fold(cond.value, cond.ci)
    return _apply(left, right, value, cond.value, cond)


def _apply(left: Any, right: Any, raw_left: Any, raw_right: Any, cond: Condition) -> bool:
    """Operator dispatch, shared by the literal and cross-field paths.

    `left`/`right` are case-folded when `ci` is set; `raw_left`/`raw_right` are
    not, and the two operators that must not fold use them: `matches` compiles
    its pattern as written, and `_compare` needs the original types rather than
    folded strings.
    """
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
        return bool(re.search(str(raw_right), str(raw_left)))
    if cond.op == "is_user_writable":
        return _is_user_writable(str(raw_left)) is bool(raw_right)
    if cond.op in ("gt", "gte", "lt", "lte"):
        return _compare(raw_left, raw_right, cond.op)
    raise KeyError(f"unknown operator {cond.op!r}; the set is closed (schema section 3.3)")


#: Operators that ask about the corpus rather than about one event.
_RARITY_OPS = frozenset({"entity_count_lte", "entity_count_gte"})


def _evaluate_rarity(event: Any, cond: Condition, context: RunContext) -> bool:
    """How many events in this run name the same executable.

    The claim a rule may make with this is deliberately narrow: **rare within
    this collection**, never "unseen in a baseline". The engine receives no
    training set, so it cannot distinguish a binary that is new from one that is
    merely infrequent here. `features.build_rarity_index` makes the stronger
    claim because it is given a training profile; this is not that.

    An event with no derivable executable name returns False rather than a count
    of zero. Zero would read as "maximally rare" and would make every EVTX
    log-on record the rarest thing in the collection.
    """
    name = entity.exe_name(event)
    if not name:
        return False
    count = context.entity_counts.get(name, 0)
    if count == 0:
        # The event carries a name the context never saw, which happens only
        # when a caller scores events the context was not built from. Treating
        # it as maximally rare would invent a fact.
        return False
    threshold = cond.value
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise ValueError(f"{cond.op} requires an integer value, got {threshold!r}")
    if cond.op == "entity_count_lte":
        return count <= threshold
    return count >= threshold


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
    event: Any,
    conditions: Conditions,
    stats: EngineStats | None = None,
    context: RunContext | None = None,
) -> bool:
    for cond in conditions.all_of:
        if not evaluate_condition(event, cond, stats, context):
            return False
    if conditions.any_of and not any(
        evaluate_condition(event, c, stats, context) for c in conditions.any_of
    ):
        return False
    for cond in conditions.none_of:
        if evaluate_condition(event, cond, stats, context):
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


def _burst_findings(rule: Rule, matched: Sequence[Any]) -> list[Finding]:
    """One finding per burst: N matching events sharing a key inside a window.

    A sliding window over each group's events in time order. The first window
    that reaches `count` produces a finding and the group is then **skipped**,
    rather than emitting one finding per position the window could occupy --
    fifty failed logons in a minute is one spray observed once, and reporting it
    fifty times would be the same event counted repeatedly.

    Events whose `group_by` key cannot be derived are dropped, not pooled. A
    shared "unknown" bucket would manufacture a burst out of unrelated events,
    which is the fabricated-join failure the engine exists to prevent.
    """
    agg = rule.aggregate
    assert agg is not None

    grouped: dict[str, list[Any]] = {}
    for event in matched:
        key = entity.resolve(event, agg.group_by)
        if key:
            grouped.setdefault(key, []).append(event)

    findings: list[Finding] = []
    for key in sorted(grouped):
        bucket = sorted(
            grouped[key],
            key=lambda e: (e.timestamp, e.source_file, e.source_locator, e.event_id),
        )
        start = 0
        for end in range(len(bucket)):
            while bucket[end].timestamp - bucket[start].timestamp > agg.within:
                start += 1
            size = end - start + 1
            if size < agg.count:
                continue
            members = bucket[start : end + 1]
            span = (members[-1].timestamp - members[0].timestamp).total_seconds()
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
        rule_class=rule.rule_class,
                    rule_version=rule.schema_version,
                    schema_version=rule.schema_version,
                    title=rule.title,
                    severity=rule.severity,
                    weight=rule.weight,
                    attack_technique=rule.attack_technique,
                    matched=tuple(MatchedEvent.of(e) for e in members),
                    entity_keys=((agg.group_by, key),),
                    # A burst spans real recorded times, so unlike a presence
                    # event it CAN claim an interval.
                    time_claim="observed_interval",
                    window_observed_seconds=span,
                    reason=(
                        f"{rule.title}: {size} matching events for {agg.group_by}={key} "
                        f"within {span:.3f}s (threshold {agg.count} in "
                        f"{agg.within.total_seconds():.0f}s)"
                    ),
                )
            )
            break  # one finding per group; see docstring
    return findings


def evaluate_atomic(
    rule: Rule,
    events: Sequence[Any],
    stats: EngineStats,
    context: RunContext | None = None,
) -> list[Finding]:
    if rule.aggregate is not None:
        matched = [
            e
            for e in events
            if matches_select(e, rule.select)
            and evaluate_conditions(e, rule.conditions, stats, context)
        ]
        return _burst_findings(rule, matched)

    findings: list[Finding] = []
    for event in events:
        if not matches_select(event, rule.select):
            continue
        if not evaluate_conditions(event, rule.conditions, stats, context):
            continue
        keys = entity.keys_for(event)
        claim = "none" if event.timestamp_type == "presence" else "observed_occurrence"
        findings.append(
            Finding(
                rule_id=rule.rule_id,
        rule_class=rule.rule_class,
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
    step: Step,
    events: Sequence[Any],
    join_on: Sequence[str],
    stats: EngineStats,
    context: RunContext | None = None,
) -> dict[tuple[str, ...], list[Any]]:
    # A step may join on a narrower key set than the rule (gap 6): a lateral
    # chain joins the execution on the binary while the principal changes. The
    # loader guarantees an override shares at least one key with `join.on`, so
    # the projection below always has something to project onto.
    effective = step.join_override or tuple(join_on)

    grouped: dict[tuple[str, ...], list[Any]] = {}
    for event in events:
        if not matches_select(event, step.select):
            continue
        if not evaluate_conditions(event, step.conditions, stats, context):
            continue
        key = _join_key(event, effective)
        if key is None:
            continue
        if step.join_override:
            # Re-key onto the SHARED subset so this step's buckets line up with
            # the other steps'. The override's extra keys have already done
            # their filtering work in _join_key -- an event whose override key
            # could not be derived was dropped above.
            shared_key = tuple(
                entity.resolve(event, k) or "" for k in tuple(join_on)
            )
            if any(not part for part in shared_key):
                continue
            key = shared_key
        grouped.setdefault(key, []).append(event)
    for bucket in grouped.values():
        bucket.sort(key=lambda e: (e.timestamp, e.source_file, e.source_locator, e.event_id))
    return grouped


def evaluate_correlation(
    rule: Rule,
    events: Sequence[Any],
    stats: EngineStats,
    context: RunContext | None = None,
) -> list[Finding]:
    if rule.window is None:
        # ruleset.load_rule guarantees this, so reaching it means a rule was
        # built by hand and bypassed the loader. Fail loudly, never silently.
        raise ValueError(f"{rule.rule_id}: a correlation rule must carry a window")
    per_step = {
        step.name: _candidates(step, events, rule.join_on, stats, context)
        for step in rule.steps
    }
    # A negative step contributes no candidates to the join and is checked
    # against each surviving key instead -- see below. It is excluded from the
    # window by the loader, so it cannot appear in either list here.
    present_steps = [s for s in rule.steps if not s.absent]
    absent_steps = [s for s in rule.steps if s.absent]
    windowed = [s for s in present_steps if s.in_window]
    unwindowed = [s for s in present_steps if not s.in_window]

    required_keys = [
        set(per_step[s.name]) for s in present_steps if not s.optional
    ]
    if not required_keys:
        return []
    shared = set.intersection(*required_keys)

    # Drop every key for which a negative step DID match. The rule claims the
    # absence, so a key with a matching event is not a finding.
    for step in absent_steps:
        shared -= set(per_step[step.name])

    # Repetition bounds, checked per key. min_count > 1 is a stronger
    # requirement than membership of `shared`, which only proves one candidate.
    bounded = [s for s in present_steps if s.min_count > 1 or s.max_count is not None]
    if bounded:
        kept = set()
        for key in shared:
            if all(
                s.min_count <= len(per_step[s.name].get(key, []))
                and (s.max_count is None or len(per_step[s.name].get(key, [])) <= s.max_count)
                for s in bounded
            ):
                kept.add(key)
        shared = kept

    findings: list[Finding] = []
    for key in sorted(shared):
        combination = _first_valid_combination(rule, per_step, key, windowed, stats)
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
    stats: EngineStats | None = None,
) -> list[tuple[Step, Any]] | None:
    """Earliest combination of windowed steps satisfying order AND window.

    Earliest rather than every combination, for two reasons: it is bounded and
    it is deterministic. Reporting one finding per entity per rule is also the
    honest shape -- five downloads of one binary followed by one execution is
    one chain observed once, not five chains.

    **This searches candidates rather than taking the first that satisfies
    ordering.** An earlier version picked, for each later step, the first
    candidate at or after the previous one, tested the window once, and gave up
    on the anchor if it failed. With `window.min` greater than zero that misses
    real chains: a candidate two minutes after the anchor fails a `PT10M`
    minimum, and the version that gave up never reached the valid one twenty
    minutes later. All four current rules use `min: PT0S`, where the earliest
    ordered candidate is always the best one, so nothing in the corpus was
    affected -- but the schema permits a non-zero minimum, and a miss with no
    error is the worst failure this engine can produce. Found by probing the
    engine after the week closed, not by a test that already existed.
    """
    if rule.window is None:
        raise ValueError(f"{rule.rule_id}: a correlation rule must carry a window")
    if not windowed:
        return []

    budget = [SEARCH_BUDGET]

    def search(index: int, previous: Any, chain: list[tuple[Step, Any]]):
        if index == len(windowed):
            return list(chain) if _window_holds(rule, chain) else None
        step = windowed[index]
        for candidate in per_step[step.name].get(key, []):
            if budget[0] <= 0:
                if stats is not None:
                    stats.search_truncated.add(rule.rule_id)
                return None
            budget[0] -= 1
            if (
                previous is not None
                and rule.order == "strict"
                and candidate.timestamp < previous.timestamp
            ):
                continue
            chain.append((step, candidate))
            found = search(index + 1, candidate, chain)
            chain.pop()
            if found is not None:
                return found
        if step.optional:
            return search(index + 1, previous, chain)
        return None

    return search(0, None, [])


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
        rule_class=rule.rule_class,
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
    # Built once for the whole run rather than per rule: the counts are a
    # property of the corpus, not of any rule, and rebuilding them per rule
    # would be both slower and an invitation for two rules to disagree.
    context = RunContext.build(events)
    findings: list[Finding] = []
    for rule in sorted(rules, key=lambda r: r.rule_id):
        if not rule.enabled:
            continue
        stats.rules_evaluated += 1
        produced = (
            evaluate_atomic(rule, events, stats, context)
            if rule.kind == "atomic"
            else evaluate_correlation(rule, events, stats, context)
        )
        stats.findings_by_rule[rule.rule_id] = len(produced)
        findings.extend(produced)
    return sort_findings(findings), stats
