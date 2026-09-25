"""Loading rule files into the structures the engine evaluates.

This is the engine's loader, not the checker. `rules/validate_rules.py` remains
the standalone checker and the two are deliberately independent: a single shared
implementation would mean a bug in the grammar passes both. What guards against
them drifting apart is a test -- `tests/test_ruleset_agrees_with_validator.py`
asserts the engine loads exactly the set the validator passes, over the real
rules in the repository.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

# Bumped to 2 on 2026-09-15 with schema 2.0.0. Every 1.x rule file
# still loads: the check below accepts the current major and the one
# before it, because a major bump that invalidated ten working rule
# files would be a breaking change and this one is not.
SCHEMA_MAJOR = "2"
SCHEMA_MAJOR_COMPATIBLE = frozenset({"1", "2"})

_DURATION = re.compile(
    r"^P(?!$)(?:(?P<days>\d+)D)?"
    r"(?:T(?!$)(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?$"
)


class RuleError(ValueError):
    """A rule file that cannot be loaded. Always raised at load time, never
    turned into a silent non-match at evaluation time (schema section 3.4)."""


class StrictLoader(yaml.SafeLoader):
    """SafeLoader with anchors and aliases rejected (schema section 1)."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, yaml.events.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not permitted by this schema")
        if getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML anchors are not permitted by this schema")
        return super().compose_node(parent, index)


# PyYAML implements YAML 1.1, where bare on/off/yes/no are booleans. The schema
# says YAML 1.2 core, where they are strings. Without this, `join: {on: [...]}`
# parses as the key True and the join silently disappears.
_BOOL_TAG = "tag:yaml.org,2002:bool"
StrictLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != _BOOL_TAG]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictLoader.add_implicit_resolver(
    _BOOL_TAG, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def parse_duration(text: str) -> timedelta:
    """ISO-8601 duration, restricted to the subset the schema permits."""
    match = _DURATION.match(text or "")
    if not match:
        raise RuleError(f"{text!r} is not an ISO-8601 duration in the permitted subset")
    parts = {k: float(v) for k, v in match.groupdict().items() if v is not None}
    return timedelta(
        days=parts.get("days", 0.0),
        hours=parts.get("hours", 0.0),
        minutes=parts.get("minutes", 0.0),
        seconds=parts.get("seconds", 0.0),
    )


@dataclass(frozen=True, slots=True)
class Condition:
    field: str
    op: str
    value: Any = None
    ci: bool = False
    has_value: bool = False
    #: Compare `field` against another FIELD rather than against `value`
    #: (schema 2.0.0, gap 3). Exactly one of `value` and `value_field` may be
    #: given: a condition that carried both would have two right-hand sides and
    #: no defined precedence.
    value_field: str | None = None


@dataclass(frozen=True, slots=True)
class Conditions:
    all_of: tuple[Condition, ...] = ()
    any_of: tuple[Condition, ...] = ()
    none_of: tuple[Condition, ...] = ()


@dataclass(frozen=True, slots=True)
class Select:
    event_types: tuple[str, ...]
    source_artifacts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Step:
    name: str
    select: Select
    conditions: Conditions
    in_window: bool
    optional: bool
    #: Negative step (schema 2.0.0, gap 2): the chain matches only when NO event
    #: satisfies this step for the joined entity. "Executed with no arrival
    #: record" is the shape -- how a tool that did not come through the download
    #: path is caught.
    #:
    #: A negative step is excluded from the window by construction: there is no
    #: event to measure an interval to. `absent: true` with `in_window: true` is
    #: a load-time error rather than a silently ignored flag.
    absent: bool = False
    #: Repetition (schema 2.0.0, gap 7). `min_count` events must satisfy this
    #: step for the entity; `max_count` is an upper bound, None for unbounded.
    #: "One execution, then five or more registry writes" is the shape.
    min_count: int = 1
    max_count: int | None = None
    #: Multi-entity chains (schema 2.0.0, gap 6). When set, this step joins on
    #: these keys instead of the rule's `join.on`. Lateral movement is the
    #: shape it exists for: user A's credentials used on host B, where the
    #: binary is the constant and the principal changes.
    #:
    #: The override must share at least one key with `join.on`, checked at load
    #: time. Without that overlap the steps have no common ground and the
    #: "chain" would be two unrelated events reported as one -- the fabricated
    #: join the engine exists to prevent.
    join_override: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Aggregate:
    """A burst condition on an atomic rule (schema 2.0.0, gap 1).

    N matching events sharing `group_by` inside `within`. The plan's second
    chain -- "failed-logon **burst** -> success" -- needed this and could not be
    written, so `R-CORR-0002` says *one* failure followed by a success, a weaker
    claim that its description states rather than implies.

    `group_by` is an entity key, never a raw field. A burst of failures against
    one ACCOUNT is a spray; a burst across every account on a domain controller
    at 09:00 is Monday morning. Grouping on `path` or `source_file` would
    correlate events that share only a filename, which is why section 4.3
    forbids joining on those.
    """

    count: int
    within: timedelta
    group_by: str


@dataclass(frozen=True, slots=True)
class Window:
    from_step: str
    to_step: str
    minimum: timedelta
    maximum: timedelta
    justification: str


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    kind: str
    title: str
    description: str
    severity: str
    weight: int
    attack_technique: str
    attack_name: str
    enabled: bool
    schema_version: str
    select: Select
    conditions: Conditions
    source_path: str
    steps: tuple[Step, ...] = ()
    join_on: tuple[str, ...] = ()
    window: Window | None = None
    order: str = "any"
    expected: tuple[tuple[str, str], ...] = ()
    #: Burst condition, atomic rules only (schema 2.0.0, gap 1).
    aggregate: Aggregate | None = None
    #: Rule class. `corpus-validated` (the default, and what every rule written
    #: before 2026-09-20 is) means the rule fires on the scenario and not on
    #: clean, and carries measured `expected:` figures. `known-behavior` means
    #: it expresses a real intrusion behaviour this corpus never exercises, so
    #: it ships a false-positive profile instead of a detection rate.
    #:
    #: **The class decides whether a finding contributes to `entity_score`.**
    #: Only `corpus-validated` does. A known-behavior rule still produces
    #: findings in `findings.csv`; it must never move the entity ranking,
    #: because the 99-vs-86 separation is the project's headline result and a
    #: rule with no measured true positive cannot be allowed to alter it.
    #: Enforced in `entity_score.aggregate`, once, for the same reason D-058
    #: excludes `entity.host` there rather than in each caller.
    rule_class: str = "corpus-validated"
    # Chain stage, from the rule's `phase:`. Metadata only -- no matching or
    # scoring path reads it. Defaults to "" so a hand-built Rule in a test need
    # not carry one; the validator is what makes it mandatory on disk.
    #
    # Closed set of five as of schema 2.1.0: delivery, execute, persist,
    # destroy, exfiltrate. The fifth is not in the phase-span ranking map,
    # whose four stages were the scenario's steps rather than a taxonomy.
    phase: str = ""


def _conditions(node: Any, where: str) -> Conditions:
    if not isinstance(node, dict):
        raise RuleError(f"{where}: conditions must be a mapping of all/any/none")
    groups: dict[str, tuple[Condition, ...]] = {}
    for group in ("all", "any", "none"):
        items = node.get(group) or []
        if not isinstance(items, list):
            raise RuleError(f"{where}.{group}: must be a list")
        built = []
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                raise RuleError(f"{where}.{group}[{index}]: a condition must be a mapping")
            field = item.get("field")
            op = item.get("op")
            if not isinstance(field, str) or not isinstance(op, str):
                raise RuleError(f"{where}.{group}[{index}]: field and op are required")
            if op == "matches":
                try:
                    re.compile(str(item.get("value")))
                except re.error as exc:
                    raise RuleError(f"{where}.{group}[{index}]: regex: {exc}") from None
            value_field = item.get("value_field")
            if value_field is not None:
                if not isinstance(value_field, str):
                    raise RuleError(f"{where}.{group}[{index}]: value_field must be a string")
                if "value" in item:
                    # Two right-hand sides with no defined precedence. Rejected
                    # rather than resolved, because either resolution would make
                    # half of all such rules silently mean the other thing.
                    raise RuleError(
                        f"{where}.{group}[{index}]: value and value_field are mutually "
                        "exclusive -- a condition has one right-hand side"
                    )
            built.append(
                Condition(
                    field=field,
                    op=op,
                    value=item.get("value"),
                    ci=bool(item.get("ci", False)),
                    has_value="value" in item,
                    value_field=value_field,
                )
            )
        groups[group] = tuple(built)
    if not any(groups.values()):
        raise RuleError(f"{where}: at least one of all/any/none must be non-empty")
    return Conditions(groups["all"], groups["any"], groups["none"])


#: Entity keys an aggregate may group on. Same set section 4.3 permits for a
#: correlation join, and for the same reason: `path` and `source_file` group
#: events that share only a filename.
_GROUPABLE = frozenset({"entity.exe_name", "entity.user", "entity.host", "entity.src_ip"})


def _aggregate(node: Any, where: str) -> Aggregate | None:
    """Parse an `aggregate:` block, or None when the rule has none."""
    if node is None:
        return None
    if not isinstance(node, dict):
        raise RuleError(f"{where}.aggregate: must be a mapping")

    for required in ("count", "within", "group_by"):
        if required not in node:
            raise RuleError(f"{where}.aggregate: {required} is required")

    count = node["count"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 2:
        # Below 2 there is no burst: `count: 1` is the rule without the
        # aggregate, written in a way that implies a threshold it does not
        # enforce. Rejected rather than accepted as a no-op.
        raise RuleError(f"{where}.aggregate.count: must be an integer of 2 or more")

    within = parse_duration(str(node["within"]))
    if within <= timedelta(0):
        raise RuleError(f"{where}.aggregate.within: must be a positive duration")

    group_by = node["group_by"]
    if group_by not in _GROUPABLE:
        raise RuleError(
            f"{where}.aggregate.group_by: {group_by!r} is not groupable; "
            f"one of {sorted(_GROUPABLE)} (schema section 4.3)"
        )

    return Aggregate(count=count, within=within, group_by=str(group_by))


def _select(node: Any, where: str) -> Select:
    if not isinstance(node, dict):
        raise RuleError(f"{where}: select must be a mapping")
    event_types = node.get("event_type")
    if not isinstance(event_types, list) or not event_types:
        raise RuleError(f"{where}: select.event_type is required and must be non-empty")
    artifacts = node.get("source_artifact") or []
    if not isinstance(artifacts, list):
        raise RuleError(f"{where}: select.source_artifact must be a list")
    return Select(tuple(str(v) for v in event_types), tuple(str(v) for v in artifacts))


#: The collections an `expected:` block declares, in schema order. Must equal
#: rules/validate_rules.py COLLECTIONS (pinned by a test).
EXPECTED_COLLECTIONS = ("clean_a", "clean_b", "s1_v2", "clean_c", "s1_v3")


def load_rule(path: Path) -> Rule:
    text = path.read_text(encoding="utf-8")
    documents = list(yaml.load_all(text, Loader=StrictLoader))
    if len(documents) != 1:
        raise RuleError(f"{path.name}: exactly one YAML document per file")
    data = documents[0]
    if not isinstance(data, dict):
        raise RuleError(f"{path.name}: the rule must be a mapping at the top level")

    version = str(data.get("schema_version", ""))
    if version.split(".")[0] not in SCHEMA_MAJOR_COMPATIBLE:
        raise RuleError(
            f"{path.name}: schema_version {version!r} is not one of "
            f"{sorted(SCHEMA_MAJOR_COMPATIBLE)}"
        )

    kind = data.get("type")
    if kind not in ("atomic", "correlation"):
        raise RuleError(f"{path.name}: type must be 'atomic' or 'correlation'")

    attack = data.get("attack") or {}
    if not isinstance(attack, dict):
        raise RuleError(f"{path.name}: attack must be a mapping")

    steps: list[Step] = []
    join_on: tuple[str, ...] = ()
    window: Window | None = None
    order = "any"

    if kind == "correlation":
        raw_steps = data.get("steps")
        if not isinstance(raw_steps, list) or len(raw_steps) < 2:
            raise RuleError(f"{path.name}: a correlation rule needs at least two steps")
        for index, raw in enumerate(raw_steps):
            where = f"{path.name}.steps[{index}]"
            if not isinstance(raw, dict):
                raise RuleError(f"{where}: step must be a mapping")
            for required in ("name", "in_window", "optional"):
                if required not in raw:
                    raise RuleError(f"{where}: {required} is required")
            absent = bool(raw.get("absent", False))
            min_count = raw.get("min_count", 1)
            max_count = raw.get("max_count")

            if absent:
                if bool(raw["in_window"]):
                    # There is no event to measure an interval to. Accepting the
                    # combination and ignoring in_window would leave the rule
                    # file asserting a window it does not have.
                    raise RuleError(
                        f"{where}: absent and in_window are mutually exclusive -- "
                        "a step that matches nothing has no time to place in a window"
                    )
                if bool(raw["optional"]):
                    # "Optional absence" is satisfied by everything: the step
                    # passes when the event is missing AND when it is present.
                    raise RuleError(f"{where}: absent and optional are mutually exclusive")
                if "min_count" in raw or "max_count" in raw:
                    raise RuleError(f"{where}: absent takes no min_count or max_count")

            if not isinstance(min_count, int) or isinstance(min_count, bool) or min_count < 1:
                raise RuleError(f"{where}.min_count: must be an integer of 1 or more")
            if max_count is not None:
                if not isinstance(max_count, int) or isinstance(max_count, bool):
                    raise RuleError(f"{where}.max_count: must be an integer or omitted")
                if max_count < min_count:
                    raise RuleError(
                        f"{where}.max_count: {max_count} is below min_count {min_count}, "
                        "so the step can never be satisfied"
                    )

            raw_override = raw.get("join_override")
            join_override: tuple[str, ...] = ()
            if raw_override is not None:
                if not isinstance(raw_override, list) or not raw_override:
                    raise RuleError(f"{where}.join_override: must be a non-empty list")
                join_override = tuple(str(k) for k in raw_override)
                if absent:
                    raise RuleError(f"{where}: absent steps take no join_override")

            steps.append(
                Step(
                    name=str(raw["name"]),
                    select=_select(raw.get("select"), f"{where}.select"),
                    conditions=_conditions(raw.get("conditions"), f"{where}.conditions"),
                    in_window=bool(raw["in_window"]),
                    optional=bool(raw["optional"]),
                    absent=absent,
                    min_count=min_count,
                    max_count=max_count,
                    join_override=join_override,
                )
            )
        join = data.get("join") or {}
        raw_join = join.get("on") if isinstance(join, dict) else None
        if not isinstance(raw_join, list) or not raw_join:
            raise RuleError(
                f"{path.name}: join.on is required and must be non-empty. A correlation "
                "rule that cannot name a shared entity cannot be loaded (schema 6.1)"
            )
        join_on = tuple(str(v) for v in raw_join)
        # A step that joins on entirely different keys shares no ground with the
        # rule, and the "chain" would be two unrelated events reported as one.
        join_set = {str(k) for k in raw_join}
        for step in steps:
            if step.join_override and not (set(step.join_override) & join_set):
                raise RuleError(
                    f"{path.name}.steps[{step.name}].join_override: shares no key with "
                    f"join.on {sorted(join_set)} -- a step joining on unrelated keys "
                    "correlates unrelated events (schema section 4.3)"
                )
        raw_window = data.get("window") or {}
        if not isinstance(raw_window, dict):
            raise RuleError(f"{path.name}: window must be a mapping")
        for required in ("from", "to", "min", "max", "justification"):
            if required not in raw_window:
                raise RuleError(f"{path.name}: window.{required} is required")
        window = Window(
            from_step=str(raw_window["from"]),
            to_step=str(raw_window["to"]),
            minimum=parse_duration(str(raw_window["min"])),
            maximum=parse_duration(str(raw_window["max"])),
            justification=str(raw_window["justification"]),
        )
        order = str(data.get("order", "any"))
        if order not in ("strict", "any"):
            raise RuleError(f"{path.name}: order must be 'strict' or 'any'")

    # Only the collection counts. An `expected` block may also carry `note` and
    # other prose keys -- R-ATOMIC-0003 carries `note_on_excluded_patterns` --
    # and pulling those in would put a paragraph where a count belongs.
    #
    # All FIVE collections. This read three (clean_a, clean_b, s1_v2) and
    # silently dropped clean_c and s1_v3 for as long as host 2 existed: every
    # rule declared host-2 figures and no consumer of Rule.expected ever saw
    # them. Found 2026-09-24 when tools/measure_rules.py reported every host-2
    # cell as "unmeasured". Pinned to rules/validate_rules.py's COLLECTIONS by
    # test_ruleset_agrees_with_validator.
    expected_raw = data.get("expected") or {}
    expected = (
        tuple(
            (name, str(expected_raw[name]))
            for name in EXPECTED_COLLECTIONS
            if name in expected_raw
        )
        if isinstance(expected_raw, dict)
        else ()
    )

    return Rule(
        rule_id=str(data.get("id", "")),
        kind=kind,
        title=str(data.get("title", "")),
        description=str(data.get("description", "")),
        severity=str(data.get("severity", "")),
        weight=int(data.get("weight", 0)),
        attack_technique=str(attack.get("technique", "")),
        attack_name=str(attack.get("name", "")),
        enabled=bool(data.get("enabled", False)),
        schema_version=version,
        select=_select(data.get("select"), f"{path.name}.select"),
        conditions=_conditions(data.get("conditions"), f"{path.name}.conditions"),
        source_path=path.name,
        aggregate=_aggregate(data.get("aggregate"), path.name),
        steps=tuple(steps),
        join_on=join_on,
        window=window,
        order=order,
        expected=expected,
        rule_class=str(data.get("class", "corpus-validated")),
        phase=str(data.get("phase", "")),
    )


def load_rules(root: Path, include_disabled: bool = False) -> list[Rule]:
    """Every rule under `root`, in `id` order.

    Load order is by id and not by directory order, so the same tree always
    produces the same rule sequence and therefore the same finding order
    (schema section 9). Files ending `.yml.draft` are ignored by design --
    `rules/blocked/` holds rules that are specified but cannot load.
    """
    paths = sorted(p for p in root.rglob("*.yml") if p.is_file())
    paths += sorted(p for p in root.rglob("*.yaml") if p.is_file())
    rules = [load_rule(p) for p in paths]
    if not include_disabled:
        rules = [r for r in rules if r.enabled]
    return sorted(rules, key=lambda r: r.rule_id)
