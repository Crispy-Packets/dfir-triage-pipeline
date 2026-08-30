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

SCHEMA_MAJOR = "1"

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
            built.append(
                Condition(
                    field=field,
                    op=op,
                    value=item.get("value"),
                    ci=bool(item.get("ci", False)),
                    has_value="value" in item,
                )
            )
        groups[group] = tuple(built)
    if not any(groups.values()):
        raise RuleError(f"{where}: at least one of all/any/none must be non-empty")
    return Conditions(groups["all"], groups["any"], groups["none"])


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


def load_rule(path: Path) -> Rule:
    text = path.read_text(encoding="utf-8")
    documents = list(yaml.load_all(text, Loader=StrictLoader))
    if len(documents) != 1:
        raise RuleError(f"{path.name}: exactly one YAML document per file")
    data = documents[0]
    if not isinstance(data, dict):
        raise RuleError(f"{path.name}: the rule must be a mapping at the top level")

    version = str(data.get("schema_version", ""))
    if version.split(".")[0] != SCHEMA_MAJOR:
        raise RuleError(f"{path.name}: schema_version {version!r} is not major {SCHEMA_MAJOR}")

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
            steps.append(
                Step(
                    name=str(raw["name"]),
                    select=_select(raw.get("select"), f"{where}.select"),
                    conditions=_conditions(raw.get("conditions"), f"{where}.conditions"),
                    in_window=bool(raw["in_window"]),
                    optional=bool(raw["optional"]),
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

    # Only the three collection counts. An `expected` block may also carry
    # `note` and other prose keys -- R-ATOMIC-0003 carries
    # `note_on_excluded_patterns` -- and pulling those in would put a paragraph
    # where a count belongs.
    expected_raw = data.get("expected") or {}
    expected = (
        tuple(
            (name, str(expected_raw[name]))
            for name in ("clean_a", "clean_b", "s1_v2")
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
        steps=tuple(steps),
        join_on=join_on,
        window=window,
        order=order,
        expected=expected,
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
