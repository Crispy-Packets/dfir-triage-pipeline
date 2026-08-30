"""Validate rule files against rules/schema.md.

Person A owns rules/**. This script reads only; it never edits a rule, a
contract document or anything under dfir_triage_pipeline/.

    python rules/validate_rules.py rules/

Exit status is 0 only when every rule passed every check that could be run.
A check that could not be run is reported as NOT PERFORMED and is never
silently treated as a pass.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - environment guard
    sys.stderr.write(
        "PyYAML is not installed. It is not yet in pyproject.toml - that is item 7 on the\n"
        "list in rules/schema.md section 11. Until it lands: pip install pyyaml\n"
    )
    raise SystemExit(2) from None

SCHEMA_MAJOR = "1"
SCHEMA_VERSION = "1.4.0"

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTRACT_DOC = REPO_ROOT / "docs" / "contract-decisions.md"
DETAILS_DOC = REPO_ROOT / "docs" / "details-schema.md"

ID_RE = re.compile(r"^R-(ATOMIC|CORR|TEST)-\d{4}$")
LOCATOR_SAFE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
DURATION_RE = re.compile(r"^P(?!$)(\d+D)?(T(?!$)(\d+H)?(\d+M)?(\d+(\.\d+)?S)?)?$")
ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Event attributes a condition may name bare. All eleven exist on model.py's Event
# as of 0994251; timestamp_type is required and validated against CD-019.
EVENT_ATTRS = frozenset(
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

# Declared-truncated details keys. A value under one of these may hold only the
# first N bytes of a longer original, so a rule can prove presence in what was
# recorded but can never prove absence from the whole. See schema section 3.4
# and D-031.
TRUNCATED_KEYS = frozenset({"script_block_text"})

# Operators that assert an absence. Rejected against a truncated key wherever
# they appear, and so is any operator inside a `none:` block -- `none: contains`
# is "does not contain" however positively the operator itself reads.
NEGATIVE_OPS = frozenset({"absent", "not_equals", "not_in", "not_contains"})

NO_VALUE_OPS = frozenset({"present", "absent"})
LIST_OPS = frozenset({"in", "not_in"})
CI_OPS = frozenset(
    {"equals", "not_equals", "in", "not_in", "contains", "not_contains", "starts_with", "ends_with"}
)
OPERATORS = (
    NO_VALUE_OPS
    | LIST_OPS
    | CI_OPS
    | frozenset({"matches", "gt", "gte", "lt", "lte"})
)

SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
COLLECTIONS = ("clean_a", "clean_b", "s1_v2")

JOINABLE = frozenset({"entity.exe_name", "entity.user"})
FORBIDDEN_JOIN = frozenset({"path", "source_file", "source_locator", "action", "entity.host"})

# schema.md section 5.3. Static map for load-time checking only; at run time the
# Event's own timestamp_type field is authoritative and nothing is derived. Each
# entry was read out of the parser that emits it, not assumed.
TIMESTAMP_TYPE_BY_ARTIFACT = {
    "evtx.security": "recorded",     # evtx_windows.py:190
    "evtx.system": "recorded",       # evtx_windows.py:190
    "evtx.powershell": "recorded",   # evtx_windows.py:190
    "browser": "recorded",           # browser.py:129
    "prefetch": "last_run",          # prefetch.py:175
    "registry": "presence",          # registry.py:138
    "amcache": "presence",           # amcache.py:126
}

# schema.md 4.7 (D-027): ten downloads share the name invoice_scan.exe; only size
# and source host separate the scenario from nine decoys.
DOWNLOAD_DISAMBIGUATORS = ("bytes", "url")

REQUIRED_TOP = (
    "schema_version",
    "id",
    "type",
    "title",
    "description",
    "severity",
    "weight",
    "attack",
    "select",
    "conditions",
    "enabled",
)


class Report:
    """Errors, warnings and checks that could not be run."""

    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.not_performed: list[str] = []

    def error(self, where: str, message: str) -> None:
        self.errors.append(f"{where}: {message}")

    def warn(self, where: str, message: str) -> None:
        self.warnings.append(f"{where}: {message}")


class StrictLoader(yaml.SafeLoader):
    """SafeLoader with anchors and aliases rejected (schema.md section 1)."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, yaml.events.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not permitted by this schema")
        if getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError("YAML anchors are not permitted by this schema")
        return super().compose_node(parent, index)


# PyYAML implements YAML 1.1, where bare on/off/yes/no/y/n are booleans. schema.md
# section 1 says YAML 1.2 core, where they are strings. Without this, `join: {on: [...]}`
# parses as the key True and the join silently disappears - which is exactly the class of
# silent failure the schema exists to prevent. Found by a negative fixture, not by reading.
_BOOL_TAG = "tag:yaml.org,2002:bool"
StrictLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != _BOOL_TAG]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictLoader.add_implicit_resolver(
    _BOOL_TAG, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


def load_cd007_event_types(report: Report) -> set[str] | None:
    """Read the fixed event vocabulary out of CD-007 rather than hard-coding it."""
    if not CONTRACT_DOC.is_file():
        report.not_performed.append(
            f"select.event_type against CD-007 - {CONTRACT_DOC} not found"
        )
        return None
    text = CONTRACT_DOC.read_text(encoding="utf-8", errors="replace")
    block = re.search(r"^CD-007(.*?)(?=^CD-\d{3}|\Z)", text, re.S | re.M)
    if block is None:
        report.not_performed.append("select.event_type against CD-007 - clause not found in doc")
        return None
    found = set()
    for line in block.group(1).splitlines():
        match = re.search(r"->\s+(\S+)\s+(\S+)\s*$", line.strip())
        if match:
            found.add(match.group(2))
    if not found:
        report.not_performed.append("select.event_type against CD-007 - no mappings parsed")
        return None
    return found


def load_declared_details_keys(report: Report) -> set[str] | None:
    """CD-012: a details key must be declared before anything reads it."""
    if not DETAILS_DOC.is_file():
        report.not_performed.append(
            f"details.<key> declaration against CD-012 - {DETAILS_DOC} does not exist"
        )
        return None
    text = DETAILS_DOC.read_text(encoding="utf-8", errors="replace")
    keys = set()
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) <= 2:
            continue
        cell = cells[1]
        # Only a back-quoted cell is a declared key. Without this the header row
        # ("key") and the separator row ("---") would both enter the set.
        if len(cell) > 2 and cell.startswith("`") and cell.endswith("`"):
            name = cell[1:-1]
            if LOCATOR_SAFE_RE.match(name):
                keys.add(name)
    return keys


def check_condition(
    node: Any,
    where: str,
    report: Report,
    details_refs: set[str],
    block: str = "all",
) -> None:
    if not isinstance(node, dict):
        report.error(where, "a condition must be a mapping")
        return
    unknown = set(node) - {"field", "op", "value", "ci"}
    if unknown:
        report.error(where, f"unknown condition key(s): {sorted(unknown)}")
    field = node.get("field")
    op = node.get("op")
    if not isinstance(field, str) or not field:
        report.error(where, "field is required and must be a string")
        return
    if op not in OPERATORS:
        report.error(where, f"unknown operator {op!r}; the set is closed (schema section 3.3)")
        return
    if field.startswith("details."):
        key = field[len("details.") :]
        if not key or "." in key:
            report.error(where, f"{field!r}: exactly one level of nesting (schema section 3.2)")
        else:
            details_refs.add(key)
            if key in TRUNCATED_KEYS:
                if op in NEGATIVE_OPS:
                    report.error(
                        where,
                        f"{field!r} is a declared-truncated key and {op!r} asserts an "
                        "absence it cannot support: the value may hold only the first "
                        "bytes of a longer original (schema section 3.4)",
                    )
                elif block == "none":
                    report.error(
                        where,
                        f"{field!r} is a declared-truncated key and cannot appear in a "
                        "none: block -- negating a match over a truncated value asserts "
                        "an absence the evidence cannot support (schema section 3.4)",
                    )
    elif field not in EVENT_ATTRS:
        report.error(
            where,
            f"{field!r} is not an Event attribute and has no details. prefix "
            "(schema section 3.2)",
        )
    has_value = "value" in node
    if op in NO_VALUE_OPS and has_value:
        report.error(where, f"{op} takes no value")
    if op not in NO_VALUE_OPS and not has_value:
        report.error(where, f"{op} requires a value")
    if op in LIST_OPS and not isinstance(node.get("value"), list):
        report.error(where, f"{op} requires a list value")
    if "ci" in node:
        if not isinstance(node["ci"], bool):
            report.error(where, "ci must be a boolean")
        elif op not in CI_OPS:
            report.error(where, f"ci is not meaningful for {op}")
    if op == "matches":
        pattern = node.get("value")
        if not isinstance(pattern, str):
            report.error(where, "matches requires a string pattern")
        else:
            try:
                re.compile(pattern)
            except re.error as exc:
                report.error(where, f"regex does not compile: {exc}")


def check_conditions_block(block: Any, where: str, report: Report, details_refs: set[str]) -> None:
    if not isinstance(block, dict):
        report.error(where, "conditions must be a mapping of all/any/none")
        return
    unknown = set(block) - {"all", "any", "none"}
    if unknown:
        report.error(where, f"unknown conditions key(s): {sorted(unknown)}")
    if not any(block.get(group) for group in ("all", "any", "none")):
        report.error(where, "at least one of all/any/none must be present and non-empty")
    for group in ("all", "any", "none"):
        items = block.get(group)
        if items is None:
            continue
        if not isinstance(items, list):
            report.error(f"{where}.{group}", "must be a list")
            continue
        for index, item in enumerate(items):
            check_condition(item, f"{where}.{group}[{index}]", report, details_refs, group)


def check_select(node: Any, where: str, report: Report, vocabulary: set[str] | None) -> list[str]:
    """Returns the declared source_artifact list, empty when not given."""
    if not isinstance(node, dict):
        report.error(where, "select must be a mapping")
        return []
    unknown = set(node) - {"event_type", "source_artifact"}
    if unknown:
        report.error(where, f"unknown select key(s): {sorted(unknown)}")
    event_types = node.get("event_type")
    if not isinstance(event_types, list) or not event_types:
        report.error(where, "select.event_type is required and must be a non-empty list")
    elif vocabulary is not None:
        for value in event_types:
            if value not in vocabulary:
                report.error(where, f"event_type {value!r} is not in CD-007")
    artifacts = node.get("source_artifact") or []
    if not isinstance(artifacts, list):
        report.error(where, "select.source_artifact must be a list")
        return []
    for value in artifacts:
        if value not in TIMESTAMP_TYPE_BY_ARTIFACT:
            report.error(
                where,
                f"source_artifact {value!r} has no timestamp_type (schema section 5.3); "
                "an unknown artifact is an error, not a default",
            )
    return list(artifacts)


def check_window(node: Any, where: str, step_names: set[str], report: Report) -> None:
    if not isinstance(node, dict):
        report.error(where, "window must be a mapping")
        return
    for key in ("from", "to", "min", "max", "justification"):
        if key not in node:
            report.error(where, f"window.{key} is required")
    for key in ("from", "to"):
        value = node.get(key)
        if value is not None and value not in step_names:
            report.error(where, f"window.{key}={value!r} names no step")
    for key in ("min", "max"):
        value = node.get(key)
        if isinstance(value, str) and not DURATION_RE.match(value):
            report.error(where, f"window.{key}={value!r} is not an ISO-8601 duration")
    justification = node.get("justification")
    if isinstance(justification, str) and not re.search(r"\d", justification):
        report.error(
            where,
            "window.justification cites no measurement (schema section 6): the "
            "download-to-execution interval in this corpus is 37m 09.122s, not a round number",
        )


def check_correlation(data: dict, where: str, report: Report, details_refs: set[str],
                      vocabulary: set[str] | None) -> None:
    steps = data.get("steps")
    if not isinstance(steps, list) or len(steps) < 2:
        report.error(where, "a correlation rule needs a steps list with at least two steps")
        return
    names: set[str] = set()
    for index, step in enumerate(steps):
        at = f"{where}.steps[{index}]"
        if not isinstance(step, dict):
            report.error(at, "step must be a mapping")
            continue
        unknown = set(step) - {
            "name", "select", "conditions", "in_window", "optional", "ambiguity_ack",
        }
        if unknown:
            report.error(at, f"unknown step key(s): {sorted(unknown)}")
        name = step.get("name")
        if not isinstance(name, str) or not name:
            report.error(at, "step.name is required")
        elif name in names:
            report.error(at, f"duplicate step name {name!r}")
        else:
            names.add(name)
        artifacts = check_select(step.get("select"), f"{at}.select", report, vocabulary)
        step_refs: set[str] = set()
        check_conditions_block(step.get("conditions"), f"{at}.conditions", report, step_refs)
        details_refs |= step_refs

        optional = step.get("optional")
        if not isinstance(optional, bool):
            report.error(at, "optional is required and must be a boolean (schema section 6.2)")
            optional = False

        selected_types = (step.get("select") or {}).get("event_type") or []
        if "file_download" in selected_types and not step.get("ambiguity_ack"):
            if not any(key in step_refs for key in DOWNLOAD_DISAMBIGUATORS):
                report.error(
                    at,
                    "a file_download step must constrain details.bytes or details.url "
                    "(schema 4.7): ten downloads in s1_v2 share the name invoice_scan.exe "
                    "and only size and source host separate the scenario from nine decoys "
                    "(D-027). Set ambiguity_ack citing D-027 to match any download on purpose",
                )

        in_window = step.get("in_window")
        if not isinstance(in_window, bool):
            report.error(at, "in_window is required and must be a boolean")
            continue
        if not artifacts:
            report.error(
                at,
                "select.source_artifact is required on a correlation step, or the "
                "presence check cannot be made (schema section 6)",
            )
            continue
        if "amcache" in artifacts and not optional:
            report.error(
                at,
                "an amcache step must be optional: true (schema 6.2). The scenario binary "
                "executed and has no Amcache entry at all, so a rule requiring Amcache to "
                "corroborate would miss the only real detection in the corpus (D-028)",
            )
        presence = [a for a in artifacts if TIMESTAMP_TYPE_BY_ARTIFACT.get(a) == "presence"]
        if presence and in_window:
            report.error(
                at,
                f"steps selecting {presence} are presence-typed and may not enter a "
                "sliding window (schema section 5.2); set in_window: false",
            )

    join = data.get("join")
    if not isinstance(join, dict) or not isinstance(join.get("on"), list) or not join["on"]:
        report.error(where, "join.on is required and must be non-empty for a correlation rule")
    else:
        for value in join["on"]:
            if value in FORBIDDEN_JOIN:
                report.error(
                    f"{where}.join",
                    f"{value!r} is a forbidden join field (schema section 4.3)",
                )
            elif value not in JOINABLE:
                report.error(
                    f"{where}.join",
                    f"{value!r} is not a defined entity key (schema section 4.1)",
                )
    check_window(data.get("window"), f"{where}.window", names, report)
    if data.get("order") not in ("strict", "any"):
        report.error(where, "order must be 'strict' or 'any'")


def check_expected(node: Any, where: str, report: Report) -> None:
    if not isinstance(node, dict):
        report.error(where, "expected is required on an atomic rule and must be a mapping")
        return
    for collection in COLLECTIONS:
        if collection not in node:
            report.error(where, f"expected.{collection} is required")
            continue
        value = node[collection]
        if isinstance(value, bool) or not (isinstance(value, int) or value == "unmeasured"):
            report.error(
                where,
                f"expected.{collection} must be an integer or the string 'unmeasured'; "
                "it is never guessed and never silently 0",
            )


def validate_file(path: Path, report: Report, details_refs: set[str],
                  vocabulary: set[str] | None) -> None:
    where = path.name
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        documents = list(yaml.load_all(text, Loader=StrictLoader))
    except yaml.YAMLError as exc:
        report.error(where, f"YAML did not load: {exc}")
        return
    if len(documents) != 1:
        report.error(where, f"exactly one YAML document per file, found {len(documents)}")
        return
    data = documents[0]
    if not isinstance(data, dict):
        report.error(where, "the rule must be a mapping at the top level")
        return

    for key in REQUIRED_TOP:
        if key not in data:
            report.error(where, f"required field {key!r} is missing")

    version = str(data.get("schema_version", ""))
    if version.split(".")[0] != SCHEMA_MAJOR:
        report.error(where, f"schema_version {version!r} is not major {SCHEMA_MAJOR}")

    rule_id = data.get("id")
    if not isinstance(rule_id, str) or not ID_RE.match(rule_id):
        report.error(where, f"id {rule_id!r} does not match ^R-(ATOMIC|CORR|TEST)-\\d{{4}}$")
        rule_id = None
    elif not path.name.startswith(f"{rule_id}-"):
        report.error(where, f"filename does not start with the id {rule_id!r}")

    rule_type = data.get("type")
    if rule_type not in ("atomic", "correlation"):
        report.error(where, "type must be 'atomic' or 'correlation'")
    if rule_id and rule_type == "atomic" and path.parent.name != "atomic":
        report.error(where, "an atomic rule belongs in rules/atomic/")
    if rule_id and rule_type == "correlation" and path.parent.name != "correlation":
        report.error(where, "a correlation rule belongs in rules/correlation/")
    if rule_id and rule_id.startswith("R-CORR-") and rule_type != "correlation":
        report.error(where, "an R-CORR- id must carry type: correlation")

    if data.get("severity") not in SEVERITIES:
        report.error(where, f"severity must be one of {sorted(SEVERITIES)}")
    weight = data.get("weight")
    if isinstance(weight, bool) or not isinstance(weight, int) or not 0 <= weight <= 100:
        report.error(where, "weight must be an integer 0..100")
    if not isinstance(data.get("enabled"), bool):
        report.error(where, "enabled must be a boolean")
    for key in ("title", "description"):
        if not isinstance(data.get(key), str) or not data.get(key, "").strip():
            report.error(where, f"{key} must be a non-empty string")

    attack = data.get("attack")
    if not isinstance(attack, dict):
        report.error(where, "attack must be a mapping with technique and name")
    else:
        technique = attack.get("technique")
        if not isinstance(technique, str) or not ATTACK_RE.match(technique):
            report.error(where, f"attack.technique {technique!r} is not a Txxxx[.yyy] id")
        if not isinstance(attack.get("name"), str) or not attack.get("name", "").strip():
            report.error(where, "attack.name must be a non-empty string")

    check_select(data.get("select"), f"{where}.select", report, vocabulary)
    check_conditions_block(data.get("conditions"), f"{where}.conditions", report, details_refs)

    # Required on BOTH kinds since 1.4.0. It was atomic-only until the first
    # real run showed R-CORR-0003 firing five times on a collection with no
    # attack in it -- the four rules most likely to be quoted as detections were
    # the four with no recorded base rate.
    check_expected(data.get("expected"), f"{where}.expected", report)

    if rule_type == "atomic":
        for key in ("steps", "join", "window", "order"):
            if key in data:
                report.error(where, f"{key} is a correlation field and has no meaning here")
    elif rule_type == "correlation":
        check_correlation(data, where, report, details_refs, vocabulary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=f"Validate rules against schema {SCHEMA_VERSION}")
    parser.add_argument("root", nargs="?", default=str(REPO_ROOT / "rules"))
    args = parser.parse_args(argv)

    root = Path(args.root)
    if not root.is_dir():
        sys.stderr.write(f"not a directory: {root}\n")
        return 2

    report = Report()
    vocabulary = load_cd007_event_types(report)
    declared_details = load_declared_details_keys(report)
    details_refs: set[str] = set()

    paths = sorted(p for p in root.rglob("*.yml") if p.is_file())
    paths += sorted(p for p in root.rglob("*.yaml") if p.is_file())
    for path in paths:
        before = len(report.errors)
        validate_file(path, report, details_refs, vocabulary)
        status = "PASS" if len(report.errors) == before else "FAIL"
        print(f"{status}  {path.relative_to(root)}")

    if details_refs:
        if declared_details is None:
            report.error(
                "CD-012",
                f"rules reference details keys {sorted(details_refs)} but "
                f"{DETAILS_DOC.name} does not exist, so the declaration cannot be checked",
            )
        else:
            undeclared = sorted(details_refs - declared_details)
            if undeclared:
                report.error("CD-012", f"details keys not declared: {undeclared}")

    print()
    print(f"schema {SCHEMA_VERSION}   rules {len(paths)}   "
          f"errors {len(report.errors)}   warnings {len(report.warnings)}")
    for line in report.not_performed:
        print(f"NOT PERFORMED  {line}")
    for line in report.warnings:
        print(f"WARN   {line}")
    for line in report.errors:
        print(f"ERROR  {line}")
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
