"""Citation validator for narration prose. Decoupled from any model.

`validate(text, facts)` extracts every rule id, executable name and salient
number the prose cites and checks each against `facts` -- the exact slice of
run.json the narrator was shown. Anything it cannot resolve to the facts is a
potential fabrication and is reported in `unresolvable`.

This runs on ANY narrator's output; it never imports or knows about a backend.
That separation is the point: the model is untrusted, the check is fixed.

Scope, stated honestly: the validator catches fabricated RULE IDS, EXECUTABLE
names and salient NUMBERS (percentiles, ranks, scores). It does not police
free-text that matches none of those patterns -- the prompt constrains the model
to refer to entities only by executable name, which is what keeps the surface
small enough to check mechanically. A `validated` narration is one whose
checkable citations all resolve, not a guarantee of perfect prose.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

#: Rule ids: the same shape validate_rules.py enforces (R-ATOMIC/CORR/TEST-NNNN).
_RULE_RE = re.compile(r"\bR-(?:ATOMIC|CORR|TEST)-\d{4}\b")
#: Executable tokens. Lowercased before comparison; entity keys are lowercase.
_EXE_RE = re.compile(r"\b[\w.\-]+\.exe\b", re.IGNORECASE)
#: Salient numbers: a percentile/score/rank. Matches `14`, `1.0`, `1/443`, `99`.
#: Only numbers ADJACENT to a triage word or symbol are checked, to avoid
#: flagging incidental digits (a year, a count) the facts need not contain.
_NUM_RE = re.compile(
    r"(?<![\w.])(\d+(?:\.\d+)?)\s*(?:%|percentile|/\s*\d+|score|rank)",
    re.IGNORECASE,
)


@dataclass
class ValidationResult:
    validated: bool
    citations: dict[str, list[str]]
    unresolvable: list[str]
    mentions_scorer: bool
    numbers_checked: list[str] = field(default_factory=list)


def _allowed_rule_ids(facts: dict[str, Any]) -> set[str]:
    return {r for r in facts.get("rule_ids", []) if r}


def _allowed_exes(facts: dict[str, Any]) -> set[str]:
    exes = set(facts.get("verdict_entities", []))
    exes.update(a.get("entity") for a in facts.get("top_anomalies", []))
    return {e.lower() for e in exes if e}


def _allowed_numbers(facts: dict[str, Any]) -> set[str]:
    """Every number the prose is permitted to state, as normalised strings."""
    allowed: set[str] = set()
    fc = facts.get("finding_count")
    if fc is not None:
        allowed.add(_norm(fc))
    for a in facts.get("top_anomalies", []):
        pct = a.get("percentile_in_family")
        if pct is not None:
            allowed.add(_norm(pct))
    return allowed


def _norm(n: Any) -> str:
    """Normalise a number so `1.0`, `1`, and `1.00` compare equal."""
    try:
        f = float(n)
    except (TypeError, ValueError):
        return str(n).strip()
    return str(int(f)) if f == int(f) else str(f)


def validate(text: str, facts: dict[str, Any]) -> ValidationResult:
    """Check `text`'s citations against `facts`. Never raises."""
    unresolvable: list[str] = []

    rules_cited = sorted(set(_RULE_RE.findall(text)))
    allowed_rules = _allowed_rule_ids(facts)
    for r in rules_cited:
        if r not in allowed_rules:
            unresolvable.append(f"rule_id:{r}")

    exes_cited = sorted({m.lower() for m in _EXE_RE.findall(text)})
    allowed_exes = _allowed_exes(facts)
    for e in exes_cited:
        if e not in allowed_exes:
            unresolvable.append(f"exe:{e}")

    nums_cited = sorted({_norm(m) for m in _NUM_RE.findall(text)})
    allowed_nums = _allowed_numbers(facts)
    for n in nums_cited:
        if n not in allowed_nums:
            unresolvable.append(f"number:{n}")

    scorer = facts.get("scorer")
    mentions_scorer = bool(scorer) and scorer.lower() in text.lower()

    return ValidationResult(
        validated=not unresolvable,
        citations={"rule_ids": rules_cited, "exes": exes_cited},
        unresolvable=unresolvable,
        mentions_scorer=mentions_scorer,
        numbers_checked=nums_cited,
    )
