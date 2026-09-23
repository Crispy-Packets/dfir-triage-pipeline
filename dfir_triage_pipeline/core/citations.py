"""Citation validator for narration prose. Decoupled from any model.

`validate(text, facts)` extracts every rule id, executable name and salient
number the prose cites and checks each against `facts` -- the exact slice of
run.json the narrator was shown. Anything it cannot resolve to the facts is a
potential fabrication and is reported in `unresolvable`.

This runs on ANY narrator's output; it never imports or knows about a backend.
That separation is the point: the model is untrusted, the check is fixed.

The check has two halves, and the second exists because the first was not
enough:

- **Precision** -- nothing cited is fabricated. Every rule id, executable and
  salient number resolves to `facts`.
- **Completeness** -- the thing that matters is actually there. The first live
  narration (qwen2.5:7b) fabricated nothing and still failed: it omitted the
  99/critical entity entirely and described the anomaly ranking instead. A
  precision-only validator accepted it. `required_mentions` closes that: every
  `critical` verdict entity (or the top-scoring one if none is critical) must
  appear in the prose, or the narration is rejected.

Scope, stated honestly: the validator catches fabricated RULE IDS, EXECUTABLE
names and salient NUMBERS (percentiles, ranks, scores), and omission of the
top verdict entity. It does not police free-text that matches none of those
patterns -- the prompt constrains the model to refer to entities only by name,
which is what keeps the surface small enough to check mechanically. A
`validated` narration is one whose checkable citations all resolve and which
names the verdict, not a guarantee of perfect prose.
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
#: The same numbers written the other way round -- `percentile of 0.0986`,
#: `score of 99`, `rank 14`. The first live run wrote `a percentile of 0.0986`,
#: which `_NUM_RE` could not see, so the number went unchecked.
_NUM_RE_SUFFIX = re.compile(
    r"\b(?:percentile|score|rank)\s+(?:of\s+)?(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
#: Backwards attribution: the anomaly layer described as if it DETECTED. This is
#: the project's own two-panel rule stated as a check -- rules detect, the
#: anomaly layer ranks. Non-fatal: recorded as a flag, not a rejection, because
#: the phrasing space is open-ended and a regex cannot own a verdict.
_DETECT_CONFUSION_RE = re.compile(
    r"anomal\w+(?:\s+\w+){0,3}?\s+(?:detect|flagg?|identif)\w*",
    re.IGNORECASE,
)


@dataclass
class ValidationResult:
    validated: bool
    citations: dict[str, list[str]]
    unresolvable: list[str]
    mentions_scorer: bool
    numbers_checked: list[str] = field(default_factory=list)
    #: Verdict entities the prose was required to name and did not. Non-empty
    #: means rejection: the narration omitted the detection.
    missing_mentions: list[str] = field(default_factory=list)
    #: True when the prose credits the anomaly layer with detecting. Advisory.
    describes_ranking_as_detection: bool = False


def _verdicts(facts: dict[str, Any]) -> list[dict[str, Any]]:
    """`verdict_entities` as dicts. Tolerates the old flat list-of-names shape so
    an older fact slice still validates."""
    out: list[dict[str, Any]] = []
    for v in facts.get("verdict_entities", []) or []:
        out.append({"entity": v} if isinstance(v, str) else v)
    return out


def _ranking(facts: dict[str, Any]) -> list[dict[str, Any]]:
    return facts.get("prioritisation_ranking_not_detections") or facts.get("top_anomalies") or []


def _allowed_rule_ids(facts: dict[str, Any]) -> set[str]:
    allowed = {r for r in facts.get("rule_ids", []) if r}
    for v in _verdicts(facts):
        allowed.update(r for r in v.get("rule_ids", []) or [] if r)
    return allowed


def _allowed_exes(facts: dict[str, Any]) -> set[str]:
    exes = {v.get("entity") for v in _verdicts(facts)}
    exes.update(a.get("entity") for a in _ranking(facts))
    return {e.lower() for e in exes if e}


def _allowed_numbers(facts: dict[str, Any]) -> set[str]:
    """Every number the prose is permitted to state, as normalised strings."""
    allowed: set[str] = set()
    fc = facts.get("finding_count")
    if fc is not None:
        allowed.add(_norm(fc))
    for v in _verdicts(facts):
        if v.get("score") is not None:
            allowed.add(_norm(v["score"]))
    for a in _ranking(facts):
        pct = a.get("percentile_in_family")
        if pct is not None:
            allowed.add(_norm(pct))
    return allowed


def _required_mentions(facts: dict[str, Any]) -> set[str]:
    """The entities the narration MUST name: every `critical` verdict entity, or
    the single top-scoring one when nothing is critical. This is the recall half
    -- a narration that omits the detection is not a narration of the run."""
    verdicts = _verdicts(facts)
    critical = [
        v["entity"]
        for v in verdicts
        if v.get("entity") and str(v.get("severity", "")).lower() == "critical"
    ]
    if critical:
        return {e.lower() for e in critical}
    scored = [v for v in verdicts if v.get("entity") and v.get("score") is not None]
    if scored:
        top = max(scored, key=lambda v: v["score"])
        return {str(top["entity"]).lower()}
    return set()


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

    nums_cited = sorted(
        {_norm(m) for m in _NUM_RE.findall(text)}
        | {_norm(m) for m in _NUM_RE_SUFFIX.findall(text)}
    )
    allowed_nums = _allowed_numbers(facts)
    for n in nums_cited:
        if n not in allowed_nums:
            unresolvable.append(f"number:{n}")

    # Completeness: the verdict must actually be narrated. Omitting it is a
    # failure of the same kind as fabricating -- the prose does not describe the
    # run -- so it is fatal, and named in `unresolvable` for one audit trail.
    lowered = text.lower()
    missing = sorted(e for e in _required_mentions(facts) if e not in lowered)
    unresolvable.extend(f"missing:{e}" for e in missing)

    scorer = facts.get("scorer")
    mentions_scorer = bool(scorer) and scorer.lower() in lowered

    return ValidationResult(
        validated=not unresolvable,
        citations={"rule_ids": rules_cited, "exes": exes_cited},
        unresolvable=unresolvable,
        mentions_scorer=mentions_scorer,
        numbers_checked=nums_cited,
        missing_mentions=missing,
        describes_ranking_as_detection=bool(_DETECT_CONFUSION_RE.search(text)),
    )
