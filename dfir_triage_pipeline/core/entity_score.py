"""Entity-level aggregation of findings (schema gap 9).

Findings are produced per rule. An analyst triages **entities** -- a binary, an
account -- not rule matches, and the same binary can appear in several findings:
in `s1_v3`, `invoice_scan.exe` is named by both `R-CORR-0003` and
`R-ATOMIC-0006`, which is one thing to look at rather than two.

This module groups findings by entity key and produces one scored row each.

Two decisions shape it.

**Score combines distinct rule weights with diminishing returns, bounded by
100.** Combining rewards independent corroboration: two rules agreeing on one
binary is stronger evidence than either alone. Taking the maximum would discard
that, and averaging would let a weak finding *lower* an entity's score, which is
the wrong direction entirely -- more evidence should never reduce suspicion.

**Distinct rules, not distinct findings.** A rule that fires five times on one
entity contributes its weight once. Otherwise `R-CORR-0003` firing on five
autorun values would score an entity 425, and the count would measure how many
registry values a program registered rather than how suspicious it is.

**Why not a plain sum with a cap.** That was the first implementation and it
was measurably wrong: on `s1_v3` both `invoice_scan.exe` and `onedrive.exe`
matched `R-CORR-0003` (85) and `R-ATOMIC-0006` (60), summed to 145, and both
clamped to 100 -- indistinguishable, with the ordering destroyed at exactly the
top of the list where it matters most. A cap that flattens the leaders is worse
than no cap.

The combination used instead is probabilistic-style: each weight is treated as
a fraction of the remaining headroom, so

    combined = 100 * (1 - product over rules of (1 - weight/100))

Two rules at 85 and 60 give 94, not 145-clamped-to-100. It is monotonic -- an
extra rule always raises the score -- it never reaches 100 unless a rule is
itself 100, and it degrades gracefully: the twentieth rule adds less than the
second, which is the right shape for corroboration.

`raw_sum` is kept alongside, because it is what a reader would compute by hand
and its absence would look like an error.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .findings import Finding

#: Scores are reported out of 100 and approach it asymptotically.
SCORE_MAX = 100

#: Severity order, worst first. An entity takes the worst severity among its
#: findings: an entity with one `critical` and three `low` findings is a
#: critical entity, and reporting the modal or mean severity would bury it.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


@dataclass(frozen=True, slots=True)
class ScoredEntity:
    """One entity and every finding that named it."""

    #: The join key, e.g. `entity.exe_name`.
    key: str
    #: Its value, e.g. `invoice_scan.exe`.
    value: str
    #: Distinct rule weights combined with diminishing returns, 0..100.
    score: int
    #: Plain sum of the same weights. Kept because it is what a reader would
    #: compute by hand, and its absence would read as an error rather than as a
    #: deliberate choice of combination.
    raw_sum: int
    #: Worst severity among the findings, by _SEVERITY_ORDER.
    severity: str
    #: Distinct rule ids that named this entity, sorted. Displayed beside the
    #: score so a reader can see WHICH rules agreed, not merely how many.
    rule_ids: tuple[str, ...]
    #: ATT&CK techniques from those rules, sorted and de-duplicated.
    techniques: tuple[str, ...]
    #: Every finding naming this entity, in the order they were given.
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def was_combined(self) -> bool:
        """True when more than one rule contributed, so the combination is
        visible rather than looking like an unexplained discrepancy."""
        return len(self.rule_ids) > 1


def combine_weights(weights: Iterable[int]) -> int:
    """Combine rule weights with diminishing returns, 0..100.

    Each weight is treated as a fraction of the headroom that remains, so
    combining 85 and 60 gives 94 rather than 145. Monotonic: adding a rule never
    lowers the score. Bounded: the result reaches 100 only if some rule is
    itself 100, so a genuine certainty stays distinguishable from an
    accumulation of partial evidence.

    A weight outside 0..100 is clamped rather than rejected. The loader already
    validates the range, so reaching this means a Finding was built by hand, and
    a negative weight would otherwise *reduce* the score below a previous rule's
    -- silently inverting the direction of the whole scale.
    """
    remaining = 1.0
    saturated = False
    for weight in weights:
        w = max(0, min(100, int(weight)))
        saturated = saturated or w >= SCORE_MAX
        remaining *= 1.0 - (w / 100.0)

    combined = (1.0 - remaining) * 100
    if saturated:
        return SCORE_MAX
    # Ten rules at 90 combine to 99.9999999, which rounds to 100 and becomes
    # indistinguishable from a rule that actually asserts certainty. Floor
    # instead of round once the value is within one point of the ceiling, so
    # accumulated partial evidence stays below a single definite finding.
    return min(SCORE_MAX - 1, int(round(combined)))


def _severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        # An unknown severity sorts last rather than raising. The loader
        # validates severities, so reaching this means a Finding was built by
        # hand; ranking it worst would let a typo outrank a real critical.
        return len(_SEVERITY_ORDER)


def aggregate(findings: Iterable[Finding]) -> list[ScoredEntity]:
    """Group findings by entity key and score each entity.

    A finding carrying several entity keys contributes to **each** of them. A
    download-to-execution finding names both an executable and a user, and both
    are things an analyst would pivot on, so neither is discarded.

    Findings with no entity key are dropped rather than grouped under a
    placeholder. `R-ATOMIC-0002` keys on `entity.host`, which is deliberately
    not joinable, so a log-clear finding has nothing to aggregate on -- it is
    still reported as a finding, just not as an entity.
    """
    buckets: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        for key, value in finding.entity_keys:
            buckets.setdefault((key, value), []).append(finding)

    scored: list[ScoredEntity] = []
    for (key, value), group in buckets.items():
        by_rule = {f.rule_id: f for f in group}
        weights = [f.weight for f in by_rule.values()]
        severity = min((f.severity for f in group), key=_severity_rank)
        techniques = sorted({f.attack_technique for f in group if f.attack_technique})
        scored.append(
            ScoredEntity(
                key=key,
                value=value,
                score=combine_weights(weights),
                raw_sum=sum(weights),
                severity=severity,
                rule_ids=tuple(sorted(by_rule)),
                techniques=tuple(techniques),
                findings=tuple(group),
            )
        )

    # Worst first: score descending, then severity, then value for determinism.
    # The value tie-break matters -- two entities on the same score and severity
    # would otherwise order by dict insertion, and two runs could disagree.
    scored.sort(key=lambda e: (-e.score, _severity_rank(e.severity), e.value))
    return scored


def summary_lines(entities: Sequence[ScoredEntity], limit: int = 10) -> list[str]:
    """The entity table, for the run summary. Every number is checkable."""
    if not entities:
        return ["Entities   : none (no finding carried a joinable entity key)"]

    lines = [f"Entities   : {len(entities)} scored, worst first"]
    for e in entities[:limit]:
        combined = f" (from {e.raw_sum} across {len(e.rule_ids)} rules)" if e.was_combined else ""
        lines.append(
            f"  {e.score:>3}{combined}  [{e.severity}] {e.key}={e.value}  "
            f"{e.finding_count} finding(s) from {', '.join(e.rule_ids)}"
        )
    if len(entities) > limit:
        lines.append(f"  ... {len(entities) - limit} more")
    return lines
