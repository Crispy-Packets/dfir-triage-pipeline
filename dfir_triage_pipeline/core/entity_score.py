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

**Entity kinds are ranked separately, and `entity.host` is not ranked at all
(D-058, 2026-09-19).** A user's 97 and a binary's 99 do not measure the same
thing: `entity.user=youssef` scored 97 on a collection containing no attack,
from five rules that individually are reasonable and jointly describe an
ordinary person using an ordinary computer. Mixing the kinds in one table
invited that comparison and concealed a discriminator that was there all along
-- restricted to binaries, the clean hosts top out at 86/86/75 `high` and the
scenario hosts reach 99 `critical`, and **no clean collection produces a
critical binary at all**.

`entity.host` is excluded from scoring outright rather than given its own
table. There is exactly ONE host per collection, so a host ranking is a table
of one row, which is not a ranking; and a host entity aggregates every finding
in the run, which makes its score a count of unrelated evidence attached to a
label that cannot discriminate by construction. `core/entity.py` already
records that `host_key` is "defined for reporting; not joinable (schema 4.5)"
-- it was excluded from JOINS and not from SCORING, and nothing stated why
those should differ. Now they agree. The host is still reported: it is
collection metadata, which is where a single-valued fact belongs.

**Why not a plain sum with a cap.** That was the first implementation and it
was measurably wrong: on `s1_v3` both `invoice_scan.exe` and `onedrive.exe`
matched `R-CORR-0003` (85) and `R-ATOMIC-0006` (60), summed to 145, and both
clamped to 100 -- indistinguishable, with the ordering destroyed at exactly the
top of the list where it matters most. A cap that flattens the leaders is worse
than no cap.

**And the limit of that fix, which the example above concealed for four days.**
Diminishing returns moved that pair from 100/100 to 94/94. It did not separate
them and could not: two entities matched by the SAME rules carry the SAME
weights, and every order-independent combination of equal inputs returns equal
outputs. The scorer was tested against the failing case's NUMBERS rather than
its CAUSE. `onedrive.exe` was separated on 2026-09-17 by adding a predicate to
`R-CORR-0003` -- in the rule, where the distinction actually lives -- after
which it scores 60 and `invoice_scan.exe` scores 94. **A tie here is a report
that the rules did not discriminate; it is not a scoring defect to be tuned
away.** See D-056.

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


#: Entity kinds that are SCORED and ranked. `entity.host` is deliberately
#: absent -- see the module docstring and D-058. One host per collection means
#: a host table is one row, and a host aggregates every finding in the run.
SCORED_ENTITY_KINDS: tuple[str, ...] = ("entity.exe_name", "entity.user")

#: The only rule class whose findings contribute to the entity ranking.
#: See `Rule.rule_class` and the exclusion in `aggregate`.
SCORING_RULE_CLASS = "corpus-validated"

#: Ranking order for the per-kind tables. Binaries first: that is the kind the
#: corpus shows separating cleanly (86/86/75 high vs 99/99 critical), and the
#: kind an analyst triages first.
KIND_ORDER: tuple[str, ...] = ("entity.exe_name", "entity.user")


def aggregate(findings: Iterable[Finding]) -> list[ScoredEntity]:
    """Group findings by entity key and score each entity.

    A finding carrying several entity keys contributes to **each** of them. A
    download-to-execution finding names both an executable and a user, and both
    are things an analyst would pivot on, so neither is discarded.

    Findings with no entity key are dropped rather than grouped under a
    placeholder. `R-ATOMIC-0002` keys on `entity.host`, which is deliberately
    not joinable, so a log-clear finding has nothing to aggregate on -- it is
    still reported as a finding, just not as an entity.

    **`entity.host` is not scored** (D-058). It is excluded here rather than
    filtered by the caller, so every consumer gets the same answer and no
    report can reintroduce it by accident. `aggregate_by_kind` splits what
    remains into one ranked table per kind; this flat list is retained for
    callers that want a single worst-first ordering.
    """
    buckets: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        # Class 2 (`known-behavior`) rules never move the ranking. They have no
        # measured true positive anywhere, so any weight they add to an entity
        # is unvalidated -- and the clean ceiling (86/86/75) against the
        # payload (99) is the project's headline result. Excluded HERE, beside
        # the entity-kind filter, so it happens once and no consumer can
        # reintroduce it, exactly as D-058 does for `entity.host`.
        if finding.rule_class != SCORING_RULE_CLASS:
            continue
        for key, value in finding.entity_keys:
            if key not in SCORED_ENTITY_KINDS:
                continue
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


def aggregate_by_kind(
    findings: Iterable[Finding],
) -> dict[str, list[ScoredEntity]]:
    """One ranked table per entity kind, worst first within each (D-058).

    Kinds are not comparable: a user aggregating five inventory-ish rules
    reaches 97 on a clean host, and a binary reaching 99 on a scenario host
    means something else entirely. Ranking them in one table invites exactly
    that comparison.

    Every kind in `SCORED_ENTITY_KINDS` is present as a key, even when empty,
    so a consumer never has to distinguish "no such kind" from "none found".
    `entity.host` never appears -- it is not scored.
    """
    tables: dict[str, list[ScoredEntity]] = {kind: [] for kind in KIND_ORDER}
    for entity in aggregate(findings):
        tables.setdefault(entity.key, []).append(entity)
    return tables


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


def summary_lines_by_kind(
    tables: dict[str, list[ScoredEntity]], limit: int = 5
) -> list[str]:
    """The per-kind entity tables, for the run summary (D-058).

    Each kind is headed and counted separately so that no two kinds appear as
    neighbouring rows of one ranking.
    """
    total = sum(len(rows) for rows in tables.values())
    if not total:
        return ["Entities   : none (no finding carried a scored entity key)"]

    lines = [f"Entities   : {total} scored, ranked separately per kind"]
    for kind in KIND_ORDER:
        rows = tables.get(kind, [])
        label = kind.split(".", 1)[-1]
        if not rows:
            lines.append(f"  {label}: none")
            continue
        lines.append(f"  {label}: {len(rows)} scored, worst first")
        for e in rows[:limit]:
            combined = (
                f" (from {e.raw_sum} across {len(e.rule_ids)} rules)"
                if e.was_combined
                else ""
            )
            lines.append(
                f"    {e.score:>3}{combined}  [{e.severity}] {e.value}  "
                f"{e.finding_count} finding(s) from {', '.join(e.rule_ids)}"
            )
        if len(rows) > limit:
            lines.append(f"    ... {len(rows) - limit} more")
    return lines
