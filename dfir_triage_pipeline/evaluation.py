"""Ranking metrics for the anomaly layer (B-3, B-4).

This module answers one question: **if an analyst reads the top K rows of the
anomaly ranking, do they find the attack?** That is the only claim the ML layer
is allowed to make -- it prioritises, it does not decide -- so the metrics are
ranking metrics rather than classification metrics.

Two decisions that shape everything below.

**Metrics are entity-level, not row-level.** `invoice_scan.exe` produces
several rows across Prefetch, Amcache and the registry. Counting it once per
row would inflate every figure by however many artefacts happened to record it,
which is a property of the collection rather than of the detector. An analyst
triages *a binary*, not *a Prefetch record*, so the unit is the entity.

**Recall is reported against evaluable rows only.** Person A's
`groundtruth/verification-method.md` fixes a closed verdict vocabulary and one
reporting rule: a recall figure that divides matches by every ground-truth row
charges the pipeline for collection scope and for a declared roadmap. The same
rule applies here. An entity the anomaly layer never scored -- because its
family fell below `MIN_TRAINING_ROWS`, or because no parser emits it -- is
excluded from the denominator and reported separately as unscored. It is not
counted as a miss.

Nothing here tunes anything. These functions measure; what they measure is
recorded whether or not it flatters the model.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from .anomaly import Scored

#: Ground-truth entity keys for Scenario 1, as `path_basename_canonical`.
#:
#: Taken from `groundtruth/scenario1-verification-week3.md`, which records four
#: MATCHED rows -- the Edge download, the Prefetch execution, the NTUSER.DAT Run
#: key, and the EID 1102 log clear. The first three are all the same binary, so
#: they collapse to one entity here; that collapse is the entity-level counting
#: this module exists to do.
#:
#: The log clear is deliberately NOT in this set. It is an EVTX record with no
#: executable, so it has no `path_basename_canonical` to join on and is
#: evaluated by `attack_event_ids` below instead.
SCENARIO1_ENTITIES: frozenset[str] = frozenset({"invoice_scan.exe"})

#: Ground-truth `event_id`s for Scenario 1, for the rows that are not entities.
#:
#: These are content hashes and they moved once already: CD-019 put
#: `timestamp_type` into the hash, so any id quoted before that change is stale
#: (section 3.1 of the Week 3 verification). If one of these stops matching,
#: check the contract change before assuming the pipeline broke.
SCENARIO1_EVENT_IDS: dict[str, str] = {
    "5573ac8d6a6363d2": "log clear (EID 1102, EventRecordID 28201)",
    "4c58a24247dc3d22": "download (Edge History, downloads.id=13)",
    "58c5d22e63b89ca7": "execution (Prefetch INVOICE_SCAN.EXE-A345C2FE.pf)",
    "c1bb6d9de5ff273f": "persistence (NTUSER.DAT Run\\SecurityUpdate)",
}


def entity_of(scored: Scored) -> str | None:
    """The entity a scored row belongs to, or None if it has no entity key.

    Uses `path_basename_canonical` from B-9, the same key Person A's
    `core/entity.py` joins correlation rules on. Using a different key here
    would make the ML metrics incomparable with the rule findings, which is
    the comparison the two-layer argument rests on.
    """
    event = scored.event
    details = getattr(event, "details", None)
    if not isinstance(details, dict):
        return None
    return details.get("path_basename_canonical") or None


@dataclass(frozen=True, slots=True)
class EntityRank:
    """One entity's position in the ranking, with the row that put it there."""

    entity: str
    #: Best (lowest) percentile among this entity's rows. An entity is as
    #: suspicious as its most suspicious row: an analyst who opens it sees
    #: every row, so burying one anomalous row under nine ordinary ones is a
    #: property of the artefacts, not evidence that the entity is ordinary.
    best_percentile: float
    #: The family that produced `best_percentile`. Percentiles are only
    #: comparable within a family, so the family has to travel with the number.
    family: str
    row_count: int
    #: 1-based position in the ranking, 1 being the most anomalous entity.
    rank: int


def rank_entities(scores: Sequence[Scored]) -> list[EntityRank]:
    """Collapse scored rows to a ranked list of entities.

    Rows with no entity key are dropped rather than grouped under a placeholder.
    An EVTX log-on record genuinely has no executable, and inventing a bucket
    for "no entity" would put unrelated rows in competition with one another.

    Ties are broken by entity name so the ranking is deterministic. Two entities
    with the same best percentile are genuinely tied and the order between them
    carries no meaning -- but an unstable order would make two runs of the same
    evaluation disagree, and that is worse.
    """
    best: dict[str, tuple[float, str]] = {}
    counts: dict[str, int] = {}

    for scored in scores:
        entity = entity_of(scored)
        pct = scored.percentile_in_family
        if entity is None or pct is None:
            continue
        counts[entity] = counts.get(entity, 0) + 1
        current = best.get(entity)
        if current is None or pct < current[0]:
            best[entity] = (pct, scored.family)

    ordered = sorted(best.items(), key=lambda kv: (kv[1][0], kv[0]))
    return [
        EntityRank(
            entity=entity,
            best_percentile=pct,
            family=family,
            row_count=counts[entity],
            rank=position,
        )
        for position, (entity, (pct, family)) in enumerate(ordered, start=1)
    ]


@dataclass(frozen=True, slots=True)
class RankingResult:
    """What an evaluation run measured. Every field is reportable as-is."""

    k: int
    total_entities: int
    #: Ground-truth entities that were scored at all. The denominator.
    evaluable: tuple[str, ...]
    #: Ground-truth entities the anomaly layer never scored, with the reason.
    #: Reported separately and NOT counted as misses -- see the module docstring
    #: and `groundtruth/verification-method.md` section 2.
    unscored: tuple[str, ...]
    #: Evaluable ground-truth entities inside the top K.
    found: tuple[str, ...]
    #: Evaluable ground-truth entities outside the top K. These ARE misses.
    missed: tuple[str, ...]
    #: Where each ground-truth entity actually landed, whether or not in top K.
    positions: dict[str, int] = field(default_factory=dict)

    @property
    def precision_at_k(self) -> float:
        """Share of the top K that is ground truth.

        On this corpus the ceiling is low by construction: one attack entity
        against a K of 10 caps precision at 0.10. That is a property of a
        single-scenario corpus, not a result about the model, and the write-up
        has to say so wherever this number appears.
        """
        return len(self.found) / self.k if self.k else 0.0

    @property
    def recall_at_k(self) -> float:
        """Share of EVALUABLE ground truth inside the top K.

        Zero evaluable entities returns 0.0 rather than raising: a run where
        nothing could be evaluated is a real outcome that should be reported,
        not an error that stops the evaluation.
        """
        return len(self.found) / len(self.evaluable) if self.evaluable else 0.0

    @property
    def lift(self) -> float:
        """Recall@K divided by the recall random ordering would give.

        Random ordering finds K/N of the ground truth, so lift is 1.0 for a
        model that ranks no better than chance and 0.0 for one that ranks
        actively worse. This is the number that says whether the ranking is
        worth anything at all, and it is the one to lead with -- precision@K
        is capped by the corpus, lift is not.
        """
        if not self.evaluable or not self.total_entities or not self.k:
            return 0.0
        chance = self.k / self.total_entities
        return self.recall_at_k / chance if chance else 0.0

    def lines(self) -> list[str]:
        """A reportable summary. Every number here is one a reader can check."""
        out = [
            f"K              : {self.k} of {self.total_entities} entities",
            f"Evaluable      : {len(self.evaluable)} ground-truth entities",
            f"Found in top K : {len(self.found)}",
            f"Precision@{self.k:<4} : {self.precision_at_k:.3f}",
            f"Recall@{self.k:<7} : {self.recall_at_k:.3f}",
            f"Lift           : {self.lift:.2f}x over random ordering",
        ]
        for entity in sorted(self.positions):
            position = self.positions[entity]
            marker = "in top K" if entity in self.found else "MISSED"
            out.append(f"  {entity}: rank {position}/{self.total_entities} ({marker})")
        for entity in self.unscored:
            # Not a miss. Separated because merging the two would charge the
            # model for a row it was never given.
            out.append(f"  {entity}: UNSCORED (no model for its family)")
        return out


def evaluate_ranking(
    scores: Sequence[Scored],
    ground_truth: Iterable[str] = SCENARIO1_ENTITIES,
    k: int = 10,
) -> RankingResult:
    """Measure how well the anomaly ranking surfaces known-attack entities.

    `k` is the number of entities an analyst is assumed to read. It is a
    reporting choice, not a model parameter -- nothing about the model changes
    with `k`, and results should be reported at several values rather than at
    whichever one looks best.
    """
    ranked = rank_entities(scores)
    positions = {entry.entity: entry.rank for entry in ranked}
    truth = set(ground_truth)

    evaluable = sorted(e for e in truth if e in positions)
    unscored = sorted(e for e in truth if e not in positions)

    top_k = {entry.entity for entry in ranked[:k]}
    found = sorted(e for e in evaluable if e in top_k)
    missed = sorted(e for e in evaluable if e not in top_k)

    return RankingResult(
        k=k,
        total_entities=len(ranked),
        evaluable=tuple(evaluable),
        unscored=tuple(unscored),
        found=tuple(found),
        missed=tuple(missed),
        positions={e: positions[e] for e in evaluable},
    )


def sweep(
    scores: Sequence[Scored],
    ground_truth: Iterable[str] = SCENARIO1_ENTITIES,
    ks: Sequence[int] = (1, 5, 10, 25, 50, 100),
) -> list[RankingResult]:
    """Evaluate at several K, because a single K invites choosing one.

    Reporting a sweep makes the shape of the result visible: a model that only
    surfaces the attack at K=100 is saying something different from one that
    surfaces it at K=5, and a single figure hides which.
    """
    truth = list(ground_truth)
    return [evaluate_ranking(scores, truth, k=k) for k in ks]
