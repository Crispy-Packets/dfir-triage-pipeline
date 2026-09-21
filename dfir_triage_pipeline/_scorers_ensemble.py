"""IF + MODA*-G ensemble scorer (OD-01 Phase 5, experiment 3).

Combines Isolation Forest and MODA*-G by averaging their WITHIN-BATCH percentile
ranks. Raw scores from two different algorithms are not comparable -- an IF
decision_function and a MODA*-G divergence are different scales -- but each
scorer's rank of a row within the same batch is, so the average is taken on
ranks, not on raw values.

Convention preserved: `decision_function` returns a value where LOWER is more
anomalous, so `AnomalyModel.score` (untouched) and the downstream
`assign_percentiles` behave exactly as for a single scorer. The averaged rank is
returned negated for that reason; `assign_percentiles` then re-ranks the averaged
value into the reported percentile, which is correct -- the ensemble decides the
ordering, the percentile just reads it off.

Imported ONLY when `DFIR_ANOMALY_SCORER=ensemble_if_moda`. Removable: delete this
file and the registry line.

An ensemble of two cannot beat its better member on a single entity by more than
the two disagree: if IF ranks prefetch's payload at 38% and MODA at 23%, the
average lands between. A rank BETTER than MODA's 14/443 would mean the two
scorers rank *different* benign entities as anomalous and the average suppresses
both crowds -- that is the informative outcome, not a foregone one.
"""

from __future__ import annotations

import numpy as np


def make_ensemble_scorer(n_estimators: int, contamination: float, random_state: int):
    from ._scorers_moda import make_moda_scorer
    from .anomaly import _make_isolation_forest

    return _EnsembleScorer(
        _make_isolation_forest(n_estimators),
        make_moda_scorer(n_estimators, contamination, random_state),
        contamination=contamination,
    )


def _percentile_ranks(scores: np.ndarray) -> np.ndarray:
    """Rank each score into [0,1], lower score -> lower rank (more anomalous).

    Ties share the average of the positions they span, so two identical scores
    do not get an arbitrary order -- the same principle assign_percentiles uses.
    """
    order = np.argsort(scores, kind="stable")
    ranks = np.empty(len(scores), dtype=float)
    i = 0
    n = len(scores)
    while i < n:
        j = i
        while j + 1 < n and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        avg_pos = (i + j) / 2.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_pos / max(n - 1, 1)
        i = j + 1
    return ranks


class _EnsembleScorer:
    def __init__(self, iforest, moda, contamination) -> None:
        self._if = iforest
        self._moda = moda
        self._contamination = contamination
        self._threshold: float | None = None

    def fit(self, rows: list[list[float]]) -> _EnsembleScorer:
        x = np.asarray(rows, dtype=float)
        self._if.fit(x)
        self._moda.fit(rows)
        train = self.decision_function(rows)
        self._threshold = float(np.quantile(train, self._contamination))
        return self

    def decision_function(self, rows: list[list[float]]):
        x = np.asarray(rows, dtype=float)
        # Both members already use LOWER = more anomalous.
        if_scores = np.asarray(self._if.decision_function(x), dtype=float)
        moda_scores = np.asarray(self._moda.decision_function(rows), dtype=float)
        avg_rank = 0.5 * (_percentile_ranks(if_scores) + _percentile_ranks(moda_scores))
        # Lower averaged rank = more anomalous, already in our convention.
        return avg_rank

    def predict(self, rows: list[list[float]]):
        scores = self.decision_function(rows)
        thr = (
            self._threshold
            if self._threshold is not None
            else np.quantile(scores, self._contamination)
        )
        return np.where(scores <= thr, -1, 1)
