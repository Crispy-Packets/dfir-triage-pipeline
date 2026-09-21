"""MODA*-G scorer wrapper (OD-01 Phase 5, experiment 2).

MODA*-G (Marcano Verde, 2026; Zenodo 19439683) is "Mixed-Data Outlier
Divergence Analysis with Softmax Gating" -- four statistical engines (MCD,
Peña kurtosis, Gower-kNN, categorical entropy) combined by an observation-level
softmax gate. The core is vendored under `_vendor/moda_star.py` (MIT), with one
determinism patch documented there.

Imported ONLY when `DFIR_ANOMALY_SCORER=moda_g`. Removable: delete this file,
`_vendor/moda_star.py`, and the `"moda_g"` line in `anomaly._SCORER_REGISTRY`.

Two adaptations to the project's Scorer contract:

* **Transductive -> fit/score.** MODA*-G has no trained model: `moda_star(X)`
  scores rows relative to the batch it is given. To answer the same question
  Isolation Forest does -- "how unusual is this row relative to the CLEAN
  baseline?" -- `fit` stores the training rows and `decision_function` scores
  `vstack(train, rows)`, returning only the tail (the query rows). The reference
  distribution is therefore clean_c plus the family being scored; the query rows
  do influence the reference, which is inherent to a transductive method and is
  stated in the evidence doc.

* **Sign + predict.** MODA*-G scores HIGHER = more anomalous (`scores >= tau`
  is an outlier); we negate for the project's lower-is-anomalous convention, and
  derive `predict` at the contamination quantile of the training scores, same as
  the other scorers and with the same contamination.

Caveat recorded in the evidence doc: this feature layer is all-numeric, so
MODA*-G's categorical engine (SDC) is inert and only MCD+Peña+Gower gate. The
comparison tests that subset of the method, not the full mixed-data design.
"""

from __future__ import annotations

import numpy as np


def make_moda_scorer(n_estimators: int, contamination: float, random_state: int):
    # n_estimators is unused: MODA*-G is not an ensemble of trees. Kept in the
    # signature so the registry factory contract is uniform across scorers.
    from ._vendor import moda_star as moda

    return _MODAScorer(moda, contamination=contamination, random_state=random_state)


class _MODAScorer:
    def __init__(self, moda, contamination, random_state) -> None:
        self._moda = moda
        self._contamination = contamination
        self._random_state = random_state
        self._train: np.ndarray | None = None
        self._threshold: float | None = None

    def fit(self, rows: list[list[float]]) -> _MODAScorer:
        self._train = np.asarray(rows, dtype=float)
        # Threshold for predict(): contamination quantile of the training rows'
        # own scores, scored in the training-only context.
        train_scores = self._score(self._train)
        self._threshold = float(np.quantile(train_scores, self._contamination))
        return self

    def _score(self, x: np.ndarray) -> np.ndarray:
        """Raw MODA*-G scores in OUR convention (lower = more anomalous).

        Seeded before every call so the run is byte-reproducible."""
        self._moda.moda_seed(self._random_state)
        # All-numeric feature layer: X_cat is empty, so SDC is inert by design.
        raw = self._moda.moda_star(x, X_cat=None)
        return -np.asarray(raw, dtype=float)

    def decision_function(self, rows: list[list[float]]):
        x = np.asarray(rows, dtype=float)
        if self._train is None:
            return self._score(x)
        # Score train+query together so a query row's anomalousness is measured
        # against the clean baseline plus its own batch, then return the query
        # tail. The closest a transductive method gets to IF's fit/score split.
        n_train = self._train.shape[0]
        combined = np.vstack([self._train, x])
        return self._score(combined)[n_train:]

    def predict(self, rows: list[list[float]]):
        scores = self.decision_function(rows)
        thr = (
            self._threshold
            if self._threshold is not None
            else np.quantile(scores, self._contamination)
        )
        return np.where(scores <= thr, -1, 1)
