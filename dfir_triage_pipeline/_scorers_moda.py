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
        self._train_cat: np.ndarray | None = None  # int-encoded, aligned with _train
        self._cat_maps: list[dict[str, int]] = []  # one value->int map per cat column
        self._threshold: float | None = None

    def fit(self, rows: list[list[float]]) -> _MODAScorer:
        self._train = np.asarray(rows, dtype=float)
        self._train_cat = None
        train_scores = self._score(self._train, None)
        self._threshold = float(np.quantile(train_scores, self._contamination))
        return self

    def _score(self, x: np.ndarray, x_cat) -> np.ndarray:
        """Raw MODA*-G scores in OUR convention (lower = more anomalous).

        Seeded before every call so the run is byte-reproducible. `x_cat` is the
        int-encoded categorical matrix or None (SDC inert when None)."""
        self._moda.moda_seed(self._random_state)
        raw = self._moda.moda_star(x, X_cat=x_cat)
        return -np.asarray(raw, dtype=float)

    def decision_function(self, rows: list[list[float]]):
        return self._decision(np.asarray(rows, dtype=float), None)

    def _decision(self, x: np.ndarray, x_cat):
        if self._train is None:
            return self._score(x, x_cat)
        # Score train+query together so a query row's anomalousness is measured
        # against the clean baseline plus its own batch, then return the query
        # tail. The concat applies to BOTH matrices; SDC's category rarity is
        # therefore measured over clean_c u the scored family (stated in the doc).
        n_train = self._train.shape[0]
        combined = np.vstack([self._train, x])
        combined_cat = None
        if x_cat is not None and self._train_cat is not None:
            combined_cat = np.vstack([self._train_cat, x_cat])
        return self._score(combined, combined_cat)[n_train:]

    def predict(self, rows: list[list[float]]):
        return self._apply_threshold(self.decision_function(rows))

    def _apply_threshold(self, scores):
        thr = (
            self._threshold
            if self._threshold is not None
            else np.quantile(scores, self._contamination)
        )
        return np.where(scores <= thr, -1, 1)

    # -- Table-aware path: fires SDC on the FeatureTable's categorical columns --
    #
    # AnomalyModel calls these when the estimator has them (duck-typed). The int
    # encoding is built from the TRAINING table; a value unseen at score time
    # maps to a reserved id, which is exactly the case score_sdc's p_unseen
    # branch handles. Isolation Forest has none of these methods, so its path is
    # untouched.
    def _encode(self, table, fit_maps: bool):
        if not table.categorical:
            return None
        cols = sorted(table.categorical)  # deterministic column order
        if fit_maps:
            self._cat_maps = []
            for name in cols:
                values = table.categorical[name]
                mapping: dict[str, int] = {}
                for v in values:
                    mapping.setdefault(v, len(mapping))
                self._cat_maps.append(mapping)
        encoded = []
        for j, name in enumerate(cols):
            mp = self._cat_maps[j]
            unseen = len(mp)  # reserved id for values not in training
            encoded.append([mp.get(v, unseen) for v in table.categorical[name]])
        return np.asarray(encoded, dtype=int).T  # (n_rows, n_cat_cols)

    def fit_table(self, table) -> _MODAScorer:
        self._train = np.asarray([list(r) for r in table.rows], dtype=float)
        self._train_cat = self._encode(table, fit_maps=True)
        train_scores = self._score(self._train, self._train_cat)
        self._threshold = float(np.quantile(train_scores, self._contamination))
        return self

    def decision_function_table(self, table):
        x = np.asarray([list(r) for r in table.rows], dtype=float)
        x_cat = self._encode(table, fit_maps=False)
        return self._decision(x, x_cat)

    def predict_table(self, table):
        return self._apply_threshold(self.decision_function_table(table))
