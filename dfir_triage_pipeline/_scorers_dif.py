"""Deep Isolation Forest (DIF) scorer wrapper (OD-01 Phase 5, experiment 1).

DIF (Xu et al., TKDE 2023, `xuhongzuo/deep-iforest`, packaged as `deepod`)
applies isolation forest over deep random projections, giving non-linear
partitions Isolation Forest cannot make. It is the one alternative here with a
genuine chance of finding an axis IF misses -- Phase 3 showed the attack entity
is already extreme on every LINEAR axis.

This module is imported ONLY when `DFIR_ANOMALY_SCORER=dif`. The default path
never touches it, so torch (deepod's backend) is not a dependency of the shipped
pipeline. Removable: delete this file and the `"dif"` line in
`anomaly._SCORER_REGISTRY`.

Two adaptations to sklearn's outlier-estimator contract, both required for
`AnomalyModel.score` (which is untouched) to stay correct:

* **Sign.** deepod scores HIGHER = more anomalous; sklearn (and this project)
  use LOWER = more anomalous. `decision_function` negates.
* **`predict`.** deepod's DIF exposes a score, not a -1/1 label. We threshold at
  the `contamination` quantile of the TRAINING scores, matching how Isolation
  Forest sets its own boundary, and using the SAME contamination so the
  clean-host outlier rate is a property of the algorithm, not a free parameter.
"""

from __future__ import annotations

import numpy as np


def make_dif_scorer(n_estimators: int, contamination: float, random_state: int):
    try:
        from deepod.models.tabular import DeepIsolationForest
    except ImportError as exc:  # pragma: no cover - environment-dependent
        raise RuntimeError(
            "DFIR_ANOMALY_SCORER=dif requires deepod (and torch). "
            "Install with: pip install deepod"
        ) from exc

    return _DIFScorer(
        DeepIsolationForest,
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )


class _DIFScorer:
    """Adapts deepod's DeepIsolationForest to the project's Scorer contract.

    LOWER decision_function = more anomalous (sign-flipped from deepod), and
    predict returns {-1 outlier, 1 inlier} thresholded at the contamination
    quantile of the training scores.
    """

    def __init__(self, cls, n_estimators, contamination, random_state) -> None:
        self._contamination = contamination
        # n_estimators maps to DIF's ensemble size. random_state is set both on
        # the estimator and via numpy/torch seeds (below) because a neural model
        # left unseeded gives different scores each run, which would break the
        # manifest's byte-reproducibility property (test_two_builds_produce...).
        self._model = cls(
            n_ensemble=n_estimators,
            random_state=random_state,
        )
        self._random_state = random_state
        self._threshold: float | None = None

    def _seed(self) -> None:
        np.random.seed(self._random_state)
        try:
            import torch

            torch.manual_seed(self._random_state)
            torch.use_deterministic_algorithms(True, warn_only=True)
        except ImportError:  # pragma: no cover
            pass

    def fit(self, rows: list[list[float]]) -> _DIFScorer:
        self._seed()
        x = np.asarray(rows, dtype=float)
        self._model.fit(x)
        # Threshold for predict(): the contamination quantile of the training
        # decision scores. Computed on our sign (lower = more anomalous), so the
        # most anomalous `contamination` fraction sits at or below it.
        train = self.decision_function(rows)
        self._threshold = float(np.quantile(train, self._contamination))
        return self

    def decision_function(self, rows: list[list[float]]):
        x = np.asarray(rows, dtype=float)
        # deepod: higher = more anomalous. Negate to our convention.
        return -np.asarray(self._model.decision_function(x), dtype=float)

    def predict(self, rows: list[list[float]]):
        scores = self.decision_function(rows)
        thr = self._threshold if self._threshold is not None else np.quantile(
            scores, self._contamination
        )
        return np.where(scores <= thr, -1, 1)
