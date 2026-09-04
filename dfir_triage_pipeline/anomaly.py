"""Isolation Forest scoring over the behavioural feature layer (B-12).

The model is unsupervised by necessity, not by preference: the corpus holds one
attack-attributable row in roughly 24,000, so there is nothing to train a
classifier on. Isolation Forest is fitted on a baseline collection and used to
score others, which asks "how unlike the baseline is this row?" rather than
"is this row malicious?".

The distinction matters for what may be claimed. A high score means the row is
unusual relative to what the model was shown. It does not mean the row is an
attack, and on this corpus most high scores are benign -- installer activity,
maintenance tasks, and the VirtualBox build difference (D-026).
"""

from __future__ import annotations

from dataclasses import dataclass

from .features import FeatureTable

# Fixed so a run is reproducible. Isolation Forest samples both features and
# split points, so an unseeded model gives different scores every run and no
# result could be checked against a previous one.
RANDOM_SEED = 20260830

# The proportion of the training set the model is told to treat as outlying.
# Left explicit rather than "auto" because auto's value has changed between
# scikit-learn versions, and a threshold that moves with a library upgrade is
# not a threshold anyone can reason about.
CONTAMINATION = 0.05


@dataclass(frozen=True, slots=True)
class Scored:
    """A scored row, kept beside the event that produced it.

    `score` is the raw decision function: lower is more anomalous. It is not a
    probability and not a severity, and it is comparable only against other
    scores from the same fitted model.

    `percentile_in_family` is the reportable form. Under `PerFamilyModel` each
    family has its own fitted forest, so raw scores are not comparable between
    families: a -0.09 from the Prefetch model and a -0.09 from the Amcache
    model are not the same statement. The percentile is, by construction.

    It is a RANK, not a probability. 0.0 is the most anomalous row in its
    family and 100.0 the least. A row at 2.0 is "in the most unusual 2% of
    rows of this kind", which is a statement about the population scored -- not
    a 98% chance of anything. Rescaling it to look like a probability is
    rejected in `docs/feature-decisions.md`; the acceptance gate requires the
    ML be labelled as anomaly prioritisation rather than a malicious verdict,
    and a number that reads as confidence-of-malice fights that label.
    """

    event: object
    score: float
    is_outlier: bool
    #: The family this row was scored within. Empty when a bare `AnomalyModel`
    #: was used directly, which does not know what it was fitted on.
    family: str = ""
    #: Rank position within `family`, 0.0 (most anomalous) to 100.0. `None`
    #: when the row was not scored as part of a family population.
    percentile_in_family: float | None = None


def assign_percentiles(scores: list[Scored], family: str) -> list[Scored]:
    """Return `scores` with `family` and `percentile_in_family` filled in.

    Ties share the lowest position they span. Isolation Forest cannot isolate
    identical rows, so tied scores are common and D-038 is the same phenomenon
    seen from the other side: `evtx.powershell` reports 3.71% outliers against
    a 5% setting because its rows are largely identical. Handing tied rows
    different percentiles would invent an ordering the model did not produce.
    """
    if not scores:
        return []

    order = sorted(range(len(scores)), key=lambda i: scores[i].score)
    n = len(scores)
    out: list[Scored | None] = [None] * n

    i = 0
    while i < n:
        j = i
        while j + 1 < n and scores[order[j + 1]].score == scores[order[i]].score:
            j += 1
        # Position of the tie block's first member, as a percentage. A single
        # row is a block of one, so the general form covers the untied case.
        pct = 100.0 * i / n if n > 1 else 0.0
        for k in range(i, j + 1):
            idx = order[k]
            s = scores[idx]
            out[idx] = Scored(
                event=s.event,
                score=s.score,
                is_outlier=s.is_outlier,
                family=family,
                percentile_in_family=pct,
            )
        i = j + 1

    return [s for s in out if s is not None]


class AnomalyModel:
    """Isolation Forest wrapper that keeps scores attached to their evidence."""

    def __init__(self, n_estimators: int = 200) -> None:
        from sklearn.ensemble import IsolationForest

        self._forest = IsolationForest(
            n_estimators=n_estimators,
            contamination=CONTAMINATION,
            random_state=RANDOM_SEED,
            # Use every row rather than the default 256-row subsample. The
            # collections are small enough that subsampling adds variance for
            # no speed benefit worth having.
            max_samples=1.0,
        )
        self.feature_names: tuple[str, ...] = ()

    def fit(self, table: FeatureTable) -> AnomalyModel:
        if not table.rows:
            raise ValueError("cannot fit on an empty feature table")
        self.feature_names = table.names
        self._forest.fit([list(r) for r in table.rows])
        return self

    def score(self, table: FeatureTable) -> list[Scored]:
        """Score rows against the fitted model.

        The feature names are checked rather than trusted. The model scores by
        column position, so a table built with a different feature order would
        be scored silently and wrongly -- every column reinterpreted as its
        neighbour.
        """
        if table.names != self.feature_names:
            raise ValueError(
                "feature layout differs from the fitted model: "
                f"fitted {self.feature_names}, given {table.names}"
            )
        if not table.rows:
            return []

        raw = [list(r) for r in table.rows]
        scores = self._forest.decision_function(raw)
        flags = self._forest.predict(raw)
        return [
            Scored(event=event, score=float(s), is_outlier=bool(f == -1))
            for event, s, f in zip(table.events, scores, flags, strict=True)
        ]


# Below this many training rows a family cannot support its own model: the
# forest would be fitted on too few points for its splits to mean anything.
# Those families are reported as unscored rather than folded into another
# model, because folding them back is exactly the mixing this class avoids.
MIN_TRAINING_ROWS = 50


class PerFamilyModel:
    """One Isolation Forest per source_artifact.

    A single model over all families does not work on this corpus, and the
    reason is structural rather than a tuning problem. The feature vector has
    columns that only one family can populate -- `run_count` is non-zero only
    for Prefetch, `path_depth` only for rows that carry a path -- so a mixed
    model spends its splits separating artifact types instead of behaviours.

    Measured on clean_b as training:

    | model | clean_a outlier rate | s1_v2 outlier rate |
    |---|---|---|
    | single | 5.5% | 27.4% |
    | per family | 5.3% | 7.7% |

    The single model's 27.4% was almost entirely artifact mix: s1_v2 is 51%
    Prefetch and Amcache against 15% in the baselines, and those rows scored
    anomalously whatever they contained. Only 2 of its 938 flagged rows were
    VirtualBox-related, so this was not the D-026 build difference either.

    Comparing like with like is also the more defensible claim: "this execution
    is unusual among executions" is a statement a reader can check, where "this
    execution is unusual among log-on records" is not.
    """

    def __init__(self, n_estimators: int = 200) -> None:
        self._n_estimators = n_estimators
        self.models: dict[str, AnomalyModel] = {}
        self.unscored_families: set[str] = set()

    def fit(self, events, rarity) -> PerFamilyModel:
        from . import features

        grouped: dict[str, list] = {}
        for event in events:
            grouped.setdefault(event.source_artifact, []).append(event)

        for family, rows in grouped.items():
            if len(rows) < MIN_TRAINING_ROWS:
                self.unscored_families.add(family)
                continue
            table = features.build(rows, rarity)
            self.models[family] = AnomalyModel(self._n_estimators).fit(table)
        return self

    def score(self, events, rarity) -> list[Scored]:
        """Score events, each against the model for its own family.

        Events from a family with no fitted model are omitted from the result
        rather than given a default score. A score of "not anomalous" for a row
        that was never modelled is a claim the model did not make.
        """
        from . import features

        grouped: dict[str, list] = {}
        for event in events:
            grouped.setdefault(event.source_artifact, []).append(event)

        out: list[Scored] = []
        for family, rows in grouped.items():
            model = self.models.get(family)
            if model is None:
                continue
            # Percentiles are assigned within the family population being
            # scored, which is what makes them comparable across families.
            out.extend(assign_percentiles(model.score(features.build(rows, rarity)), family))
        return out


def summarise(scores: list[Scored]) -> dict[str, float]:
    """Distribution summary, for comparing one collection against another."""
    if not scores:
        return {}
    values = sorted(s.score for s in scores)

    def pct(p: float) -> float:
        return values[min(len(values) - 1, int(len(values) * p))]

    return {
        "n": float(len(values)),
        "min": values[0],
        "p05": pct(0.05),
        "p25": pct(0.25),
        "median": pct(0.50),
        "p75": pct(0.75),
        "p95": pct(0.95),
        "max": values[-1],
        "mean": sum(values) / len(values),
        "outlier_rate": sum(1 for s in scores if s.is_outlier) / len(scores),
    }


def overlap_coefficient(a: list[Scored], b: list[Scored], bins: int = 50) -> float:
    """Histogram overlap between two score distributions, 0.0 to 1.0.

    This is the acceptance criterion for B-12. Two collections that differ only
    by which day they were collected must produce distributions that sit on top
    of one another. If they do not, the features encode collection identity and
    no result from a third collection can be interpreted.

    Computed as the summed minimum of the two normalised histograms, which is
    the standard overlapping coefficient: 1.0 is identical, 0.0 is disjoint.
    """
    if not a or not b:
        return 0.0

    xs = [s.score for s in a]
    ys = [s.score for s in b]
    lo, hi = min(min(xs), min(ys)), max(max(xs), max(ys))
    if hi == lo:
        return 1.0

    width = (hi - lo) / bins
    ha = [0] * bins
    hb = [0] * bins
    for value, hist in ((xs, ha), (ys, hb)):
        for v in value:
            idx = min(bins - 1, int((v - lo) / width))
            hist[idx] += 1

    return sum(min(x / len(xs), y / len(ys)) for x, y in zip(ha, hb, strict=True))
