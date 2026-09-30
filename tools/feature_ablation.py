"""B-11b: feature ablation. Drop each feature in turn, measure the effect.

Evidence, not a search. Run once, record what it says. Removing features until
the rank improves is tuning the corpus to the test -- the process that produced
the 27.4% artefact-mix result.

The reduced table is rebuilt with an explicit name tuple rather than by slicing
row indices, because AnomalyModel.score checks names against the fitted model
precisely so a shifted layout cannot be scored silently.
"""
from pathlib import Path

from dfir_triage_pipeline import anomaly, evaluation, features
from dfir_triage_pipeline.ingest import collect_events

E = Path.home() / "dfir-evidence"
GROUND_TRUTH = "invoice_scan.exe"

train = collect_events(E / "collection_clean_c")[0]
test = collect_events(E / "collection_s1_v3")[0]
assert train and test, "a collection produced no events"

ALL = features.FEATURE_NAMES


def run(drop: str | None) -> tuple[int, int, float, int]:
    """Fit and score with one feature zeroed. Returns rank, total, pct, n_scored."""
    orig_build = features.build

    def build_reduced(events, rarity=None, family=None):
        """Drop `drop` from whatever set this family would normally get.

        Family-aware since the per-family split: a feature the family does not
        carry cannot be ablated from it, and dropping by global index would
        remove the wrong column entirely.
        """
        t = orig_build(events, rarity, family)
        if drop is None or drop not in t.names:
            return t
        idx = [i for i, n in enumerate(t.names) if n != drop]
        rows = [tuple(r[i] for i in idx) for r in t.rows]
        names = tuple(t.names[i] for i in idx)
        return features.FeatureTable(names=names, rows=rows, events=t.events)

    features.build = build_reduced
    try:
        rarity = features.build_rarity_index(train)
        model = anomaly.PerFamilyModel().fit(train, rarity)
        scored = model.score(test, rarity)
        ranked = evaluation.rank_entities(scored)
        n_attack = sum(
            1 for s in scored
            if GROUND_TRUTH in str(evaluation.entity_of(s) or "").lower()
        )
        for r in ranked:
            if GROUND_TRUTH in r.entity:
                return r.rank, len(ranked), r.best_percentile, n_attack
        return -1, len(ranked), -1.0, n_attack
    finally:
        features.build = orig_build


base_rank, base_total, base_pct, base_n = run(None)
print(f"BASELINE: rank {base_rank}/{base_total}  pct {base_pct:.2f}  "
      f"({base_n} attack rows scored)\n")

print(f"{'feature removed':<48} {'rank':>6} {'change':>8} {'pct':>7}")
print("-" * 73)
print(f"{'(none - baseline)':<48} {base_rank:>6} {'--':>8} {base_pct:>7.2f}")

results = []
for name in ALL:
    rank, total, pct, _ = run(name)
    delta = rank - base_rank
    results.append((name, rank, delta, pct))
    arrow = "worse" if delta > 0 else ("better" if delta < 0 else "")
    print(f"{name:<48} {rank:>6} {delta:>+8} {pct:>7.2f}  {arrow}")

print("\n=== FEATURES THAT CARRY SIGNAL (removal makes it worse) ===")
for n, _r, d, _p in sorted(results, key=lambda x: -x[2]):
    if d > 0:
        print(f"  {n:<46} +{d} places when removed")

print("\n=== FEATURES CONTRIBUTING NOTHING (removal changes nothing) ===")
dead = [n for n, _r, d, _p in results if d == 0]
for n in dead:
    print(f"  {n}")
if not dead:
    print("  (none)")
