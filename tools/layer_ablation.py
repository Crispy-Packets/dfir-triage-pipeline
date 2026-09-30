"""B-11a: what does each layer contribute?

The project's central claim is that detection is deterministic and the anomaly
layer prioritises. This measures both halves separately and together, which is
the only way that claim can be checked rather than asserted.

    python tools/layer_ablation.py

**This is not a tuning exercise.** Unlike the feature ablation, nothing here
produces a configuration to choose between: the two layers both ship, and the
question is what each is worth. A result showing one layer contributes nothing
would be reported, not acted on.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from dfir_triage_pipeline import anomaly, evaluation, features  # noqa: E402
from dfir_triage_pipeline.core import entity_score  # noqa: E402
from dfir_triage_pipeline.core.engine import run as run_rules  # noqa: E402
from dfir_triage_pipeline.core.ruleset import load_rules  # noqa: E402
from dfir_triage_pipeline.ingest import collect_events  # noqa: E402
from dfir_triage_pipeline.timeline import sort_events  # noqa: E402

EVIDENCE = Path.home() / "dfir-evidence"

#: The entity Scenario 1 is about. Both layers are asked the same question:
#: does this surface, and how much else surfaces alongside it?
GROUND_TRUTH = "invoice_scan.exe"

#: Analyst review budget. A triage tool is used by someone with limited time,
#: so "did it surface in the first K things read" is the question that matters
#: rather than "did it appear anywhere in the output".
REVIEW_BUDGET = 10


def rules_only(events, rules):
    """Findings, and the entities they name."""
    findings, _ = run_rules(rules, events)
    entities = entity_score.aggregate(findings)
    ranked = [e.value for e in entities]
    position = ranked.index(GROUND_TRUTH) + 1 if GROUND_TRUTH in ranked else None
    return {
        "findings": len(findings),
        "entities": len(entities),
        "position": position,
        "top": ranked[:REVIEW_BUDGET],
    }


def ml_only(train_events, test_events):
    """Ranked entities from the anomaly layer alone."""
    rarity = features.build_rarity_index(train_events)
    model = anomaly.PerFamilyModel().fit(train_events, rarity)
    scored = model.score(test_events, rarity)
    ranked = evaluation.rank_entities(scored)
    names = [r.entity for r in ranked]
    position = names.index(GROUND_TRUTH) + 1 if GROUND_TRUTH in names else None
    return {
        "scored_rows": len(scored),
        "entities": len(ranked),
        "position": position,
        "top": names[:REVIEW_BUDGET],
    }


def both(events, rules, train_events):
    """Rule entities first, then anomaly rank among the remainder.

    This is what the pipeline actually reports: the verdict panel is read
    before the prioritisation panel, so an entity named by a rule is reached
    before any entity that is merely unusual.
    """
    findings, _ = run_rules(rules, events)
    entities = entity_score.aggregate(findings)
    named = [e.value for e in entities]

    rarity = features.build_rarity_index(train_events)
    model = anomaly.PerFamilyModel().fit(train_events, rarity)
    scored = model.score(events, rarity)
    ranked = [r.entity for r in evaluation.rank_entities(scored)]

    combined = named + [e for e in ranked if e not in named]
    position = combined.index(GROUND_TRUTH) + 1 if GROUND_TRUTH in combined else None
    return {"entities": len(combined), "position": position, "top": combined[:REVIEW_BUDGET]}


def main() -> int:
    rules = load_rules(REPO / "rules")
    train = collect_events(EVIDENCE / "collection_clean_c")[0]

    for label, name in (("SCENARIO", "collection_s1_v3"), ("CLEAN", "collection_clean_c")):
        events = sort_events(collect_events(EVIDENCE / name)[0])
        print(f"\n{'=' * 66}")
        print(f"{label}: {name}  ({len(events)} events)")
        print("=" * 66)

        r = rules_only(events, rules)
        m = ml_only(train, events)
        b = both(events, rules, train)

        print(f"\n{'layer':<14} {'entities':>9} {'attack rank':>12} {'in top 10':>10}")
        print("-" * 50)
        for tag, result in (("rules only", r), ("ML only", m), ("both", b)):
            pos = result["position"]
            rank = f"{pos}/{result['entities']}" if pos else "not surfaced"
            hit = "yes" if pos and pos <= REVIEW_BUDGET else "no"
            print(f"{tag:<14} {result['entities']:>9} {rank:>12} {hit:>10}")

        if label == "SCENARIO":
            print(f"\nrules only -- {r['findings']} findings, top {REVIEW_BUDGET} entities:")
            for i, e in enumerate(r["top"], 1):
                mark = "  <-- ATTACK" if e == GROUND_TRUTH else ""
                print(f"  {i:>2}. {e}{mark}")
            print(f"\nML only -- top {REVIEW_BUDGET} entities:")
            for i, e in enumerate(m["top"], 1):
                mark = "  <-- ATTACK" if e == GROUND_TRUTH else ""
                print(f"  {i:>2}. {e}{mark}")
        else:
            print(f"\nrules only -- {r['findings']} findings on a collection with NO attack")
            print(f"  entities named: {', '.join(r['top']) or 'none'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
