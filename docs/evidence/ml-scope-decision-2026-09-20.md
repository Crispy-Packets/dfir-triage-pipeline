# ML scope decision — 2026-09-20

**Decision: (b). The ML workstream is complete. The ablation is the result.**

Deliverable (a) — a working ML layer across 38 families — is **not** started.
`FAMILY_FEATURES` stays at its seven declared families.

---

## The question was already answered in writing, before any model code existed

`docs/week2-plan.md` §7, decided 2026-08-28, committed the ML component as an
**unsupervised anomaly baseline**, and scoped the deliverable explicitly:

> **Consequence:** the Week 4 evaluation reports rule detection rates and
> false-positive rates, plus an unsupervised anomaly baseline. It does not
> report classifier precision, recall or F1 against a trained model. Any such
> figure would be measuring one example.

The reason given there is not a corpus accident. The corpus holds **one
attack-attributable row in 24,323** (0.004%). One execution produces one
Prefetch record; that is a property of a single-scenario lab. A supervised
model reaches 99.996% accuracy by answering "benign" every time, and every
ranking metric over one ground-truth entity reduces to its position.

So the deliverable was never "a detector". It was "does unsupervised anomaly
detection contribute to forensic triage on disk collections, and by how much" —
and that question now has a measured answer.

## The measured answer

From `docs/evidence/layer-ablation-2026-09-18.md` and D-062:

| configuration | host 1 | host 2 |
|---|---|---|
| rules only | payload rank **1** | payload rank **1** |
| ML only | 298 / 1189 (25.1%) | 134 / 892 (15.0%) |
| 7 families declared, 7 parsed | — | 40 / 525 (7.6%) |
| 7 families declared, 38 parsed | 298 / 1189 | 81 / 443 (18.3%) |

And from `CLAUDE.md`, measured per family: **no family places the attack
entity in its own top decile** — `bam` 33%, `prefetch` 41%, `amcache` 89%.

**The anomaly layer ranks; it does not detect.** Detection comes entirely from
the deterministic rules. The layer contributes triage ordering and a measured
~5% false-positive floor on clean hosts. That is the finding, and it is a
negative result stated as a result rather than a gap.

## Why (a) would not change it

Extending `FAMILY_FEATURES` to 31 further families is a large workstream —
per-family feature design, per-family leakage testing, per-family measurement
— with an honest expected outcome of *ranks more families, still does not
detect*. Three things already measured say so:

1. **The percentile fell when families were added** (7.6% -> 18.3% on host 2),
   because the entity denominator grew while the model stayed fitted on seven
   families. Extending the model would recover that dilution. Recovering
   dilution is not detection.
2. **The per-family figures are the ceiling.** The layer's best family places
   the payload at 33%. Adding families adds more families like those.
3. **Leakage is the binding constraint, not coverage.** `hour_of_day` scores
   86.0% by learning collection identity; one model over mixed families put
   `s1_v2` at 27.4% outliers almost entirely from artifact mix. Each new family
   is another opportunity to learn the collection rather than the behaviour,
   and the defence against that is per-family feature restriction —
   i.e. more of the work that produced the current ceiling.

## No re-measurement is required to close this

The advisor's caveat was that "the ablation is the result" needs an ablation
that is not superseded. Checked: `layer-ablation-2026-09-18.md` carries a
SUPERSEDED banner for D-058, and the banner itself states at line 37 that the
**anomaly-side percentiles (81/443) are unaffected — D-058 changes entity
scoring, not the model.** Only the rules-side ranks were invalidated, and
those were re-measured when D-058 landed.

So the ML-side figures this decision rests on are current. **D-062's
re-measure is not a precondition for (b)** and is not run here.

## What this closes, and what it does not

**Closed.** The ML workstream. The question "does unsupervised anomaly
detection contribute to forensic detection on disk collections" is answered:
not beyond triage ranking and a ~5% FP floor, on this corpus, with the
per-family and leakage measurements that establish why.

**Not closed, and deliberately not started.** Extending `FAMILY_FEATURES`;
feature design for the 31 new families; any re-run of the ablation in
anticipation of ML work. Each is a workstream the current result does not
justify.

**Honest framing for the write-up.** This is a negative result about a
technique, not a failure of the project. It is also the second time this
session that a measured answer closed a workstream that looked open: the rules
backlog emptied at seven-measured-one-written, and the ML layer closes at
ranks-but-does-not-detect. Both are results.
