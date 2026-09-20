# ML scope — evidence for a decision not yet made — 2026-09-20

**This document does not decide anything.** It assembles what is measured that
bears on the eventual (a)-versus-(b) scope call. That call belongs to the
project owner and is made when the ML workstream is reached.

**Status correction, 2026-09-20.** This file was first written as a decision
("Decision: (b), the workstream is complete") and `CLAUDE.md` was edited to
match. That overstepped: the task was to *answer the scope question*, not to
settle it, and the answer was then filed as though the decision had been
taken. Both are corrected. The measurements below are unchanged — only the
claim about what they settle.

Nothing here has been started or extended: `FAMILY_FEATURES` remains at its
seven declared families.

---

## What `week2-plan.md` §7 does and does not establish

§7 is the earliest statement of scope, and it is **not** binding on the
decision, for a reason of ordering: it was written 2026-08-28, *before any
model code existed* and therefore before the ablation. A document cannot
settle a question that later evidence reframes. It is recorded here as the
original intent, not as the answer.

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

So the *original* framing was a baseline rather than a detector. Whether that
framing still stands once the ablation is in hand is exactly the open
question — it is not answered by quoting the document that predates it.

## What is measured

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

## What bears against (a), for the owner to weigh

Extending `FAMILY_FEATURES` to 31 further families is a large workstream —
per-family feature design, per-family leakage testing, per-family measurement.
Three measured facts bear on its expected value. They are arguments to weigh,
not a verdict:

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

## The figures above are current; no re-measurement is needed to read them

The advisor's caveat was that "the ablation is the result" needs an ablation
that is not superseded. Checked: `layer-ablation-2026-09-18.md` carries a
SUPERSEDED banner for D-058, and the banner itself states at line 37 that the
**anomaly-side percentiles (81/443) are unaffected — D-058 changes entity
scoring, not the model.** Only the rules-side ranks were invalidated, and
those were re-measured when D-058 landed.

So the ML-side figures above are current, and **D-062's re-measure is not a
precondition for reading them.** It is not run here.

## What is settled and what is not

**Settled, because measured.** The anomaly layer ranks rather than detects:
rules place the payload at rank 1 on both hosts, ML alone at 298/1189 and
134/892, and no family places it in its own top decile. There is a ~5%
false-positive floor on clean hosts. These figures are current post-D-058.

**Not settled.** Whether that result answers the project's ML question (b), or
motivates the 38-family extension (a), or something else. That is a scope
judgement about what the project is for, and it is the owner's to make when
the ML workstream is reached.

**Not started, and not to be started ahead of that call.** Extending
`FAMILY_FEATURES`; feature design for the 31 new families; re-running the
ablation in anticipation of ML work.

**Framing note for whenever the call is made.** A negative result about a
technique is a result, not a failure of the project — the rules backlog
emptying at seven-measured-one-written is the same shape. But "the measurement
is a result" is not itself an argument for stopping, and this document should
not be read as making one.
