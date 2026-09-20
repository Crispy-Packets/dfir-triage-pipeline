# Open decisions

Two decisions that were being carried by citation rather than by choice. Filed
2026-09-20.

---

## OD-01 — ML scope. OPEN; owner decides.

`week2-plan.md` §7 predates the ablation result and does not bind this. It is
recorded here as an open decision with both options, not resolved.

**Option (a) — build a working ML layer across the 38 families.** Extend
`FAMILY_FEATURES` to the 31 families that have none, then run unsupervised
anomaly detection over all of them.

*Cost:* feature design for 31 families, each needing the same per-family
measurement the existing 7 got. *Risk:* the measured ablation already showed
the anomaly layer does not separate the scenario entity on the families it
covers. Extending it to more families is a bet that coverage was the problem.
Nothing measured so far supports that bet.

**Option (b) — report the measured answer about unsupervised anomaly
detection on this corpus.** Treat the ablation as the result: state what was
tried, what it scored, and why a disk-image triage corpus of this size and
composition does not support the method.

*Cost:* the project ships without a working ML component. *Value:* a measured
negative about method-corpus fit, which is a real finding and is defensible
under questioning in a way a non-working layer is not.

**The tradeoff in one line.** (a) is more implementation and a weaker claim;
(b) is less implementation and a stronger one. The evidence in
`docs/evidence/ml-scope-evidence-2026-09-20.md` currently favours (b), but
that is an input to the decision, not the decision.

**Not decided here.** Owner's call.

---

## OD-02 — T1070.001 via SAM-vs-4624. DECIDED: leave as recorded measurement.

Grid §3.8 measures a clean discriminator: `sam.logon_count > interactive 4624`
separates every clean account (gap <= 0) from every scenario account
(gap >= +12), on the full non-built-in account population of both hosts. The
usual objection to writing a rule — no measured true positive — does not apply.
This one is measured.

**Decision: do not bump the schema to express it. Leave §3.8 as the record.**

Two reasons, in order of weight:

1. **On this corpus the rule would be corroborating, not corrective.** It
   identifies the same two hosts that R-ATOMIC-0002 already finds via EID 1102,
   which fires 0/0/0/1/1. Its distinct value is the case 1102 cannot cover —
   an attacker who deletes the `.evtx` outright, or clears twice so the 1102
   record is itself removed. **That case does not occur here.** A rule added
   now would be validated only in the condition where the existing rule already
   works, and would have to say so in its own notes.

2. **It is not expressible in the current schema, and the gap is structural.**
   Verified in the engine rather than assumed: numeric operators exist, and a
   corpus-level aggregate exists, but neither reaches a predicate comparing a
   per-entity count in one family against a per-entity count in another. That
   is a cross-family field-to-field comparison, which the grammar does not
   have. Closing it is a schema change of real size, not a new operator.

Spending a schema bump so that one rule can agree with an existing rule is the
wrong order of work. If the corpus later contains a deleted-log or
double-clear case, gate 1 disappears and this should be revisited — at which
point the schema work is justified by a case only this rule can cover.

**What stands:** §3.8 keeps the measurement, the reading-method checks, and the
reason it is not written. Nothing is discarded.
