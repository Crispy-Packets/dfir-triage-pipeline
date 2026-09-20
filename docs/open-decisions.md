# Open decisions

Two decisions that were being carried by citation rather than by choice. Filed
2026-09-20.

---

## OD-01 — ML scope. DECIDED: (b), report the measured answer.

`week2-plan.md` §7 predates the ablation and does not bind this. The decision
is made here on the ablation's result, not by citation.

**Decision: do not extend `FAMILY_FEATURES` to the 31 further families. Report
what unsupervised anomaly detection does on this corpus, as the result.**

`FAMILY_FEATURES` stays at 7.

**Why.** The measured facts, none of which are new:

* The anomaly layer **ranks; it does not detect.** Nothing is flagged as an
  outlier in either host's scenario collection.
* **No family places the attack entity in its own top decile** — `bam` 33%,
  `prefetch` 41%, `amcache` 89%. The 1-of-894 headline is the rules layer
  placing the entity first, with the anomaly ranking appended behind it.
* The ablation moved the wrong way when the event pool grew: 7.6% -> 18.3% on
  host 2, because the entity denominator grew while the model stayed fitted on
  seven families. Dilution, not damage — but it means more families is not
  obviously the lever.
* The layer carries a **~5% false-positive floor** on clean hosts.

Option (a) — feature design for 31 further families — is a bet that coverage
was the limiting factor. Nothing measured supports that bet. The families
already covered include the ones the attack entity appears in, and it ranks
badly in all of them. Extending to families the attack does not touch cannot
improve its rank; it enlarges the denominator, which the ablation already
showed makes the percentile worse.

**What (b) commits to saying.** Not "ML was out of scope" — that is the effort
claim principle 2 rejects. The claim is narrower and defensible: on a
five-collection disk-image triage corpus with one ground-truth entity and four
attack events in 2,304, unsupervised per-family anomaly detection ranks rather
than detects, and its ranking does not place the attack entity high enough to
triage on. The deterministic rules do that. This is a measured negative about
method-corpus fit and it stands on the record already in
`docs/evidence/ml-stage-record-2026-09-13.md` and `ml-scope-evidence-2026-09-20.md`.

**What would reopen this.** A corpus with enough labelled intrusion entities to
compute lift rather than a single rank. That is a collection problem, not a
feature-engineering one — which is itself the finding.

**Not a rejection of the anomaly layer.** It stays in the pipeline, in the
prioritisation panel, labelled as ranking. D-062's rule holds: a rank figure
quoted without its pipeline version is the defect.

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
