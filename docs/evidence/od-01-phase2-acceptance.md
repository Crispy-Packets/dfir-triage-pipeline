# OD-01 Phase 2 — acceptance test: both candidates dropped

Measured 2026-09-20 on the two scenario collections. The Phase 2 acceptance
criterion, before any feature design: does the attack entity have enough rows
and enough behavioural variance to *plausibly* rank top-quartile in this
family? This is a drop test (a necessary condition for ranking high), not a
prediction of the Isolation Forest's percentile — that is Phase 3's.

Phase 1 left two candidates: `userassist` and `defender_mplog`. Both fail.

## `defender_mplog` — dropped: attack entity absent

| collection | family rows | attack-entity rows |
|---|---|---|
| s1_v2 | 2,704 | **0** |
| s1_v3 | 216 | 1 (no numeric value) |

`defender_mplog` records Defender's own scan activity, not the payload's
identity. The attack entity does not appear in it on s1_v2 and appears once,
value-less, on s1_v3. A family the entity is absent from cannot change the
entity's rank — the exact OD-01(b) mechanism. Dropped.

## `userassist` — dropped: attack entity mid-distribution

The entity is sparse (2 rows on s1_v2, 1 on s1_v3) and, more decisively, not an
upper outlier:

| feature | s1_v2 percentile | s1_v3 percentile |
|---|---|---|
| `run_count` | 0.97 | **0.64** |
| `focus_count` | 0.57 | 0.65 |
| `focus_seconds` | 0.52 | 0.67 |

`run_count` is an upper outlier on one host and middling on the other —
inconsistent across the two scenario collections. `focus_count` and
`focus_seconds` are mid-distribution on both: the payload was launched once or
twice and closed, while ordinary applications accumulate far more focus time
and count. A model on these features places the attack entity mid-pack on
s1_v3. That is dilution, not signal. Dropped.

## Phase 2 result: no families survive to feature design

Zero of the two candidates pass acceptance. There is nothing to add to
`FAMILY_FEATURES`.

This reaches the **Phase 3 stop condition before Phase 3 runs**: with no family
to extend the model by, the entity rank cannot move, so the ablation would
measure 7 vs 7. `FAMILY_FEATURES` stays at 7. The clean-host ceiling (86/86/75)
is untouched because nothing changed.

## What this settles for OD-01

OD-01(b) held that coverage was not the limiting factor on the attack entity's
rank. Reopening to (a) and measuring it end to end:

- 31 unmodelled families → **2** clear rows + numeric variance + attack presence
  (Phase 1).
- **2 → 0** survive the requirement that the attack entity be plausibly
  top-quartile (Phase 2).

The measurement **confirms OD-01(b), and now on stronger evidence than the
original ablation.** The original decision rested on the attack entity ranking
badly in the families it *was* modelled in (bam 33%, prefetch 41%, amcache
89%). This adds the other direction: of the families it was *not* modelled in,
none carry the entity with enough distinct behavioural signal to rank it high.
Coverage was not the limit because the unmodelled families either do not carry
the attack entity, do not carry numeric variance, or carry the entity
mid-distribution. Extending the model to them would move the denominator, not
the entity.

This does not touch the separate temporal/relational feature question, which
remains a decision for another time. It answers only the coverage question OD-01
posed, and the answer is the one (b) already gave — measured, not assumed.
