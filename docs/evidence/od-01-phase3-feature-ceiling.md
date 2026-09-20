# OD-01 Phase 3 (feature lever) — the features are already saturated

Measured 2026-09-20. After Phases 1–2 dropped all coverage candidates, the
remaining lever was *better features on the 7 modelled families* — the deferred
"feature engineering" question. This measures whether that lever can move the
attack entity's rank. It cannot, and the reason is instructive.

## Method

For each family the attack entity appears in (`prefetch`, `browser`,
`amcache`), compute the real `features.build()` vectors and report the
percentile of the attack entity's value on every existing feature. If the
entity is already at an extreme (≥0.90 or ≤0.10) but still ranks 41%, the limit
is not the features.

## Result: the entity is already extreme on nearly every feature

**prefetch (ranks 41%), s1_v2 — 1 attack row of 868:**

| feature | attack percentile |
|---|---|
| `executable_rarity` | 0.03 (rarest) |
| `run_count` | 0.06 (lowest) |
| `executable_is_unseen` | 1.00 |
| `run_count_is_known` | 1.00 |
| `exec_location_rarity` | 1.00 |
| `path_depth` | 1.00 |
| `path_is_user_writable` | 1.00 |

7 of 11 features already at a boundary. s1_v3 is the same shape.

**browser, both collections:** `executable_rarity`, `executable_is_unseen`,
`download_size`, `mime_type_is_executable`, `filename_length`,
`filename_entropy` all ≥0.91. 6–7 of 9 features extreme.

**amcache, s1_v3:** `has_publisher` 0.08 (the None-publisher discriminator
firing as designed), `executable_is_unseen` 1.00, `path_is_user_writable` 1.00.

## Why extreme features still rank 41%

Because **being an extreme outlier is not rare on a clean host.** An Isolation
Forest scores a row as anomalous when it is easy to isolate — but every
legitimate installer, one-off tool and setup binary on a real machine is
*also* rare, *also* user-writable, *also* unseen, *also* an executable
download. The attack entity is one extreme point in a cloud of extreme points,
most of them benign.

Adding features on these same axes cannot separate them: a new rarity- or
path- or size-shaped feature makes `invoice_scan.exe` more extreme and makes
the legitimate installers equally more extreme. The axes are saturated. The 41%
is not "the features are too weak"; it is "half the clean host is also unusual,
and unusualness is all a disk artifact carries about a single execution."

## What this settles

Three levers have now been measured against the attack entity's rank:

1. **More families** (Phase 1–2): no unmodelled family carries the entity with
   usable numeric signal. Dead.
2. **Better features on modelled families** (this phase): the entity is already
   saturated on the existing features. Dead — more of the same axis dilutes.
3. **The remaining lever is relational** — treating downloaded→executed→
   persisted→deleted as one signal. That is exactly what the deterministic
   rules already encode (R-CORR-0001/0003/0006), which is why the rules place
   the entity at 99/critical while the anomaly layer sits at 41. Building it
   into the ML layer would re-derive the rules' signal probabilistically, is
   the most leakage-prone direction, and remains a separate research decision —
   not undertaken here.

**The ML ceiling is a property of what a disk artifact records about a single
execution, not of the model's coverage or its features.** A malicious installer
run twice from a user-writable path is feature-identical, on disk, to a
legitimate installer run twice from a user-writable path. What distinguishes
them is the chain, and the chain is the rules layer's job. This is the measured
reason OD-01 lands where it does, and it is a stronger statement than the
original ablation supported.

`FAMILY_FEATURES` stays at 7. The rollback snapshot taken before this work
(git bundle at d2efa95, `%USERPROFILE%\dfir-rollback-2026-09-20`) is
therefore also the current state — no code changed, because the measurement
said changing it would only dilute.
