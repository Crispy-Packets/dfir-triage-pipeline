# OD-01 Phase 5 — is the anomaly ALGORITHM the limit?

Measured 2026-09-21/22. Phases 1–4 exhausted three levers on the attack
entity's anomaly rank — coverage (more families), features (better columns on
the modelled families), and the D-074 temporal-leak fix — and identified the
fourth as the algorithm itself: every result so far used one scorer, Isolation
Forest. This phase swaps the scorer behind `DFIR_ANOMALY_SCORER` (default
`isolation_forest`, unchanged) and measures whether a different algorithm moves
the rank, with everything else held fixed.

**Verdict thresholds, fixed before running:** *improved* = attack rank moves
≥ 10 places up with the clean-host behaviour intact; *no change* = within ±10;
*reverted* = clean-host ceiling moves (outlier rate leaves the contamination
band, or clean_c entity count ≠ 368). Entity count 443 is an **invariant**, not
a result — the guards are upstream of the scorer, so if it moves the swap did
more than swap and the run is void.

## Method

Same features, same families, same leakage-tested feature sets, same
`PerFamilyModel` (MIN_TRAINING_ROWS, MIN_DISTINCT_RATIO), same ablation tool
(`tools/layer_ablation.py`), same contamination (0.05). Only the estimator
inside `AnomalyModel` changes, selected once per run through a closed registry.
One scorer per run; a batch would hide which moved the number.

**Inertness proof (flag unset, on the final interface code):** bit-identical to
the committed post-D-074 baseline — attack rank **40/443**, 443 entities, and
the ML-only top-10 in the *same order* (svchost, microsoftedgeupdate, msedge,
searchfilterhost, searchprotocolhost, vboxtray, conhost, wmiprvse, onedrivesetup,
tiworker). Clean host 368, attack absent. The interface changes nothing when
off; the default path builds the exact committed `IsolationForest(**same kwargs)`.

## Results (ML-only, s1_v3)

| Algorithm | Attack rank | Clean-host outlier rate | Entity count | Verdict |
|---|---|---|---|---|
| Isolation Forest (default, baseline) | 40/443 (top 9.0%) | 0.051 (in band), 368 entities | 443 | current |
| MODA*-G | **14/443 (top 3.2%)** | 0.048 (in band), 368 entities | 443 | **improved** |
| DIF (Deep Isolation Forest) | not run — dependency wall | — | — | skipped |
| HF-DIF | not run — no public implementation | — | — | skipped |

**Per-family percentile of the attack entity (s1_v3), the two runs side by side:**

| family | Isolation Forest | MODA*-G |
|---|---|---|
| amcache | 4.2% | **1.0%** |
| evtx.powershell | 3.1% | 7.3% |
| prefetch | 38.3% | **23.0%** |

MODA's gain comes from amcache (4.2 → 1.0) and, tellingly, prefetch (38.3 →
23.0) — the family Phase 3 showed the entity is feature-saturated in, where IF's
axis-aligned isolation ranked it mid-pack. A divergence method found structure
there that isolation could not. evtx.powershell is slightly worse under MODA
(3.1 → 7.3) but the entity's strongest family is amcache at 1.0%, so the
combined rank improves to 14th.

### MODA*-G — improved, rank 40 → 14

MODA*-G (Marcano Verde 2026, Zenodo 19439683; MIT, vendored) combines four
statistical engines (MCD robust distance, Peña kurtosis projection, Gower-kNN,
categorical entropy) through an observation-level softmax gate. It ranks the
attack entity **14th of 443**, up 26 places from Isolation Forest's 40th — the
**first lever in the entire OD-01 investigation to move the rank meaningfully.**
Entity count is unchanged (443) and the clean host is unchanged (368, attack
absent), so this is a genuine ranking improvement, not a guard or denominator
artefact, and the revert condition did not trigger.

**Two caveats, stated up front rather than as footnotes:**

1. **Transductive.** MODA*-G has no trained model; it scores rows relative to
   the batch it is given. To match Isolation Forest's "unusual vs the clean
   baseline?" question, the wrapper scores `vstack(train, query)` and returns the
   query tail, so the reference is clean_c ∪ the scored family. The query rows
   therefore influence the reference — inherent to a transductive method, and the
   reason its result is "closest comparable," not "identical methodology."
2. **One engine inert.** This feature layer is all-numeric, so MODA*-G's
   categorical entropy engine (SDC) contributes zeros and only MCD + Peña +
   Gower gate. The comparison tests that subset, not the full mixed-data method
   — it improved on IF *with one hand*, which strengthens rather than weakens the
   finding, but the full method is untested here.

**Clean-host rate checked, not assumed.** The transductive concat scores the
clean host as clean_c-train ∪ clean_c-query — the same rows twice — which could
compress the Gower-kNN scores and make the ceiling *look* intact via entity
count while the outlier rate collapsed to near zero. It did not: MODA's clean_c
ML outlier rate is **0.048**, in the contamination band (IF is 0.051). The
result is not a degenerate-distance artefact.

Determinism: the vendored core's Peña engine used an unseeded RNG; a one-line
patch (`_vendor/moda_star.py`, documented in its header) makes it reproducible,
confirmed by two fits producing identical scores. So its run.json is
byte-reproducible and the manifest holds.

### DIF — not run: dependency wall

DIF (Xu et al., TKDE 2023, `xuhongzuo/deep-iforest`, packaged as `deepod`) could
not be installed in this environment, for a concrete and documented reason:

* **deepod** ships DIF only in versions ≥ 0.3, which pin `torch<1.13.1,>=1.10.0`.
  No torch below 2.0.0 is available for Python 3.11 on this platform, so pip
  silently backtracks to deepod 0.1.1/0.2.0 — neither of which contains a Deep
  Isolation Forest class at all (their models are anogan, devnet, dsad, dsvdd,
  goad, icl, neutral, prenet, rca, rdp, repen).
* The **standalone `xuhongzuo/deep-iforest`** repo pins `torch==1.10.1+cu113`
  plus a torch-geometric/scatter/sparse/cluster GPU stack — not installable on
  this CPU / Python 3.11 setup.

Porting DIF to torch 2.14 is the "separate multi-day workstream" the protocol
reserves (the same rule that skips HF-DIF from the paper), not a scorer swap.
DIF is therefore skipped with the reason recorded. The wrapper
(`_scorers_dif.py`) is retained and correct against the documented deepod API, so
DIF runs unchanged in an environment where a compatible torch exists.

### HF-DIF — skipped

HF-DIF (Hierarchical Feature-selected Deep Isolation Forest, King Saud Univ.
J. Comp. & Info. Sci., 2026) is real and positioned as DIF's successor, but a
five-minute search (PyPI, GitHub, web) found **no public implementation** —
only the DIF base it builds on. Per protocol it is not implemented from the
paper (a separate multi-day workstream, not a scorer swap) and not fabricated.

## What this settles

Four levers have now been measured against the attack entity's anomaly rank:

1. **More families** (Phase 1–2): no unmodelled family carries the entity with
   usable signal. Inert.
2. **Better features** (Phase 3): the entity is already saturated on the
   existing features. Inert.
3. **The temporal-leak fix** (D-074): recovered rank the leak was masking
   (79 → 40), but that was removing a defect, not adding signal.
4. **The algorithm** (this phase): **not inert.** A divergence/gating method
   places the payload 14th where isolation-based placed it 40th — same families,
   same features, same guards, clean host in band.

So the honest thesis sentence is not "four levers, none is the limit." It is:
**three levers were inert; the fourth — the algorithm — was not. Isolation
Forest's axis-aligned isolation was leaving rank on the table that a
divergence-based method recovers, most visibly in the feature-saturated
`prefetch` family (38.3% → 23.0%).** That is a stronger, measured result than
the negative it replaced.

It does **not** change the architecture or the headline. The anomaly layer still
*ranks* rather than *detects*: 14th is still not surfaced as an outlier, the
clean host still shows nothing, and the deterministic rules still place the
entity 1st. The finding is about the scorer, not the ceiling — the ceiling
(what a disk artifact records about a single execution) is unchanged.

Isolation Forest remains the default and the fallback. Whether to adopt MODA*-G
is the user's decision, not this measurement; the flag makes the switch one env
var and the removal one deletion. DIF and HF-DIF remain untested for
environment/availability reasons, either of which could be revisited if a
compatible deep-learning stack or a public HF-DIF implementation appears.

---

# Phase 5 follow-ups (2026-09-22): three more scorer experiments

Same protocol, same invariants (entity count 443, clean-host 368 / rate in
band), same inertness discipline (flag-unset re-proven 40/443 with identical
top-10 after the `AnomalyModel` changes these needed).

## §6 — 4-candidate family extension under MODA*-G

Re-ran the OD-01 Phase 4 extension (`DFIR_EXTENDED_FAMILIES=1`) under
`moda_g` to check whether coverage helps a *different* scorer.

| config | attack rank | fitted extra families | clean rate | entity count |
|---|---|---|---|---|
| MODA*-G, 7 families | 14/443 | — | 0.048 | 443 |
| MODA*-G, extended | 16/443 | `evtx.bits` only | 0.049 | 443 |

The guards are scorer-independent, so the fit set is identical to the IF case:
`evtx.bits` is the only extra family that fits, and it carries no attack row.
Rank moved 14 → 16 (2 worse), the same denominator non-result coverage gave
under IF (40 → 41). **Coverage is a dead lever regardless of scorer**; the MODA
gain is not enlarged by adding families.

## §7 — MODA*-G with the SDC categorical engine fired

MODA*-G is a mixed-data method; on the all-numeric feature layer its categorical
engine (SDC) is inert (§ MODA caveat). This fires it, on the two categorical
fields that pass the leakage bar, int-encoded and family-scoped:

* leakage re-check (majority-collection-per-category, +6.0 bar): `mime_type`
  (browser) acc 0.547 = baseline; `publisher` (amcache) 0.576 vs 0.566 — both
  pass. (Method note: the map is built and scored on the pooled rows, which is
  optimistic for a value seen only in one collection; with 19/31 distinct values
  on ~1,000 rows the effect is small.)
* implementation: a gated `categorical` attribute on `FeatureTable` (never in
  `rows`/`names`/hashes; `DFIR_MODA_CATEGORICAL`), split into MODA's `X_cat` in
  the wrapper via a train-built int map. IF's path is byte-identical (inertness
  re-proven 40/443).

| config | attack rank | clean-host | entity count |
|---|---|---|---|
| MODA*-G numeric-only | 14/443 | 368 | 443 |
| MODA*-G + SDC | **60/443** | 368 | 443 |

**SDC hurts, and the mechanism is instructive.** Firing it pushed the rank
14 → 60. `invoice_scan.exe` carries a **None/empty publisher**, and an empty
publisher is *common* on this corpus's amcache rows — so SDC scores the payload
as an ordinary category, not a rare one. The softmax gate amplifies the
dominant engine per row, so SDC's "ordinary" verdict pulls weight away from the
MCD/Gower engines that had ranked the payload at 1.0% in amcache. In practice
SDC fires on one column for two families (and browser does not even fit on
clean_c), so it is exercised on amcache alone.

The finding: **MODA*-G helps because of its numeric divergence engines, not its
categorical one.** The full mixed-data method is *worse* here than its numeric
subset — the opposite of the hoped-for direction, but a measured one. The
`has_publisher` boolean (already in the numeric feature set) is the right way to
use publisher on this corpus; the raw category via SDC is not.

## §8 — IF + MODA*-G ensemble (percentile-rank average)

A third registered scorer, `ensemble_if_moda`: fit both, average their
within-batch percentile ranks (raw scores across two algorithms are not
comparable; ranks are), lower = more anomalous.

| config | attack rank | clean-host | entity count |
|---|---|---|---|
| IF | 40/443 | 368 | 443 |
| MODA*-G | 14/443 | 368 | 443 |
| ensemble | 17/443 | 368 | 443 |

17 sits between the members, closer to MODA — the pre-committed flat outcome.
An average of two ranks cannot beat the better member unless the two scorers
rank *different* benign entities as anomalous and the average suppresses both
crowds. It does not: they rank the same crowd, so the ensemble regresses toward
the middle. **MODA*-G alone is the best single configuration measured.**

## Phase 5 follow-ups — what they settle

The algorithm is the one lever that moved the rank (14 vs IF's 40), and these
three probes locate *why* and bound it:

* not coverage (§6): extension is inert under MODA too.
* not the categorical engine (§7): SDC hurts; the gain is the numeric
  divergence engines.
* not an ensemble (§8): averaging with IF regresses toward the middle.

So the improvement is specifically MODA*-G's numeric MCD/Peña/Gower divergence
scoring, and it is not compounded by any of the three obvious extensions. It
does not change the architecture or the headline: the anomaly layer still ranks
rather than detects (14th is not surfaced), and the rules still detect. Isolation
Forest remains the default; MODA*-G (numeric-only) is the measured alternative,
adoption the user's call.
