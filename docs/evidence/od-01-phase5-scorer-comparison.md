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

Isolation Forest was the default when this section was written; the flag made
adoption one env var and removal one deletion. **UPDATE 2026-09-22: the user
adopted MODA*-G as the default (`DEFAULT_SCORER = "moda_g"`). Isolation Forest is
now the explicit fallback (`DFIR_ANOMALY_SCORER=isolation_forest`), kept
byte-exact.** DIF and HF-DIF remain untested for
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

# Engine attribution and robustness (2026-09-22): why MODA moved the rank

The follow-ups above bound *what does not* compound the gain. These two probes
locate *what does* — which of MODA's engines sees the payload where Isolation
Forest did not — and test whether the 14/443 result is a lucky parameter.
Neither probe selects anything: the default stays `isolation_forest`, and
MODA's `k_temp` stays the paper's 3.0. Diagnostic only.

Both use `return_components=True` on the concat (clean_c ∪ s1_v3, per family),
seeded identically to the pipeline, with `sort_events` applied so row order
matches the scored run. All four engines pass through `phi(d)=d/(d+κ) → [0,1)`,
so the softmax gate compares engines on a **common scale** — a large gate weight
is information, not units.

*Tie convention:* percentiles here count `score ≤ payload` (ties in); the
pipeline harness takes first index in descending order (ties out). This is the
only reason these read 1.1 % / 24.5 % where the harness reported 1.0 % / 23.0 %
— the prefetch family holds a 15-way tie on the payload's exact feature vector
(below), and 14 of those fall the other side of the convention. Same rows, same
scores.

## §9 — engine attribution: MCD and Peña saturate on the payload

Per-engine percentile of the payload within its family, and the payload's raw
engine scores:

    family     MCD    Peña   Gower   gated    raw: MCD / Peña / Gower
    amcache    1.1 %  3.3 %  100.0 % 1.1 %    0.9997 / 1.0000 / 1.0000
    prefetch   3.5 %  3.3 %  2.0 %   24.5 %   0.6277 / 1.0000 / 1.0000

**amcache is the rank driver.** The entity rank is the payload's best-family
percentile, and its best is amcache at ~1.0 %. There, MCD and Peña both
**saturate** on the payload (0.9997, 1.0000): it is far from the robust MCD
centre *and* extreme along Peña's kurtosis-maximising projections. Isolation
Forest, splitting axis-aligned on the same columns, did not isolate it —
amcache was 4.2 % under IF and 1.0 % under MODA, and that drop is the whole
40 → 14 move. Gower is uninformative here: its score is 1.0 for **every** amcache
query row (quantiles [1.0, 1.0, 1.0]) — the family sits on a Gower plateau, so
kNN distance cannot discriminate. The payload's gate weights are near-uniform
(0.33/0.33/0.33) only because all three numeric engines are saturated; the two
that carry information (MCD, Peña) still set the gated score. The payload's
feature vector is unique in the concat (1 identical row = itself), so this is a
genuinely isolated point on the MCD/Peña axes, not a cluster artefact. This is
Phase 3's "extreme but not rare" measured at the engine level: extreme along the
robust-covariance and projection axes, which is exactly what an axis-aligned
forest averages away.

**Prefetch is a property of the gate, not a rank contribution.** All three
engines individually rank the payload well (MCD 3.5 %, Peña 3.3 %, Gower 2.0 %),
yet the gated score puts it at 24.5 % — *worse* than any single engine. This is
not noise; it is the softmax-weighted average being **non-monotone**. Its
derivative in engine *j* is `w_j·(1 + k(s_j − f))`, negative whenever
`s_j < f − 1/k`. The payload scores MCD = 0.628 against Peña = Gower = 1.0, so
its gated value is ≈ 0.93; a benign row reporting MCD ≈ 0.1 with Peña ≈ Gower
≈ 0.99 scores ≈ 0.94 and **beats the payload while exceeding it on no single
engine**. Measured: of the 248 prefetch rows that gate at or above the payload,
only **35 (3.5 %)** are genuinely extreme on ≥ 1 engine; the other **213** are
this drag effect (drag-row medians MCD 0.40, Peña 0.996, Gower 1.000). Prefetch
does not set the rank (amcache's 1.0 % does), so this costs nothing here — but it
is a documented cost of softmax gating over a family where one engine is weak,
and it is the reason a per-family scorer choice looks tempting (see below).

## §10 — k_temp robustness: 14 is not a tuned figure

The MODA ablation re-run on host 2 across the paper's tested temperature range,
default 3.0:

    k_temp   ML rank
    1.0      15/443
    3.0      14/443   (default, shipped)
    5.0      14/443
    10.0      9/443

The rank holds at 9–15 across a 10× range, so **14/443 is not a lucky
setting** — it is robust to the one free parameter. The clean-host ceiling was
not re-measured at k ≠ 3 because no other k is adopted; only the default matters
and it is in band (0.048, entity count 443, unchanged).

The k = 10 → 9/443 row is **not** an improvement to bank. As k → ∞ the softmax
gate approaches max-of-engines, which is monotone and removes the §9 drag
effect; the payload's prefetch percentile then approaches Gower's 2.0 % and pulls
the entity rank down. k = 10 helps because it is approaching a *different
algorithm* (any single-engine spike wins), not because 3.0 was mis-tuned.
Adopting it would be selecting the parameter that best places the one
ground-truth entity — the same move the project's standard forbids for features
(`feature_ablation.py`'s own docstring rejects tuning to a single label). The
default stays 3.0.

## The lever named and not taken: a per-family scorer

§9 makes the tempting next step explicit: MODA helps amcache and prefetch but
hurts evtx.powershell (3.1 % → 7.3 %), and the prefetch gate demonstrably costs
~20 points against its own engines. A per-family scorer — IF for powershell,
MODA elsewhere, or max-of-engines instead of softmax on prefetch — would improve
the combined rank. It is not taken, for the same reason k = 10 is not: with one
ground-truth entity, choosing the scorer per family *is* tuning the pipeline to
that entity's position. It would produce a better number and a worse method. The
honest result is the single-scorer rank; the per-family gain is recorded here as
a known, deliberately unused lever.

## What §9–10 settle

The 40 → 14 improvement is now explained, not just observed: MODA's MCD and Peña
engines saturate on the payload's amcache vector — an isolated point on the
robust-covariance and projection axes that an axis-aligned Isolation Forest
averages away — and that single family sets the entity rank. The result is
robust to `k_temp` across a 10× range. The gate's non-monotone drag on prefetch
and the per-family scorer are documented as properties/levers, both deliberately
unused because acting on either would tune to the one label. Nothing here changes
the default, the architecture, or the headline: the layer ranks (14th is not
surfaced), the rules detect. MODA*-G numeric-only is the measured, understood
scorer — and as of 2026-09-22 it is the **default** (the user's call); Isolation
Forest is the byte-exact fallback one env var away.

# §11 — merged a+b+c baseline (2026-09-22): the within-host rule, measured for MODA

Hypothesis tested (the user's): a bigger, richer baseline — clean_a + clean_b +
clean_c merged into one training pool — helps MODA. It does not. It reproduces
the 27.4% host-mixing failure CLAUDE.md's "train and score within one host" rule
exists to prevent, and it does so *worse* for MODA than for Isolation Forest.

The corpus makes this a confounded test by design: clean_a and clean_b are
**host 1**, clean_c is **host 2**, and s1_v3 is **host 2**. So a+b+c mixes two
machines' software/user/hostname profiles into the baseline, then scores a host-2
scenario against it. "Bigger baseline" and "different host profile" cannot be
separated with one clean collection per host — what a+b+c actually measures is
host mixing.

**Read the ceiling first — the rank is meaningless without it.**

    training pool   scorer            clean_c ceiling   s1_v3 rank    verdict
    clean_c only    isolation_forest  ~0.05             40/443 alone  valid (shipped)
    clean_c only    moda_g            0.048             14/443 alone  valid (measured)
    a+b+c           isolation_forest  0.037             18/446        diluted denominator
    a+b+c           moda_g            0.129             (2/446)       NOT REPORTABLE

**MODA on a+b+c flags 12.9% of a clean host as anomalous** — nearly triple the
~0.05 contamination band. The "rank 2" and the ceiling blow-up are the same
phenomenon: mixing host 1 into the baseline makes host-2 rows look anomalous —
the attack row and ordinary clean_c rows alike. A rank that arrives with a 13%
clean-host false-positive rate is not a better rank; it is the ranking of a model
that has lost the clean baseline. It is stated after the ceiling and labelled not
reportable, never as "2/446".

### The 13% is the clean host's own software (composition)

MODA fitted on a+b+c, scored on clean_c (a host with no attack):

    per-family clean_c outlier rate (band ~0.05)
      amcache            0.005   (2/400)
      evtx.powershell    0.562   (264/470)   <-- the blow-up
      evtx.security      0.000   (0/740)
      evtx.system        0.000   (0/18)
      prefetch           0.055   (41/747)
      OVERALL            0.129

    top-10 clean_c entities flagged (a host with NO attack)
      1. msedge.exe               prefetch
      2. registry                 evtx.security
      3. vboxguest.sys            evtx.system      (the VM's own guest driver)
      4. vlc-3.0.23-win64.exe     amcache
      5. runtimebroker.exe        prefetch
      6. identity_helper.exe      amcache
      7-10. dot.exe, gdbus.exe, gegl.exe, gimp-debug-tool-3.2.exe   amcache  (GIMP)

The 12.9% is not spread evenly — it is **one family, `evtx.powershell` at 56%**
(264 of 470 clean rows), with amcache and prefetch near-normal. And the named
entities are ordinary host-2 software: Edge, the registry, VLC, RuntimeBroker,
and a cluster of GIMP binaries — plus `vboxguest.sys`, the VirtualBox guest
driver. These are programs present on host 2 and **absent or different on host 1**.
When host 1's 1.38M events dominate the training mass, host 2's own normal
software falls far from that mass and MODA calls it anomalous. That is the
host-mixing mechanism named exactly: the merged baseline makes a clean host look
like an intrusion because it is a *different* clean host. "MODA on the merged
baseline names a clean machine's own OS, VM tooling and installed apps as its top
anomalies" is the one-sentence proof that a+b+c is not a baseline — it is two
baselines the model cannot reconcile.

### Isolation Forest did not blow up — the sensitivity is MODA-specific

This is the one new finding. IF's clean_c ceiling on the same merged baseline is
**0.037**, in band; MODA's is **0.129**. IF's axis-aligned splits tolerate a
bimodal two-host distribution; MODA's distance and covariance engines (MCD's
robust centre, Gower's kNN) do not — a baseline with two software profiles gives
them two clusters, and host-2 points sit far from the host-1 mass. This is an
argument *for* the within-host rule, not against MODA: MODA on c-only is still
14/443 alone at a 0.048 ceiling. The merge breaks MODA specifically because its
strength — distance-to-the-mass — is exactly what host mixing corrupts.

### The payload's own vector did not improve

`executable_rarity` for the payload is **0.0 under both the c-only and the a+b+c
index** — the floor. The payload is *unseen* in every training pool, so its
rarity is saturated and the merge cannot move it. The rank change is entirely in
the *other* rows (clean_c false positives and s1_v3 competitors moving under the
host-mixed distribution), never in the payload's own signal. Nothing about the
merge made the attack more isolable; it made the clean host less clean.

### Denominator caveat on the IF 18/446

IF's 18/446 is not a clean improvement over 40/443 either: the merged baseline's
3× rows push `evtx.security` and `evtx.system` over the row floor, so **five
families fit instead of three** and the entity count is **446, not 443**. That is
a different pipeline version (D-062), not a rank gain on the same one — a rank
quoted against a changed denominator is the defect D-062 names.

## What §11 settles

The within-host training rule holds, and is now measured for MODA specifically,
not just IF. Merging clean_a+b+c does not help: it mixes two hosts, and MODA's
divergence engines are more sensitive to that than IF's splits, so the clean-host
ceiling leaves the band (0.129) and the rank becomes an artifact. The obvious
next move — a host-normalised merge or a per-host rarity index — is the fourth
"tune it until the scenario surfaces" lever this line of work has surfaced, and
it is declined for the same reason as the others: it engineers the baseline
toward the one ground-truth entity. **Train within one host. MODA on clean_c
alone (14/443, ceiling 0.048) remains the best measured configuration; Isolation
Forest on clean_c (40/443) remains the shipped default.**
