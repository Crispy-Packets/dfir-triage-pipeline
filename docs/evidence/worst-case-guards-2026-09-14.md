# Worst-case stress test, and the three guards it produced

**2026-09-14.** The question asked was not "does this work on our corpus" but
**"what breaks when someone points it at a real machine".** Three failures were
found by measurement. All three had the same shape: **the layer reported numbers
it should have refused to report.**

---

## 1. The engine scales; nothing to fix there

Synthetic collections, worst-case join shapes (few distinct binaries means large
join groups, which is what stresses the correlation search):

| events | distinct binaries | seconds | budget truncations |
|---|---|---|---|
| 1,000 | 500 | 0.02 | 0 |
| 5,000 | 500 | 0.07 | 0 |
| 20,000 | 500 | 0.28 | 0 |
| 20,000 | 20 | 0.29 | 0 |
| 50,000 | 10 | **0.73** | 0 |

Linear, sub-second at 50,000 events, and `SEARCH_BUDGET` was never approached.
The correlation engine needs no further work for a real-estate collection size.

---

## 2. SEVERE — cross-host scoring reported 50.3% outliers

Fitting on host 2 and scoring host 1 flagged **50.3% of rows** against a 5%
contamination setting. Half the collection.

**Nothing errored.** The forest correctly reported that two machines differ in
software, accounts and hostname. What was wrong was presenting the result as a
triage ranking: when every row is unusual, the ordering among them is noise.

This is the failure most likely to happen in real use. An analyst points the
tool at a machine the baseline did not come from, receives thousands of
"anomalies", and either trusts them or discards the tool.

**Fix: `baseline_warning()`.** When the outlier rate exceeds
`CONTAMINATION * BASELINE_MISMATCH_FACTOR` (3x), the summary carries an explicit
warning naming the likely cause and the remedy. The threshold is a multiple of
`CONTAMINATION` rather than a literal, so changing one cannot silently
invalidate the other.

---

## 3. SEVERE — two families were fitted but degenerate

`MIN_TRAINING_ROWS = 50` guards **quantity**. Nothing guarded **variety**.

| family | rows | distinct vectors | ratio | was | now |
|---|---|---|---|---|---|
| `prefetch` | 747 | 726 | 0.97 | fitted | fitted |
| `browser` | 62 | 62 | 1.00 | fitted | fitted |
| `amcache` | 400 | 150 | 0.38 | fitted | fitted |
| `evtx.security` | 740 | 121 | 0.16 | **fitted** | **unscored** |
| `evtx.powershell` | 470 | **4** | **0.01** | **fitted** | **unscored** |

`evtx.powershell` cleared the row floor by nine times over and produced **four
distinct feature vectors from 470 rows**. Isolation Forest isolates a point by
how few splits separate it from the rest; identical points cannot be separated
at all. Its percentiles were reported with the same confidence as Prefetch's and
ranked nothing.

This is D-039 recurring in a family that was not checked when `browser` was
fixed — the same defect, found by looking rather than by it surfacing.

**Fix: `MIN_DISTINCT_RATIO = 0.25`.** A family whose distinct-vector ratio falls
below it is reported unscored with the measured reason, not fitted.

**The threshold was not tuned.** No value between 0.10 and 0.40 changes which
families pass on this corpus, so the exact figure is not load-bearing. A
threshold chosen where the data is sparse would be a threshold chosen to produce
a result.

---

## 4. MINOR — unscored families were dropped silently at score time

Scoring a collection containing `browser` against a model fitted only on
`prefetch` dropped **86 of 1,100 events** with no indication.

Omitting them is correct — a score of "not anomalous" for a row that was never
modelled is a claim the model did not make — but a caller must be able to tell
how much of a collection went unexamined.

**Fix: `PerFamilyModel.skipped_at_score`**, a family-to-count map populated by
every `score()` call.

---

## 5. The guards, running

```
=== 1. DEGENERACY GUARD ===
  fitted  : ['amcache', 'browser', 'prefetch']
  unscored:
    evtx.security: only 121 distinct feature vectors in 740 rows (ratio 0.164, floor 0.25)
    evtx.powershell: only 4 distinct feature vectors in 470 rows (ratio 0.009, floor 0.25)
    evtx.system: below MIN_TRAINING_ROWS
    registry: below MIN_TRAINING_ROWS

=== 2. BASELINE MISMATCH ===
  s1_v3 (same host)          7.8%  ok
  s1_v2 (DIFFERENT host)    19.3%  BASELINE MISMATCH: 19.3% of rows flagged against a 5% contamination se

=== 3. SKIPPED AT SCORE ===
   {'registry': 8, 'evtx.powershell': 644, 'evtx.security': 12, 'evtx.system': 18}
```

---

## 6. What this did to the result

**Nothing. `invoice_scan.exe` still ranks 40 of 525.**

That is the point. The two families removed were contributing no ordering, which
is what the degeneracy ratio predicted before the rank was re-measured. Dropping
them changed which numbers are *reported*, not which are *useful*.

Two consequences worth stating:

- **Three families are now modelled, not five.** The earlier figure of five was
  counting two families whose scores meant nothing. The honest count is three,
  and the ML record's comparison with host 1 is updated accordingly.
- **The attack's score comes entirely from `browser`, `amcache` and `prefetch`,**
  all of which pass the variety check comfortably (1.00, 0.38, 0.97).

---

## 7. What is still not guarded

**A degenerate family in the SCORED collection.** The ratio is measured on the
training collection only. A test collection whose rows collapse would produce
tied percentiles across the board; `assign_percentiles` handles ties correctly,
but nothing warns that the ordering is largely arbitrary.

**Feature drift between fit and score.** `AnomalyModel.score` checks feature
*names* against the fitted model and would reject a layout change — but a
feature whose *distribution* has shifted (a new software rollout changing every
path depth) is scored without comment.

**An entirely absent family.** If the scored collection has no `browser` rows at
all, `skipped_at_score` records nothing, because there is nothing to skip. The
absence of the download step would be invisible.

All three are recorded rather than fixed: each needs a design decision about
what the pipeline should *do*, and inventing one without a case that demands it
is how thresholds get chosen to flatter a result.
