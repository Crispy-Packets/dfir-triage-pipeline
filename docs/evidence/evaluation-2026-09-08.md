# Evaluation run — 2026-09-08 (B-3, B-4, B-5)

First run of the ranking harness. Fit on `collection_clean_b`, score
`collection_s1_v2`, metrics at entity level.

Command:

    python -m dfir_triage_pipeline.evaluation  (via the B-5 run script)

Everything below is real command output, not transcription.

---

## 1. The run

```
train clean_b : 13556 events
test  s1_v2   : 3429 events
families fitted: ['amcache', 'evtx.powershell', 'evtx.security', 'prefetch']
families unscored: ['browser', 'evtx.system', 'registry']
scored rows   : 3375
entities      : 616

=== TOP 15 ENTITIES ===
   1. mpcmdrun.exe                             pct=  0.00 family=evtx.security    rows=13
   2. mscorsvw.exe                             pct=  0.00 family=amcache          rows=15
   3. conhost.exe                              pct=  0.12 family=prefetch         rows=40
   4. tiworker.exe                             pct=  0.23 family=amcache          rows=12
   5. searchfilterhost.exe                     pct=  0.23 family=prefetch         rows=11
   6. svchost.exe                              pct=  0.28 family=evtx.security    rows=229
   7. microsoftedgeupdate.exe                  pct=  0.34 family=amcache          rows=15
   8. searchprotocolhost.exe                   pct=  0.35 family=prefetch         rows=11
   9. backgroundtaskhost.exe                   pct=  0.46 family=amcache          rows=15
  10. taskhostw.exe                            pct=  0.46 family=prefetch         rows=23
  11. nissrv.exe                               pct=  0.56 family=evtx.security    rows=2
  12. rg.exe                                   pct=  0.57 family=amcache          rows=2
  13. msedgewebview2.exe                       pct=  0.58 family=prefetch         rows=32
  14. scenarioengine.exe                       pct=  0.68 family=amcache          rows=3
  15. wmiprvse.exe                             pct=  0.81 family=prefetch         rows=14

=== GROUND TRUTH POSITION ===
invoice_scan.exe: rank 351/616, percentile 51.50 in prefetch, 1 rows

=== SWEEP ===
K=1    P@K=0.000  R@K=0.000  lift=0.00x
K=5    P@K=0.000  R@K=0.000  lift=0.00x
K=10   P@K=0.000  R@K=0.000  lift=0.00x
K=25   P@K=0.000  R@K=0.000  lift=0.00x
K=50   P@K=0.000  R@K=0.000  lift=0.00x
K=100  P@K=0.000  R@K=0.000  lift=0.00x

=== DETAIL AT K=10 ===
K              : 10 of 616 entities
Evaluable      : 1 ground-truth entities
Found in top K : 0
Precision@10   : 0.000
Recall@10      : 0.000
Lift           : 0.00x over random ordering
  invoice_scan.exe: rank 351/616 (MISSED)
```

---

## 2. The headline result

**Lift 0.00x at every K.** `invoice_scan.exe` ranks **351 of 616** entities at
the 51.50th percentile of the Prefetch family. It is not surfaced at K=1, 5, 10,
25, 50 or 100.

This confirms at entity level what was already recorded at row level in
`shared/DECIDED.md`: the anomaly layer does not detect Scenario 1. Entity
aggregation changed the row-level rank of 448/868 into an entity rank of
351/616 — the same answer in different units, not an improvement.

**This is reported as a result, not repaired.** Tuning until the scenario
surfaces is the process that produced the 27.4% artefact-mix figure, and it is
closed in `shared/DECIDED.md`.

---

## 3. The new finding — most of the attack's evidence is unscored

Investigating why the ground-truth entity contributed only **one** scored row:

```
=== every s1_v2 event naming invoice_scan ===
  2026-08-21T01:34:07.976260+00:00  registry         persistence_autorun key='invoice_scan.exe'
  2026-08-20T15:36:43.686891+00:00  browser          file_download      key='invoice_scan.exe'
  2026-08-20T15:51:59.977244+00:00  browser          file_download      key='invoice_scan.exe'
  2026-08-20T16:23:32.650934+00:00  browser          file_download      key='invoice_scan (1).exe'
  2026-08-20T18:41:10.511567+00:00  browser          file_download      key='invoice_scan (1).exe'
  2026-08-20T18:41:37.428021+00:00  browser          file_download      key='invoice_scan (2).exe'
  2026-08-21T00:04:33.670147+00:00  browser          file_download      key='invoice_scan (1).exe'
  2026-08-21T00:42:46.210969+00:00  browser          file_download      key='invoice_scan (1).exe'
  2026-08-21T00:52:39.127227+00:00  browser          file_download      key='invoice_scan.exe'
  2026-08-23T22:20:06.710763+00:00  browser          file_download      key='invoice_scan.exe'
  2026-08-23T22:57:15.832788+00:00  prefetch         process_exec       key='invoice_scan.exe'
  total: 11 events

=== family sizes in s1_v2 ===
  amcache               878
  browser                20
  evtx.powershell      1270
  evtx.security         359
  evtx.system            23
  prefetch              868
  registry               11

=== which of those families have a fitted model ===
  amcache            FITTED
  browser            unscored
  evtx.powershell    FITTED
  evtx.security      FITTED
  evtx.system        unscored
  prefetch           FITTED
  registry           unscored

=== so: invoice_scan rows by family, and whether scored ===
  registry           NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  browser            NOT SCORED
  prefetch           scored
```

### What this establishes

`invoice_scan.exe` appears in **11 events** across three families:

| family | events | fitted model? | scored? |
|---|---|---|---|
| `browser` | 9 (the download chain) | no — 20 rows in s1_v2, below `MIN_TRAINING_ROWS=50` | **no** |
| `registry` | 1 (the Run-key persistence) | no — 11 rows | **no** |
| `prefetch` | 1 (the execution) | yes — 868 rows | yes |

**Ten of the eleven rows are invisible to the anomaly layer**, and not because
the model ranked them poorly. Their families never got a model at all: `browser`
(20 rows) and `registry` (11) both fall below `MIN_TRAINING_ROWS = 50`, so
`PerFamilyModel` reports them unscored rather than folding them into another
family's forest.

The one row that *is* scored is the execution — the single weakest signal in the
chain. A 4,608-byte binary that runs once, from a path Prefetch does not record,
with no run history. The download (remote host, 4,608 bytes, `janed`) and the
persistence (Run key naming a Downloads path) are the two rows an analyst would
actually act on, and neither reaches the model.

### Why this matters for the write-up

It reframes the negative result. The honest statement is no longer "Isolation
Forest ranked the attack at the 51st percentile", it is:

> The anomaly layer scored 1 of the 11 events that constitute the attack. The
> other 10 belong to artefact families too small in this collection to support
> a model, and were reported unscored rather than guessed at.

That is a **corpus limitation with a named cause and a measured threshold**,
which is a materially stronger paragraph than a poor rank.

### What it says about entity aggregation

Aggregation cannot recover what was never scored. Taking the best percentile
across an entity's rows helps only when the entity *has* rows in scored
families; here it has one. The expected large win from B-4 does not arrive on
this corpus, and the reason is measurable rather than speculative.

---

## 4. Families fitted and unscored

| family | s1_v2 rows | model |
|---|---|---|
| `amcache` | 878 | fitted |
| `evtx.powershell` | 1,270 | fitted |
| `evtx.security` | 359 | fitted |
| `prefetch` | 868 | fitted |
| `evtx.system` | 23 | unscored |
| `browser` | 20 | unscored |
| `registry` | 11 | unscored |

3,375 of 3,429 rows scored; 54 rows (1.6%) in unscored families.

Note the asymmetry: those three families are small *in this collection*, but
`browser` and `registry` are exactly where initial access and persistence are
recorded. The families that carry the most forensic weight per row are the ones
with the fewest rows.

---

## 5. What the top of the ranking actually contains

The 15 most anomalous entities are Windows maintenance and telemetry:
`mpcmdrun.exe` (Defender), `mscorsvw.exe` (.NET precompilation), `tiworker.exe`
(Windows Update), `searchfilterhost.exe`, `svchost.exe`, `microsoftedgeupdate.exe`.

These are not false positives in the sense of a broken model. They are genuinely
the least-like-baseline rows in the collection, because s1_v2 was collected
after a period of inactivity and Windows spent that window updating itself. The
model is answering the question it was asked; the question is not the one an
analyst is asking.

---

## 6. What was NOT done

- No threshold was changed.
- No feature was added or removed to move this number.
- `MIN_TRAINING_ROWS` was not lowered to force `browser` and `registry` into
  the model. Fitting a forest on 20 rows would produce a ranking with no
  meaning, and the unscored report is the honest output.

The next measured step is the feature work (B-2d procedure), and the prediction
recorded before running it is that it will not move the rank materially,
because the constraint identified here is coverage rather than ranking.
