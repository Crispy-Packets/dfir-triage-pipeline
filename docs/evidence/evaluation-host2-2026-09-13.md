# Evaluation and feature ablation — host 2, 2026-09-13

Fit on `collection_clean_c`, score `collection_s1_v3`. Both collections come
from the **second** host, built for this measurement; see
`FYP/01-brief-and-planning/host2-collection-steps.md`.

Everything below is real command output.

---

## 1. Why host 2 exists

The 2026-09-08 run established that the anomaly layer scored **1 of the 11
events** constituting Scenario 1 on host 1. The other ten were never scored:
`browser` (11 rows in `clean_b`) and `registry` (15) fell below
`MIN_TRAINING_ROWS = 50`, and the *training* collection is what fits the forest.

Host 2 was collected to answer one question: **does the anomaly layer detect the
download and the persistence when it can actually see them?**

---

## 2. The run

```
trained on 2444 events
  fitted   : ['amcache', 'browser', 'evtx.powershell', 'evtx.security', 'prefetch']
  unscored : ['evtx.system', 'registry']

self-score outlier rate: 4.55%

scored 2278 of 2304 s1_v3 events
  outlier rate: 8.56%

=== ATTACK EVENTS SCORED: 3 ===
  browser          pct=  8.14  outlier=False
  amcache          pct= 11.49  outlier=False
  prefetch         pct= 36.59  outlier=False

=== RANKING: 525 entities ===
     1. npp.8.9.8.installer.x64.exe                pct=  0.00 browser       
     2. svchost.exe                                pct=  0.00 amcache       
     3. msmpeng.exe                                pct=  0.19 amcache       
     4. searchfilterhost.exe                       pct=  0.20 prefetch      
     5. searchprotocolhost.exe                     pct=  0.20 prefetch      
     6. msedge.exe                                 pct=  0.38 amcache       
     7. microsoftedgeupdate.exe                    pct=  0.39 prefetch      
     8. taskhostw.exe                              pct=  0.49 prefetch      
     9. onedrivesetup.exe                          pct=  0.57 amcache       
    10. sppsvc.exe                                 pct=  0.59 prefetch      

  invoice_scan.exe -> rank 71/525, pct 8.14 in browser, 3 rows

=== SWEEP ===
  K=1    P@K=0.000  R@K=0.000  lift=0.00x
  K=5    P@K=0.000  R@K=0.000  lift=0.00x
  K=10   P@K=0.000  R@K=0.000  lift=0.00x
  K=25   P@K=0.000  R@K=0.000  lift=0.00x
  K=50   P@K=0.000  R@K=0.000  lift=0.00x
  K=100  P@K=0.010  R@K=1.000  lift=5.25x
```

---

## 3. Host 1 against host 2

| | host 1 (`clean_b` -> `s1_v2`) | host 2 (`clean_c` -> `s1_v3`) |
|---|---|---|
| attack events scored | 1 of 11 | **3 of 4** |
| families with a fitted model | 4 | **5** |
| entity rank | 351 / 616 | **71 / 525** |
| position | top 57% | **top 13.5%** |
| lift | 0.00x at every K | **5.25x at K=100** |

Three changes produced this, in order of contribution:

1. **Collection.** `browser` went from 11 training rows to 62, so a browser
   model exists at all. 62 downloads across roughly a dozen domains.
2. **Recollection.** `clean_c` was first collected with script-block logging
   disabled, giving 5 `evtx.powershell` rows. Logging was enabled and the
   collection retaken: 470 rows, a fifth modelled family. See section 7.
3. **Features.** Three columns appended to the feature table, below.

**Amcache recorded the execution**, which it did not on host 1 (D-028). That is
a third independent artefact family scoring the attack entity.

---

## 4. The new features, and the measurement that admitted them

`browser` rows were near-unmodellable: 86 downloads in `s1_v3` collapsed to
**8 distinct feature vectors**. Six of the ten original features are
execution-specific and sit at zero for a download; `path_depth` and
`path_is_user_writable` are constant because every download lands in
`Downloads\`. Only the hourly-density pair varied.

The parser already recorded `bytes` and `mime_type` into `details`. Neither
reached the feature table. Three columns appended:

| feature | form |
|---|---|
| `download_size_log10` | `log10(bytes + 1)`; the measured range is 153 B to 1.07 GB |
| `download_size_is_known` | missing is flagged, never imputed |
| `mime_type_is_executable` | membership of a closed MIME set — a shape feature |

**Leakage-tested before implementation**, per the B-2d procedure. Both measured
**58.1%** single-field accuracy separating `clean_c` from `s1_v3` against a
**58.1%** majority-class baseline — no collection identity whatsoever, the
cleanest result any feature has returned on this project.

Effect:

| | 10 features | 13 features |
|---|---|---|
| distinct browser vectors | 8 | **84** (of 86) |
| download percentile | 16.28 | **8.14** |
| amcache percentile | 20.88 | **11.49** |
| entity rank | 116 / 525 | **71 / 525** |
| lift @ K=100 | 0.00x | **5.25x** |

---

## 5. Feature ablation (B-11b)

Each feature dropped in turn, model refitted, rank remeasured. Fourteen runs.

```
BASELINE: rank 71/525  pct 8.14  (3 attack rows scored)

feature removed                                    rank   change     pct
-------------------------------------------------------------------------
(none - baseline)                                    71       --    8.14
run_count                                            66       -5    6.98  better
run_count_is_known                                   66       -5    6.98  better
executable_rarity                                    56      -15    4.65  better
executable_is_unseen                                 74       +3    8.14  worse
events_in_same_hour                                  34      -37    3.49  better
distinct_executables_in_same_hour                    35      -36    3.49  better
seconds_since_previous_run_of_same_executable        31      -40    3.49  better
previous_run_is_known                                39      -32    3.49  better
path_depth                                           37      -34    3.49  better
path_is_user_writable                                36      -35    3.49  better
download_size_log10                                  77       +6    9.30  worse
download_size_is_known                               54      -17    5.81  better
mime_type_is_executable                             107      +36   14.94  worse

=== FEATURES THAT CARRY SIGNAL (removal makes it worse) ===
  mime_type_is_executable                        +36 places when removed
  download_size_log10                            +6 places when removed
  executable_is_unseen                           +3 places when removed

=== FEATURES CONTRIBUTING NOTHING (removal changes nothing) ===
  (none)
```

### What this establishes

**Three features carry signal. Ten make the result worse by being present.**

| feature | rank when removed | reading |
|---|---|---|
| `mime_type_is_executable` | 107 (+36) | the most informative single feature |
| `download_size_log10` | 77 (+6) | contributes |
| `executable_is_unseen` | 74 (+3) | contributes slightly |
| *baseline* | **71** | |
| `seconds_since_previous_run_of_same_executable` | 31 (-40) | dilutes most |
| `events_in_same_hour` | 34 (-37) | dilutes |
| `path_is_user_writable` | 36 (-35) | dilutes |
| `path_depth` | 37 (-34) | dilutes |

The two features added on 2026-09-13 rank **first and second** by contribution.

**Why the execution features hurt.** Isolation Forest selects a feature and a
split point at random. A column that is constant across every row in a family
cannot separate anything, so each time the forest selects one it spends a split
achieving nothing. For `browser` rows, six of the thirteen features are
constant, and they dilute the three that carry information.

**No feature is dead.** Every one of the thirteen changes the result, which is
itself a finding: the ablation was run partly to look for columns contributing
nothing, and there are none.

### What was NOT done, and why

The table says that removing any of ten features improves the rank, and that
dropping the six execution-only columns for `browser` rows would likely place
the attack entity around rank 25-30.

**No feature was removed on the strength of this table.** Selecting features by
which removal improves the known answer is tuning the corpus to the test — the
process that produced the 27.4% artefact-mix result, and closed in
`shared/DECIDED.md`.

The defensible form of the same change is a **per-family feature set**,
justified before any rank is consulted: a download has no run count, and a
Prefetch record has no MIME type, so scoring both with one column layout wastes
splits by construction. That is a design decision this ablation is evidence
*for*, not a conclusion drawn *from* it. Recorded in Future Work.

---

## 6. What the result is, stated precisely

**There is no accuracy figure and none can be computed.** Four
attack-attributable events in 2,304 is not a labelled test set, and constructing
one by labelling collections would measure collection identity rather than
behaviour — `hour_of_day` alone scores 86.0% that way.

**The ranking metrics reduce to one number.** With a single ground-truth entity,
precision, recall and lift are all transformations of "where did that entity
land". Lift in particular is a step function: 0.00x at every K below 71, 5.25x
at K=100. Reporting 5.25x without that caveat would overstate it.

**The defensible claim:**

> The anomaly layer places the attack entity at rank 71 of 525 (top 13.5%),
> improved from 116 of 525 before the download-size and content-type features
> were added. It contributes measurable triage ranking but does not detect: the
> entity is not flagged as an outlier, and 70 benign entities rank above it.
> Detection comes from the deterministic rules.

---

## 7. Threats to validity

**No negative control on host 2.** The model is fitted on `clean_c` and scored
on `s1_v3`; there is no second clean host-2 collection to confirm that nothing
ranks like the attack on a collection without one. Host 1's baselines cannot
serve, because cross-host scoring flags nearly every row.

**`clean_c` was collected twice.** The first collection had script-block logging
disabled (5 `evtx.powershell` rows). The configuration was corrected and the
collection retaken, giving 470. This is a lab-setup correction of the same kind
as the network misconfiguration behind `s1_v2` — and `browser`, the family the
experiment is about, was already at 62 rows in both. The fix did not touch the
family under test.

**Persistence is still unscored.** `registry` carries 8 rows in `s1_v3`, below
the threshold. Measured across four machines — 4 on a fresh VM, 7 here, 11-15 on
host 1, 13 on a personally-used machine of several years — autorun values number
in the low teens on any real Windows host. Population-based anomaly detection
cannot model a family that small. This is structural to the artefact rather than
a property of this corpus, and it is why persistence detection belongs to the
deterministic rules, which need one event where a model needs a population.

**The scenario order differs from `s1_v2`.** The Run key was written *after* the
Security log clear rather than before, because the persistence step was missed
on the first pass and added once noticed. The clear affects only `Security.evtx`
and the Run key is a registry artefact, so no evidence was lost — but the
interval ordering is not identical to host 1 and the timeline reflects the
actual order.
