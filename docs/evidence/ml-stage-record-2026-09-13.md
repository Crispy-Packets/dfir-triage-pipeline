# The machine-learning stage — complete record

Every measurement taken on the anomaly layer, in the order taken, with what was
decided at each point and why. Real command output throughout.

**Final result: the attack entity ranks 40 of 525 (top 7.6%), improved from
351 of 616 on host 1.** It is still not flagged as an outlier. The layer
contributes triage ranking; detection comes from the deterministic rules.

---

## 1. Where this started

`docs/evidence/evaluation-2026-09-08.md` established that on host 1 the anomaly
layer scored **1 of the 11 events** making up Scenario 1. The other ten were
never scored: `browser` (11 rows in `clean_b`) and `registry` (15) fell below
`MIN_TRAINING_ROWS = 50`, and the *training* collection is what fits the forest.

The one row that was scored was the execution — the weakest signal in the chain.
The download and the persistence, which are what an analyst acts on, never
reached the model.

That diagnosis produced two pieces of work: collect a corpus the model can see
(section 2), and give it features that describe what it is looking at
(sections 3 and 5).

---

## 2. Host 2: a corpus the model can see

`FYP/01-brief-and-planning/host2-collection-steps.md` records the plan, written
before collecting. Two collections from a second machine: `clean_c` to train,
`s1_v3` to test.

Two facts from the parser source decided the activity plan, both
counter-intuitive and both checked rather than assumed:

- `parsers/browser.py` runs `SELECT ... FROM downloads` only. The `urls` and
  `visits` tables are never read, so **browsing produces zero events**. Sixty
  actual file downloads were needed, and were performed across roughly a dozen
  domains with sizes from 153 bytes to 1.07 GB.
- `parsers/registry.py` reads Run and RunOnce only, one event per value.

### Family row counts

| family | clean_b (host 1) | clean_c | s1_v3 | modelled? |
|---|---|---|---|---|
| `prefetch` | 1,248 | 747 | 1,014 | yes |
| `evtx.security` | 10,439 | 740 | 12 | train only |
| `evtx.powershell` | 997 | 470 | 644 | yes |
| `amcache` | 830 | 400 | 522 | yes |
| `browser` | **11** | **62** | **86** | **yes — new** |
| `evtx.system` | 16 | 18 | 18 | no |
| `registry` | 15 | 7 | 8 | no |

**Five families fitted**, against four on host 1.

### `clean_c` was collected twice

The first collection had script-block logging disabled and yielded 5
`evtx.powershell` rows. The Group Policy value was set, activity regenerated,
and the collection retaken: 470 rows.

This is a lab-setup correction of the same kind as the network misconfiguration
behind `s1_v2`, and it is recorded rather than quietly applied. **`browser`, the
family the experiment is about, was at 62 rows in both collections** — the fix
did not touch the family under test.

### The registry finding, measured across four machines

`registry` never cleared the threshold and cannot on any real host:

| machine | autorun values |
|---|---|
| fresh VM, 7 applications installed | **4** (all OS defaults) |
| host 2 at collection | 7 |
| host 1 | 11-15 |
| a personally-used machine, several years | **13** |

> Autorun persistence is recorded in a handful of registry values on any Windows
> host. Population-based anomaly detection requires a population; a family of
> ten cannot supply one. This is structural to the artefact rather than a
> property of this corpus, and it is why persistence detection belongs to the
> deterministic rules — a rule needs one event where a model needs a population.

Padding the count with synthetic Run values was considered and rejected: it
would be fabricating evidence.

---

## 3. Browser features (2026-09-13)

Even with 62 training rows, `browser` was near-unmodellable: **86 downloads in
`s1_v3` collapsed to 8 distinct feature vectors.** Six of the ten original
features are execution-specific and sit at zero for a download; `path_depth` and
`path_is_user_writable` are constant because every download lands in
`Downloads\`. Only the hourly-density pair varied.

The parser already recorded `bytes` and `mime_type` into `details`. Neither
reached the feature table. Three columns appended:

| feature | form |
|---|---|
| `download_size_log10` | `log10(bytes + 1)`; measured range 153 B to 1.07 GB |
| `download_size_is_known` | missing is flagged, never imputed |
| `mime_type_is_executable` | membership of a closed MIME set — shape, not string |

**Leakage-tested before implementation.** Both measured **58.1%** single-field
accuracy separating `clean_c` from `s1_v3` against a **58.1%** majority-class
baseline — no collection identity whatsoever.

| | 10 features | 13 features |
|---|---|---|
| distinct browser vectors | 8 | **84** (of 86) |
| entity rank | 116 / 525 | **71 / 525** |
| lift @ K=100 | 0.00x | 5.25x |

---

## 4. Per-family feature sets

Argued in `docs/per-family-features.md` and **committed before the
implementation and before any rank was remeasured** (commit `af0ca77`). The
ordering is the point: the 2026-09-13 ablation also favoured this change, and
the only way to show the ablation was not the reason is to state the structural
argument first, on its own terms.

The argument in one line: a browser download has never run, so `run_count` and
the interval columns are *undefined* for it rather than missing; a Prefetch
record has no byte count or MIME type. Isolation Forest picks a feature
uniformly at random, so a column constant across a family spends split attempts
that partition nothing.

### Columns per family after the change

```
columns each family is now fitted on:
  amcache             8 cols
  browser             9 cols
  evtx.powershell     8 cols
  evtx.security       8 cols
  prefetch           10 cols

browser: 86 rows -> 86 distinct vectors
  names: ('executable_rarity', 'executable_is_unseen', 'events_in_same_hour', 'distinct_executables_in_same_hour', 'download_size_log10', 'download_size_is_known', 'mime_type_is_executable', 'filename_length', 'filename_entropy')

  invoice_scan.exe is 4 of 86 browser rows, pct 3.49

  top 5 browser rows by anomaly:
    pct=  0.00  cat.exe
    pct=  1.16  FileZilla_3.71.1_win64_sponsored2-setup.exe
    pct=  2.33  npp.8.9.8.Installer.x64.exe
    pct=  3.49  invoice_scan.exe
    pct=  4.65  DiscordSetup.exe
```

### Result: rank 71, unchanged

The prediction in `per-family-features.md` §5 was rank 25-30. **It did not
happen**, and the reason is visible in the browser ordering above:
`invoice_scan.exe` sits 8th of 86 browser rows, behind
`npp.8.9.8.Installer.x64.exe`, `gimp-3.2.4-setup.exe`, `vlc-3.0.23-win64.exe`
and `cat.exe` — **the other executable downloads**. `mime_type_is_executable`
lifts all six executables together, and the payload is one of six rather than
one of one.

**The change was kept anyway**, on the §1-§2 structural argument, exactly as
that document committed to doing. An argument only kept when it pays is not a
structural argument. The B-12 acceptance test also improved under it: overlap
0.949 to **0.972**.

---

## 5. Filename-shape features

Four further candidates were leakage-tested before any was implemented:

```
clean_c 62  s1_v3 86  baseline 58.1%

filename_length           58.1%   accept
    invoice_scan.exe = 16.0 chars; median 23
filename_entropy          58.1%   accept
filename_digit_ratio      58.1%   accept
url_path_depth            58.1%   accept
```

All four passed at exactly baseline. Two were implemented — the two describing
the *shape* of the name rather than anything derived from the URL, which is
closer to the excluded `path` field:

| feature | rationale |
|---|---|
| `filename_length` | `invoice_scan.exe` is 16 characters; the corpus median is 23, and book downloads carrying author and edition metadata run to 60-200 |
| `filename_entropy` | Shannon entropy over the basename. Separates a readable name from a machine-generated one. The characters never enter the model, only their distribution |

**Result: rank 71 -> 40.**

---

## 6. The final run

```
trained on 2444 events
  fitted   : ['amcache', 'browser', 'evtx.powershell', 'evtx.security', 'prefetch']
  unscored : ['evtx.system', 'registry']

self-score outlier rate: 4.55%

scored 2278 of 2304 s1_v3 events
  outlier rate: 7.99%

=== ATTACK EVENTS SCORED: 3 ===
  browser          pct=  3.49  outlier=True
  amcache          pct= 13.98  outlier=False
  prefetch         pct= 41.42  outlier=False

=== RANKING: 525 entities ===
     1. cat.exe                                    pct=  0.00 browser       
     2. svchost.exe                                pct=  0.00 amcache       
     3. msmpeng.exe                                pct=  0.19 amcache       
     4. microsoftedgeupdate.exe                    pct=  0.30 prefetch      
     5. onedrivesetup.exe                          pct=  0.38 amcache       
     6. searchfilterhost.exe                       pct=  0.39 prefetch      
     7. searchprotocolhost.exe                     pct=  0.49 prefetch      
     8. msedge.exe                                 pct=  0.57 amcache       
     9. conhost.exe                                pct=  0.59 prefetch      
    10. wmiprvse.exe                               pct=  0.59 prefetch      

  invoice_scan.exe -> rank 40/525, pct 3.49 in browser, 3 rows

=== SWEEP ===
  K=1    P@K=0.000  R@K=0.000  lift=0.00x
  K=5    P@K=0.000  R@K=0.000  lift=0.00x
  K=10   P@K=0.000  R@K=0.000  lift=0.00x
  K=25   P@K=0.000  R@K=0.000  lift=0.00x
  K=50   P@K=0.020  R@K=1.000  lift=10.50x
  K=100  P@K=0.010  R@K=1.000  lift=5.25x
```

---

## 7. Final feature ablation

Each feature dropped in turn from whatever set its family normally receives,
model refitted, rank remeasured.

```
BASELINE: rank 40/525  pct 3.49  (3 attack rows scored)

feature removed                                    rank   change     pct
-------------------------------------------------------------------------
(none - baseline)                                    40       --    3.49
run_count                                            35       -5    3.49  better
run_count_is_known                                   38       -2    3.49  better
executable_rarity                                    57      +17    4.65  worse
executable_is_unseen                                 61      +21    5.81  worse
events_in_same_hour                                  57      +17    5.81  worse
distinct_executables_in_same_hour                    52      +12    5.81  worse
seconds_since_previous_run_of_same_executable        32       -8    3.49  better
previous_run_is_known                                42       +2    3.49  worse
path_depth                                           36       -4    3.49  better
path_is_user_writable                                35       -5    3.49  better
download_size_log10                                  64      +24    6.98  worse
download_size_is_known                               58      +18    5.81  worse
mime_type_is_executable                             104      +64   13.98  worse
filename_length                                      40       +0    3.49  
filename_entropy                                     83      +43    9.30  worse

=== FEATURES THAT CARRY SIGNAL (removal makes it worse) ===
  mime_type_is_executable                        +64 places when removed
  filename_entropy                               +43 places when removed
  download_size_log10                            +24 places when removed
  executable_is_unseen                           +21 places when removed
  download_size_is_known                         +18 places when removed
  executable_rarity                              +17 places when removed
  events_in_same_hour                            +17 places when removed
  distinct_executables_in_same_hour              +12 places when removed
  previous_run_is_known                          +2 places when removed

=== FEATURES CONTRIBUTING NOTHING (removal changes nothing) ===
  filename_length
```

### The picture inverted

Before the per-family split, three features carried signal and ten made the
result worse by being present. After it, **nine carry signal and only one is
inert**:

| feature | rank when removed | |
|---|---|---|
| `mime_type_is_executable` | 104 (+64) | most informative |
| `filename_entropy` | 83 (+43) | |
| `download_size_log10` | 64 (+24) | |
| `executable_is_unseen` | 61 (+21) | |
| `download_size_is_known` | 58 (+18) | |
| `executable_rarity` | 57 (+17) | |
| `events_in_same_hour` | 57 (+17) | |
| `distinct_executables_in_same_hour` | 52 (+12) | |
| `previous_run_is_known` | 42 (+2) | |
| *baseline* | **40** | |
| `filename_length` | 40 (0) | **inert** |

**This is the strongest evidence for the per-family decision**, and it is
evidence collected after the decision was committed. The §2 argument predicted
that constant columns dilute; before the split, ten of thirteen features
appeared to "hurt" precisely because they were constant for the family carrying
the result. After the split, the same features carry signal in the families that
populate them. The dilution was real and the fix addressed it, even though the
attack's rank moved for a different reason than predicted.

**`filename_length` is inert** and is retained rather than removed: removing a
feature because it does not move a known answer is the selection-on-the-answer
this project has refused throughout. It is recorded as measured-and-inert, which
is a reportable result.

---

## 8. Where the result stands

```
entities: 525   attack entity rank: 40

    K     P@K     R@K     lift
------------------------------
    1  0.0000   0.000     0.00x
    5  0.0000   0.000     0.00x
   10  0.0000   0.000     0.00x
   25  0.0000   0.000     0.00x
   50  0.0200   1.000    10.50x
   65  0.0154   1.000     8.08x
   70  0.0143   1.000     7.50x
   71  0.0141   1.000     7.39x
   72  0.0139   1.000     7.29x
   75  0.0133   1.000     7.00x
   80  0.0125   1.000     6.56x
   90  0.0111   1.000     5.83x
  100  0.0100   1.000     5.25x
  150  0.0067   1.000     3.50x
  200  0.0050   1.000     2.62x
  300  0.0033   1.000     1.75x
  400  0.0025   1.000     1.31x
  525  0.0019   1.000     1.00x

PEAK LIFT: 10.50x at K=50
Maximum possible lift = N/rank = 525/40 = 13.12x

Lift = recall / (K/N). Below K=71 recall is 0, so lift is 0.
At K=71 recall jumps to 1.0 and lift peaks. Beyond that recall stays
1.0 while K/N grows, so lift decays as N/K. The peak is an artefact of
where the single entity sits, not a property of the ranking.
```

### Host 1 to host 2

| | host 1 | host 2 |
|---|---|---|
| attack events scored | 1 of 11 | **3 of 4** |
| families fitted | 4 | **5** |
| entity rank | 351 / 616 | **40 / 525** |
| position | top 57% | **top 7.6%** |
| peak lift | 0.00x at every K | **10.50x at K=50** |

### Rank at each stage

| stage | rank | position |
|---|---|---|
| host 1, 10 features | 351 / 616 | top 57% |
| host 2, 10 features | 116 / 525 | top 22% |
| + size and MIME features | 71 / 525 | top 13.5% |
| + per-family sets | 71 / 525 | top 13.5% |
| + filename shape | **40 / 525** | **top 7.6%** |

---

## 9. What this result is NOT

**There is no accuracy figure and none can be computed.** Four
attack-attributable events in 2,304 is not a labelled test set. Constructing one
by labelling collections would measure collection identity rather than
behaviour: `hour_of_day` alone scores 86.0% that way, which is why it is in
`EXCLUDED_FIELDS`.

**Ranking metrics reduce to one number.** With a single ground-truth entity,
precision, recall and lift are all transformations of its position. Lift is a
step function — 0.00x below the entity's rank, peaking at `N/rank` the instant
K reaches it, then decaying as `N/K`. Peak lift 10.50x at K=50 is `525/40`
scaled by K, not an independent measurement. **The rank is reported instead.**

**It is not detection.** The entity is not flagged as an outlier at the 5%
contamination setting, and 39 benign entities rank above it — `npp installer`,
`svchost`, `msmpeng`, the Edge updater, and the other executable downloads.

### The defensible claim

> The anomaly layer places the attack entity at rank 40 of 525 (top 7.6%),
> improved from 351 of 616 on the first host. It contributes measurable triage
> ranking but does not detect: the entity is not flagged as an outlier.
> Detection comes from the deterministic rules.

---

## 10. What was refused

Recorded because refusals are part of the method.

**No comparator models.** One-Class SVM and LOF were closed on 2026-09-04. The
justification for Isolation Forest is explainability — it names the feature that
isolated a row — and a model whose output cannot be defended to an examiner is
not a candidate, so there is nothing to benchmark against.

**`MIN_TRAINING_ROWS` was never lowered** to force `registry` or `evtx.system`
into the model. A forest fitted on 8 rows produces a ranking with no meaning.

**No feature was removed because the ablation said removing it helped.** That is
selection on the known answer — the process behind the 27.4% artefact-mix
result, closed in `shared/DECIDED.md`. `filename_length` is inert and stays.

**Corroboration tiers were rejected on measurement**, not taste: on this corpus
they would promote `vboxtray.exe`, a known false positive, and demote the actual
attack into the bucket an analyst skims.

**The evidence was never edited.** Synthetic Run values were considered as a way
to clear the registry threshold and rejected.

---

## 11. Threats to validity

**No negative control on host 2.** There is no second clean host-2 collection to
confirm that nothing ranks like the attack on a collection without one. Host 1's
baselines cannot serve: cross-host scoring flags nearly every row, because two
machines differ in software, users and hostname.

**One scenario, one payload.** Every ranking number describes where a single
4,608-byte stand-in landed. Nothing here establishes behaviour across attack
types.

**`evtx.security` is 740 rows in `clean_c` and 12 in `s1_v3`** — the log clear
worked. The family is fitted but has almost nothing to score, so the anti-
forensic action is visible in the row counts rather than in a ranking.

**Persistence remains unscored.** `registry` carries 8 rows; see section 2.

**The scenario order differs from `s1_v2`.** The Run key was written *after* the
Security clear rather than before, because the step was missed on the first pass
and added once noticed. The clear affects only `Security.evtx` and the Run key is
a registry artefact, so no evidence was lost — but the ordering is not identical
to host 1 and the timeline reflects what actually happened.

---

## 12. Future work, with evidence behind it

**Per-entity multi-family weighting.** An entity currently takes its best
percentile across families. `invoice_scan.exe` scores 3.49 (browser), 11.49
(amcache), 36.59 (prefetch) — three independent models each finding it unusual.
Rewarding agreement across families is defensible in principle, but it was not
implemented here: the weighting would have to be chosen, and with one
ground-truth entity any choice would be selected on the answer. It needs a
corpus with several scenarios before it can be tuned honestly.

**A negative control collection**, to close the gap in section 11.

**More attack types.** Every number here rests on one payload.
