# Feature decisions for the anomaly layer

Measured 2026-08-30 across all three collections. Every exclusion below is a
measurement, not a precaution, and the number that justifies it is quoted.

Training collection is `clean_b` throughout. "Single-field accuracy" is the
accuracy of the best possible rule that looks at one field alone, separating
`clean_b` from `s1_v2`. The baseline is **79.8%**, from always guessing the
majority class. Anything meaningfully above that is separating *collections*,
not behaviours.

---

## 1. Why leakage is the governing risk here

The three collections came from one machine, built by one operator, over about
nine days. They differ from one another in ways that have nothing to do with the
attack:

| | clean_a | clean_b | s1_v2 |
|---|---|---|---|
| `evtx.security` share | 76.8% | 77.0% | **10.5%** |
| `evtx.powershell` share | 7.4% | 7.4% | **37.0%** |
| `prefetch` + `amcache` share | 15.5% | 15.3% | **50.9%** |
| rows with no `user` | 23.1% | 22.8% | **88.9%** |
| distinct dates | 9 | 9 | 10 |

A model given any field that tracks these differences will separate the
collections perfectly and detect nothing.

---

## 2. Excluded fields

| field | single-field accuracy | why |
|---|---|---|
| `source_file` | 83.0% | Names the collection layout directly: 335 distinct files in `clean_b`, 209 in `s1_v2`. |
| `source_artifact` | 81.8% | The artifact mix above. A property of what was collected, not what happened. |
| `event_type` | 81.8% | Moves with `source_artifact` and to the same degree: `process_exec` is 79.3% of `clean_b` and 34.0% of `s1_v2`. |
| `path` | 81.3% | 139 canonical paths appear only in `s1_v2`, most of them the Guest Additions install (D-026). A model given raw `path` learns "Guest Additions present, therefore malicious". |
| `timestamp_type` | 80.1% | A restatement of the artifact mix. |
| `user` | 79.8% | Not separating on its own, but excluded anyway: its emptiness tracks the artifact mix exactly, and it would combine with anything else that does. |
| **`hour_of_day`** | **86.0%** | The worst leaker measured. Hours 21–23 hold **33% of `s1_v2` and about 1% of the baselines** — not because intrusions happen at night, but because the operator ran the scenario in the evening. |
| **`is_weekend`** | **84.2%** | The corpus spans 9–10 distinct dates, so weekday-ness records which days the lab was run. |

`event_type`, `timestamp_type`, `hour_of_day` and `is_weekend` were **not** in
the original plan's exclusion list. The plan proposed hour-of-day and
weekday/weekend as features. They are excluded on evidence.

### `ps_history` content is excluded from BOTH layers (2026-09-18)

Found by the family signal survey
(`docs/evidence/family-signal-survey-2026-09-18.md`), not by a feature
measurement, and recorded here because it is the same class of defect as
`hour_of_day` and affects rule authorship as well as the model.

PSReadLine history normalises to 3.4x and 2.95x more commands on the scenario
hosts than the clean ones — a strong ratio, on both hosts, in the same
direction. **Reading the rows shows the extra commands are the operator
building the scenario**, not an intruder acting:

    Copy-Item -Path C:\Windows\System32\notepad.exe -Destination Z:\invoice_scan.exe
    Test-Path Z:\invoice_scan.exe
    python -m http.server 8000
    sc.exe create DummyLabSvc binPath= "C:\Windows\System32\svchost.exe"

And the decisive case — **`clean_c`, a CLEAN collection, names the payload**:

    Get-Item C:\staging\invoice_scan.exe | Select-Object Name, Length
    Get-FileHash C:\staging\invoice_scan.exe
    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

A model or rule keyed on this content learns the shape of lab construction and
would score a clean collection as compromised on the strength of the string
`invoice_scan.exe` appearing in a shell history. `clean_b` carries a milder
form: `net user testuser temppass1123 /addddddddddddddddddddddddddd`, a
typo'd command retried.

**The family stays parsed and stays in the timeline** — it is genuine evidence
of what was typed, and it survives when script-block logging is off, which is
the reason it was written. It is excluded from being a rule anchor and from
supplying model features. The distinction matters: the artefact is sound, the
corpus is contaminated, and only the second fact restricts what may be built
on it.

### `recyclebin` deleted_size and repetition count are excluded (2026-09-18)

Same category, found while choosing the predicate for R-CORR-0006
(`docs/evidence/recyclebin-predicate-2026-09-18.md`).

**`deleted_size` separates this corpus well and must not be used.** A
threshold of 512 KB matches 10 payload deletions against 2 benign across all
five collections. It works because this lab's payload is a copied
`notepad.exe` of 4,608-360,448 bytes while this lab's benign deletions are
software installers of 1.6 MB to 495 MB. It is `hour_of_day` in a different
coordinate: a real property of the data that encodes how the lab was built
rather than what an attack looks like. A real payload can be 50 MB, and a real
user deletes small files constantly.

**Repetition count is scenario construction.** `invoice_scan.exe` is deleted
**nine times** on `s1_v2`, at three different sizes (201,216 → 360,448 →
4,608) across four days — the operator retrying. `s1_v3`, the other scenario
host, holds exactly **one** deletion. Any feature or rule keyed on how often a
name recurs in the bin fires on host 1 and misses host 2.

**The deleting SID is excluded for the third time in this document's logic.**
On `s1_v2` every payload deletion belongs to `S-1-5-21-…-1002` (janed) and
every benign one to `…-1000` (Youssef). It separates perfectly and it is the
scenario user's account, not a property of attacks.

A numeric threshold deserves more suspicion than a name list, not less,
because it presents as principled. The test is the same one: could the value
be derived from the technique, or only from reading these collections?

---

## 3. Features retained

Each describes behaviour that would still mean something on a different machine.

| feature | rationale |
|---|---|
| `run_count`, `run_count_is_known` | How many times a binary has executed. A missing count is flagged, never imputed — a mean would invent an execution history the artifact did not record. |
| `executable_rarity`, `executable_is_unseen` | Frequency **in the training profile**, never the name. A name is tied to this corpus; a frequency transfers. |
| `events_in_same_hour`, `distinct_executables_in_same_hour` | Activity density. The hour groups nearby events; the hour *itself* is never a feature. |
| `seconds_since_previous_run_of_same_executable`, `previous_run_is_known` | Execution rhythm. A gap of zero and a gap that does not exist are different claims. |
| `path_depth`, `path_is_user_writable` | Shape, not identity. Carries no collection-specific string. |
| `download_size_log10`, `download_size_is_known` | Added 2026-09-13. Log-scaled because the measured range is 153 B to 1.07 GB; on a linear scale one 1 GB download dominates every split. Missing is flagged, never imputed. |
| `mime_type_is_executable` | Added 2026-09-13. Membership of a closed MIME set -- shape, not the string. |
| `filename_length`, `filename_entropy` | Added 2026-09-13. How long the basename is and how evenly its characters are distributed. The characters themselves never enter the model. |

Rarity is computed on the **training** collection and applied unchanged to
whatever is scored. Recomputing per collection would make every binary
averagely rare within its own collection, hiding precisely the binary that
appears nowhere else.

### Per-family feature sets (2026-09-13)

The fifteen names above are the full vocabulary; **no family receives all of
them.** `features.FAMILY_FEATURES` restricts each artifact family to the columns
its records can populate: a download has never run, so `run_count` and the
interval columns are undefined for `browser`; a Prefetch record carries no byte
count or MIME type.

A constant column is not merely ignored. Isolation Forest selects a feature
uniformly at random and then a split point within its observed range, so a
column identical across every row in a family spends a node and partitions
nothing. The argument is made in full in `docs/per-family-features.md`, which
was committed **before** the implementation and before any rank was remeasured.

### The five new features were leakage-tested before implementation

Each measured single-field accuracy separating `clean_c` from `s1_v3`, against a
**58.1%** majority-class baseline:

| feature | accuracy | verdict |
|---|---|---|
| `download_size_log10` | 58.1% | accept |
| `mime_type_is_executable` | 58.1% | accept |
| `filename_length` | 58.1% | accept |
| `filename_entropy` | 58.1% | accept |

All four sit exactly on the baseline -- they carry no collection identity at
all, the cleanest result any feature has returned on this project. Two further
candidates, `filename_digit_ratio` and `url_path_depth`, also passed and were
**not** implemented: both are closer to the excluded `path` field than to a
shape, and four accepted features were enough to test the idea.

---

## 4. One model per artifact family

A single model over all families does not work here, and the reason is
structural rather than a tuning problem. Some feature columns can only be
populated by one family — `run_count` is non-zero only for Prefetch — so a mixed
model spends its splits telling artifact types apart instead of behaviours.

| model | `clean_a` outlier rate | `s1_v2` outlier rate |
|---|---|---|
| single | 5.5% | **27.4%** |
| per family | 5.3% | **7.7%** |

The single model's 27.4% looked like detection and was not. Only **2 of its 938**
flagged rows were VirtualBox-related, so it was not the D-026 build difference
either; it was the artifact mix, and `s1_v2` is 51% Prefetch and Amcache against
15% in the baselines.

Per-family scoring is also the more defensible claim. "This execution is unusual
among executions" is checkable. "This execution is unusual among log-on records"
is not.

Three families — `browser`, `evtx.system`, `registry` — have fewer than 50
training rows and get no model. Their rows are reported **unscored** rather than
scored as normal, because "not anomalous" for a row that was never modelled is a
claim the model did not make.

---

## 5. The B-12 acceptance result

Fit on `clean_b`, score `clean_a`. Both are no-attack baselines collected eleven
days apart.

| | value |
|---|---|
| overlap coefficient | **0.949** (1.0 identical, 0.0 disjoint) |
| `clean_b` outlier rate | 5.00% |
| `clean_a` outlier rate | 5.53% |

**Accepted.** The model does not separate two collections that differ only by
when they were taken, so a difference on `s1_v2` means something. This is
asserted in `tests/test_features.py`, not eyeballed once and forgotten.

---

## 6. What the model actually detects — stated plainly

**Superseded 2026-09-13 by the host-2 measurement. Both results are kept: the
host-1 figures are what this corpus supports, and the change between them is
the finding.**

### Host 2 — current (`clean_c` training, `s1_v3` scored)

| step | artifact | percentile | flagged? |
|---|---|---|---|
| download | `browser` | 3.49 | no |
| amcache | `amcache` | 11.49 | no |
| execution | `prefetch` | 36.59 | no |

Entity rank **40 of 525 — top 7.6%**. Three of the four attack events are
scored, against 1 of 11 on host 1.

> **Measured 2026-09-13, against SEVEN parsed families. Superseded as a
> current figure — see D-062.** Re-run on 2026-09-18 against 38 families, the
> same host and the same model configuration gives **134 of 892 (top 15.0%)**.
> The position halved in percentile terms, and the cause is that
> `FAMILY_FEATURES` below still lists only the original seven: none of the 31
> families added since has a feature set, 5 of 126 families are modelled, and
> the entity denominator grew with the event pool while the model did not
> change. The 7.6% figure remains correct for the pipeline it describes and
> must not be quoted as current.

### Host 1 — as originally measured (`clean_b` training, `s1_v2` scored)

| step | artifact | rank | flagged? |
|---|---|---|---|
| log clear | `evtx.security` | 86 / 359 (top 24%) | no |
| execution | `prefetch` | 448 / 868 (top 52%) | no |

Entity rank 351 of 616 — top 57%.

**Nothing is flagged as an outlier in either case.** The layer ranks; it does
not detect. What changed between the two is coverage and feature fit, not the
model: host 1's `browser` family held 11 training rows and could not be modelled
at all, so the download and the persistence were never scored. See
`docs/evidence/ml-stage-record-2026-09-13.md` for the full progression.

This is a real result and it is not a bug. `invoice_scan.exe` is **1 of 30**
Prefetch binaries in `s1_v2` unseen in training, sitting alongside `drvinst.exe`,
`ipconfig.exe`, `grpconv.exe` and `chxsmartscreen.exe` — all Guest Additions
install artifacts. Behaviourally, a 4,608-byte stand-in that runs once and exits
looks exactly like any other first-run utility. It carries no distinguishing
behaviour to find, because the stand-in does not behave like malware; it is a
marker-writing placeholder.

The log clear is a single EID 1102 among 359 Security rows with nothing unusual
in its density, rarity or timing features.

### Why this is the right result to report

An anomaly model that flagged this scenario on this corpus would almost
certainly be reading the Guest Additions build difference (D-026) or the
artifact mix, not the attack. The single-model configuration *did* produce a
27.4% outlier rate on `s1_v2`, which would have looked like a strong detection
in a chart, and it was measurably an artifact of collection composition.

The detections that do work on this corpus are the deterministic rules:
R-ATOMIC-0002 on the log clear, R-ATOMIC-0003 on the PowerShell delivery, and
R-ATOMIC-0006 on the Run-key persistence. The anomaly layer's role is triage
ranking over a large event set, and its honest contribution here is a **measured
false-positive floor of roughly 5% on clean hosts** — which is itself a useful
number for the write-up.

This is consistent with what was agreed in `shared/DECIDED.md`: the corpus will
not support a trained classifier, and the unsupervised layer is exploratory.
