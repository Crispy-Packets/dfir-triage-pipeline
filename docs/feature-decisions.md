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

Rarity is computed on the **training** collection and applied unchanged to
whatever is scored. Recomputing per collection would make every binary
averagely rare within its own collection, hiding precisely the binary that
appears nowhere else.

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

It ranks the Scenario 1 rows as follows, per-family, `clean_b` as training:

| step | artifact | rank | flagged? |
|---|---|---|---|
| log clear | `evtx.security` | 86 / 359 (top 24%) | no |
| execution | `prefetch` | 448 / 868 (top 52%) | no |

**Neither is flagged.** The unsupervised layer does not detect Scenario 1.

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
