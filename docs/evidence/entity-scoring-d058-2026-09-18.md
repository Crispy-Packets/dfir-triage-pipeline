# D-058 measurement and decision — 2026-09-18

Measured before choosing between the three candidate fixes, because the
options differ in what they would actually change and two of the three turned
out to rest on premises the evidence does not support.

---

## 1. Score range per entity kind

| collection | kind | n | max | min | top value |
|---|---|---|---|---|---|
| clean_a | exe_name | 20 | 86 | 45 | cursorusersetup-x64-3.15.6.exe |
| clean_a | user | 4 | **97** | 40 | youssef |
| clean_a | host | 2 | 88 | 40 | windows10 |
| clean_b | exe_name | 21 | 86 | 45 | 7z2602-x64.exe |
| clean_b | user | 5 | **97** | 40 | youssef |
| clean_b | host | 2 | 88 | 40 | windows10 |
| s1_v2 | exe_name | 5 | **99** | 45 | invoice_scan.exe |
| s1_v2 | user | 3 | 93 | 60 | admin_local |
| s1_v2 | host | 1 | 94 | 94 | windows10 |
| clean_c | exe_name | 2 | 75 | 60 | npp.8.9.8.installer.x64.exe |
| clean_c | user | 2 | **92** | 40 | vboxuser |
| clean_c | host | 2 | 40 | 40 | win-l0cdivojagf |
| s1_v3 | exe_name | 3 | **99** | 60 | invoice_scan.exe |
| s1_v3 | user | 1 | 88 | 88 | vboxuser |
| s1_v3 | host | 1 | 70 | 70 | winvm |

**A correction to the original D-058 entry.** No clean-host entity outscores
the payload: 97 and 92 are both below 99. The entry claimed an inversion,
which was true before R-CORR-0006 landed and is not true now. **The defect is
a two-point margin on a scale that mixes incomparable kinds**, not a
misordering.

---

## 2. Which rules feed which entity kinds

| rule | exe_name | user | host |
|---|---|---|---|
| R-ATOMIC-0001 | **36** | **7** | **3** |
| R-ATOMIC-0002 | 0 | 2 | 2 |
| R-ATOMIC-0003 | 0 | 0 | 3 |
| R-ATOMIC-0006 | **9** | **11** | 0 |
| R-ATOMIC-0009 | 0 | 11 | 6 |
| R-CORR-0001 | 12 | 0 | 0 |
| R-CORR-0002 | 0 | 4 | 0 |
| R-CORR-0003 | 2 | 0 | 0 |
| R-CORR-0005 | 0 | 3 | 0 |
| R-CORR-0006 | 2 | 0 | 0 |

**This is what decides the option.** R-ATOMIC-0001 and R-ATOMIC-0006 each feed
binaries *and* users — the same finding names the executable and the account
that ran it, which is correct behaviour and exactly what `aggregate` was built
to do. **Rules do not partition into classes**, so Option A's premise fails on
measurement rather than on taste.

---

## 3. The three options, simulated on the real findings

| collection | A: rule-class | B: per-kind (binaries) | C: drop host |
|---|---|---|---|
| clean_a | 86 npp installer | 86 npp installer | **97 user=youssef** |
| clean_b | 86 npp installer | 86 npp installer | **97 user=youssef** |
| s1_v2 | 99 invoice_scan.exe | 99 invoice_scan.exe | 99 invoice_scan.exe |
| clean_c | 75 npp installer | 75 npp installer | **92 user=vboxuser** |
| s1_v3 | 99 invoice_scan.exe | 99 invoice_scan.exe | 99 invoice_scan.exe |

**Option C is nearly useless.** Removing `entity.host` leaves a clean-host
*user* at 97 as the top entity on two collections. It deletes the 94-on-s1_v2
host artifact and not the defect.

**A and B produce the same binary ranking** — because excluding the
user-lifecycle rules and ranking binaries separately reach the same place by
different routes. A gets there by classifying rules, which requires a premise
section 2 disproves.

---

## 4. The binary-only ranking, which is what B exposes

| collection | top binary | score | severity |
|---|---|---|---|
| clean_a | cursorusersetup-x64-3.15.6.exe | 86 | high |
| clean_b | 7z2602-x64.exe | 86 | high |
| clean_c | npp.8.9.8.installer.x64.exe | 75 | high |
| **s1_v2** | **invoice_scan.exe** | **99** | **critical** |
| **s1_v3** | **invoice_scan.exe** | **99** | **critical** |

**Thirteen points of separation, and `critical` appears on scenario hosts
only.** No clean collection produces a critical binary. That discriminator
existed the whole time and was invisible because users and hosts shared the
table.

---

## 5. Decision: Option B

**Rank entity kinds separately.** `run.json` carries a table per kind; the
verdict panel reads binaries first.

**Why, in order of weight:**

1. **A's premise is false.** Rules feed multiple entity kinds (section 2), so
   there is no clean class boundary to declare. Implementing A means
   hand-labelling rules against measurement that says they do not partition.
2. **C does not fix it** (section 3).
3. **B is the only one that addresses the actual error**, which is a category
   error: a user's 97 and a binary's 99 are not measurements of the same
   thing, and presenting them in one ranked list invites the comparison.
4. **B subsumes C** — `entity.host` gets its own table and stops contaminating
   the headline.
5. **No schema change.** A needs a `class:` field on every rule, which is a
   schema version bump and a re-validation of all 15 (Person A's call). B is
   `entity_score.py` and the `run.json` shape.

**What B costs.** `run.json`'s shape changes, so Person A's report template
moves with it. An analyst asking "what do I look at first?" gets three ordered
lists instead of one — which is the honest answer, since the previous single
list was ordering incomparable things.

**What B does NOT fix.** `youssef` still scores 97 among users, and that is
still "a person who uses a computer" scoring high. Separating the kinds stops
it contaminating the binary ranking; it does not make the user score
meaningful. Whether a user entity should aggregate rule weights at all is a
further question this decision does not settle.

---

## 6. Consequence for the ablation

Every rules-side figure in `docs/evidence/layer-ablation-2026-09-18.md` was
measured against the current single-table scoring. **Implementing B changes
what "rank 1 of 5" means and the ablation must be re-run after it lands** —
recorded in D-062 as well, because a deferred re-measurement is the thing that
gets lost.
