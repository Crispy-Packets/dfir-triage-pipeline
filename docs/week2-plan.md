# Week 2 plan

Ordered by what unblocks the most downstream work. Items carried from Week 1
limitations keep their reference so nothing is silently dropped.

---

## 1. Toolchain smoke tests -- do this FIRST

**Ninety minutes, before Week 4 depends on any of them.** Hayabusa, Plaso and
dftpl. The only question to answer per tool: does it install, run against one of
our collections, and produce parseable output on this host?

Rationale for going first: a tool that cannot be made to work is a Week 4
schedule problem, and finding that out in Week 4 leaves no room to replace it.
Ninety minutes now buys the option to change course.

Record the result either way in `docs/evidence/`, including versions.

---

## 2. `clean_c` decision

With one realistic clean collection, false-positive measurement and
anomaly-model training draw on the same data (CD-014). Either collect a third
clean collection with a differing benign workload, or state explicitly in the
evaluation that the two draws are not independent and accept the weaker claim.

**This is a decision, not a task.** It needs making early because collecting
`clean_c` requires lab time that must be scheduled, and the lab VM used for the
scenario has already been decommissioned once.

---

## 3. Count downloads in `collection_s1_v2` browser history

*Done 2026-08-30.* The browser parser exists and the count is **20 in
`collection_s1_v2`**, of which 9 are `invoice_scan.exe`: eight from the two
abandoned attempts recorded in D-027, plus the one under test. Baselines carry
10 and 11 downloads and no `invoice_scan` artifact.

This discharges the false-positive concern in the direction that matters: a
download-to-execution rule keyed on filename would match nine downloads for one
execution. Size and source host are the discriminating fields.

---

## 4. Parsers

In dependency order, not preference order:

| parser | why this order |
|---|---|
| **Amcache** | `presence` timestamp_type, already in the CD-019 vocabulary. Gives execution evidence where Prefetch is absent |
| **Shimcache** | Same `presence` semantics; pairs with Amcache for the same question |
| **Registry autoruns** | Directly evaluable against the scenario's `HKCU\...\Run\SecurityUpdate` persistence |
| **Browser downloads** | Unblocks item 3 and the download-to-execution sequence rule |
| **MFT (narrow mode)** | Largest and least constrained; last so the pattern is settled first |

Each parser follows the Week 1 shape that held up under real evidence:

- a `_records()` adapter that is the **only** library-coupled code
- a pure `record_to_events()` transform taking a dict and returning Events
- `can_handle()` tested against the **real directory listing**, not invented paths
- every `details` key declared in `docs/details-schema.md` **before** emission

**Read `03-findings-for-you.md` before writing any of them.** Three of Week 1's
four defects produced wrong output without raising an exception. Assume the same
class of fault exists in every new library until checked against raw bytes or
ground truth.

---

## 5. `core/entity.py`

Entity identity across artifact families (CD-010). The volume-serial to
drive-letter map is read from the collection manifest.

**Two constraints established in Week 1 that this must respect:**

- The volume serial is **per-record**, and marks which volume a binary ran from
  -- not whether it is tool noise. `KAPE.EXE` appears under both serials in
  `clean_b`. Do not use the serial as a noise classifier.
- Basename joining is the primary key and **will** join distinct binaries
  sharing a name. That cost must be measured against the clean baselines and
  reported, not estimated.

---

## 6. Freeze and tag the YAML rule schema

Once the rule engine has a shape, freeze the schema and tag it. Week 3 and Week 4
both write rules against it, and an unfrozen schema means every rule written
early gets rewritten late.

---

## 7. Anomaly detection -- what this corpus can and cannot support

Decided 2026-08-28 from a full run over all three collections, before any model
code exists, because the constraint changes what the Week 4 evaluation may claim
and is cheaper to accept now than to discover late.

### The corpus will not support a trained classifier

The whole corpus holds **one attack-attributable row in 24,323** -- the
`INVOICE_SCAN.EXE` Prefetch record at 2026-08-23T22:57:15.832788Z. A positive
rate of 0.004% is not an imbalance to be resampled; it is a single point, and no
supervised model learns a boundary from one example. A classifier trained here
reaches 99.996% accuracy by answering "benign" every time.

This is a property of a single-scenario lab, not a collection fault. One
execution produces one Prefetch record.

**Consequence:** the Week 4 evaluation reports rule detection rates and
false-positive rates, plus an unsupervised anomaly baseline. It does not report
classifier precision, recall or F1 against a trained model. Any such figure
would be measuring one example.

### Isolation Forest is the right shape, and needs no positives

Isolation Forest is unsupervised: it learns normality from the baseline and
scores how readily a point isolates. The single attack row is not a training
deficiency at all -- it is the test case.

| Collection | Role |
|---|---|
| `clean_b` | training. 11,703 rows, the only collection with benign user activity |
| `clean_a` | false-positive floor. No user activity, so anything scoring anomalous is system noise (CD-014) |
| `s1_v2` | scoring. Does the `INVOICE_SCAN.EXE` row surface, and at what rank |

This is also why the `clean_c` decision in item 2 matters here. Training on
`clean_b` and measuring false positives on `clean_b` is not an independent
draw. Using `clean_a` as the FP floor partly mitigates it, but `clean_a` has no
user activity and so understates the rate a real workload would produce.

### The leakage risk, and the feature rule that prevents it

The scenario differs from the baselines by far more than the attack, and a model
given raw fields will learn the difference rather than the behaviour. Measured:

| Signal | `clean_b` | `s1_v2` |
|---|---|---|
| `evtx.security` share | 89.20% | 28.72% |
| `prefetch` share | 10.66% | 69.44% |
| paths present only in `s1_v2` | -- | 37 |

The artifact-share gap is the `wevtutil cl Security` clear, not the intrusion.
Of the 37 scenario-only paths, the majority are the VirtualBox Guest Additions
install absent from both baselines -- `vboxservice.exe`, `vboxtray.exe`,
`vboxsf.sys`, `vboxwddm.sys`, `vboxdrvinst.exe` -- the same difference recorded
as D-026 in the 7045 counts, appearing here as a modelling hazard.

A model fed `path` as a raw categorical feature learns **"Guest Additions
present, therefore malicious."** It would validate well and detect nothing.

**Rule: `path`, `source_file` and `source_artifact` are excluded as raw
categorical features.** They stay in the timeline for triage and provenance;
they do not enter the feature matrix as identities. Derive behavioural features
instead:

- hour of day, and weekday or weekend
- event-type frequency per user, per hour
- Prefetch `run_count`, and the interval since the previous execution of the
  same binary
- rarity of the executable name across the training collection, as a frequency,
  never as the name itself
- count of distinct executables per user session

A second-order form of the same hazard: the machine account holds 76% of the
EVTX rows and human accounts contribute roughly 13% of process executions, so a
"normal behaviour" model built without stratifying by account type is largely a
model of `WINDOWS10$`. Fit per account class, or carry account class as an
explicit feature.

### Acceptance test before any result is reported

Train on `clean_b`, score `clean_a`. The two are network-identical, both NAT,
neither carrying a USB device or the scenario. Their anomaly-score
distributions should overlap heavily. **If `clean_a` scores broadly anomalous
against a `clean_b` model, the features are encoding collection identity rather
than behaviour, and no scenario result computed from them means anything.**
Run this before scoring `s1_v2`, not after.

---

## Carried from Week 1, unresolved

- **D-019** -- 24 files in `collection_s1_v2` covered only from receipt onward.
  Cannot be resolved; the lab VM is decommissioned. Stays recorded.
- **D-014** -- ruff `I001` on parser registration imports. Resolved by `,I001` on
  the first import line each time a parser is added. Will recur with every new
  parser in item 4.
- **CD-014 7045 counts** -- filled 2026-08-28. The measurement reversed the
  clause's premise; see D-026 and the anomaly-detection section below, where the
  same finding is the principal leakage risk.
