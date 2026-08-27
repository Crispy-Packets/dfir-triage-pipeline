# Verification method — Week 1, Scenario 1

Pre-registered. This document fixes the rules by which the Week 1 pipeline
output is compared against ground truth. It is committed on its own, before the
pipeline is run over any collection and before any comparison is performed. The
commit timestamp is the evidence that every threshold and every decision rule
below was chosen without sight of the numbers it will be applied to.

Nothing in this document may be revised after the comparison has been run. If a
rule here turns out to be wrong, the correction is recorded as a dated
amendment at the end of this file, with the original left visible and the reason
stated. A silently rewritten threshold is indistinguishable from a threshold
chosen to produce a result.

Author: Person A. Scope: evidence and forensic-semantics correctness.

---

## 1. Timestamp tolerance

**Decision: plus or minus 60 seconds. EVTX is authoritative. The operator log is
a researcher's note, not a measurement.**

The operator log timestamps were captured on the **host**, with
`(Get-Date).ToUniversalTime()` (`groundtruth/Scenario1.md`, "Operator log"). The
EVTX timestamps are the **guest's**. These are two machines with independent
clocks and no calibration record between them. The guest clock is independently
known to have moved: `clean_b` Security carries 25 records of EID 4616, the
system time was changed, over the lab period (`docs/lab-setup.md`, "Host clock
integrity"). The observed 6.1 s difference between the operator log's log-clear
time (23:05:12.794670Z) and the EVTX 1102 (23:05:06.682356Z) is therefore an
inter-machine clock offset plus human transcription latency, not a measurement
error in either record.

The tolerance is set at 60 s because the quantity being bounded is an
uncalibrated host-to-guest offset over a 19-minute scenario, and because the
scenario's own event spacing is 2m 32s at its tightest. **A 60 s tolerance is
smaller than the smallest interval the timeline needs to resolve, so it cannot
reorder any pair of ground-truth steps and cannot manufacture an ordering
result.** That property, not the number itself, is what makes this a method.

EVTX is authoritative because the events occurred on the guest and were
timestamped by the guest kernel at the moment of occurrence. The operator log
was typed by a human on a different machine at approximately the moment of
occurrence.

**Where the tolerance does not apply.** A discrepancy larger than 60 s is not
absorbed by widening the tolerance. It is a finding, and it is recorded as one.
OQ-003 is the worked case: the log-clear delta is 6.1 s and the download delta
is 425 s, and a single uncalibrated offset cannot produce both. That is an
ordering contradiction in the ground truth, and it is settled by evidence, not
by a threshold.

---

## 2. Verdict vocabulary

Action 93 asks whether ground truth "matches" the timeline. Left as a
match/no-match question, a ground-truth row whose artefact was destroyed by the
actor, or was never collected, or belongs to a family this project has not yet
written a parser for, all score identically with a row the pipeline genuinely
failed to produce. Those four situations make different claims about the
pipeline and must not share a verdict.

**Every ground-truth row receives exactly one verdict from this closed list. No
row is left unverdicted, and no verdict outside this list may be introduced
after the comparison has been run.**

| Verdict | Definition | Pipeline failure? |
|---|---|---|
| `MATCHED` | Artefact present in the collection, family declared in CD-007, and the pipeline produced a timeline row within tolerance | — |
| `DESTROYED` | The artefact existed on the live host and was removed by the actor's anti-forensic action before collection | **No.** This is the project's premise being demonstrated |
| `NOT-EVALUABLE` | The artefact existed on the live host but lies outside the KAPE `KapeTriage` collection scope | **No.** A property of collection scope, not of the pipeline |
| `NOT-PARSED` | The artefact is present in the collection but its family is not among the declared Week 1 families | **No.** Declared roadmap; the week it lands is cited |
| `MISSED` | Artefact present, family declared and parsed, and the pipeline produced no matching row | **Yes. This is the only failure category** |

**Reporting rule.** The `MISSED` count is stated explicitly and separately in
every place a Week 1 result is reported, including when it is zero. A recall
figure that divides `MATCHED` by all ground-truth rows is not reported, because
it charges the pipeline for collection scope and for a declared roadmap. Where a
single figure is required, it is `MATCHED` over `MATCHED + MISSED`, and the four
excluded verdicts are listed with their counts beside it.

**Every non-`MATCHED` verdict carries a reason and a resolver.** `DESTROYED`
cites the record that destroyed it. `NOT-EVALUABLE` cites the collection-scope
decision or the OQ number. `NOT-PARSED` cites the week the family lands.
`MISSED` cites what was expected and what the pipeline produced instead.

---

## 3. Action 99 — clean-collection contamination check

**The runbook rule is withdrawn.** It reads: *"A clean collection containing
Scenario 1 artifacts -> discard and recollect."* It is replaced in full, for two
reasons.

First, **re-collection is impossible.** The lab virtual machine was
decommissioned on 2026-08-25. The runbook's only prescribed remedy cannot be
performed. Every other instance of the phrase "discard and recollect" in the
Week 1 runbook and its contingency list is void for the same reason and is
replaced by "record as a limitation with the number attached".

Second, **the rule will probably fire, and firing is not evidence of
contamination.** `clean_b`'s Security log runs unbroken from EventRecordID 1
(2026-06-20) to 15,897 (2026-08-24) and therefore contains the entire
lab-construction period, including 2026-08-20 and 2026-08-21, when the project's
own PowerShell 4104 evidence shows `invoice_scan.exe` being created, copied to
`C:\Users\janed\Downloads\`, header-inspected and marker-tested. A hit for
`invoice_scan` in `clean_b` dated 20 or 21 August is **expected**. It is a
statement about baseline purity, not about whether the snapshot revert took.

**Replacement rule. Every `invoice_scan` hit in a clean collection is dated
before it is interpreted.**

| Hit timestamp | Interpretation | Action |
|---|---|---|
| Inside 2026-08-23T22:45:00Z–23:31:59Z (the incident window) | The revert did not take. The clean baselines are contaminated | Since re-collection is impossible, record as a **fatal limitation** on the Week 4 false-positive measurement, and withdraw the affected collection from that role |
| On 2026-08-20 or 2026-08-21 | Lab construction. `BASELINE-CLEAN+TOOLS` was captured after the binary was staged | The baseline is not attack-free. Declare this alongside the `testuser` staging in `docs/lab-setup.md` |
| Any other date, or no resolvable timestamp | Unresolved | Record as unresolved, with what was found, in full |
| No hit | The revert took | State as a **positive result**, naming the search terms used and the three trees searched |

**The negative case is a result and is written down.** "Searched three collection
trees and three timeline CSVs for `invoice`, case-insensitively; N hits, all
dated 2026-08-20 or 21" belongs in the record exactly as a positive hit would.

**Sharpest instrument, and it needs no parser.** Before the timeline search, list
`<collection>\C\Windows\prefetch\` for each of the three collections and look for
`INVOICE_SCAN.EXE-*.pf`. A Prefetch file for that executable is direct evidence
the binary executed on the machine the snapshot was taken from, and it is more
sensitive than the EVTX timeline, which can only see the execution if a 4688
record survived the log clear. The total `.pf` count per directory is reported
alongside, so a zero result can be distinguished from an empty directory.

---

## 4. Provenance sampling

The provenance claim this project inherits is that every timeline row resolves
by hand to a named record in a named source file. It is verified, not asserted.

**Three rows are drawn from `outputs/s1_v2/timeline.csv` at random**, not chosen
for convenience. For each, the named `source_file` is opened in the collection
and the `EventRecordID` in `source_locator` is located by hand. The three rows
are **named in the verification sheet** together with their resolution. "Three
rows sampled and resolved" without the rows named is an assertion, not evidence.

If any sampled row cannot be resolved by hand, the provenance claim is false as
stated, and that is recorded as a finding rather than resolved by drawing a
different row.

---

## 5. Recording corrections to ground truth

Where evidence contradicts the operator log, the operator log is corrected and
**the original line is kept visible and annotated as superseded**, with the
evidence that superseded it cited. A superseded ground-truth entry is never
deleted. Deleting one destroys the audit trail; annotating one is the record of
a correction, which is a methodology strength rather than an embarrassment.

The three possible outcomes of the OQ-003 Edge History read are recorded in
`docs/open-questions.md` **before** the query is run, so that whichever occurs
cannot afterwards be presented as the one that was expected.

---

## 6. What this document does not fix

Recorded so that the boundary of the pre-registration is explicit:

- The counts, deltas and verdicts themselves. Those are measured after this file
  is committed.
- The Prefetch parser review criteria, which are recorded separately in
  `groundtruth/scenario1-verification.md` at the time the review is attempted or
  recorded blocked.
- Anything that depends on Person B's contract decisions, in particular the
  normalisation rule for `Event.path` across artefact families. That is a
  contract question and is theirs; see OQ-006.

---

## Amendments

### 2026-08-26 - scenario span, section 1

**Rule changed:** none. **Figure corrected:** the descriptive phrase in section 1.

Original text: *"the quantity being bounded is an uncalibrated host-to-guest
offset over a 19-minute scenario, and because the scenario's own event spacing
is 2m 32s at its tightest"*.

Reason: the 19-minute figure derived from the operator log, whose download entry
has since been shown to be late by 25m 25.6s (OQ-003, closed from Edge
`History`). Measured from the Edge download `start_time` of
2026-08-23T22:20:06.710763Z to the EID 1102 at 23:05:06.682356Z, the scenario
spans **44m 59.97s**.

**The tolerance is unchanged and its justification is unaffected.** The argument
for 60 s rests on the *tightest* interval the timeline must resolve, not on the
total span. That interval is execute -> persist, 2m 32s, and both its endpoints
are operator-log entries carrying the same offset, so it is unchanged. A 60 s
tolerance still cannot reorder any pair of ground-truth steps.

This amendment is recorded rather than applied silently to section 1, because
section 1 was committed before the pipeline ran and its value as evidence
depends on it not being rewritten afterwards.

### 2026-08-26 - correction to a claim made in this repository

Not an amendment to this document, recorded here because it concerns method.
A claim was briefly committed to `docs/lab-setup.md` that the lab subnet was
192.168.56 rather than 192.168.50, inferred from a single line of host-side
PowerShell console history. It was wrong, and it was used to alter a search term
in a planned query. Guest-side evidence - eleven Edge `downloads` rows, all
`192.168.50.x` - settles it. The claim is retracted in place in that file rather
than deleted.
