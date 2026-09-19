# Scenario-design constraints

Rules for building the **next** collection. Every entry here was established by
measuring the corpus we already have, and each one describes a way that
scenario construction wrote itself into the evidence and then read back as an
attack signal.

None of these is a defect in the pipeline. The parsers extracted exactly what
was on disk; the numbers were real. What failed was the **scenario**, which
placed operator activity and attacker activity in the same fields. A rule
calibrated on such a field learns the lab.

This document is therefore a **collection-design input**, not a bug list. The
defect log records what was measured and when; this records what the next
scenario must do differently. Where an entry has a D-number, that entry is the
measurement; this is the consequence.

**C-05 runs the other way.** C-01 to C-04 are all the lab writing signal it
did not intend. C-05 is the lab failing to write signal it did intend, found by
fixing two parsers and discovering that neither unblocked the technique it was
blocking. Both halves have to hold for a corpus to calibrate a rule.

**The shared failure mode.** In C-01, C-02 and C-03 the base rate looked
good — clean separation between scenario and clean hosts, often on a single
field, and C-01's 9-vs-0 was the single best field-level number in the
project. C-04 is the inverse and is listed with them because the cause is the
same: its rules fire on the clean hosts and not the scenario. A base rate is a
reason to read the rows, not a licence to write the rule
(`docs/technique-coverage-grid.md` §3.5, which makes the same point about a
different set of three techniques).

---

## C-01  Evidence must not leave the host by a route the pipeline parses

**Established by:** D-064; `docs/technique-coverage-grid.md` T1052.001.

USB staging writes the volume into `lnk`, `jumplist` and `shellbags`, and reads
as an attack signal. Measured, `drive_type: removable` is 9 rows on `s1_v2` and
**0** on the other four collections — the single best field-level base rate in
the project. The nine rows are `E:\collection_clean_a`, `E:\collection_clean_b`,
`E:\collection_s1`, `E:\handoff` and personal media from 2020 and 2024. It is
the stick the collections were carried off on, browsed on 2026-08-20, before
the `s1` directory existed.

A rule on that field would fire 9-vs-0, look perfect, and detect the
evidence-handling procedure.

**For the next collection:** move the output by a route whose identifiers are
**recorded in the manifest before collection**, so its rows can be excluded by
identity rather than discovered later by inspection. No route is asserted here
to be traceless: a network share writes UNC and mapped-drive paths into
`shellbags`, `lnk` and `MountPoints2`, and which families a hypervisor shared
folder touches has not been measured in this corpus. The defensible procedure
is to know the identifier in advance, not to assume the route is invisible. The capability being tested is real — `lnk` and
`jumplist` do retain removable-volume serials after the device is gone — so the
goal is a corpus in which that evidence means what it appears to mean.

## C-02  The operator's shell history is inside the evidence

**Established by:** `docs/feature-decisions.md`, *`ps_history` content is
excluded from BOTH layers*; `docs/evidence/family-signal-survey-2026-09-18.md`
§2 for the ratios (normalised, rows per 100,000 events) and §3.1 for the
reading of the rows.

PSReadLine history normalises to **3.43x and 2.95x** more commands on the
scenario hosts than the clean ones — a strong ratio, on both hosts, in the same
direction. Reading the rows shows the extra commands are the operator building
the scenario:

    Copy-Item -Path C:\Windows\System32\notepad.exe -Destination Z:\invoice_scan.exe
    Test-Path Z:\invoice_scan.exe
    python -m http.server 8000

PSReadLine persists across logoff and is collected by `KapeTriage`. It is not
cleared by anything in the scenario.

**For the next collection:** build the scenario from a session whose history is
not collected — a different account, a different host, or a remote driver — or
clear PSReadLine after construction and before the final snapshot. **Say which
was done in the manifest**, because "no operator commands present" and "history
was cleared" are different claims and only one of them can be checked later.

**The separate-session option is preferred.** Clearing PSReadLine leaves an
absent or truncated `ConsoleHost_history.txt`, which is T1070.003-shaped and is
the kind of thing this rule set may later anchor on. If it is done, record it
as a known anti-forensic-shaped artefact rather than leaving a future analyst
to find it.

## C-03  Retrying a step leaves counting artefacts

**Established by:** `docs/evidence/recyclebin-predicate-2026-09-18.md` §4;
D-027.

`invoice_scan.exe` is deleted **nine times on `s1_v2`**, at three different
sizes (201,216 → 360,448 → 4,608) over four days. That is the operator
retrying the scenario. `s1_v3`, the other scenario host, holds exactly **one**
deletion. A rule keyed on repetition fires on host 1 and misses host 2.

The same cause produced **D-027**, where the `SecurityUpdate` autorun on
`s1_v2` carries a key last-write of 2026-08-21T01:34:07Z while the download it
points at is 2026-08-23T22:20:06Z — persistence appearing, on timestamps alone,
two days *before* the file it launches was delivered. D-027 states the cause
directly: "Scenario 1 was attempted three times. Only the third is the run
under test." An earlier attempt's registry write survived into the run that was
collected.

**For the next collection:** one clean attempt per scenario, from a restored
snapshot. If a step has to be retried, restore first. If a retry survives into
the collection anyway, record it in the manifest as a known artefact with its
count, so that count is never mistaken for actor behaviour.

## C-04  Lab provisioning is indistinguishable from the technique it resembles

**Established by:** `docs/technique-coverage-grid.md` §3.3 (T1136.001).

R-ATOMIC-0009 and R-CORR-0005 both exist, both fire, and both fire **on all
three clean hosts and neither scenario** — 4/5/0/2/0 and 1/1/0/1/0. The rules
correctly match local account creation. Local account creation in this corpus
is never an attack step. It is two different non-attack things, and they are
worth separating because only one of them is provisioning:

* **`janed`** is baseline provisioning — the account the scenario runs as,
  created so there would be a user to attack with.
* **`testuser`** on `clean_b` is a **staged test event**, created and deleted
  at 18:44 and 18:45 on 2026-08-24 during post-revert activity
  (`docs/collection-manifest.md`, Collection provenance) to exercise the
  account-lifecycle path. It is deliberate, and it is on a clean host.

The technique is genuinely covered and the coverage is genuinely worthless
here, because the corpus contains the technique only as our own housekeeping.

**Provisioning before the baseline snapshot is necessary and NOT sufficient,
and this corpus shows why.** Measured 2026-09-19, `account_created` (4720) by
account:

| collection | 4720 rows | accounts |
|---|---|---|
| clean_a | 4 | `WDAGUtilityAccount`, `Youssef`, `janed`, `admin_local` |
| clean_b | 5 | the same four, plus `testuser` |
| s1_v2 | **0** | — |
| clean_c | 2 | `WDAGUtilityAccount`, `vboxuser` |
| s1_v3 | **0** | — |

`janed` *was* provisioned before the snapshot, exactly as the naive form of
this rule would prescribe — and it still did not cancel out, because the
scenario's `wevtutil cl security` destroyed the Security log that held the
4720. The attestation matrix records the same mechanism for the payload's 4688
(`docs/artifact-attestation-matrix.md`, `evtx.security`). **A zero on the
scenario host means the log was cleared, not that no account was created.**
The 4/5/0/2/0 inversion is therefore two effects at once: provisioning on the
clean side, and anti-forensics on the scenario side.

**For the next collection:** provision every account, share and service
**before** the baseline snapshot — necessary, so setup is identical on both
sides — and additionally **verify after collection that the scenario host still
retains the channel the rule reads**. Where the scenario destroys that channel,
the technique cannot be evaluated from it at all, and the rule must be
re-anchored on a family the scenario does not destroy (for T1136.001 that is
`sam`, which is why the re-anchoring in grid §3.3 points at a standalone `sam`
shape). Anything the scenario needs to create *as part of the attack* must be
created only in the scenario run.

**One neighbouring case is measured, one is not.** `scheduled_task` holds the
**same five tasks on all five collections** — four Defender `MpCmdRun.exe`
entries and one `OneDriveLauncher.exe` — which is why T1053.005 is
`measured-no-discriminator` in the grid rather than written. Services are
**not** a parallel case on the evidence: `sc.exe create DummyLabSvc` appears in
the operator's shell history (C-02), but `DummyLabSvc` matches **zero rows in
the `services` family on all five collections** (measured 2026-09-19). A
provisioning command in history is not a provisioned row. Firewall rules are
untested.


## C-05  The scenario must produce the indicator the rule set is meant to detect

**Established by:** D-065 and D-055, both resolved 2026-09-19;
`docs/technique-coverage-grid.md` T1071.001 and T1059.001.

The other four constraints are about the lab writing signal it did not mean to.
This one is the opposite and was found by fixing two parser defects that turned
out not to unblock anything: **the lab did not write the signal it did mean
to.**

Two techniques were listed as blocked on a parser. Both parsers are now fixed --
`evtx.bits` and `evtx.ps_classic` went from `details == {}` on every row to
carrying a URL, a byte count, a result code and two kinds of command line -- and
**neither technique became writable**, because the scenario never produced the
indicator:

| technique | the indicator a rule needs | what the corpus contains |
|---|---|---|
| **T1071.001** Web C2 / download | an attacker-controlled background transfer | **every** BITS transfer on all five collections is Microsoft or Google update infrastructure (`msedge.b.tlu.dl.delivery.mp.microsoft.com`, `g.live.com`, `oneclient.sfx.ms`, `fs.microsoft.com`, `edgedl.me.gvt1.com`). Both scenarios delivered over `WebClient.DownloadFile` |
| **T1059.001** PowerShell *with logging off* | PowerShell running while script-block logging is OFF, launched with a flag a rule can read | **the precondition never held**: 4104 rows are 982/997/1270/470/644, so logging was ON everywhere. And the scenario's PowerShell was **interactive** -- bare `powershell.exe`, no flags to match. Neither candidate flag discriminates: `bypass` is host-1-only (640/640/460/0/0), `restricted` fires on all five and most on clean_c (56/56/72/104/138) |

In both cases the technique is covered in principle, the family is parsed, rich
and joinable, and there is **no positive class to calibrate against**. The
`Bypass` case is worse than absence: the textbook predicate is inverted, so a
rule written from a reference catalogue would fire on the clean hosts and miss
both scenarios.

**A parser blocker and a missing positive class look identical from the
coverage grid** until the parser is fixed. Two rows sat in `blocked` for a
reason that was only half true.

**For the next collection:** before collecting, enumerate the techniques the
rule set is meant to cover and confirm for each that **the scenario actually
produces its indicator** -- not merely that the family which would record it is
parsed. Deliver over the channel the rule reads; use the flags the rule looks
for. Where a technique is deliberately not exercised, say so in the manifest,
so a later reader finds "not attempted" rather than inferring "attempted and
not detected".

---

## Checklist for the next collection

- [ ] Output leaves the host by a route no parsed family records (C-01); if
      not, the volume's serial and label are in the manifest
- [ ] Scenario built from a session whose history is not collected, **or**
      PSReadLine cleared before snapshot — stated either way (C-02)
- [ ] One attempt per scenario, from a restored snapshot; any surviving retry
      recorded with its count (C-03)
- [ ] All lab accounts, services and tasks provisioned before the baseline
      snapshot (C-04)
- [ ] Every technique the rule set covers has its indicator actually produced
      by the scenario, delivered over the channel the rule reads and with the
      flags the rule looks for; techniques deliberately not exercised are named
      as such (C-05)
- [ ] Manifest states which of the above were satisfied and which were not.
      An unmet constraint that is written down is a limitation; an unmet
      constraint that is not is a finding waiting to be believed
