# Phase-span ranking signal — 2026-09-20

Candidate signal arising from the ranking-signal evaluation
(`ranking-signals-2026-09-20.md`), which accepted the *shape* of signal 3 and
rejected its *count*: what separated the payload was **which** families
corroborated it, not how many.

**Hypothesis.** An entity whose corroborating families span distinct phases of
an attack chain separates better than one named in many families that all
record the same behaviour.

**Result: ACCEPT under V1, with scope.** On each scenario host the payload is
the only entity spanning all four phases, and no clean collection has an
entity above three.

Everything in "Method, fixed before measurement" — including the mapping, the
corpus-fit statement, the acceptance criterion, the three sensitivity variants
and the three predictions — was written and saved *before* the distribution
was read. The ordering is deliberate and is the point: a mapping written after
the numbers cannot be tested against them.

---

## Method, fixed before measurement

### The mapping is `event_type -> phase`, not `family -> phase`

A family is not a phase. `registry` records autorun persistence, execution
MRUs and configuration; `mft` and `usn` record creation and deletion;
`evtx.security` records everything. Assigning one phase per family would make
the result an artifact of the assignment rather than of the evidence.

The mapping was written from the declared `event_type` vocabulary in
`docs/contract-decisions.md` (the CD-007 grid) and the values actually
constructed in `dfir_triage_pipeline/`, **before** any entity's families were
read.

### The adopted mapping

This is the mapping as **adopted under V1**, which is the definition the
verdict accepts. The `usn` exception below is part of the definition, not a
variant of it.

| event_type | phase | ATT&CK tactic (alternative axis) |
|---|---|---|
| `file_download` | DELIVERY | Command and Control |
| `background_transfer` | DELIVERY | Command and Control |
| `bits_job_created` | DELIVERY | Command and Control |
| `bits_transfer_started` | DELIVERY | Command and Control |
| `bits_transfer_completed` | DELIVERY | Command and Control |
| `bits_job_completed` | DELIVERY | Command and Control |
| `page_visited` | DELIVERY | Reconnaissance |
| `search_term` | DELIVERY | Reconnaissance |
| `file_created` | DELIVERY | — |
| `process_exec` | EXECUTE | Execution |
| `program_shimcached` | EXECUTE | Execution |
| `program_inventoried` | EXECUTE | Execution |
| `script_block` | EXECUTE | Execution |
| `command_typed` | EXECUTE | Execution |
| `ps_engine_start` | EXECUTE | Execution |
| `ps_engine_stop` | EXECUTE | Execution |
| `ps_provider_start` | EXECUTE | Execution |
| `app_opened` | EXECUTE | Execution |
| `app_engaged` | EXECUTE | Execution |
| `resource_usage` | EXECUTE | Execution |
| `network_usage` | EXECUTE | Command and Control |
| `persistence_autorun` | PERSIST | Persistence |
| `task_registered` | PERSIST | Persistence |
| `service_install` | PERSIST | Persistence |
| `service_registered` | PERSIST | Persistence |
| `wmi_subscription` | PERSIST | Persistence |
| `local_account` | PERSIST | Persistence |
| `account_created` | PERSIST | Persistence |
| `privilege_granted` | PERSIST | Privilege Escalation |
| `file_deleted` | DESTROY | Defense Evasion |
| `log_cleared` | DESTROY | Defense Evasion |
| `defense_disabled` | DESTROY | Defense Evasion |
| `firewall_rule_added` | DESTROY | Defense Evasion |
| `firewall_rule_changed` | DESTROY | Defense Evasion |
| `firewall_rule_deleted` | DESTROY | Defense Evasion |
| `firewall_rules_deleted` | DESTROY | Defense Evasion |
| `bits_job_cancelled` | DESTROY | Defense Evasion |

**The `usn` exception (V1).** `file_created` and `file_deleted` carry **no
phase when the emitting family is `usn`**. `recyclebin`'s `file_deleted`
keeps DESTROY. This requires `(family, event_type)` granularity — the table
above is `event_type -> phase` and cannot express it on its own, because
`file_deleted` is emitted by both `usn` (`parsers/usn_journal.py:79`) and
`recyclebin` (`parsers/recycle_bin.py:154`). Any implementation must key the
exception on the pair.

**Unmapped — these carry no phase.** They assert that a file or path exists,
not that a phase occurred. Counting them would let filesystem journalling
alone manufacture a span (measured: doing so is V2, which fails).

    file_record            file_referenced        file_opened
    folder_browsed         path_typed             file_renamed_from
    file_renamed_to        pending_registry_write servicing_pending
    component_version_change  file_reported       scan_skipped
    av_service_started     malware_detected       malware_remediated
    defense_configured     logon                  logon_failed
    logon_ui               rdp_session            dom_storage
    log_record

**C-02 families excluded entirely.** `ps_history` and `runmru` (both
`command_typed`) are dropped before phases are computed, regardless of the
mapping above.

**Taxonomy.** Four chain stages, chosen to match the scenario's own four steps
so the acceptance test is stated on the same axis the scenario was built on —
which is also the corpus-fit risk recorded below. The ATT&CK tactic column is
the more defensible external citation but does **not** partition: several
event types map to two tactics (`persistence_autorun` is Persistence and
Privilege Escalation), so it is recorded as an alternative axis rather than
used.

### Presence-only event types carry no phase

The 22 record-keeping types listed above are deliberately unmapped, for the
reason given there. Restated because it is the load-bearing choice: counting
them would let filesystem journalling alone manufacture a span.

The contestable line is that `file_created` / `file_deleted` **do** bear a
phase while `file_record` / `file_referenced` do not. The justification:
`$MFT` and `$LogFile` name a file without asserting an action on it, while
`$J` and `$I` record the action. `recyclebin`'s `file_deleted` is additionally
a `recorded` observation — Windows wrote the FILETIME at the moment it moved
the file (`parsers/recycle_bin.py:147-159`) — not a presence inference.

Because this line is contestable it is **measured**, not argued: see the
pre-registered sensitivity variants.

### C-02 exclusion

`ps_history` and `runmru` both emit `command_typed` and both carry the
operator's own lab-construction typing (C-02). Both are excluded from every
figure in this document. The pre-check established they are **redundant**
rather than load-bearing for the payload — see "Why this is not signal 1"
below.

### Corpus-fit risk — stated before the numbers

The four stages are DELIVERY / EXECUTE / PERSIST / DESTROY. **These are the
scenario's own four steps** (HTTP delivery, exec, persist, log clear;
`CLAUDE.md` collection table). The payload reaching span 4 is therefore
**partly definitional**: a map built from the scenario's structure will score
that scenario's payload at full span. That half of the result carries no
information and is not evidence for the signal.

The half that is not circular is whether any **clean** entity reaches the same
span. A clean host never ran the scenario, so nothing in the map's
construction holds its entities down. That asymmetry is the whole test, and it
is why the criterion is range separation on the clean side rather than a
margin on the payload side.

### Worst-case coverage

Per the standing rule that rules are judged on worst-case coverage rather than
dataset-derived convenience, phase-span does **not** rank:

  * download -> execute with no persistence (most commodity droppers) — span 2,
    identical to `msedge.exe`
  * fileless / living-off-the-land intrusions — no DELIVERY artefact at all
  * persistence without deletion — span 3, tying any installer that bins itself

It ranks a **four-step intrusion**. It is not a general maliciousness score,
and no accept may be stated without this sentence beside it.

### Acceptance criterion

Not "does it flip the s1_v3 tie". That tie exists in the raw family count,
which is neither ranked pool; rules-side there is no tie (99 vs 86), and
composing the two is a decision explicitly deferred. The criterion is **range
separation** — the property signal 3 actually failed, where clean leaders at
10-11 families sat inside the scenario's 10-13 range:

> max phase-span over **all** entities on **all three** clean collections
> **<** payload phase-span on **both** s1_v2 and s1_v3, strictly.

### Pre-registered sensitivity variants

Run in one pass, registered before the distribution was read:

| variant | change |
|---|---|
| **V0** | as mapped |
| **V1** | `file_created`/`file_deleted` unmapped **when from `usn`**; `recyclebin`'s `file_deleted` keeps DESTROY |
| **V2** | `file_record`/`file_referenced` mapped to DELIVERY |

V1 requires `(family, event_type)` granularity because `file_deleted` is
emitted by both `usn` (`parsers/usn_journal.py:79`) and `recyclebin`
(`parsers/recycle_bin.py:154`). The mapping as written is `event_type ->
phase` and **cannot express V1**; the measurement keys the override on the
pair. This is a real limitation of the map and is recorded rather than quietly
patched.

**Verdict rule, fixed before running:** accept only if V0 passes strictly
**and** the result does not flip under V1. If it holds under V0 and dies under
V1, the signal depends on counting USN file creation as delivery — and that
dependency is the finding, not a reason to prefer V0. V2 is reported for
completeness and is not part of the accept condition.

### Predictions, recorded so they can be wrong

  * **P1.** Clean entities will reach 3 via `usn file_created` +
    `process_exec` + `recyclebin file_deleted` — an installer downloaded, run
    and binned. The `$i*.exe` recyclebin names from signal 1 are this shape.
  * **P2.** Service binaries replaced by Windows Update reach 3 via
    `usn file_created` + `process_exec` + `service_registered`.
  * **P3.** `vboxdrvinst.exe` on s1_v2 takes DELIVERY from `usn file_created`;
    under V1 it drops to span 1.

If clean max is 3 under V0 the strict test still passes at 4, but the gap is
one stage — a materially weaker result than the pre-check's 2-vs-4 suggested.

---

## Pre-check (16 named entities, not a base rate)

Ran before the full distribution, to test two premises that would have killed
the signal before it was worth measuring.

### The contrast claim in `ranking-signals-2026-09-20.md` was wrong

That document states clean_a's `powershell.exe` "reaches 10-11 through a
different and duller set ... which is *one behaviour*". Re-read at row level,
it is **not** one behaviour. It spans 2:

    scheduled_task   PERSIST    task_registered
    + ten families recording EXECUTE

The narrated family list omitted `scheduled_task`. Same on clean_b, clean_c
and s1_v2 — clean `powershell.exe` is EXECUTE+PERSIST everywhere. This is the
class of error recorded in the verification-coverage pattern at the top of
`docs/defect-log.md`: a claim carried forward from a document rather than
re-read.

It does not kill the signal, but it relocates the discrimination. The
separator is not "one behaviour versus many" — that framing is dead.

**Superseded by the full distribution below.** Every clean leader in this
16-entity pre-check reaches exactly 2, which suggested a two-stage gap. The
base rate shows clean entities reaching **3**, so the real gap is one stage.
The pre-check's named-entity selection is exactly the partial-coverage form of
the verification-coverage pattern, and it is left here rather than deleted
because it is the reason the base rate was required.

### Why this is not signal 1

The watched failure mode — C-02 leakage inflating the span the way it inflated
rarity — **did not occur**. `ps_history` and `runmru` both emit only
`command_typed` = EXECUTE, which the payload already holds from `bam`,
`prefetch`, `shimcache`, `userassist` and `timeline`. They are redundant.
Payload span is 4 raw, 4 minus `ps_history`, 4 minus both; and on s1_v3 the
payload carries **neither family** and still spans 4.

In signal 1 the leakage *created* the payload's presence in `clean_c`, so
removing it changed the answer. Here the contaminated family lands in a phase
four other families already establish. The property that matters is not "is
this family contaminated" but **"is it the sole carrier of a phase"** — a
sharper exclusion test, and one worth carrying to future signals.

### Pre-check spans

| collection | entity | families | span |
|---|---|---|---|
| clean_a | `powershell.exe` | 11 | 2 — EXECUTE, PERSIST |
| clean_a | `cursor.exe` | 10 | 1 — EXECUTE |
| clean_a | `msedge.exe` | 10 | 2 — DELIVERY, EXECUTE |
| clean_b | `msedge.exe` | 11 | 2 — DELIVERY, EXECUTE |
| clean_b | `powershell.exe` | 11 | 2 — EXECUTE, PERSIST |
| clean_b | `7z2602-x64.exe` | 7 | 2 — DELIVERY, EXECUTE |
| clean_c | `powershell.exe` | 10 | 2 — EXECUTE, PERSIST |
| clean_c | `msedge.exe` | 9 | 2 — DELIVERY, EXECUTE |
| clean_c | `npp.8.9.8.installer` | 9 | 2 — DELIVERY, EXECUTE |
| **s1_v2** | **`invoice_scan.exe`** | 13 | **4 — all four** |
| s1_v2 | `powershell.exe` | 11 | 2 — EXECUTE, PERSIST |
| s1_v2 | `vboxdrvinst.exe` | 11 | 2 — DELIVERY, EXECUTE |
| **s1_v3** | **`invoice_scan.exe`** | 10 | **4 — all four** |
| s1_v3 | `msedge.exe` | 10 | 2 — DELIVERY, EXECUTE |
| s1_v3 | `powershell.exe` | 10 | 2 — EXECUTE, PERSIST |
| s1_v3 | `vboxtray.exe` | 10 | 2 — EXECUTE, PERSIST |

`vboxtray.exe` is the C-04 case: lab-provisioned, carries a Run key, tied at
10 families under the count. It spans 2. Phase-span leaves it where the count
promoted it, without suppressing it by name — which the corpus-limitations
memory requires.

The payload's family set shrinks 13 -> 10 between scenario hosts (lost
`ntfs_logfile`, `ps_history`, `runmru`, `shimcache`, `usn`; gained `amcache`,
`defender_mplog`). **`browser` is retained**, so DELIVERY survives on the host
where the count tied. Every family lost was C-02, unmapped, or
redundant-EXECUTE; the span is unchanged.

---

## Results

Full distribution: every entity, all five collections, three variants, two
pools. Raw pool sizes 233,918 / 294,639 / 232,508 / 218,629 / 194,694 —
s1_v2's figure reproduces the 218,629 in `ranking-signals-2026-09-20.md`
exactly.

### V0 — as mapped

| collection | n | span distribution | max | payload |
|---|---|---|---|---|
| clean_a | 233,918 | 0:228307 1:5557 2:52 **3:2** | 3 | — |
| clean_b | 294,639 | 0:255178 1:32784 2:6649 **3:28** | 3 | — |
| clean_c | 232,508 | 0:202888 1:28825 2:793 **3:2** | 3 | span 0 |
| s1_v2 | 218,629 | 0:187364 1:24856 2:6368 3:36 **4:5** | 4 | **4** |
| s1_v3 | 194,694 | 0:181415 1:10323 2:2952 3:3 **4:1** | 4 | **4** |

**Clean max 3, payload 4 on both scenario hosts. Strict range separation
PASSES.**

**P1 and P2 were both right, and the pre-check's 2-vs-4 was wrong.** Clean
entities do reach 3, in exactly the two predicted shapes:

    sql2025-ssei-stddev.exe   browser/file_download -> userassist/process_exec
                              -> recyclebin/file_deleted
    ssms-setup-enu.exe        same
    vs_community__...exe      same
    vscodeusersetup-x64...    same
      -- P1: an installer downloaded, run, and binned. Ordinary user behaviour.

    usoclient.exe, spoolsv.exe, vssvc.exe, compattelrunner.exe, +20 more
      evtx.security/process_exec + scheduled_task/task_registered
      + usn/file_deleted
      -- P2: Windows servicing. A task-registered binary whose old copy the
         updater deleted.

The gap is therefore **one stage, not two**. The pre-check suggested 2 vs 4
because it read 16 named entities; the base rate says 3 vs 4.

### The finding V0 alone would have hidden

On `s1_v2` the payload is **not the only span-4 entity — it is 1 of 5**:

    invoice_scan.exe   browser/file_download | bam,prefetch,shimcache,timeline
                       | registry/persistence_autorun | recyclebin/file_deleted
    vboxguest.sys      usn/file_created | amcache | evtx.system/service_install
                       | usn/file_deleted
    vboxmouse.sys      same shape
    vboxwddm.sys       same shape
    vboxtray.exe       usn/file_created | prefetch,evtx.security
                       | registry/persistence_autorun | usn/file_deleted

The four VirtualBox Guest Additions entities (D-026) reach full span. The
strict test passed only because they sit on a **scenario** collection, where
the criterion does not look. Had Guest Additions been installed on a clean
host, clean max would be 4 and V0 would FAIL.

**This is the same false positive signal 1 promoted**, reached by a different
route, and the corpus-limitations memory forbids suppressing it by name.

### V1 — `usn` file_created/file_deleted unmapped (`recyclebin` retained)

| collection | span distribution | max | payload |
|---|---|---|---|
| clean_a | 0:232380 1:1485 2:51 **3:2** | 3 | — |
| clean_b | 0:293053 1:1532 2:48 **3:6** | 3 | — |
| clean_c | 0:231086 1:1373 2:47 **3:2** | 3 | span 0 |
| s1_v2 | 0:216978 1:1590 2:53 3:7 **4:1** | 4 | **4** |
| s1_v3 | 0:193115 1:1525 2:51 3:2 **4:1** | 4 | **4** |

**PASSES, and more cleanly than V0.** All four VirtualBox entities drop out of
span 4 (**P3 confirmed** — their DELIVERY came from `usn/file_created`). The
payload becomes the **unique span-4 entity in the entire corpus**: 1 of
218,629 and 1 of 194,694, with zero clean entities anywhere above 3.

The six clean_b survivors at span 3 are all genuine behaviour — the four
download/run/bin installers plus `microsoftedgeupdate.exe` and
`onedrivestandaloneupdater.exe` reaching DELIVERY through
`evtx.bits/bits_job_created`, which is a real download, not a journal entry.

`recyclebin`'s `file_deleted` is additionally a `recorded` observation
(Windows wrote the FILETIME when it moved the file,
`parsers/recycle_bin.py:147-159`), whereas `usn`'s `file_created` /
`file_deleted` fire for every transient file the OS touches. The span-1
population on s1_v2 falls from 24,856 under V0 to 1,590 under V1, which shows
how much of the raw pool USN alone was animating.

**That argument alone is not why V1 is adopted** — it was available before the
run and V0 was still registered as the map. The deciding reason is in the next
section.

### V2 — `file_record`/`file_referenced` mapped to DELIVERY

| collection | span distribution | max |
|---|---|---|
| clean_a | 0:57 1:232742 2:1078 **3:41** | 3 |
| clean_b | 0:2157 1:270480 2:21793 3:191 **4:18** | **4** |
| clean_c | 0:56 1:230863 2:1549 **3:40** | 3 |
| s1_v2 | 0:1479 1:206629 2:10438 3:78 4:5 | 4 |
| s1_v3 | 0:3093 1:182536 2:9005 3:59 4:1 | 4 |

**FAILS, as predicted.** 18 clean_b entities reach span 4 and the payload is
no longer distinguishable. Mapping `$MFT` presence to a phase gives nearly
every entity a DELIVERY — only 57 entities on clean_a remain at span 0,
against 228,307 under V0.

**The exclusion of presence-only event types is therefore load-bearing.** Per
the pre-registered rule, its justification must stand on its own argument —
presence is not an action; `$MFT` names a file without asserting anything
happened to it — and not on the fact that it produced the wanted answer. It
does stand on that argument, but the dependency is now measured rather than
assumed.

### Composed surface — rules-side `entity.exe_name`

Span beside score, for the 51 entities the rules layer actually ranks:

| collection | score | span | entity |
|---|---|---|---|
| clean_a | 86 high | 2 | `cursorusersetup-x64-3.15.6.exe` |
| clean_a | 86 high | 2 | `npp.8.9.6.2.installer.x64.exe` |
| clean_a | 75 high | 2 | `ssms-setup-enu.exe` |
| clean_b | 86 high | 2 | `7z2602-x64.exe` |
| clean_b | 75 high | **3** | `ssms-setup-enu.exe` |
| clean_c | 75 high | 2 | `npp.8.9.8.installer.x64.exe` |
| **s1_v2** | **99 critical** | **4** | **`invoice_scan.exe`** |
| s1_v2 | 75 high | 3 | `ssms-setup-enu.exe` |
| s1_v2 | 45 medium | 3 | `dismhost.exe` |
| **s1_v3** | **99 critical** | **4** | **`invoice_scan.exe`** |

Spans shown are **V0**. Under V1 the table is unchanged except
`dismhost.exe`, which falls from 3 to 1 (its DELIVERY and DESTROY were both
`usn`); every other entity keeps its span, and the payload keeps 4 on both
hosts because none of its carriers is `usn`.

On the pool that is actually ranked, **the payload is the only span-4 entity
on any collection, and no clean entity exceeds 3** — under V0 as well as V1,
because the VirtualBox entities are not rules-side scored.

**What this does and does not add.** Rules-side the payload already leads 99
vs 86 without phase-span, so here the signal is **confirmatory, not
corrective** — it agrees with an ordering the rules already produce. Its
additive value would appear only where the rules have not already separated,
and the corpus contains no such case. That is a statement about where the
signal would attach, not the deferred composition decision.

---

## Pre-registration defect: the criterion could not see an alphabetical tie

Adopting V1 after seeing the numbers would be post-hoc if the reason were that
it "passes more cleanly" — that clause *is* the result. There is a legitimate
ground, and it is a criterion this project fixed **before** this evaluation.

Under V0 on `s1_v2` the payload is 1 of 5 entities at span 4. Ranked by span,
it leads `vboxguest.sys` **only because `i` sorts before `v`**. That is
signal 3's failure reproduced verbatim — the reason the count was rejected was
that it "ties at 10 on s1_v3 and wins only on the alphabetical tie-break", and
`ranking-signals-2026-09-20.md` already established that a tie broken
alphabetically is not separation.

**The pre-registered criterion did not catch this**, because it compared clean
max against payload span and never asked whether the payload is unique at its
span *on the scenario host*. That is a real defect in the acceptance test as
registered, and it is the partial-coverage form of the verification-coverage
pattern applied to a criterion rather than a check: it could fail on clean-side
overlap but not on scenario-side ties.

So the two variants stand differently against the full set of criteria this
project has committed to:

| | registered test (clean max < payload) | pre-existing test (no alphabetical tie-break) |
|---|---|---|
| **V0** | PASS | **FAIL** — 1 of 5 at span 4 on s1_v2 |
| **V1** | PASS | PASS — 1 of 1 on both scenario hosts |

V1 is adopted on that basis. Had only V0 been run, the signal would have been
accepted on a result that repeats the failure its predecessor was rejected for.

## Verdict: **ACCEPT under V1, with scope**

    clean max, per collection    clean_a 3 of 233,918
                                 clean_b 3 of 294,639
                                 clean_c 3 of 232,508
    payload span 4, unique       1 of 218,629 on s1_v2
                                 1 of 194,694 on s1_v3

**This is the first ranking signal in this evaluation series to survive
measurement.** Signals 1, 2 and 3 died; the execution gate survived as
preventive-only with nothing to correct.

### Scope, which must travel with any use of it

1. **The four stages are the scenario's four steps.** The payload reaching 4
   is partly definitional. What is not definitional is that no clean entity
   reaches 4 on any of the three clean collections (max 3 on each of 233,918 /
   294,639 / 232,508) — that is the load-bearing half.

   These counts are **not** summed into a corpus population. `clean_a` and
   `clean_b` are the same host restored from snapshot minutes apart, so their
   shared entities are a snapshot identity rather than a population norm —
   the constraint signal 1's verdict recorded. Three per-collection facts, not
   one figure of 761,000.
2. **It ranks a four-step intrusion only.** Download-to-execute droppers,
   fileless intrusions and persistence-without-deletion all span ≤3 and tie
   ordinary software. Phase-span is not a maliciousness score.
3. **The margin is one stage, not two.** Clean hosts legitimately reach 3.
4. **Two hosts, five collections.** The clean_b span-3 population under V0
   is 28: **24 Windows servicing binaries and 4 user installers** downloaded,
   run and binned. A differently-patched host, or a user who installs
   different software, would produce a different population.
5. **Under V0, four Guest Additions entities tie the payload at span 4 on
   s1_v2** (C-04 lab provisioning). V0 still passed the registered test,
   because they sit on a scenario collection where that test does not look —
   see the pre-registration defect above. Had Guest Additions been installed
   on a clean host, clean max would be 4 and V0 would fail outright. The
   sensitivity is real and one mapping decision away.
6. **On the ranked pool it is confirmatory.** It does not currently correct
   any ordering the rules get wrong.

### Not implemented

Per the standing instruction, nothing here changes the pipeline. Composition
with the execution gate remains deferred. `rules/**` is Person A's directory.

## Correction to `ranking-signals-2026-09-20.md`

That document's signal-3 row-level read states a Windows binary's 10-11
families are "*one behaviour* (a program ran)". Measured at row level, clean
`powershell.exe` spans 2 — `scheduled_task/task_registered` is PERSIST — on
all four collections where it appears. The narrated family list
(`amcache, bam, evtx.security, mft, prefetch, shimcache, srum, timeline,
userassist, usn`) also does not match the measured set, which contains
`defender_mplog` and `scheduled_task` and no `usn`.

The signal-3 verdict is unaffected: the count still ties at 10 on s1_v3. But
the justification as written is wrong, and it is the same class of error the
verification-coverage pattern records — a claim carried forward from a
document rather than re-read against the evidence.
