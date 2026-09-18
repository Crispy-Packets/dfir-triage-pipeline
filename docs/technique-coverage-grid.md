# Technique coverage grid

**What this pipeline can be asked to detect, what it cannot, and why — per
ATT&CK technique.**

First pass 2026-09-17. The `state` column is a draft for every row not marked
`covered`; it is refilled from measurement as rules land. The other three
columns are inputs and do not move.

---

## 0. What this document is for

`docs/artifact-attestation-matrix.md` answers "what can each ARTEFACT attest
to." This answers the question an examiner actually asks: **"technique X
happened — would you have seen it, and if not, why not?"**

The two are different axes over the same evidence and neither substitutes for
the other. A family can be fully parsed and still leave a technique invisible,
because the observable for that technique was never written to disk.

**The honest answer to "why not" is worth more than another rule.** A tool
claiming 220 rules that can field 40 is weaker than one claiming 40 and
proving why 180 are correctly out of scope. Volume is not the deliverable;
a defensible boundary is.

---

## 1. The four columns

**Technique** — ATT&CK ID and name.

**Evidence class** — where the observable for this technique lives. This is a
property of Windows and of the collection method, not of this project:

| Class | Meaning |
|---|---|
| `disk-resident` | The observable survives to a disk collection. KAPE collects it. |
| `requires-telemetry` | The observable exists only in live/agent telemetry — Sysmon, EDR hooks, network capture. A disk image never held it. |
| `requires-domain` | The observable is written on a domain controller, not on this endpoint. |
| `requires-memory` | The observable exists only in volatile memory. |
| `disk-resident-but-overwritten` | Written to disk, into a **fixed-size circular buffer** that the host itself overwrites. Present or absent as a function of how busy the machine was, not of what happened. |

**`disk-resident-but-overwritten` is a property of Windows, not of this
corpus,** and it applies to `$LogFile` and to the USN journal. Measured
2026-09-18: `ntfs_logfile` yields 169,570 rows on `clean_b` against **6,708**
on `s1_v2` — a 20x drop in the direction opposite to every other family,
because scenario activity overwrote the buffer faster. The USN journal's head
is likewise sparse, its oldest records zeroed.

Two consequences hold on every host, permanently:

* **Absence is never evidence of absence.** "No record of X in `$LogFile`"
  says the buffer wrapped, not that X did not occur — and the window covered
  cannot be stated in hours without knowing the write rate.
* **The turnover is not itself detectable.** A busy machine and an adversary
  generating noise produce the same drop. This corpus contains only the benign
  case.

A rule may therefore use these families to say *this name appeared*, never
*this name did not appear* and never *this is how far back we can see*.

**Writability** — what it would take to field a rule. Three classes, not two,
so that "cannot today" and "cannot ever" stay distinguishable:

| Class | Meaning | Action |
|---|---|---|
| `writable-now` | Artefact disk-resident, parser exists, join key legal | write the rule |
| `writable-if-collection-expands` | Would become writable with a collection change (install Sysmon, collect from a DC, add PCAP) | document the collection change |
| `structurally-out-of-scope` | Evidence cannot survive a post-mortem disk collection at all | scope statement |

**State** — where it stands today:

| State | Meaning |
|---|---|
| `covered` | Rule exists, measured, discriminates |
| `observable-unwritten` | Parsed, joinable, no rule that discriminates yet — the backlog |
| `measured-no-discriminator` | Measured; clean and scenario indistinguishable, and the REASON is stated. Deliberately not written |
| `not-observable` | Per evidence class, with the specific blocker named |
| `blocked` | Parsed but something specific prevents a rule; the blocker is named |

**Five states were briefly six.** A `covered-weak` bucket was drafted for
T1136.001 — a rule that exists and fires, but more often on clean hosts than
on scenario ones. It is not kept. A state per shade of partial success is how
a taxonomy dies: `covered-probably` follows within a week and the labels stop
carrying information. A rule whose anchor does not discriminate is
`observable-unwritten` with the anchor named as the problem, which says
**re-anchor it** rather than merely recording disappointment. Where a
qualifier is genuinely needed it belongs in the note, not in a new bucket.

---

## 2. The grid

### 2.1 Covered — rule exists and measured

| Technique | Evidence class | Writability | State | Rules / measurement |
|---|---|---|---|---|
| **T1204.002** User Execution — Malicious File | disk-resident | writable-now | `covered` | R-ATOMIC-0001, R-CORR-0001. **See §3.1** — R-ATOMIC-0001 selects only `evtx.security`, which carries 0 path-bearing rows on `s1_v3` |
| **T1547.001** Registry Run Keys | disk-resident | writable-now | `covered` | R-ATOMIC-0006 (8/8/4/1/2), R-CORR-0003 (0/0/1/0/1 after D-056). The strongest discriminator in the set |
| **T1070.001** Clear Windows Event Logs | disk-resident | writable-now | `covered` | R-ATOMIC-0002, 0/0/1/0/1. Validated end-to-end through `run.json` + manifest |
| **T1059.001** PowerShell | disk-resident | writable-now | `covered` | R-ATOMIC-0003, 3/3/8/0/0. Fires on the delivery step s1_v2's cleared 4688 destroyed |
| **T1136.001** Create Account — Local | disk-resident | writable-now | `observable-unwritten` — **anchored wrong**, see §3.2 | R-ATOMIC-0009 and R-CORR-0005 exist and fire, but 4/5/0/2/0 and 1/1/0/1/0: on all three CLEAN hosts and neither scenario. The rules match account creation; account creation is a routine lab-setup event here and not part of either scenario. The fix is re-anchoring on a discriminating property, not reclassifying the technique |
| **T1543.003** Windows Service | disk-resident | writable-now | `covered` (untested) | R-ATOMIC-0004, R-CORR-0004 — 0 on all five. No service persistence in either scenario; exercised via `tools/rule_harness.py` |
| **T1546.003** WMI Event Subscription | disk-resident | writable-now | `covered` (untested) | R-ATOMIC-0007 — 0 on all five. `CommandLineEventConsumer` is execution-capable by definition; the zero is structural |
| **T1021.001** RDP | disk-resident | writable-now | `covered` (untested) | R-ATOMIC-0005, R-ATOMIC-0008 — 0 on all five. No RDP in either lab |
| **T1110** Brute Force | disk-resident | writable-now | `covered` | R-CORR-0002, 2/2/0/0/0 |
| **T1070.004** Indicator Removal — File Deletion | disk-resident | writable-now | `covered` **(new 2026-09-18)** | **R-CORR-0006, 0/0/1/0/1** — an autorun-registered executable deleted to the Recycle Bin. Zero on every clean host, `invoice_scan.exe` on both scenario hosts. **Two predicates were measured and rejected first**: "executed then deleted" (4 of 5 benign `clean_b` deletions match it — installing software looks exactly like this) and "deleted file ≤ 512 KB" (10 payload vs 2 benign, rejected as corpus-fitting: it separates a copied `notepad.exe` from installers, not malware from software). The SID and the 9x repetition were also rejected — see §3.4. Caveats as R-CORR-0003: two findings, one operator, no held-out collection, and `recyclebin` is empty on two of three clean hosts so only `clean_b` is a real negative |

### 2.2 Observable and unwritten — the real backlog

Every row here is parsed, has a legal join key, and has a family that attests
to it. These are the only rows where "write a rule" is the correct next action.

| Technique | Evidence class | Writability | State | Family and note |
|---|---|---|---|---|
| ~~**T1070.004** File Deletion~~ | — | — | **moved to §2.1 — `covered` by R-CORR-0006, 2026-09-18** | See the row in §2.1 and `docs/evidence/recyclebin-predicate-2026-09-18.md` |
| ~~**T1053.005** Scheduled Task~~ | disk-resident | writable-now | **`measured-no-discriminator`** (2026-09-18) | The user-writable shape predicate was measured and finds **exactly the same 5 tasks on all five collections**: four Windows Defender `MpCmdRun.exe` entries under `C:\ProgramData\Microsoft\Windows Defender\platform\` and one `OneDriveLauncher.exe` under `AppData\Local`. Microsoft ships both. 5/5/5/5/5 — the predicate identifies vendors that install outside Program Files, and no other discriminator is available: `<Date>` is absent from most tasks and `<Author>` is self-declared |
| ~~**T1027** Obfuscated Files~~ | disk-resident | writable-now | **`measured-no-discriminator`** (2026-09-18) | Re-measured across 4,393 script blocks. `-EncodedCommand` with a substantial payload: **0 on all five collections** — R-ATOMIC-0003 already carries that branch and it is correctly a zero-base-rate pattern. `FromBase64String`: **123 / 123 / 67 / 0 / 0** — nearly twice as high on the CLEAN hosts, which R-ATOMIC-0003's `note_on_excluded_patterns` already recorded and rejected. Compression-stream markers: 0 everywhere. **No obfuscation indicator in this corpus points the right way**; the technique is covered as far as it can be by R-ATOMIC-0003's existing encoded branch |
| **T1074.001** Local Data Staging | disk-resident | writable-now | `observable-unwritten` | `usn`/`mft` — archive creation in a temp/download directory |
| ~~**T1052.001** Exfiltration over USB~~ | disk-resident | writable-now | **`not-observable` in this corpus (D-064)** — moved out of the backlog 2026-09-18 on inspection | The capability is real: `lnk` and `jumplist` record a removable volume's serial and label, surviving the device's removal, and CD-013's point stands. **But this corpus's only removable-media activity is the operator's own.** `drive_type` measures 9 removable rows on `s1_v2` and 0 on the other four — apparently the best single-field base rate in the project — and the rows are `E:\collection_clean_a`, `E:\collection_clean_b`, `E:\collection_s1`, `E:\handoff` and personal media from 2020/2024. **It is the USB stick the collections were carried off on**, browsed on 2026-08-20, before the `s1` directory existed. A rule here detects the evidence-handling procedure. `s1_v3` has zero removable rows |
| **T1071.001** Web C2 / download | disk-resident | writable-now | **`blocked` — D-065** | Both candidate families fail today for different reasons. **`evtx.bits` emits `details == {}` on every row in every collection** while its raw records carry `url`, the destination `name`, `bytesTotal`, `jobOwner` and `processPath` — a more complete download record than the `browser` family produces, entirely discarded (D-065, the third instance after D-055 and D-057). **`webcache` `background_transfer`'s `url` field holds a cache-entry GUID, not a URL**, and every row's `cache_directory` sits under a Store or ContentDeliveryManager app package — OS app-content fetches, not user downloads. `blocked` rather than `not-observable`: the evidence is rich and a parser change makes it writable |
| ~~**T1078.003** Valid Accounts — Local~~ | disk-resident | writable-now | **`measured-no-discriminator`** (2026-09-18) | The corrected predicate (`rid >= 1000`, `well_known` absent, and `password_not_required` or `logon_count: 0`) matches **zero accounts on all five collections**. The full population is 7 accounts per host on host 1 and 5 on host 2, so this is the whole set and not a sample: every RID ≥ 1000 account has non-zero logons, and every `password_not_required` account is a disabled well-known built-in (Guest, DefaultAccount). A staged account is exactly what the shape would catch and this corpus contains none — `testuser` was created on `clean_b` and is **absent from SAM entirely** (§1). Zero is the correct result, not a miss |

### 2.3 Blocked — parsed, but something specific prevents a rule

| Technique | Evidence class | Writability | State | Blocker |
|---|---|---|---|---|
| **T1134** Token / privilege abuse | disk-resident | writable-now | `blocked` | `lsa_policy` emits raw SID strings; `sam`/4720 emit account names; **no SID→name resolver exists** anywhere in the pipeline. Any chain joining them matches zero rows forever (D-041 shape). Resolver is local-accounts-only even when built — `lsa_policy`'s rows are mostly well-known GROUP SIDs with no `sam` row to resolve against |
| **T1059.001** PowerShell *when script-block logging is off* | disk-resident | writable-now | `blocked` | **D-055** — `evtx.ps_classic` was taken precisely because EID 600 carries `HostApplication`, and the parser extracts no `details` for 400/403/600. 0 of 203 rows carry any field. Needs a parser change plus a CD-012 details-key declaration |
| **T1547.004** Winlogon Helper DLL — *and any claim resting on 811/812* | disk-resident | writable-now | `blocked` | **D-057** — `evtx.winlogon` emits 1,913 rows with `details == {}` across four collections, and the raw records DO carry `SubscriberName` (`GPClient`) and `Event`. `_details_for()` has no branch for 811/812 and drops both. The same raw read found **EIDs 1 and 2 present and absent from the curated map**, discarded unseen — the generic `evtx.x.*` fallback does not catch an unmapped EID inside a curated channel. Whether the channel discriminates is **unknown and unmeasurable** until the parser emits its fields |

### 2.4 Measured, no discriminator — deliberately not written

These were measured before being written. Recording them here is coverage
work: it converts "we didn't get to it" into "we looked, and a rule would be
noise."

**A number is a result, not a reason.** Each row states WHY the observable
fails to discriminate — the mechanism that makes the figures come out as they
do — with the measurement as support. A reader who does not already trust the
measurement can still check the reasoning.

| Technique | Why it cannot discriminate | Measurement supporting it |
|---|---|---|
| **T1562.004** Disable/Modify Firewall | **Windows rewrites firewall rules during ordinary policy refresh**, on a schedule, by `S-1-5-19`. The event therefore fires as a function of uptime and profile changes rather than of anything an actor did, so its rate is roughly independent of whether the host was attacked | `firewall_rules_deleted` (EID 2033) = 4 / 4 / 12 / 10 / 17 across clean_a/clean_b/s1_v2/clean_c/s1_v3 — the two scenario hosts (12, 17) sit inside the range of the three clean ones (4, 4, 10). EIDs 2004-2006 are worse; CD-007 records 200+/collection on clean hosts |
| **T1070.006** Timestomp | **A file written from a Windows install image keeps the image's `$SI` and receives a fresh `$FN` when it lands on the volume.** That describes every OS file on every host, so the `$SI`-earlier-than-`$FN` indicator is a property of how Windows is installed rather than of tampering | 94,262 of 351,088 records (27%) on s1_v3 and 99,955 of 287,983 (35%) on clean_c — led by `$Recycle.Bin`, `PerfLogs` and `Program Files`. Refining by unique `$SI` did not help: 96,343 of 99,955 had a non-shared value. **D-051**; both timestamps are emitted, no verdict derived |
| **T1562.001** Disable/Modify Tools | **Defender's standing internal exclusions are written to the log at service start, identically on every boot of a given build.** The rows therefore describe the host's Defender configuration, not an action taken during the incident — the same three PIDs recur across three separate collections of host 1 | `scan_skipped` = 27 / 31 / 49 / 0 / 0, with PIDs 6652, 7368, 1992 identical across clean_a, clean_b and s1_v2, and **zero on both host-2 collections**. A count-based rule would score host identity. **The adversarial shape — an exclusion naming a user-profile path — has NOT been surveyed**: `details.path` is `None` on every sampled row, so this row is "not yet looked for", not "looked for and absent" |
| — (no technique; evidence-integrity signal) | **A registry hive's transaction log is ahead of its hive whenever the machine was imaged while keys were in flight**, which is the normal state of a running Windows system at collection time rather than an anomaly | `registry_txlog` log-ahead-of-hive: 21 of 27 logs ahead on a CLEAN host, up to 933 KB pending. No threshold separates that from tampering on a five-collection corpus |

### 2.5 Not observable here — the scope statement

These are the rows that make the boundary defensible. **None is a gap in this
pipeline**; each is a property of post-mortem disk collection.

Each row names the **specific** missing observable and what would have to
change. "Not observable" is a label; "requires Sysmon EID 10, not installed on
either host, zero records present" is a defence.

| Technique | Evidence class | Writability | Named blocker, and what would lift it |
|---|---|---|---|
| **T1055** Process Injection | requires-memory | structurally-out-of-scope | **The observable is a handle grant and a remote thread in RAM.** Sysmon EID 8 (CreateRemoteThread) / EID 10 (ProcessAccess) witness it live; nothing writes it to disk. A memory capture would hold it — that is a different acquisition, not a KAPE target. No collection change to KAPE lifts this |
| **T1003.001** LSASS Memory | requires-telemetry | writable-if-collection-expands | **Requires Sysmon EID 10 with `TargetImage` = `lsass.exe`. Sysmon is not installed on either host: zero Sysmon channels in all five collections.** Lifted by installing Sysmon before the next collection. NOTE: the *product* of a dump — a `.dmp` file — IS disk-resident and visible to `usn`/`mft`; that half is `observable-unwritten`, not out of scope |
| **T1071** C2 beaconing, DNS tunnelling, TLS-to-odd-port | requires-telemetry | structurally-out-of-scope | **Requires packet capture, DNS server logs, or flow records. KAPE collects none of the three** — it is a filesystem collector. `webcache`/`browser` carry what the browser recorded about its own requests, never what left the NIC. Lifted only by adding network collection, which is a different instrument |
| **T1558.003** Kerberoasting | requires-domain | writable-if-collection-expands | **Requires EID 4769 (TGS request) with RC4 encryption type, written in the DC's Security log.** Both hosts are standalone VMs with no domain membership. Lifted by collecting from a DC in a domain-joined estate |
| **T1558.001** Golden Ticket | requires-domain | writable-if-collection-expands | **Requires 4768/4769 TGT anomalies (lifetime, encryption downgrade) from the DC.** Same blocker and same lift as above |
| **T1003.006** DCSync | requires-domain | writable-if-collection-expands | **Requires EID 4662 with the DS-Replication-Get-Changes GUID, logged on the DC.** A workstation never sees the replication request |
| **T1003.003** NTDS.dit | requires-domain | writable-if-collection-expands | **`NTDS.dit` exists only on a domain controller.** Neither host has the file to protect or to steal |
| **T1021.002** SMB / Admin Shares (remote side) | requires-telemetry | writable-if-collection-expands | **The inbound authentication lands in the TARGET host's Security log, and the network session itself is never written to disk on either end.** The local artefacts an attacker leaves — service install, prefetch of the tool — are disk-resident and covered under T1543.003. Lifted by collecting from both hosts in a lateral pair |
| **T1219** Remote Access Software | requires-telemetry | writable-if-collection-expands | **Execution of the tool IS disk-resident** (`prefetch`, `amcache`, `services`) **and would be caught by the execution rules; the remote session it carried leaves nothing on disk.** Lifted by network collection, or by an application log the tool itself writes |

### 2.6 Anti-forensic detection — where worst-case coverage actually lives

Called out separately because these are the techniques whose evidence an
attacker most wants gone, and **all of them are disk-resident**. This is the
quadrant that deserves the next rules.

| Technique | State | Note |
|---|---|---|
| **T1070.001** Clear Event Logs | `covered` | R-ATOMIC-0002. Demonstrated on s1_v2/s1_v3 |
| **T1070.004** File Deletion | `observable-unwritten` | `usn` + `recyclebin` — highest-value unwritten rule in the grid |
| **T1070.006** Timestomp | `measured-no-discriminator` | D-051. Raw timestamps emitted for manual comparison |
| **T1490** Inhibit System Recovery (VSS) | `not-observable` (partial) | `vssadmin` execution would appear in `prefetch`/`amcache`; the shadow-copy deletion itself is not collected |
| **Prefetch deletion** | `measured-no-discriminator` on this corpus | `usn` does record `.pf` deletions — **measured 0 / 0 / 125 / 0 / 0**. Non-zero on `s1_v2` ONLY, and zero on `s1_v3`, the other scenario host. The s1_v2 names are `SVCHOST`, `MSMPENG`, `NISSRV`, `MAKECAB` — Windows aging its own cache, not an actor clearing tracks. A rule here would fire on one collection for the wrong reason. The capability is real and the corpus cannot calibrate it |
| **Absence-as-finding** | `observable-unwritten` | Not an ATT&CK technique. "Prefetch is empty on a host that demonstrably ran software", "the event log's earliest record post-dates the user's last known activity". The pipeline has the data and makes no such claim today. **`ntfs_logfile` turnover is a measured instance**: 169,570 rows on `clean_b` against 6,708 on `s1_v2` — a 20x drop, because `$LogFile` is a fixed-size circular buffer and heavier activity overwrites it. That bounds how far back the family reaches on a given host. It is not a rule: a busy machine and an adversarial one produce the same drop |

**`ps_history` is excluded from rule authorship on leakage grounds
(2026-09-18).** It normalises to 3.4x/2.95x on the scenario hosts — the
strongest ratio of any family after `recyclebin` — and the extra commands are
**the operator building the scenario** (`Copy-Item ... notepad.exe
-Destination Z:\invoice_scan.exe`, `python -m http.server 8000`). `clean_c`, a
CLEAN collection, names the payload in its own shell history. A rule anchored
here would learn lab construction. The family stays parsed and stays in the
timeline; it may not anchor a rule or supply a model feature. Recorded in
`docs/feature-decisions.md` beside `hour_of_day`, and measured in
`docs/evidence/family-signal-survey-2026-09-18.md`.

---

## 3. What the grid changes about the current rule set

### 3.1 R-ATOMIC-0001 is covering a technique on a channel that was destroyed

Measured on `s1_v3`, path-bearing rows per family against the rule's own six
regexes:

    evtx.security     0 rows with a path    0 matching   <- the only family it selects
    bam              47                    12
    lnk              37                    17
    amcache         522                    10
    shimcache       218                     3

T1204.002 is marked `covered`, and on the scenario host the rule matches
nothing, because the attacker cleared the log it reads. Four other parsed
families carry 42 rows its regexes match. **This is the single highest-value
change the grid identifies** and it is a `select:` widening, not a new rule —
see `artifact-attestation-matrix.md` §6.4.

`prefetch`, `userassist` and `timeline` must stay excluded: their `path` is a
bare name or an AppID, so every path regex fails silently against them.

### 3.2 Worked example: the anchor, not the predicate, decided T1070.004

The obvious rule for File Deletion is **execution followed by deletion of the
same executable name** — the payload's own behaviour on both scenario hosts,
and the strongest-sounding correlation the parser work made available.
Measured before writing, `.exe` deletions recorded by `usn`:

    clean_a    0
    clean_b  293      <- a CLEAN host, the highest count in the corpus
    s1_v2    169
    clean_c    0
    s1_v3     16      <- the scenario host with the payload on it

The rule would have fired eighteen times harder on `clean_b` than on `s1_v3`.
Not a threshold problem: **"something was deleted after something ran" is the
modal benign behaviour of Windows.** Installers delete their own temp files,
OneDrive removes superseded binaries, servicing cleans up after itself. The
anchor selects the population instead of narrowing it.

Anchoring on `recyclebin` instead inverts the result:

    clean_a  0    clean_b  5    s1_v2  14    clean_c  0    s1_v3  1

and the single `s1_v3` row is
`C:\Users\vboxuser\Desktop\invoice_scan.exe` — the payload, carrying the
original full path that the journal cannot supply.

**This is the `onedrive.exe` tie (D-056) one layer down, and the difference in
layer is what makes it more expensive.** There, two entities matched the same
rules and the fix was a predicate added to an existing rule. Here the wrong
family was chosen to anchor on, and no predicate rescues it — a rule anchored
on `usn` deletions is measuring Windows housekeeping whatever is bolted onto
it. A bad predicate produces a noisy rule that measurement exposes quickly; a
bad anchor produces a rule that looks correct in isolation and fails only
against a clean baseline. **Choose the anchor by measurement, not by which
family sounds most like the technique.**

### 3.3 T1136.001 fires more on clean hosts than on the scenario

R-ATOMIC-0009: 4/5/0/2/0. R-CORR-0005: 1/1/0/1/0. Both fire **zero** on both
scenario collections and non-zero on three of three clean ones.

The rules are not wrong: they match account creation, and account creation
genuinely happened during lab setup and not during either scenario. **The
collection constraint this establishes is C-04 in
`docs/scenario-design-constraints.md`** — provision lab accounts before the
baseline snapshot, so setup appears in clean and scenario images alike and
cancels out. But
"T1136.001 covered" must not be read as "an account creation in this corpus
would be caught and distinguished", because on this evidence the rules
identify the lab's own provisioning.

**The state is `observable-unwritten`, not a new bucket, and the note is the
prescription: re-anchor.** A discriminating rule for this technique asks not
*was an account created* but *does an account exist with a suspicious shape* —
a standalone `sam` shape predicate needing no join, listed as T1078.003 in
§2.2. It is the same re-anchoring T1070.004 needed in §3.2: creating a
`covered-weak` state would have recorded the disappointment, whereas naming
the anchor records the fix.

**The shape has to be read off the real `details` before it is written, and
doing so corrected the obvious draft.** Measured on `clean_b`:

    rid 500  Administrator       logon_count 0   disabled,...,password_never_expires   well_known
    rid 501  Guest               logon_count 0   disabled,...,password_not_required    well_known
    rid 503  DefaultAccount      logon_count 0   disabled,...,password_not_required    well_known
    rid 504  WDAGUtilityAccount  logon_count 0   disabled,normal_account               well_known
    rid 1000 Youssef             logon_count 13  normal_account
    rid 1002 janed               logon_count 1   normal_account
    rid 1003 admin_local         logon_count 5   normal_account

Three corrections to the draft predicate:

* `password_not_required` is **a token inside `details.account_flags`**, not a
  key of its own. The condition is `account_flags contains
  password_not_required`.
* `password_not_required` alone matches **Guest and DefaultAccount on every
  host** — built-in accounts that carry the flag by default. The `rid >= 1000`
  clause is what excludes them, and it does so only because the well-known
  accounts happen to sit at 500-504. `details.well_known` is the explicit
  field for that and should be required absent rather than relied on
  numerically.
* `logon_count: 0` is the DEFAULT state for all four built-ins, so on its own
  it is not suspicious — it discriminates only in combination with
  `rid >= 1000`, where every real account in this corpus has a non-zero count.

Note also that `testuser`, created on `clean_b` on 2026-08-24, is **absent
from SAM entirely** (§1 records this). A rule on account shape cannot see an
account the hive no longer holds, which is the standing limit of the family
rather than of the rule.

### 3.4 The discriminator was not in the family that carried the signal

R-CORR-0006 is the first rule of the coverage phase and the clearest
illustration of §3.2's lesson, because the family survey pointed at the right
family and the obvious rule over it still failed.

`recyclebin` carried the strongest volume signal of any uncovered family
(6.54x on host 1). But the rows show **4 of the 5 benign `clean_b` deletions
were also executed** — download an installer, run it, delete it. Execution
adds nothing to a deletion anchor because that is how software installs.

Three further predicates measured well and were rejected:

| Predicate | Result | Why rejected |
|---|---|---|
| `deleted_size <= 512 KB` | 10 payload / 2 benign | **Corpus-fitting.** Separates a copied `notepad.exe` (4,608-360,448 B) from installers (1.6 MB-495 MB). A real payload can be 50 MB. A number is easier to slip past D-040 than a name because it looks principled |
| deleting SID | perfect on host 1 | `janed` is the scenario user. Another estate's attacker may share an account with a benign user |
| repetition count | 9 deletions on `s1_v2` | **Scenario construction** — the operator retrying at three sizes over four days. `s1_v3` holds exactly one deletion, so the predicate fires on one host and misses the other |

**What survived came from the technique, not the corpus:** an installer does
not register itself to run at logon. Persistence pointing at a deleted file is
anti-forensic by construction. The control proves the mechanism — `clean_b`
has 5 autoruns and 4 deleted executables and **zero** joins between them.

The pattern across §3.2, §3.3 and this section: **the family that carries the
signal and the property that discriminates are rarely the same thing.**

### 3.5 The backlog emptied, and only one row became a rule

§2.2 began as seven writable-now unwritten rows. **All seven have now been
measured, and the backlog is empty.** One became a rule; two were blocked on
named parser defects; four measured as non-discriminating.

| row | outcome |
|---|---|
| **T1070.004** File Deletion | **→ R-CORR-0006**, 0/0/1/0/1 |
| T1052.001 USB exfiltration | → `not-observable` (D-064) |
| T1071.001 Web C2 / download | → `blocked` (D-065) |
| T1053.005 Scheduled Task | → `measured-no-discriminator` |
| T1027 Obfuscated Files | → `measured-no-discriminator` |
| T1078.003 Valid Accounts | → `measured-no-discriminator` |
| T1136.001 Create Account | → `observable-unwritten`, anchored wrong (§3.3) |

**One rule from seven candidates is the honest yield**, and the six negatives
are the output of the phase rather than its failure. Each carries a figure:

* **T1053.005** — the user-writable predicate finds the *same five tasks on
  every collection*: four Defender `MpCmdRun.exe` under `ProgramData`, one
  `OneDriveLauncher.exe` under `AppData`. 5/5/5/5/5. The shape identifies
  vendors who install outside Program Files.
* **T1027** — `-EncodedCommand` is 0 everywhere; `FromBase64String` is
  123/123/67/0/0, **higher on clean hosts**, already rejected once in
  R-ATOMIC-0003's notes.
* **T1078.003** — zero matches in a population of 7 accounts per host. Every
  RID ≥ 1000 account has non-zero logons; every `password_not_required`
  account is a disabled built-in.
* **T1052.001** — the best base rate in the project, 9 vs 0, and the rows are
  the USB stick the evidence was carried off on (D-064).
* **T1071.001** — the evidence is richer than the `browser` family's and the
  parser discards all of it (D-065).

**Three of the seven had clean numbers and the wrong meaning** — T1052.001,
T1027's base64 branch, and the "executed then deleted" form of T1070.004. That
is the finding this phase produces: *a base rate that looks excellent is a
reason to read the rows, not a reason to write the rule.* D-051 and the
firewall EID established it; these three confirm it on a larger sample.

**What is left is not more rules but two parser defects** (D-065 for BITS,
D-055 for `ps_classic` 400/403/600), one re-anchoring (T1136.001), and the
D-058 implementation. None of those is a rule-authoring task.

---

## 4. What this document does NOT claim

- **Not ATT&CK coverage.** No claim to a percentage of the matrix, and no
  claim that a `covered` technique would be caught in any estate other than
  this one.
- **Not a substitute for measurement.** A row marked `observable-unwritten`
  asserts that the evidence and the join key exist, not that a rule written
  against them would discriminate. `firewall` and `timestomp` both looked
  writable until they were measured.
- **Not fixed.** `requires-telemetry` rows become writable if Sysmon is
  installed for a future collection; `requires-domain` rows become writable
  against a domain-joined estate. The class says what would have to change,
  which is the actionable form of "no."
