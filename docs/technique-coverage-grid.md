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
| `covered` | **Class 1, corpus-validated.** Rule exists, fires on the scenario and not on clean, and carries measured `expected:` figures |
| `covered-known-behavior` | **Class 2.** Rule exists and expresses a real intrusion behaviour with defensible logic, but this corpus does not exercise it, so there is no positive instance to validate against. Ships a documented **false-positive profile** in place of a detection rate; `expected:` carries measured figures where they exist and the literal `unmeasured` where they do not (added 2026-09-20) |
| `observable-unwritten` | Parsed, joinable, no rule that discriminates yet — the backlog. **Emptied 2026-09-20** |
| `measured, not exercised` | Measured, and this scenario simply did not perform the behaviour. A fact about the corpus, **not a rejection of the family** — a Class 2 rule may still be written (§3.9) |
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
| ~~**T1136.001** Create Account — Local~~ | disk-resident | writable-now | **`not-observable` in this corpus (C-05)** — closed 2026-09-20, rules RETAINED | R-ATOMIC-0009 and R-CORR-0005 fire **4 / 5 / 2 / 0 / 0** and **1 / 1 / 1 / 0 / 0** in collection order (clean_a, clean_b, clean_c, s1_v2, s1_v3) — re-measured 2026-09-20. **Neither scenario created an account**: `janed` was provisioned before the baseline snapshot (C-04), and step 4's `wevtutil cl security` destroyed the 4720 channel that would have recorded one if it had (`account_created` 4/5/2 clean → **0/0** scenario). The rules are the correct shape for the technique and have no positive class to find here — C-05 for the third time. **§3.3's prescription to re-anchor on a SAM shape predicate is withdrawn**: that predicate is T1078.003, measured 0/0/0/0/0, correctly so — there is no staged account. See §3.3 |
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
| ~~**T1027** Obfuscated Files~~ | disk-resident | writable-now | **`measured-no-discriminator`** (2026-09-18) | Re-measured across 4,393 script blocks. `-EncodedCommand` with a substantial payload: **0 on all five collections** — R-ATOMIC-0003 already carries that branch and it is correctly a zero-base-rate pattern. `FromBase64String`: **123 / 123 / 0 / 67 / 0** in collection order (clean_a, clean_b, clean_c, s1_v2, s1_v3) — nearly twice as high on the CLEAN host-1 collections as on the scenario, which R-ATOMIC-0003's `note_on_excluded_patterns` already recorded and rejected. Compression-stream markers: 0 everywhere. **No obfuscation indicator in this corpus points the right way**; the technique is covered as far as it can be by R-ATOMIC-0003's existing encoded branch. **Re-verified 2026-09-20 against raw EVTX** — see the reading-method note below |
| **T1074.001** Local Data Staging | disk-resident | writable-now | `observable-unwritten` | `usn`/`mft` — archive creation in a temp/download directory |
| ~~**T1052.001** Exfiltration over USB~~ | disk-resident | writable-now | **`covered-known-behavior` (Class 2) 2026-09-20 — R-ATOMIC-0010**; was `not-observable` (D-064) | The capability is real: `lnk` and `jumplist` record a removable volume's serial and label, surviving the device's removal, and CD-013's point stands. **But this corpus's only removable-media activity is the operator's own.** `drive_type` measures 9 removable rows on `s1_v2` and 0 on the other four — apparently the best single-field base rate in the project — and the rows are `E:\collection_clean_a`, `E:\collection_clean_b`, `E:\collection_s1`, `E:\handoff` and personal media from 2020/2024. **It is the USB stick the collections were carried off on**, browsed on 2026-08-20, before the `s1` directory existed. A rule here detects the evidence-handling procedure. `s1_v3` has zero removable rows |
| ~~**T1071.001** Web C2 / download~~ | disk-resident | writable-now | **`measured-no-discriminator`** (2026-09-19) — was `blocked (D-065)`; the parser defect is fixed and the technique is still unwritable | **The parser fix landed and did not unblock it.** `evtx.bits` now carries `url`, size, `hr`, `jobOwner` and a joinable `entity.exe_name` from EID 3's `processPath` (D-065 resolved; D-066 corrected EID 4/5). **But every BITS transfer in the corpus is vendor update traffic** — host counts sum to the full transfer count on all five collections: `msedge.b.tlu.dl.delivery.mp.microsoft.com`, `g.live.com`, `oneclient.sfx.ms`, `fs.microsoft.com`, `edgedl.me.gvt1.com`. Both scenarios delivered over `WebClient.DownloadFile`, not BITS, so **there is no positive class**. A rule here would encode two vendors' update endpoints. `webcache` `background_transfer` fails separately: its `url` holds a cache-entry GUID and every `cache_directory` is a Store/ContentDeliveryManager package |
| ~~**T1078.003** Valid Accounts — Local~~ | disk-resident | writable-now | **`measured-no-discriminator`** (2026-09-18) | The corrected predicate (`rid >= 1000`, `well_known` absent, and `password_not_required` or `logon_count: 0`) matches **zero accounts on all five collections**. The full population is 7 accounts per host on host 1 and 5 on host 2, so this is the whole set and not a sample: every RID ≥ 1000 account has non-zero logons, and every `password_not_required` account is a disabled well-known built-in (Guest, DefaultAccount). A staged account is exactly what the shape would catch and this corpus contains none — `testuser` was created on `clean_b` and is **absent from SAM entirely** (§1). Zero is the correct result, not a miss |

### 2.3 Blocked — parsed, but something specific prevents a rule

| Technique | Evidence class | Writability | State | Blocker |
|---|---|---|---|---|
| **T1134** Token / privilege abuse | disk-resident | writable-now | `blocked` | `lsa_policy` emits raw SID strings; `sam`/4720 emit account names; **no SID→name resolver exists** anywhere in the pipeline. Any chain joining them matches zero rows forever (D-041 shape). Resolver is local-accounts-only even when built — `lsa_policy`'s rows are mostly well-known GROUP SIDs with no `sam` row to resolve against |
| **T1059.001** PowerShell *when script-block logging is off* | disk-resident | writable-now | **`not-observable` in this corpus** (2026-09-19, decided on measurement) — was `blocked (D-055)`, then briefly `observable-unwritten` on a claim that did not survive measurement | **The parser blocker is gone and the technique is still unwritable, for a reason no predicate can fix.** `host_application` is extracted on 400/403/600 since D-055, and rows with empty details fell from 100% to 0. But **the technique's own precondition never held**: 4104 rows are 982/997/1270/470/644, so script-block logging was ON for every collection and the "logging off" sub-scenario was never exercised. **And the scenario's PowerShell was interactive** — bare `powershell.exe`, no flags (149 rows on `s1_v2`, 65 on `s1_v3`, matching 180 and 90 typed `ps_history` commands) — so no flag-based predicate can match it. Neither candidate flag discriminates anyway: `bypass` is host-1-only (640/640/460/**0**/**0**), `restricted` fires on all five and MOST on clean_c (56/56/72/**104**/138) from two byte-identical Windows servicing scripts. Full working in `docs/evidence/t1059-predicate-2026-09-19.md`; C-05 names what a future collection must do |
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


**CLOSED 2026-09-20 — `not-observable` under C-05, and the prescription above
is WITHDRAWN.**

Re-measured, in collection order (clean_a, clean_b, clean_c, s1_v2, s1_v3):

    R-ATOMIC-0009   4 / 5 / 2 / 0 / 0
    R-CORR-0005     1 / 1 / 1 / 0 / 0

(The figures previously written here as `4/5/0/2/0` and `1/1/0/1/0` put
`clean_c`'s value in `s1_v2`'s slot. `clean_c` is 2 and 1; both scenario hosts
are 0. Same collection-order slip as T1027 — see §3.6.)

**Why it closes rather than re-anchors.** Two facts, both measured:

1. **Neither scenario created an account.** `janed` was provisioned before the
   baseline snapshot, which is C-04 working as intended. There is no positive
   class for an account-creation rule to find.
2. **The channel that would have recorded one was destroyed.** Step 4's
   `wevtutil cl security` took `account_created` from 4/5/2 on the clean hosts
   to **0 on both scenario hosts**, with `log_cleared` firing 1/1 there and
   0/0/0 on clean. Even had the scenario created an account, the evidence
   would be gone.

So the rules are **the correct shape for the technique** and are retained.
What is absent is the indicator, not the rule — **C-05 for the third time**,
after T1071.001 and T1059.001.

**The prescription above is withdrawn.** It said: re-anchor on "does an
account exist with a suspicious shape", a standalone `sam` shape predicate,
listed as T1078.003. That predicate was written and measured on 2026-09-18:
**0 matches on all five collections**, over the full population (7 accounts
per host on host 1, 5 on host 2). It returns zero *correctly* — every RID ≥
1000 account has a non-zero logon count, and every `password_not_required`
account is a disabled built-in. There is no staged account in this corpus to
find. Pointing T1136.001 at it would move the row from one dead end to
another, so the pointer is removed rather than left standing.

**What the SAM family *does* discriminate is a different technique.** Reading
`sam` rows against the surviving Security log produced the sharpest separation
measured in this project — and it is **not** an account-creation signal. It is
recorded in §3.8, classified as T1070.001, because it fires on every account
on a cleared host including ones the attack never touched.

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
| T1071.001 Web C2 / download | → `measured-no-discriminator` (D-065 fixed; no positive class) |
| T1053.005 Scheduled Task | → `measured-no-discriminator` |
| T1027 Obfuscated Files | → `measured-no-discriminator` |
| T1078.003 Valid Accounts | → `measured-no-discriminator` |
| T1136.001 Create Account | → `not-observable` (C-05); rules retained, §3.3 |

**One rule from seven candidates is the honest yield**, and the six negatives
are the output of the phase rather than its failure. Each carries a figure:

* **T1053.005** — the user-writable predicate finds the *same five tasks on
  every collection*: four Defender `MpCmdRun.exe` under `ProgramData`, one
  `OneDriveLauncher.exe` under `AppData`. 5/5/5/5/5. The shape identifies
  vendors who install outside Program Files.
* **T1027** — `-EncodedCommand` is 0 everywhere; `FromBase64String` is
  123/123/0/67/0 (clean_a, clean_b, clean_c, s1_v2, s1_v3), **higher on the
  clean host-1 collections than on the scenario**, already rejected once in
  R-ATOMIC-0003's notes. Re-verified against raw EVTX 2026-09-20.
* **T1078.003** — zero matches in a population of 7 accounts per host. Every
  RID ≥ 1000 account has non-zero logons; every `password_not_required`
  account is a disabled built-in.
* **T1052.001** — the best base rate in the project, 9 vs 0, and the rows are
  the USB stick the evidence was carried off on (D-064).
* **T1071.001** — the evidence is richer than the `browser` family's and the
  parser discarded all of it (D-065, **fixed 2026-09-19**). Fixing it did not
  make the technique writable: every BITS transfer in the corpus is vendor
  update traffic, so there is no positive class. A parser blocker and a missing
  positive class look identical from the grid until the parser is fixed.

**Three of the seven had clean numbers and the wrong meaning** — T1052.001,
T1027's base64 branch, and the "executed then deleted" form of T1070.004. That
is the finding this phase produces: *a base rate that looks excellent is a
reason to read the rows, not a reason to write the rule.* D-051 and the
firewall EID established it; these three confirm it on a larger sample.

**What is left is not more rules but two parser defects** (D-065 for BITS,
D-055 for `ps_classic` 400/403/600), one re-anchoring (T1136.001), and the
D-058 implementation. None of those is a rule-authoring task.

> **Update 2026-09-20 — the last row is closed and the backlog is fully
> empty.** T1136.001 closed `not-observable` under C-05 rather than being
> re-anchored (§3.3): neither scenario created an account, and the channel
> that would have recorded one was destroyed by step 4. The yield is
> unchanged at **one rule from seven candidates**. The two parser defects and
> D-058 all landed on 2026-09-19. What the re-anchoring attempt did produce
> is §3.8 — a T1070.001 signal with perfect separation that is not expressible
> in schema 2.0.0 and is not written.


### 3.6 Reading-method check on T1027's closure (2026-09-20)

T1027 and T1078.003 were re-opened on 2026-09-20 as outstanding backlog rows.
**Both were already closed on 2026-09-18** and the backlog was already empty
(§3.5). No new rule work followed. What did follow was a check of the *reading
method* behind T1027's negative, per the standing rule that a negative result
is only as good as the read that produced it.

**The concern was real.** `script_block` text is capped at
`SCRIPT_BLOCK_TEXT_CAP = 4096` bytes (`parsers/evtx_windows.py:338`), and the
closure's regex ran over parsed — therefore truncated — text:

| collection | script_block rows | truncated | longest raw block |
|---|---|---|---|
| clean_a | 992 | **400** | 20,953 B |
| clean_b | 1,007 | **400** | 20,953 B |
| clean_c | 470 | **314** | 20,839 B |
| s1_v2 | 1,280 | **418** | 20,953 B |
| s1_v3 | 644 | **422** | 20,696 B |

**1,954 of 4,393 blocks — 44% — were read cut**, some at a fifth of their
length. A zero measured that way could have been an artefact of the cap.

**Re-measured against raw EVTX**, bypassing the parser and the cap entirely:

| marker | clean_a | clean_b | clean_c | s1_v2 | s1_v3 |
|---|---|---|---|---|---|
| `-EncodedCommand` / `-Enc` | 0 | 0 | 0 | 0 | 0 |
| `FromBase64String` | 123 | 123 | **0** | 67 | 0 |
| `[Convert]::` | 0 | 0 | 0 | 0 | 0 |
| `IEX` / `Invoke-Expression` | 2 | 2 | 0 | 4 | 0 |
| `-join` | 6 | 6 | 6 | 7 | 1 |
| `[char](` arithmetic | 0 | 0 | 0 | 0 | 0 |
| `GzipStream` / `DeflateStream` | 0 | 0 | 0 | 0 | 0 |
| `ConvertTo-SecureString` | 0 | 0 | 0 | 0 | 0 |

**The conclusion is unchanged and the closure stands.** The cap did not hide
an obfuscation indicator: every marker is either zero everywhere or higher on
a clean collection.

**Two stated facts in the closure were wrong, and are corrected above.**

1. The row recorded `FromBase64String` as **123/123/67/0/0**, which reads as
   67 on `clean_c` and 0 on both scenario hosts. Measured, it is
   **123/123/0/67/0** — `clean_c` has **zero** and the 67 is on **`s1_v2`, a
   scenario host**. R-ATOMIC-0003's own `note_on_excluded_patterns` had it
   right ("123 blocks in each baseline against 67 in s1_v2"); the grid garbled
   it when transcribing two figures into a five-collection list.
2. The row said "nearly twice as high on the CLEAN hosts" without qualifying
   which. It is twice as high on the two **host-1** clean collections;
   `clean_c`, the other clean host, has none at all.

**Neither error changes the verdict** — 123 clean against 67 scenario still
points the wrong way — but the second made the corpus look more uniform than
it is, and the first inverted which collections carry the evidence.

**Row-level read, which the original closure did not record.** All
`FromBase64String` hits on both hosts are the same two shapes:

    52x / 27x   Set-Item -LiteralPath 'Env:_ZO_DOCTOR' -Value
                ([System.Text.Encoding]::UTF8.GetString([System.Convert]::...
     8x /  6x   Set-Location '...\AppData\Local\Programs\cursor'
                # Execute user command

That is `zoxide`'s shell integration and Cursor's shell wrapper — **the
operator's own editor and shell tooling**, decoding to ordinary local paths.
This is C-02 leakage, not obfuscation by an adversary. The technique is
absent from the corpus rather than present-and-undetected.

**Method point.** The grid's figure was measured, and was still wrong in two
ways that a re-read caught: a transcription slip and an unchecked reading
method. This is the same class as the `restricted` claim and the phase-span
contrast claim — see the verification-coverage pattern at the top of
`docs/defect-log.md`. A measured figure is not self-certifying; the read that
produced it is part of the claim.

### 3.7 T1078.003's closure reason is the right one (checked 2026-09-20)

A `measured-no-discriminator` closure and a `not-observable` closure mean
different things, and T1078.003 sits next to a technique whose evidence the
scenario deliberately destroyed. The check: did the SAM predicate return zero
because no staged account exists, or because `wevtutil cl security` removed
the evidence it would have matched?

Measured per collection, by `event_type`:

| event_type | clean_a | clean_b | clean_c | s1_v2 | s1_v3 |
|---|---|---|---|---|---|
| `logon` (4624) | 906 | 919 | 625 | **58** | **11** |
| `logon_failed` (4625) | 13 | 13 | 2 | 1 | 0 |
| `account_created` (4720) | 4 | 5 | 2 | **0** | **0** |
| `log_cleared` (1102) | 0 | 0 | 0 | **1** | **1** |
| `local_account` (SAM) | 7 | 7 | 5 | **7** | **5** |
| `privilege_granted` | 17 | 17 | 13 | 17 | 13 |
| `logon_ui` (Winlogon) | 316 | 316 | 196 | 786 | 615 |
| `rdp_session` | 13 | 13 | 9 | 33 | 15 |

**Two evidence classes, opposite outcomes.**

*The Security log was destroyed.* `logon` collapses from 906/919/625 on clean
hosts to 58 and 11; `account_created` from 4/5/2 to **zero on both scenario
hosts**; `log_cleared` fires 1 on each scenario host and 0 on every clean one.
The scenario's step 4 did what it was designed to do. **Any T1078.003
predicate built on 4624/4720 is not measurable on this corpus** — that would
be a `not-observable` closure, the anti-forensic case
`docs/artifact-attestation-matrix.md` §2.6 exists to cover.

*SAM survived.* `local_account` is **7 / 7 / 5 / 7 / 5** — the scenario hosts
carry exactly the same account population as their own clean baselines.
`privilege_granted` (17/17/13/17/13) likewise. Registry-hive evidence is
outside the channel `wevtutil cl security` clears.

**Therefore the closure as recorded is correct, and for a stronger reason than
it states.** The predicate is a SAM shape predicate (`rid >= 1000`,
`well_known` absent, `password_not_required` or `logon_count: 0`). It ran
against evidence the attack did not touch, over the full population of 7
accounts per host on host 1 and 5 on host 2 — not a sample. Zero matches means
no staged account is present, not that the record of one was erased.

`measured-no-discriminator` is the right label. The distinction matters
because the neighbouring rows close the other way: T1052.001 and T1071.001 are
`not-observable`, and reading all three as the same kind of negative would
misstate what this corpus can and cannot support.

**A caveat the row should carry.** The off-channel survivors —
`evtx.winlogon logon_ui`, `evtx.rdp rdp_session` — are *higher* on the
scenario hosts (786 and 615 against 316/316/196; 33 and 15 against 13/13/9).
That is the operator's own interactive and remote sessions during scenario
construction, i.e. C-02 again, not the attack's use of a valid account. They
are not an alternative anchor for this technique.

---

### 3.8 SAM counts logons the cleared Security log no longer holds (2026-09-20)

Found while closing T1136.001, by asking what `sam` discriminates once the
account-creation anchor is abandoned. It discriminates sharply — and **not the
technique that was being worked on**.

`details-schema.md` describes `logon_count` as the field the artefact exists
for: *"Interactive logons counted by SAM itself, not by the log. A non-zero
count with no 4624 is authentication the log no longer holds."* That is a
specification for a log-tampering detector, and it measures as one.

**Measured, whole population, `user_key()` join on both sides:**

| collection | account | rid | SAM count | interactive 4624 | gap |
|---|---|---|---|---|---|
| clean_a | `youssef` | 1000 | 13 | 26 | **-13** |
| clean_a | `janed` | 1002 | 1 | 1 | **0** |
| clean_a | `admin_local` | 1003 | 5 | 10 | **-5** |
| clean_b | `youssef` | 1000 | 13 | 26 | **-13** |
| clean_b | `janed` | 1002 | 1 | 1 | **0** |
| clean_b | `admin_local` | 1003 | 5 | 10 | **-5** |
| clean_c | `vboxuser` | 1000 | 9 | 18 | **-9** |
| **s1_v2** | `youssef` | 1000 | 17 | **0** | **+17** |
| **s1_v2** | `janed` | 1002 | 12 | **0** | **+12** |
| **s1_v2** | `admin_local` | 1003 | 29 | **2** | **+27** |
| **s1_v3** | `vboxuser` | 1000 | 15 | **0** | **+15** |

**Every clean account has gap ≤ 0. Every scenario account has gap ≥ +12.** No
overlap, on the full account population of both hosts — 7 rows per host on
host 1 and 5 on host 2, built-ins excluded as `well_known`.

**Why clean gaps are negative, which a reader will ask.** On an intact log
`4624_int` is exactly **twice** the SAM count on every clean host (26/13,
10/5, 18/9). Windows writes two interactive 4624 records per logon session
while SAM increments its counter once. So `4624 >= sam` is the expected
healthy relation, and the predicate is strictly **`sam > interactive 4624`** —
a count in the hive the log cannot account for.

**This is T1070.001, not T1136.001.** It fires on `youssef` (+17) and
`vboxuser` (+15), who are the machines' ordinary users and took no part in the
attack. It identifies a **host whose log was cleared**, not a malicious
account. Anchoring an account-creation rule on it would claim "an account was
created" from evidence that says nothing about account creation.

#### Reading-method checks, run before this was written

* **`LogonType` is populated and was misread first.** The distribution on
  `clean_a` is type 5 (service) 802, type 2 (console) 91, type 0 twelve, type
  3 one. An initial reconciliation reported an "interactive" column that
  matched the total exactly; that column was not measuring logon type at all,
  it was measuring *which rows resolved to a user*. Corrected: service logons
  fold to `None` through `SYSTEM_CONTEXTS`, so every 4624 that resolves to a
  real user on these hosts is interactive anyway. **The figures are unchanged
  and the reason is now verified rather than coincidental.**
* **The join resolves on both sides.** `user_key()` returns `youssef`,
  `janed`, `admin_local` for both `sam` rows and 4624 rows, so a rule joining
  on `entity.user` under CD-010 would match what this measurement matched.
* **Population, not sample.** Every non-built-in SAM account on every
  collection is in the table.

#### Status: NOT WRITTEN, and two things gate it

1. **T1070.001 is already `covered`** by R-ATOMIC-0002 on EID 1102, firing
   0/0/0/1/1 (§2.1). On this corpus the discrepancy is therefore
   **corroborating, not corrective** — it finds the same two hosts 1102
   already finds. Its distinct value is the case 1102 cannot cover: an
   attacker who deletes the `.evtx` file, or clears twice so the 1102 record
   is itself removed. **That case does not occur in this corpus**, so the rule
   would be validated only in the 1102-present condition and must say so.
2. **It is NOT expressible in schema 2.0.0 — checked in the engine, not
   assumed.** The engine does have numeric ops (`gt`, `gte`, `lt`, `lte`,
   `core/engine.py:292`) and does have a corpus-level aggregate: `RunContext`
   with `entity_count_lte` / `entity_count_gte` (`:298`). Neither reaches this
   predicate, for two specific reasons:

   * `RunContext.build` counts **`entity.exe_name` only** (`:197-204`). This
     predicate needs a count keyed on **`entity.user`**, and further restricted
     to `event_type == logon` on `evtx.security` — the context counts *all*
     events naming an executable, with no event-type filter.
   * The rarity ops compare a count against a **literal integer** supplied in
     the rule (`:320-322`, raising unless `cond.value` is an `int`). This
     predicate compares a count against a **field on another row**
     (`details.logon_count`), which no operator accepts.

   Writing it therefore requires extending `RunContext` to a second keying and
   adding a field-versus-aggregate comparison — an engine change plus a schema
   bump, in `rules/**`, which is Person A's directory. **That is a fork to
   raise, not work to start unilaterally.**

**Not started pending both.** Recorded here so the measurement is not lost and
so the next person does not re-derive it.

### 3.9 T1070.006 timestomp: the indicator inverts, then vanishes (2026-09-20)

Attempted as a Class 2 rule from the priority batch. **Not written**, for two
independent reasons, both measured.

**The naive shape is a non-discriminator at enormous scale.** `si_created <
fn_created` — $STANDARD_INFORMATION older than $FILE_NAME, the classic
SetFileTime backdating signature:

| collection | mft rows with both times | si < fn | rate |
|---|---|---|---|
| clean_a | 415,719 | 110,313 | **26.5%** |
| clean_b | 414,041 | 110,314 | **26.6%** |
| clean_c | 284,146 | 99,955 | **35.2%** |
| s1_v2 | 452,284 | 110,092 | **24.3%** |
| s1_v3 | 340,114 | 94,262 | **27.7%** |

A quarter of every collection, and **lower on the scenario host than on either
clean collection of the same machine**. Row-level, the cause is immediate:

    Program Files    si=2019-12-07T09:14:52   fn=2026-06-21T00:37:44
    PerfLogs         si=2019-12-07T09:14:52   fn=2026-06-21T00:37:44
    $Recycle.Bin     si=2019-12-07T09:14:52   fn=2026-06-21T00:37:44
    WindowsUpdate.adml  si=2023-05-05        fn=2026-08-12

Windows Setup preserves the install media's timestamps in `$SI` while the
kernel writes `$FN` at install time. Top extensions are `dll` (28,620),
`manifest` (18,451), `xml`, `mui`. This is the OS, not an adversary.

**Restricting it removes the entire population.** Three tightened variants,
all five collections:

| variant | all five |
|---|---|
| file (not dir) under a user-writable path | **0** |
| the above, executable extension, gap > 1 day | **0** |
| uniform `$SI` (created == modified == accessed), user-writable | **0** |

So the discrepancy is 110,000 rows of system files and **zero** user-writable
files anywhere in the corpus. There is no population between "everything" and
"nothing" from which to choose a threshold, and no positive instance to
validate against — the scenario did not timestomp.

**It is also not expressible in schema 2.0.0.** The predicate compares
`details.si_created` against `details.fn_created` — a **field-to-field**
comparison. Conditions compare a field to a *literal*; `value_field` is not a
condition key and the validator rejects it (`unknown condition key(s):
['value_field']`). The operator set is closed and contains no field-versus-
field form. This is the same expressibility gap recorded in §3.8, reached
from a different direction.

**State: `measured, not exercised`** — the batch's third state. The technique
is real and the artefact carries the fields; this corpus contains no instance,
and the schema cannot express the comparison even if it did. Both would have
to change before a rule is worth writing.

*(An incidental correction: the operator set does contain `is_user_writable`,
a purpose-built shape predicate added for R-CORR-0003 so that rules ask where
a binary lives rather than regex-matching paths. A first draft of this rule
hand-rolled a `contains_any` path list; that operator does not exist, and the
one that does is better. It is used in R-ATOMIC-0011.)*

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
