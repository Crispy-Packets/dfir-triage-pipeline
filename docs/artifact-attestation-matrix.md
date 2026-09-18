# Artifact attestation matrix

**What each family can prove, what it cannot, and what corroborates it.**

---

## 0. Why this document exists, and what was wrong before it

Every rule in this pipeline was written the same way: look at what the
collections contain, write a rule for it, measure the base rate. That is correct
practice for **calibrating** a rule and wrong for **scoping** a rule set, and the
difference is the defect this document corrects.

A rule set derived from five collections describes five machines. The question a
forensic tool must answer is not "what happened here" but **"if X had happened,
which artefact would carry it, and what would contradict a lie about it?"** That
question is answerable from the artefact's structure alone, before any
collection exists.

**This is not detection coverage.** It makes no claim about ATT&CK techniques
and no claim to catch anything. It is an **evidentiary completeness map**: for
each family, the scope of what it may be asked to attest, the limits of that
attestation, and the independent family that corroborates it.

Coverage in this sense is achievable and checkable. "100% detection" is neither
— `s1_v2`'s 4688 for the payload is gone, and no correlation recovers a record
that was deleted.

**Every "cannot attest" clause below is measured, not assumed**, and carries the
defect number that established it.

---

## 1. The attestation table

| Family | Attests to | **Cannot** attest | Evidence for the limit | Corroborated by |
|---|---|---|---|---|
| **prefetch** | a binary ran; when it last ran; how many times; which files it touched in its first 10 s | **who** ran it — Prefetch records no principal | parser emits no `user` for prefetch | BAM/DAM (SID), Amcache, Security 4688 |
| | | **that it did not run** — Prefetch is disabled by default on Server and capped at 1024 entries | Windows default | Amcache, Shimcache |
| | | the binary's **content** — the hash is of the path, not the file | Prefetch format | Amcache `sha1` |
| **amcache** | a binary existed on disk; its SHA-1; its size; its declared publisher | **that it ran.** Measured: Amcache held **no entry** for the executed scenario binary | **D-028** | Prefetch, `$MFT` ⛔ |
| | | **when** it ran — `timestamp_type=presence`, the value is the key's last write | CD-019 | Prefetch `last_run` |
| **registry (Run/RunOnce)** | an autorun value exists **now**, with this data | **when the value was written.** The timestamp is the containing KEY's last-write, shared by every sibling value | **D-027**, and `value_count_in_key` exists to say how many share it | `$MFT` on the hive file ⛔, USN ⛔ |
| | | that the target ever ran | — | Prefetch, Amcache |
| **evtx.security** | events the log **still contains** | **anything cleared.** `wevtutil cl security` destroyed the 4688 for the payload; `janed` appears in zero 4624 and zero 4688 afterwards | `s1_v2` ground truth; measured | LSM channel, SAM, Prefetch, Amcache |
| | | **who was created** on a 4720 without `TargetUserName` — the original parser kept only the creator | **D-029** | SAM |
| | | anything an audit subcategory suppresses — 4697/4698/4702 are **off by default** | measured: 0 across five collections | Task XML, registry Services |
| **evtx.system** | service installations the log still holds (7045) | services installed **before the log's retention window**, or after a System-log clear (EID 104) | log rollover is size-capped by default | registry `Services` key |
| **evtx.powershell** | script blocks, **capped at 4096 UTF-8 bytes** | the remainder of a longer block. A rule may read it with **positive operators only** — `not_contains` against a capped field asserts an absence the evidence cannot support | **D-031**; enforced by `validate_rules.py` | legacy `Windows PowerShell` EID 800 — **parsed since 2026-09-18**, carrying `host_application` and `ps_command_line`. The ⛔ this row carried was written when the legacy channel was unparsed and **stayed after the channel landed** (D-060) |
| | | anything at all when **script-block logging is disabled**. Measured: 5 rows against 997 with it on | `clean_c` first collection | — |
| **evtx.wmi** | that a permanent event subscription was **registered**; its filter, consumer class, and WQL query | **what the consumer executes.** 5861 records the binding, not the payload | parser reads 5861 only | WMI repository `OBJECTS.DATA` ⛔ |
| **evtx.rdp** | a Terminal Services session; its user, session ID and origin `Address` | that the session was **authorised**; and nothing when the channel is absent | — | Security 4624 type 10 |
| **shimcache** | a binary was **present** on disk, with its path and modification time | **that it ran.** Windows 10/11 populate the cache on enumeration as well as on execution | CD-007; `program_shimcached` is deliberately not `process_exec` | prefetch, bam, amcache |
| | | **when** it was seen — the FILETIME is the file's modification time, a property of the file | parser source | prefetch `last_run` |
| **bam** | a binary ran, **and which SID ran it** | anything about binaries the service has aged out; DAM is absent on most desktop builds | parser reads both, emits `bam_service` | prefetch, Security 4688 |
| **services** | a service **exists now**, with its image path, start type and account | **when it was installed.** The timestamp is the key's last write | CD-019, same limit as registry Run keys | System 7045 |
| | | that the service ever **started** | — | prefetch on the image, System 7036 |
| **sam** | a local account **exists now**; its RID, flags, and a logon count SAM maintains itself | **when the account was created.** `password_last_set` approximates it on an untouched account and is not the same fact | parser source; CD-007 `local_account` is not `account_created` | Security 4720 |
| | | **who** created it, or from where a logon came | SAM records no principal but the account itself | Security 4720 `SubjectUserName`, 4624 |
| | | anything about **domain** accounts — SAM is local only | Windows design | domain controller logs ⛔ |
| | | that an account was **deleted**. Measured: `testuser` was created in `clean_b` on 2026-08-24 and is absent from SAM entirely | measured 2026-09-17 | Security 4726 |
| **srum** | **how much data an application moved** — bytes sent and received per app per interval; CPU cycles and disk bytes | **that a short-lived process ran at all.** SRUM samples running processes rather than recording starts, so a binary that exits between samples is never observed. Measured: `invoice_scan.exe` is absent from `s1_v2` even though SRUM flushed 325 rows after it ran | measured 2026-09-17, both scenario collections | prefetch, bam, amcache |
| | | **the endpoints of a transfer.** SRUM names neither a URL nor a remote address — only a byte count per application | parser source; CD-007 `network_usage` is not `file_download` | browser `url`, `Zone.Identifier` ADS ⛔ |
| | | **when an interval began.** The timestamp is the provider's flush, not the start of the activity it summarises | CD-019 | — |
| | | anything after its **last flush**. Measured on `s1_v3`: horizon 11:48:00, payload ran 11:50:09, zero rows at or after the execution for any program | measured 2026-09-17 | prefetch, bam |
| **scheduled_task** | a task **exists**, what it would run (a command line **or** a COM class id), its triggers, and the principal it would run as | **that the task ever ran.** `LastRunTime` lives in the Task Scheduler log and in `SOFTWARE\...\Schedule\TaskCache`, neither read here | CD-019, same limit as registry Run keys (D-027) | prefetch on the command, bam, Task Scheduler `Operational` ⛔ |
| | | **when it was registered** for most tasks. Measured: only 26 of 222 on `s1_v3` carry a `<Date>` at all | measured 2026-09-17 | `$MFT` on the definition file ⛔ |
| | | **what a COM action executes.** The CLSID is recorded; resolving it to a DLL needs the SOFTWARE hive | parser source; 115 of 222 actions are `ComHandler` | SOFTWARE hive CLSID registration ⛔ |
| | | that `<Author>` names who really created it — it is self-declared and trivially forged | Windows design | Security 4698 (off by default; **measured 0 across five collections**) |
| **userassist** | a program was **launched through the GUI**, **by a named account**, with a run count and a last-run time | **anything not started from the shell.** A program run from a command line, a script, or a service leaves no entry, so a zero count is not evidence it did not run | Windows design; the key is written by Explorer | prefetch, bam, Security 4688 |
| | | **what the program did**, or where it was launched from | — | prefetch's loaded-file list, srum |
| **recentdocs** | a name was **opened through the shell**, per extension, by a named account | **that the file exists or ever did.** Measured: entry 15 on `clean_b` decodes to a URL query string, not a filename | measured 2026-09-17 | `$MFT` ⛔, LNK ⛔ |
| | | **when** it was opened. The timestamp is the containing key's last write, shared by every sibling value | **D-027**; `value_count_in_key` says how many share it | LNK ⛔, `$MFT` ⛔ |
| **typedpaths** | a path was **typed into the Explorer address bar** by a named account | anything, when the key is empty — **measured 0 across all five collections** | measured 2026-09-17 | recentdocs, runmru |
| **runmru** | a command was **typed into the Run dialog** by a named account | that the command ever executed, or succeeded | Windows design | prefetch, userassist, evtx.powershell |
| **lnk** | a file was **opened through the shell**: its full path, the **volume serial and drive type** of the volume it lived on, its size, and three FILETIMEs copied from the target file | **that the target still exists.** The times describe the target, copied into the link, which is why a link outlives the file it names | CD-019; `timestamp_type=presence` | `$MFT` ⛔, recentdocs |
| | | **who** opened an installed link. Start Menu, Desktop and Quick Launch links are written by software, not by use — 15-16 per collection regardless of activity | measured 2026-09-17; `lnk_location` separates them | userassist, recentdocs |
| | | **which application** opened the file | — | JumpLists ⛔ |
| | | anything, for a protocol link (`ms-settings:`). Those name a URI handler and carry no path at all | parser source | — |
| **usn** | a file was **created, deleted or renamed**, with a real timestamp. Sees deletions that **never went to the Recycle Bin** | **where the file was.** The journal names the parent by MFT reference number; resolving to a path needs the `$MFT` | parser source; CD-010 | recyclebin (carries the full path), `$MFT` ⛔ |
| | | that a file was merely **read or modified** — data overwrites are recorded but not emitted, being both ubiquitous and the weakest claim | measured: 169,304 records on `s1_v3`, mostly `.mui` servicing writes | prefetch, srum |
| | | anything older than the journal's rollover. Its head is sparse — records age out and the space is zeroed | measured: the file begins with a zeroed region | `$MFT` ⛔, `$LogFile` ⛔ |
| **recyclebin** | a file was **deleted to the Recycle Bin**, with its **original full path**, its size, and when | deletions that bypassed the bin (shift-delete, a program removing its own files) | Windows design | usn |
| **shellbags** | a folder was **displayed in Explorer**, by a named user, including folders since removed and volumes since detached | **when** it was browsed. The timestamp is the containing key's last write, shared by every sibling bag | **D-027** | lnk, jumplist, recentdocs |
| **timeline** | an application was opened, and **how many seconds a person actively used it** | anything for ActivityTypes 11 and 16 (settings sync, clipboard) — they name no program | parser source | userassist, prefetch, srum |
| **ps_history** | a command **typed at a PowerShell prompt**, present **whether or not script-block logging was on** | **when** it ran — PSReadLine writes no timestamps at all. Order is the only sequence information | parser source; `presence` | evtx.powershell 4104, evtx.ps_classic 600 |
| **evtx.ps_classic** | **via EID 800 (mapped 2026-09-18): the command line that launched PowerShell (`host_application`, including `-ExecutionPolicy Bypass` and the script path), the command the pipeline invoked, the script file, and a joinable user.** The only record in this pipeline carrying PowerShell command text **when script-block logging is off** | anything from EIDs 400/403/600, which still emit `details == {}`. The positional-`Data` fix made their fields reachable; giving them a branch and declaring their keys remains open (**D-055**) | **D-055**, **D-059**; measured 10/10/10/0/0 for EID 800 | evtx.powershell 4104, ps_history |
| **evtx.defender** | an AV **detection**, **remediation**, or protection being **disabled** | anything when Defender is not the installed AV | Windows design | — |
| **evtx.winlogon** | that a logon UI notification was dispatched, and when — **survives a Security-log clear** | **who** logged on. The record DOES carry a principal — `<Security UserID="S-1-5-18">` — and it is always SYSTEM, the service dispatching the notification, never the account logging on. The conclusion stands; the reason previously given here ("names no principal at all") was wrong | **D-057**, read from the raw record 2026-09-18 | evtx.security 4624, sam, evtx.rdp |
| | | anything the parser currently emits beyond a timestamp. `SubscriberName` (e.g. `GPClient`) and `Event` are present in every raw 811/812 and are **dropped** — `details` is empty on all 1,913 rows across four collections. EIDs 1 and 2 are present in the evidence and absent from the curated map, discarded unseen | **D-057** | — |
| **evtx.firewall** | a firewall rule **added, changed or deleted** | that a deletion was unusual. **Measured 200+ per collection on CLEAN hosts** — Windows churns rules constantly during policy refresh | measured 2026-09-17 | — |
| **evtx.bits** | **only that a background transfer occurred, and when.** The raw records carry `url`, the destination `name`, `bytesTotal`, `jobOwner` and `processPath` — a more complete download record than the `browser` family produces — and **`_details_for` has no branch for 3/4/59/60, so `details == {}` on every row in every collection** | the URL, the destination, the size, the owner and the responsible process: all present in the evidence, none reaching an Event | **D-065**, measured 2026-09-18 | browser, usn |
| **browser** | a file was **downloaded**; its size, MIME type, source URL, target path; a page was **visited**, with its transition (typed vs. followed); a **search term**, on the engine that ran it | that a visit or search happened when history was cleared before collection | Windows/browser design | `webcache` (a separate WinINet index, not a duplicate), evtx.bits |
| | | that the file was **executed** | — | Prefetch, Amcache |
| **browser_profile** | the same downloads/visits/searches for **additional profiles** on the same machine (a second Chrome/Edge profile, a second user) | anything a profile never wrote — an unused profile yields zero rows, which is an absence of evidence, not a fault | parser source | browser |
| **jumplist** | **which application** opened a file — the one claim `lnk` and `recentdocs` cannot make, since the container itself is keyed by the app's AppID | **when** the file was opened, for `customDestinations`, which carries no per-entry timestamp of its own — only the embedded LNK's copied FILETIMEs, which describe the **target**, not the open | parser source; CD-019 `presence` | lnk, recentdocs |
| **mft** | that a file (or a now-deleted one) **existed**, with its `$SI`/`$FN` timestamps, size and parent reference — including **1,136 records for files no longer on disk** | **who** touched the file, or **that it ran** | parser source; `file_record` is not `process_exec` | usn (names the operation), recyclebin |
| | | **timestomping**, as a verdict. `$SI`-earlier-than-`$FN` was measured at 27%/35% on two CLEAN hosts and removed as an indicator; both raw timestamps are kept as details for a human to compare | **D-051** | — |
| **ntfs_logfile** | that a filename **appeared** in a recent `$LogFile` RCRD page — the only family that reaches slightly past USN's rollover horizon | that a recovered name is the **whole** filename. A recovered run can be a **suffix** of the true name; cross-page fragments are not filtered | measured; `_drop_suffix_fragments` removes only same-page duplicates; stated as a limit, not fixed | usn (authoritative for the same window), mft |
| | | **when** — the record carries only an LSN, and deriving a time from it would be fabricated | parser source; `presence` | usn, mft |
| **txf_pending** | that a **Component-Based Servicing transaction** was pending against `$T` — a component name and version change, naming e.g. a specific KB | anything on a host with no pending CBS transaction. Measured: non-zero **only** on `s1_v3`, zero on all four other collections | measured 2026-09-17 | evtx.x. Windows Update channels ⛔ (not curated) |
| | | a **time** for the transaction — `$T` carries no timestamp at all | parser source; `presence` | — |
| **webcache** | a page **visit** attributed to a named account **inside the record itself** (`Visited: user@url`), independent of which profile directory the file sits in; **background transfers the OS performed with no Chromium history at all**; per-day visit containers | anything for `Content` containers — deliberately not emitted; they index cache **files**, not what a person did | parser source | browser (a different index of related but non-identical activity) |
| **lsa_policy** | that a **privilege was granted** to a named SID under `\Policy\Accounts` — survives a Security-log clear that destroys 4672/4673 | **when** the privilege was granted — the value carries no timestamp of its own | parser source; `presence` | evtx.security 4672 ⛔ (off by default) |
| | | LSA **secrets** or the boot key. Deliberately not read, same reasoning as SAM's `V` value | parser source | — |
| **registry_txlog** (`.LOG1`/`.LOG2`) | that a hive has **pending writes not yet flushed**, their size, and whether the **log is ahead of its hive**. Measured on `clean_b`: 21 of 27 logs ahead, up to 933 KB pending | **the content** of the pending write — the logs are read for header/sequence metadata only, never replayed. Replaying and mis-parsing risks fabricating keys, the worst failure mode available here | parser source; deliberate scope limit | the hive itself, once flushed |
| **defender_mplog** | that a process **ran**, from an AV engine independent of Prefetch/BAM/4688; that a file was **reported** for a second opinion (`ReportLowfi`) — not a verdict; a scan was **skipped**; the AV service **started** | that a `file_reported` row is a **detection**. `ReportLowfi` means low-fidelity, not malicious — conflating the two was rejected explicitly this session | parser source; measured zero 1116/1117 in the mplog text corresponding to `file_reported` rows | evtx.defender 1116/1117 (the actual verdict channel) |
| **evtx.x.\*** (88 generic channels) | that a record **exists** in a channel this pipeline has not curated, timestamped and attributed to its provider/channel, searchable by free text | **any specific claim about what the EID means.** No curated field extraction, no path, no user — `log_record` is deliberately the only event_type | parser source; CD-007; `test_a_curated_channel_is_not_given_a_generic_name` | whichever curated channel would supersede it, if written |

⛔ = not parsed by this pipeline.

---

## 2. The corroboration graph

Read as: **if the left family is suppressed, the right families still attest.**

| Suppressed | Survives | What is still provable |
|---|---|---|
| `Security.evtx` cleared (EID 1102) | prefetch, amcache, registry, browser, **evtx.rdp**, evtx.powershell | execution, presence, persistence, arrival, remote sessions. **Measured on `s1_v2`: every step of the attack remained recoverable** |
| Prefetch disabled or purged | amcache, Shimcache, BAM | that the binary existed and was inventoried |
| Amcache stale or missing (D-028) | prefetch, `$MFT` ⛔ | that the binary ran, and when |
| Script-block logging off | `evtx.ps_classic` (400/403/600), `ps_history`, prefetch | **that PowerShell ran, and when** — but NOT its command line: `HostApplication` is in the raw record and is not extracted (**D-055**). `ps_history` carries the typed commands themselves, with no timestamps |
| Registry value deleted | prefetch, amcache | that the target ran, if it did |
| Browser history cleared | `Zone.Identifier` ADS ⛔, `$MFT` ⛔ | the source URL, via the ADS `HostUrl` |
| **A family's file deleted outright** | `$MFT` ⛔ | that the file existed and was deleted — **the only artefact that attests to its own deletion** |

### The structural property

**An adversary suppressing one family leaves the others intact.** That is not a
detection claim; it is a statement about what would have to be falsified
*consistently* for the evidence to lie. Seven families was the minimum for the
property to hold at all; the pipeline now parses **38 named families**, plus
88 generic EVTX channels read uniformly as `log_record`.

**Measured on `s1_v2`:** a single `wevtutil cl security` destroyed the entire
Security-log record of arrival, execution and persistence — and all three
remained recoverable from browser history, Prefetch and the registry. That is
this document's thesis demonstrated on real evidence.

---

## 3. Where the map is incomplete, and why

**Updated 2026-09-17 (rules-coverage pass).** The SYSTEM hive (Shimcache, BAM,
Services) landed in 62cb065; SAM, SRUM, scheduled tasks, the NTUSER Explorer
keys, LNK, Recycle Bin, Timeline, PS history, JumpLists, browser widening,
Shellbags, five curated EVTX channels, USN, `$MFT`, `$LogFile`, `$T`,
`defender_mplog`, `lsa_policy`, the DEFAULT hive, registry transaction logs,
WebCache and the generic EVTX fallback all landed across this session and the
last, taking the pipeline from 7 named families to **38** (plus 88 generic
`evtx.x.*` channels). The ⛔ markers those closed have been cleared from the
table above rather than left standing — a matrix that understates what is
parsed is as misleading as one that overstates it.

### Closed since this document was written

| Family | Rows it closed | What it supplies |
|---|---|---|
| **SYSTEM hive** — `shimcache`, `bam`, `services` | 4 | Execution evidence when Prefetch is off; **the principal Prefetch cannot supply**; services when 7045 is gone. Demonstrated on `s1_v3`: BAM attributed `invoice_scan.exe` to `S-1-5-21-…-1000` 31 seconds after Prefetch recorded the same execution with no user at all |
| **SAM hive** — `sam` | 2 | Accounts and their logon counts after a Security-log clear. `s1_v3` retains **12** Security events and all five accounts |
| **SRUM** — `srum` | 4 | **Transfer volume**, which no other family carries. 6,179 rows on `clean_a`. Its own limits are now stated above rather than assumed: it did not record the scenario binary on either host, for two different and measured reasons |
| **Scheduled tasks** — `scheduled_task` | 4 | The **only** record that a task exists: 4698 is off by default and measures 0 across all five collections. Unlike services, there is no enabled-by-default event to fall back on. 222 events on `s1_v3`, of which 115 are COM actions with no command line at all |
| **NTUSER Explorer keys** — `userassist`, `recentdocs`, `typedpaths`, `runmru` | 6 | **Per-user execution and file access, attributed by construction.** On `s1_v2`, whose Security log was cleared, UserAssist names `janed` as the account that ran the payload 28 times — while Prefetch records the same execution, to the second, with no principal at all |
| **Shell links** — `lnk` | 4 | **CD-013 reopened and measured.** Two links on `s1_v2` name a removable volume — serial `18334A83`, label `JOE` — that NO other family in the pipeline mentions, in any collection. A device touched the machine and the only record is a 1 KB link |
| **JumpLists** — `jumplist` | 1 | **Which application** opened each file, carried by no other family. Also reveals four paths on that removable volume the Recent links never recorded |
| **USN journal** — `usn` | 3 | **Rename**, and deletions that never reached the bin. Caught `invoice_scan_marker.txt` — the payload's side effect, one second after execution, named by no execution-evidence family |
| **Recycle Bin** — `recyclebin` | 1 | A deletion **with the original full path**, which the journal cannot supply. `s1_v2` holds nine deletions of the payload at three sizes over four days |
| **Shellbags, Timeline, PS history** — `shellbags`, `timeline`, `ps_history` | 3 | Folders browsed; **how long a person used a program**; commands typed at a prompt regardless of logging |
| **Five EVTX channels** — `ps_classic`, `defender`, `winlogon`, `firewall`, `bits` | 4 | Selected by surveying all 100 unparsed channels. Closes the legacy-PowerShell gap this document has carried as stated since it was written |

### Still collected and not parsed

| Unparsed family | Rows it would close | Why it matters |
|---|---|---|
| **`$MFT`** (361 MB in `s1_v3`) | 4 | Resolves USN's MFT reference numbers to **full paths**, and is the only artefact attesting to **timestomping**. Needs streaming plus an index — see the feasibility study |
| **`$LogFile`**, **`$Boot`**, **`$Secure_$SDS`** | 1 | Transaction-level NTFS detail and volume metadata. `$LogFile` can recover very recent operations the journal has already rolled past |
| **Defender `MPLog`** (17 files) | 1 | Scan history in a proprietary text format, including paths scanned and threats named |
| **`WebCacheV01.dat`** | 1 | Legacy IE/Edge cache and history in an ESE database. Both hosts used Chromium Edge, whose history is already parsed |
| **95 remaining EVTX channels** | 0 | Surveyed 2026-09-17: the largest is Store/Operational with 21,068 rows of app-install telemetry. **None carries an attestation the parsed families lack** — the five taken were chosen on that basis, and this is a measured judgement rather than a backlog |

**Correctly unparsed**, and not a gap: registry transaction logs (`.LOG1`,
`.LOG2`) hold no committed values; `.chk`, `.jrs` and `.jfm` are ESE journals
and checkpoints; `desktop.ini` is a folder-view setting; KAPE's own
`ConsoleLog.txt`, `CopyLog.csv` and `SkipLog.csv` describe the collection, not
the machine.

**The map is honest about this:** every ⛔ is a stated gap, not a silent one. A
corroboration marked ⛔ is a corroboration this pipeline cannot currently
perform, and the write-up says so rather than implying the graph is complete.

---

## 4. What a rule derived this way looks like

The difference from every rule written so far, stated concretely.

**Corpus-derived (what was done):** look at the collections, see 73 WMI
subscriptions, write a rule matching them, measure 12/12/20/10/19, discover the
clean-host rate equals the scenario rate, rewrite.

**Attestation-derived (what this document enables):** ask what a WMI
subscription *structurally is* — a filter bound to a consumer — and what
distinguishes one that executes from one that records. `CommandLineEventConsumer`
executes **by definition, on any Windows host**. Write that. Measure 0/0/0/0/0,
and the zero means "no execution-capable persistence present" rather than "rule
untested."

**The second derivation transfers to a machine this corpus has never seen. The
first does not.**

R-ATOMIC-0007 was rewritten on exactly this basis and is the worked example.

---

## 5. What this document does NOT claim

- **Not detection coverage.** No ATT&CK completeness claim; no assertion that a
  technique is caught.
- **Not 100% anything.** Three of the four causes of a cross-family
  inconsistency are benign — parser gap, collection gap, artefact semantics —
  and only the fourth is adversarial. Distinguishing them requires a collection
  manifest, which `groundtruth/*-sha256.csv` provides for evidence and nothing
  yet provides at runtime.
- **Not a substitute for the base rates.** Attestation scopes a rule; measurement
  calibrates it. Both are required, and the order matters: scope first, measure
  second.

---

## 6. Rules-coverage inventory: from attestation to rule

**Started 2026-09-17**, after the parser phase was declared complete. Fourteen
rules exist, all written against the original seven families. This section
maps every one of the **38 named families** to what a rule against it would
have to claim, before any new rule YAML is written. It is B's half of the
handoff to A, who owns `rules/**` (`rules/schema.md` section header) — nothing
here is a committed rule, and A should review this section before any new file
lands in `rules/atomic/` or `rules/correlation/`.

### 6.1 A structural finding that shapes every rule below

`entity.exe_name` — the join key correlation rules use — is resolved by
`core/entity.exe_name()`: it prefers `details["path_basename_canonical"]`
(only `prefetch.py` sets this), and falls back to the last path component of
`event.path`. **Measured directly on `s1_v3`** (453,082 events):

    family           keyed / total     family           keyed / total
    recyclebin         1 /     1       mft           349,870 / 351,088
    usn            29,304 / 29,655     lnk                37 /     37
    jumplist           32 /    34      services          621 /   621
    shimcache          218 /   218     scheduled_task    106 /   222
    evtx.* (ALL curated + generic)                          0 / every family
    sam, lsa_policy, registry_txlog                          0 (correctly --
                                                    these are not executables)

**The generic fallback works for file/path-shaped families** — deletion,
creation, rename, presence — because their `path` is already a filesystem
path. **It structurally cannot work for EVTX**, because `_path_for()` in
`evtx_windows.py` only extracts a path for two EIDs (4688, 7045) out of
every curated and generic channel combined. A rule joining a PowerShell
script block (4104), a Defender verdict (1116/1117), a firewall change
(2004-2033), a BITS transfer, or any generic `evtx.x.*` record to an
execution or deletion **cannot use `entity.exe_name`** — only `entity.user`,
where the record names one.

This is not a defect to fix before writing rules: `_path_for` extracting a
path from `4104`'s `Path` field (the script's originating file, already kept
in `details`) or from a BITS transfer's remote URL would be a real
enhancement, but it changes what `evtx_windows.py` emits, which is scored
against `docs/contract-decisions.md` and `tests/`. It is called out here as a
**scoping fact**: any rule chaining an EVTX step must join on `entity.user`
or run non-windowed (name/value match without an entity join), and a chain
that assumes it can join EVTX on `exe_name` will pass validation and match
zero rows forever, which is D-041's exact shape.

### 6.2 Structural rule pattern per family, by attestation shape

Per `rules/schema.md`, a family is either **windowed** (`timestamp_type:
recorded` — the timestamp is when the thing happened, safe to put in a
`steps[].in_window` chain) or **presence** (the timestamp is a container's
last-write or a copied property, and correlating on interval would claim a
sequence the artefact does not establish). `MIXED_TIMESTAMP_TYPE` families
carry both and need a `timestamp_type equals` guard on the step.

Confirmed directly against `rules/validate_rules.py`'s own
`TIMESTAMP_TYPE_BY_ARTIFACT` dict — the table the validator enforces, not
re-derived from Section 1's prose:

| Timestamp shape | Families | Rule pattern |
|---|---|---|
| `recorded` (windowed) | evtx.\* (all curated + generic), usn, recyclebin, srum, timeline, browser, defender_mplog, webcache (mixed) | atomic or correlation `steps[].in_window` |
| `presence` (not windowed) | registry, services, sam (mixed), userassist (mixed), recentdocs, typedpaths, runmru, lnk, shellbags, mft, ntfs_logfile, txf_pending, lsa_policy, registry_txlog, scheduled_task, amcache, shimcache, ps_history, **jumplist** | atomic-with-discriminator, or a non-windowed corroboration step anchored to a `recorded` family |

`jumplist` is `presence` in the validator's own dict (confirmed by direct
grep, not by re-deriving it): `automaticDestinations` carries no per-entry
time in the container itself, only the embedded LNK's copied FILETIMEs, which
describe the target and not the open. `browser_profile` is not a distinct
entry — it shares `browser`'s registration and `browser`'s `recorded` type.

### 6.3 Per-family worst-case outcome and status

Every row states: the worst-case bad thing the family could attest to, the
join key a rule needs, and whether that is measured-safe, needs a
discriminator (D-040's rule: a bare name/ID list on a high-volume family is
noise, not detection), or is genuinely not-yet-coverable and why.

**Already covered (existing 9 atomic + 5 correlation rules, unchanged):**
evtx.security (logon/process_exec/account_created/log_cleared), evtx.system
(service_install), registry (persistence_autorun), browser (file_download),
evtx.powershell (script_block), evtx.wmi (wmi_subscription), evtx.rdp
(rdp_session).

**Deletion / execution correlation (join key confirmed working, `exe_name`, 95-100% keyed):**

| Family | Worst case | Join | Status |
|---|---|---|---|
| recyclebin | payload deleted itself post-execution | exe_name → prefetch/bam/shimcache exec | **write**: `file_deleted` joined to a prior `process_exec` of the same name is the strongest new correlation available — it is literally the scenario's own behaviour on both hosts |
| usn | file created+deleted+renamed with no Recycle Bin entry (shift-delete, self-cleanup) | exe_name → prefetch/bam exec, OR usn `file_created` → usn `file_deleted` same name, short interval | **write**, same shape as above; also close the D-027-style "created then immediately deleted" self-cleanup pattern USN alone can see |
| mft | a deleted file's `$SI`/`$FN` timestamps (no verdict — D-051) | exe_name → prefetch/bam exec, for corroboration only | **context-only.** No independent bad outcome mft can assert alone after D-051; useful as a corroborating step in a chain anchored on usn/recyclebin, not as an anchor itself |
| ntfs_logfile | a name appeared in the log window usn has already rolled past | none (presence, name-match only) | **context-only**, and must say so in the rule's `ambiguity_ack`: a recovered name can be a truncated suffix (stated limit); usable to say "this name was present," never "this name and only this name" |
| lnk, jumplist | a file was opened from a **removable volume** the rest of the corpus never mentions (measured: `s1_v2`'s serial `18334A83`/`JOE`) | none needed — atomic on `lnk_location` shape predicate (`removable`/`drive_type`) | **write**: atomic rule, shape predicate on drive type, no discriminator problem — removable-media opens are rare enough on clean hosts to measure directly (CD-013 reopened this) |

**Persistence (needs shape predicates — plain name lists fail D-040):**

| Family | Worst case | Join | Status |
|---|---|---|---|
| scheduled_task | a task whose action executes from a user-writable path, or whose COM handler has no resolvable name | none (presence); shape predicate on `details.command`/`action` path | **write**: shape predicate `is_user_writable`-style regex on the action path, same pattern as R-ATOMIC-0001. 222 tasks on s1_v3 — a bare rule fires on all of them |
| services (SYSTEM) | a service whose ImagePath is user-writable or unsigned-looking | none (presence); shape predicate | **write**, same pattern; 621 rows demand a discriminator, not a name |
| registry (DEFAULT hive) | an autorun that `runs_as: SYSTEM` for a non-well-known account | none; shape predicate on `details.runs_as` | **write**: this is the one persistence family where the discriminator is already sitting in `details` from this session's work |
| shellbags | folder browsed under a removable volume since detached | none; shape predicate on ancestry | **defer**: measured 13-14 rows per host; too sparse to calibrate a base rate yet, flag as context-only until more collections exist |
| runmru, typedpaths, recentdocs, userassist | GUI-launched command/path — corroboration only, never an anchor | exe_name (partial coverage — 42-50 of ~46-55 keyed) | **context-only**: these corroborate an execution or persistence chain (their stated role in Section 1); a standalone rule on "a command was typed" has no bad/good distinction to make |

**Account / privilege — join key form measured, and it blocks most of this batch:**

`entity.user_key()` case-folds the raw `Event.user` string; it does not resolve
a SID to the account that owns it, and no such resolver exists anywhere in
this pipeline (checked: `grep -rn "sid_to_name\|resolve_sid"` finds nothing).
Measured on `s1_v3`:

    family          user form                                     keyed
    sam             account name ('administrator', 'vboxuser')     5/5
    evtx.security   4720 TargetUserName -- account name             1/12 (rest are 'SYSTEM', excluded by design)
    bam             raw SID string ('s-1-5-21-...-1000')           47/47
    lsa_policy      raw SID string ('s-1-1-0', 's-1-5-32-544')     13/13
    registry_txlog  none -- user is None on every record             0/22

**`sam` and `evtx.security` 4720 are both name-form and join correctly.**
`lsa_policy` and `bam` are SID-form and **do not join to sam or 4720 on
`entity.user` as it exists today** — `'vboxuser' != 's-1-5-21-...-1000'`, so a
chain assuming that join would pass validation and match zero rows forever
(D-041's exact shape). Resolving a SID to the account name that owns it needs
either a SID→name table built from `sam`'s RID (`details["rid"]`) plus the
domain/well-known prefix, or a runtime join on the numeric RID suffix — both
are parser/engine changes, not rule changes, and neither exists yet.

| Family | Worst case | Join | Status |
|---|---|---|---|
| sam | an account created and never logged on (`logon_count: 0`, still true at collection time — not "used shortly after creation," which is self-contradictory) | entity.user → evtx.security account_created (4720); both name-form, confirmed joinable | **write**: correlation chain, non-windowed sam step (presence) anchored to a windowed 4720. `testuser` on `clean_b` (created 2026-08-24, per Section 1) is the base-rate check — measure its `logon_count` before setting the condition |
| sam (standalone) | RID ≥ 1000 with `password_not_required`, or an admin-flagged account with `logon_count: 0` | none — shape predicate on the family alone, no join needed | **write**: atomic rule directly on `details.rid`/`details.account_flags`/`details.logon_count`; measure the rate on all three clean-host SAM hives first (5 accounts each on `s1_v3` is the full population, not a sample) |
| lsa_policy | a privilege granted to a non-well-known SID | entity.user → sam / 4720 | **do not write as proposed.** SID-form vs. name-form blocks this join today (above). Either write lsa_policy as a **standalone shape rule** (SID not in a well-known-SID list, checkable without any join) or defer until a SID→name resolver exists |
| registry_txlog | log ahead of hive by an unusual margin | none (user is never populated — confirmed 0/22) | **do not write.** Measured 21/27 ahead on a CLEAN host, up to 933 KB. No safe threshold exists without a larger corpus; write it up as stated non-coverage |

**EVTX, curated — every base rate below is now measured across all five collections, not assumed:**

| Family/EID | Worst case | Join | Status |
|---|---|---|---|
| evtx.defender 5001/5007 | real-time protection disabled / reconfigured | none (no user field kept) | **write as a zero-base-rate atomic rule, confirmed measured**: `defense_disabled`, `malware_detected`, `malware_remediated` are **absent from the event stream on all five collections** (re-run 2026-09-17, `collect_events` per collection, `Counter` over `event_type`) — same precedent as R-ATOMIC-0004 |
| evtx.defender 1116/1117 | AV verdict on a named threat | none directly; corroborate against defender_mplog `file_reported` on path/time proximity | **write**: atomic on 1116 alone (a real verdict is never noise) — untested against a real detection in this corpus (also 0/5), so `expected:` states 0 explicitly rather than implying it was exercised |
| evtx.firewall 2004-2006, 2033 | a rule added/changed/deleted, or all rules cleared | none | **do not write any atomic rule on this channel as a standalone.** `firewall_rules_deleted` (2033) measured **4, 4, 12, 10, 17** across clean_a/clean_b/s1_v2/clean_c/s1_v3 — the two SCENARIO hosts are not distinguishable from the two CLEAN hosts by count alone (12 and 17 vs. 4 and 10 — same order of magnitude), so 2033 is **not** the discriminating EID it was assumed to be before this was measured. Corroboration-only, or needs a shape predicate (e.g. rule count deleted in one burst) not yet available in `details` |
| evtx.ps_classic 400/403/600 | — | none; `details` is empty on every row | **blocked, not context-only (D-055).** The channel was taken because EID 600 holds `HostApplication`; the parser never extracts it, so there is no field for a rule to read. Extracting it is a parser change requiring a `details` key declared under CD-012 first. Until then this family can only contribute "PowerShell ran at time T", which `evtx.powershell` and `prefetch` already carry |
| evtx.winlogon 811/812 | corroborates a logon the Security log no longer has | none — the only principal on the record is `S-1-5-18` (SYSTEM), never the user | **blocked, not context-only (D-057)**: `SubscriberName` and `Event` are on every raw record and dropped by the parser, so 1,913 rows carry `details == {}`. Whether the channel discriminates cannot be measured until it emits its fields |
| evtx.bits | a background transfer with no browser history | none — `details` is empty on every row | **blocked (D-065), not writable as previously stated.** This row said the destination was "usually not recoverable from this record alone"; measured, EID 59 carries both `url` and the full destination path and the parser discards them. A `keep` tuple plus a CD-012 declaration makes this the strongest download evidence in the pipeline |
| evtx.x.\* (88 generic) | anything — by construction, unstudied | none, deliberately | **do not write per-channel rules.** Promoting a generic channel to a rule target means promoting it to a curated EID map first (a parser change, not a rule change) — writing a rule against raw `log_record` invents semantics CD-007 explicitly declines to assert. This boundary is stated here rather than silently skipped, per the standing instruction against filtering by judgement without saying so |

**`defender_mplog` scan_skipped/av_service_started, measured rather than assumed:**

`scan_skipped` fires with **identical PIDs (6652, 7368, 1992) across three
separate collections** (`clean_a`: 27, `clean_b`: 31, `s1_v2`: 49) — standing
Windows Defender internal exclusions on host 1, not incident-specific, and
**this is a host-1-only pattern**: `clean_c` and `s1_v3` (host 2) report
**zero** `scan_skipped` rows. That asymmetry itself was not stated before
measuring and belongs in the family's row: a rule counting `scan_skipped`
volume would be scoring host identity, not behaviour, exactly the trap
`hour_of_day` fell into for the anomaly layer. No adversarial shape (a skip
whose reason names a path under a normal user profile rather than a system
exclusion) has been measured on any collection — that specific shape, if it
existed, would be T1562.001 and worth a rule; it has not been looked for by
`scan_skipped`'s `details.path` field yet, because the field is `None` on
every sampled row (Defender's own log omits it for this EID). Status
unchanged: not yet coverable, correctly stated as unsurveyed rather than
"benign."

**Genuinely not coverable yet, stated rather than omitted:**

- `txf_pending` — non-zero on exactly one collection (`s1_v3`) out of five; a
  rule here would be corpus-fitted to this project's own scenario host, the
  practice the user rejected earlier this project ("STOP... I need coverage").
  Needs a second scenario with a different CBS-transaction shape before a
  worst-case claim can be written safely.
- `amcache` — D-028 already establishes it holds no record of the one
  execution this corpus has; a rule here has nothing to calibrate against and
  none is proposed.
- `defender_mplog` `scan_skipped`/`av_service_started` — service lifecycle
  and scan-skip reasons observed so far are all benign (disk space, exclusion
  list); no adversarial shape has been measured on any collection.

### 6.4 Widening the EXISTING rules is the cheapest coverage available

The 14 existing rules each `select` a single `source_artifact`, chosen when
seven families existed. Several of the families added since make **the same
claim** the rule already tests — and on the scenario hosts they are often the
ONLY families still carrying it, because the rule's chosen channel was
cleared.

**R-ATOMIC-0001 (process executed from a user-writable location), measured on
`s1_v3` against the rule's own six regexes:**

    source_artifact   rows with a path   matching user-writable
    evtx.security                    0                        0   <- selected
    bam                             47                       12
    lnk                             37                       17
    amcache                        522                       10
    shimcache                      218                        3
    services                       621                        0
    prefetch                      1014                        0

**The rule's selected family carries zero path-bearing rows on this host** —
the Security log was cleared, exactly as the rule's own `false_positive_notes`
predicted. Four other families carry 42 rows between them that its regexes
match today, and `bam` additionally supplies the SID that 4688 would have.

Widening `select.source_artifact` to `bam` is the single highest-value change
available, and it is nearly free: `bam` already emits `process_exec`, the same
event_type, and carries a full `\Device\HarddiskVolumeN\...` path.
`shimcache` and `amcache` need their event_types (`program_shimcached`,
`program_inventoried`) added to `select.event_type` as well, and both are
`presence` — fine for an atomic rule, and they must NOT be dropped into a
windowed correlation step.

**`prefetch`, `userassist` and `timeline` must stay excluded**, and the reason
is the one R-ATOMIC-0001's `notes` already gives for prefetch: their `path` is
not a path. Measured — `prefetch`: a bare executable name (`7ZG.EXE`);
`userassist`: a shell AppID (`Microsoft.Getstarted_8wekyb3d8bbwe!App`);
`timeline`: a package moniker (`Microsoft.Windows.Explorer`). Every
path-shaped regex evaluates false against all three, **silently**, which is
the failure this rule already documents for one family and would acquire for
three more. `defender_mplog` is mixed: its `file_reported` rows carry full
paths (130/130) and its `process_exec` rows carry bare names (`explorer.exe`)
— only the former is safe to select.

**Other widenings, with the measurement that justifies or blocks each:**

| Rule | Widen to | Status |
|---|---|---|
| R-ATOMIC-0001 | `bam` (`process_exec`) | **do** — same event_type, full paths, 12 matching rows, and supplies the SID 4688 cannot |
| R-ATOMIC-0001 | `shimcache`, `amcache`, `lnk` | **do, with event_type added** — 30 matching rows between them; all `presence`, so atomic only |
| R-ATOMIC-0001 | `prefetch`, `userassist`, `timeline` | **do not** — `path` is a name/AppID, not a path; regexes fail silently |
| R-ATOMIC-0003 | `ps_history` (`command_typed`) | **do** — `path` holds the typed command text, matchable by the same content regexes; `presence`, so atomic only, and note the absent timestamps |
| R-ATOMIC-0003 | `evtx.ps_classic` | **blocked by D-055** — `details` is empty on every row; nothing to match |
| R-ATOMIC-0004 | `services` (`service_registered`) | **do** — 621 rows vs. the ~16-23 `service_install` events 7045 carries, and `services` survives a System-log clear. Zero currently match the rule's patterns, so this widening is expected to stay at 0/5: that is a coverage gain (the claim is now tested against the registry too), not a detection gain |
| R-CORR-0001 download step | `webcache` (`background_transfer`, 20 rows on `s1_v3`) | **do** — an OS-performed transfer that leaves no Chromium history |
| R-CORR-0001 download step | `evtx.bits` | **blocked until D-065 is fixed.** The event_types are `bits_transfer_started`/`bits_transfer_completed`, not `background_transfer` — but the family carries no `details` at all, so a download step selecting it would match rows that cannot name a file. Widen after the parser emits `url` and `name` |
| R-CORR-0001 exec step | `bam`, `userassist` | **`bam` yes** (`process_exec`, joins on `exe_name`). **`userassist` yes for the join only** — its `exe_name` keys 50/55 despite the path not being path-shaped, because the AppID's last component still basenames cleanly; it must not be given a path-shaped condition |

Every widening above changes an existing rule's `expected:` block, so each
must be re-measured across all five collections before the change lands — a
widened rule that fires more on clean hosts than on scenario hosts is a
finding to report, not a rule to keep.

### 6.5 Before any rule in 6.3 is written

1. Re-run `tools/rule_harness.py` against all five collections per batch, not
   per rule — a batch that changes the `clean_c` rule-entity count from 6 to
   30 is itself a finding to report, same as `docs/evidence/ml-stage-record`
   tracks for the anomaly layer.
2. Re-run the layer-ablation check after each batch. The two headline numbers
   this project stands on — rules 1/5, both hosts 1/976 — must be re-measured,
   not assumed to hold.
3. Every `expected:` block is measured against the corpus before being
   written, per the project's standing rule — scope first (this section),
   measure second.
4. `CLAUDE.md`'s `rules 14` gate line and `tests/test_ruleset_agrees_with_validator.py`
   move with every rule added.
