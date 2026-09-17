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
| **evtx.powershell** | script blocks, **capped at 4096 UTF-8 bytes** | the remainder of a longer block. A rule may read it with **positive operators only** — `not_contains` against a capped field asserts an absence the evidence cannot support | **D-031**; enforced by `validate_rules.py` | legacy `Windows PowerShell` EID 800 ⛔ |
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
| **browser** | a file was **downloaded**; its size, MIME type, source URL, target path | **page visits.** The parser reads `FROM downloads` only; `urls` and `visits` are never read | parser source; measured — browsing yields zero events | `Zone.Identifier` ADS ⛔, `$MFT` ⛔ |
| | | that the file was **executed** | — | Prefetch, Amcache |

⛔ = not parsed by this pipeline.

---

## 2. The corroboration graph

Read as: **if the left family is suppressed, the right families still attest.**

| Suppressed | Survives | What is still provable |
|---|---|---|
| `Security.evtx` cleared (EID 1102) | prefetch, amcache, registry, browser, **evtx.rdp**, evtx.powershell | execution, presence, persistence, arrival, remote sessions. **Measured on `s1_v2`: every step of the attack remained recoverable** |
| Prefetch disabled or purged | amcache, Shimcache, BAM | that the binary existed and was inventoried |
| Amcache stale or missing (D-028) | prefetch, `$MFT` ⛔ | that the binary ran, and when |
| Script-block logging off | legacy PowerShell EID 800 ⛔, prefetch | that PowerShell ran, and its `HostApplication` command line |
| Registry value deleted | prefetch, amcache | that the target ran, if it did |
| Browser history cleared | `Zone.Identifier` ADS ⛔, `$MFT` ⛔ | the source URL, via the ADS `HostUrl` |
| **A family's file deleted outright** | `$MFT` ⛔ | that the file existed and was deleted — **the only artefact that attests to its own deletion** |

### The structural property

**An adversary suppressing one family leaves the others intact.** That is not a
detection claim; it is a statement about what would have to be falsified
*consistently* for the evidence to lie. Seven families was the minimum for the
property to hold at all; the pipeline now parses **nineteen**.

**Measured on `s1_v2`:** a single `wevtutil cl security` destroyed the entire
Security-log record of arrival, execution and persistence — and all three
remained recoverable from browser history, Prefetch and the registry. That is
this document's thesis demonstrated on real evidence.

---

## 3. Where the map is incomplete, and why

**Updated 2026-09-17.** The SYSTEM hive (Shimcache, BAM, Services) landed in
62cb065; SAM, SRUM, scheduled tasks and the NTUSER Explorer keys landed today,
taking the pipeline from 7 families to **19** (18 of which appear in these
collections -- `typedpaths` parses but the key is empty on both hosts).
The ⛔ markers those closed have been cleared from the table above rather than
left standing — a matrix that understates what is parsed is as misleading as
one that overstates it.

### Closed since this document was written

| Family | Rows it closed | What it supplies |
|---|---|---|
| **SYSTEM hive** — `shimcache`, `bam`, `services` | 4 | Execution evidence when Prefetch is off; **the principal Prefetch cannot supply**; services when 7045 is gone. Demonstrated on `s1_v3`: BAM attributed `invoice_scan.exe` to `S-1-5-21-…-1000` 31 seconds after Prefetch recorded the same execution with no user at all |
| **SAM hive** — `sam` | 2 | Accounts and their logon counts after a Security-log clear. `s1_v3` retains **12** Security events and all five accounts |
| **SRUM** — `srum` | 4 | **Transfer volume**, which no other family carries. 6,179 rows on `clean_a`. Its own limits are now stated above rather than assumed: it did not record the scenario binary on either host, for two different and measured reasons |
| **Scheduled tasks** — `scheduled_task` | 4 | The **only** record that a task exists: 4698 is off by default and measures 0 across all five collections. Unlike services, there is no enabled-by-default event to fall back on. 222 events on `s1_v3`, of which 115 are COM actions with no command line at all |
| **NTUSER Explorer keys** — `userassist`, `recentdocs`, `typedpaths`, `runmru` | 6 | **Per-user execution and file access, attributed by construction.** On `s1_v2`, whose Security log was cleared, UserAssist names `janed` as the account that ran the payload 28 times — while Prefetch records the same execution, to the second, with no principal at all |

### Still collected and not parsed

| Unparsed family | Rows it would close | Why it matters |
|---|---|---|
| **`$MFT`** (361 MB in `s1_v3`) | 6 | The only artefact attesting to **file deletion** and **timestomping**. The only corroborator for a deleted family file. Needs streaming plus a SQLite index — see the feasibility study |
| **LNK / JumpLists** | 3 | File access including **removable media no longer present** — reopens CD-013 |

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
