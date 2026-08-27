# Scenario 1 ground truth

**Collection:** `collection_s1_v2` — HTTP delivery, recollected 2026-08-23.
**Where this file lives:** HOST. Never edited inside the victim VM.
Open questions remaining after Week 1 are recorded in docs/open-questions.md.

---

## Why this is the second collection

The first Scenario 1 collection delivered `invoice_scan.exe` by USB, because the host HTTP server could not be reached from the guest.

Root cause was a VirtualBox host-only misconfiguration: the DHCP pool issued `192.168.56.x` addresses while the host adapter was configured on `192.168.50.x`, so the guest received a valid-looking address with no route to the host. Nothing errored at any layer — the failure presented as an application fault in the Python HTTP server and was misdiagnosed as such.

**Consequence of the USB delivery:** no browser history entry, no `Zone.Identifier` alternate data stream, no download timestamp. The `download → execution` sequence rule, named in the concept note as the core contribution, had nothing to correlate on.

**Scope decision (CD-013):** USB-based initial access (ATT&CK T1091) is out of scope. Reconstructing it requires `USBSTOR` registry and `setupapi.dev.log` parsing, neither of which is among the seven declared artifact families. Removable-media delivery is recorded in Future Work.

This collection delivers the binary over HTTP through Edge, producing artifacts inside the declared scope.

---

## Environment

**Network — host-only, no internet route.**

```
Host (serving)  : 192.168.50.2
Guest (victim)  : 192.168.50.1
Mask            : 255.255.255.0
No default gateway on either interface.
```

Confirmed by two independent records: the host's HTTP server logged the request from `::ffff:192.168.50.1`, and the downloaded file's `Zone.Identifier` records `HostUrl=http://192.168.50.2:8000/invoice_scan.exe`.

Server command on the host:
```powershell
python -m http.server 8000
```

**Accounts on the victim VM**

| Account | Role in Scenario 1 |
|---------|--------------------|
| `janed` | Browser download, execution, HKCU Run persistence |
| `admin_local` | `wevtutil cl security`, elevated PowerShell for KAPE |
| `Youssef` | Researcher account. Not an actor in this scenario. Present in the evidence with its own Edge profile — see Limitations |

**Decoy binary**

Pending confirmation (OQ-001). The identity of the binary present for the
2026-08-23 run is not established by the collected evidence. The description
below is retained pending the Week 2 MFT parser. See docs/open-questions.md.

A purpose-built benign stand-in, **not** a renamed `notepad.exe`. On execution it prints:

```
Invoice scan utility - benign lab stand-in
Marker: C:\Users\janed\AppData\Local\invoice_scan_marker.txt
Holding 20s so the process is easy to observe...
```

It writes a marker file and holds for 20 seconds so the process is observable in Task Manager and produces a clean Prefetch record. The marker file is an additional verifiable artifact: its existence and creation time independently corroborate the execution step.

From the artifacts' point of view this is an unknown binary downloaded from a remote host and executed out of `Downloads\`, which is the evidence pattern the project targets. The claim made in the report is narrow — it reproduces the download, execution and persistence metadata. It is not claimed to be equivalent to real malware.

---

## Log-clear consequence — stated before the operator log

`wevtutil cl security` wipes the Security log only. The process-creation **4688** for `invoice_scan.exe`, and everything else in that log, is **not** present in `Security.evtx` afterwards. Other EVTX channels were not cleared. The anti-forensic action was therefore partial.

Browser history, `Zone.Identifier`, Prefetch, the registry Run key, MFT and USN
all survive the log clear on the live system. Surviving the clear and being
present in the collection are separate questions: `Zone.Identifier`
nonetheless falls outside the KAPE collection scope (see "Collection scope and
artefact evaluability" below).

**A missing 4688 is not a parser fault.** It is the intended outcome and the reason cross-artifact correlation matters: Prefetch and Amcache still prove execution after the Security log is cleared.

---

## Operator log (UTC)

Timestamps captured on the **host** with:
```powershell
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
```

| # | UTC | Machine | Actor | Action |
|---|-----|---------|-------|--------|
| 1 | `2026-08-23T22:45:32.274977Z` — **SUPERSEDED, see note below** | victim VM | `janed` | **Download** `http://192.168.50.2:8000/invoice_scan.exe` in Edge → `C:\Users\janed\Downloads\invoice_scan.exe` |
| 1c | `2026-08-23T22:20:06.710763Z` — **corrected 2026-08-26** | victim VM | `janed` | Same action. Time taken from the guest's own Edge `History`, `downloads` row id 13, `start_time` |
| 2 | `2026-08-23T22:57:22.536771Z` | victim VM | `janed` | **Execute** by double-clicking in Explorer |
| 3 | `2026-08-23T22:59:54.543367Z` | victim VM | `janed` | **Persist** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate` |
| 4 | `2026-08-23T23:05:12.794670Z` | victim VM | `admin_local` | **Log clear** — `wevtutil cl security` |

**Note on row 1, added 2026-08-26.** The original operator-log entry is retained
above and is not deleted. It is superseded by evidence from the guest, and the
correction is recorded rather than applied silently, because the audit trail of
a ground-truth correction is itself part of the methodology.

The guest's Edge `History` database, read directly from `collection_s1_v2`,
contains exactly one download on 2026-08-23: `downloads` row id 13,
`target_path` `C:\Users\janed\Downloads\invoice_scan.exe`, `tab_url`
`http://192.168.50.2:8000/invoice_scan.exe`, `total_bytes` 4,608, `state` 1,
`start_time` `2026-08-23T22:20:06.710763Z`, `end_time` `2026-08-23T22:20:07.324360Z`.
The operator log's entry is late by 25m 25.6s.

That this is a transcription error on one entry, and not a clock problem, is
shown by the two other entries that can be checked independently:

| Operator-log entry | Operator log (host) | Independent evidence (guest) | Late by |
|---|---|---|---|
| 1 · download | 22:45:32.274977Z | 22:20:06.710763Z — Edge `downloads` id 13 | **1,525.56 s** |
| 2 · execute | 22:57:22.536771Z | 22:57:15.832787Z — Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf` slot 0 | 6.70 s |
| 4 · log clear | 23:05:12.794670Z | 23:05:06.682356Z — EID 1102, EventRecordID 28,201 | 6.11 s |

Two entries agree with guest evidence to within 6.1–6.7 s, the uncalibrated
host-to-guest offset that the ±60 s tolerance in
`groundtruth/verification-method.md` exists to absorb. Entry 1 is out by a
factor of roughly 250. The most economical explanation is that the download time
was written down after the fact rather than at the moment; no other entry
behaves that way.

**Intervals, corrected:** download → execute **37m 09.1s** · execute → persist
2m 32s · persist → log clear 5m 18s. **Total span 44m 59.97s**, measured from
the Edge download `start_time` to the EID 1102.

**Intervals as originally recorded, retained:** download → execute 11m 50s ·
execute → persist 2m 32s · persist → log clear 5m 18s. Total span 19m 40s. The
last two are unchanged, because both endpoints of each are operator-log entries
carrying the same offset.

The gaps are deliberate. Every step falling within the same second would leave the timeline unable to demonstrate ordering, and ordering is what the sequence rules detect.

**Commands as executed**

Persistence:
```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /V SecurityUpdate `
  /t REG_SZ /d "C:\Users\janed\Downloads\invoice_scan.exe" /f
```

Log clear:
```powershell
wevtutil cl security
```

---

## Download verification

Performed immediately after step 1, before the scenario continued:

```powershell
Get-Content C:\Users\janed\Downloads\invoice_scan.exe -Stream Zone.Identifier
```

```
[ZoneTransfer]
ZoneId=3
HostUrl=http://192.168.50.2:8000/invoice_scan.exe
```

`ZoneId=3` is the Internet zone. This verification was performed on the live
guest immediately after the download, before the scenario continued. It is
evidence that HTTP delivery succeeded on the guest at collection time. The
first USB collection lacked this stream; its presence on the live guest is why
this recollection was kept. The stream itself is not present in
`collection_s1_v2` (see "Collection scope and artefact evaluability" below).

`HostUrl` additionally records the source URL, which independently corroborates the delivery method.

**Resolved 2026-08-26 — OQ-003 is closed.** The apparent contradiction was that
PowerShell 4104 EventRecordID 1597 and 1602 show the `Zone.Identifier` of the
downloaded file being read at 22:38:27Z and 22:38:44Z, seven minutes *before*
the operator log's download time of 22:45:32Z, and an alternate data stream
cannot be read from a file that has not been downloaded.

The contradiction was in the operator log, not in the evidence. The download
completed at 22:20:07.324360Z. The `Zone.Identifier` reads therefore fall
eighteen minutes *after* it, which is the expected order:

    22:20:06.710763Z  download starts                (Edge downloads id 13)
    22:20:07.324360Z  download completes, 4,608 bytes
    22:38:27.274684Z  Zone.Identifier read, typo     (4104 EventRecordID 1597)
    22:38:44.710217Z  Zone.Identifier read, retry    (4104 EventRecordID 1602)
    22:57:15.832787Z  execution, run count 1         (Prefetch)
    23:05:06.682356Z  Security log cleared           (EID 1102, EventRecordID 28,201)

See row 1 above and docs/open-questions.md, OQ-003.

The download was performed in **Edge**, not via PowerShell. `WebClient.DownloadFile` and `Invoke-WebRequest` are .NET calls that leave no browser history and no UserAssist entry.

---

## Expected artifacts

| Step | Actor | Path / locator | Expected artifacts |
|------|-------|----------------|--------------------|
| download | `janed` | `C:\Users\janed\Downloads\invoice_scan.exe` | Edge History, MFT, `Zone.Identifier` (ZoneId=3; out of collection scope - `C\Users\janed\Downloads` absent from tree, ADS not collected) |
| execute | `janed` | same | Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf`, Amcache, UserAssist, marker file, 4688 **then destroyed** |
| persist | `janed` | `HKCU\...\CurrentVersion\Run\SecurityUpdate` | `NTUSER.DAT` Run key |
| logclear | `admin_local` | `Security.evtx` | EID 1102; destroys the prior 4688 |

The chain this collection supports:

```
Edge History  →  Prefetch  →  Registry Run  →  EVTX 1102
  download        execute       persist        anti-forensics
```

Four artifact families, three cross-boundary links.

---

## Collection

```powershell
Z:\kape\KAPE\kape.exe --tsource C: --target KapeTriage --tdest Z:\collection_s1_v2
```

This is EventRecordID 28,777 and 28,784. EventRecordID 28,674 used `--tsource Z:`.

| | |
|---|---|
| KAPE version | 1.3.0.2 |
| Target set | `KapeTriage` (identical across all three collections) |
| Output format | plain directory, no `--vhdx` |
| Session account | `admin_local`, elevated |
| Files found | 1,127 |
| Files copied (CopyLog rows = C\ subtree) | 814 (313 deduplicated) |
| Duration | 293.68 seconds |
| **Files on disk (recorded at collection; equals SHA-256 manifest rows)** | **793** |
| Full tree (host) | 817 |
| CopyLog | `2026-08-23T23_31_48_7980143_CopyLog.csv` |

No `--vhdx`: the pipeline walks a directory tree and cannot enter a container file.

Deduplication is normal KAPE behaviour — byte-identical files are copied once.

---

## Verified present in the collection

**Browser history** — the artifact the recollection existed to obtain:
```
C\Users\janed\AppData\Local\Microsoft\Edge\User Data\Default\History
C\Users\janed\AppData\Local\Microsoft\Edge\User Data\Default\History-journal
C\Users\admin_local\AppData\Local\Microsoft\Edge\User Data\Default\History
C\Users\Youssef\AppData\Local\Microsoft\Edge\User Data\Default\History
```

**Execution artifact:**
```
C\Windows\prefetch\INVOICE_SCAN.EXE-A345C2FE.pf
C\Windows\AppCompat\Programs\Amcache.hve
```

The hash portion of a Prefetch filename derives from the executable's **full path**. The path is unchanged from the first collection (`C:\Users\janed\Downloads\invoice_scan.exe`), so the hash is identical. This is expected, not a sign of stale evidence.

---

## Real KAPE path shapes

Layout is a **flat `C\`** — no hostname or timestamp prefix. `winevt\logs` and `prefetch` are **lowercase**, not the capitalised forms the planning documents assumed. Person B's `can_handle()` rules lowercase before matching, so casing is not relied on, but the shape is confirmed against real evidence.

```text
collection_s1_v2\C\Windows\prefetch\INVOICE_SCAN.EXE-A345C2FE.pf
collection_s1_v2\C\Windows\System32\winevt\logs\Security.evtx
collection_s1_v2\C\Windows\System32\winevt\logs\System.evtx
```

One `Op-` prefixed file exists in the Prefetch directory (`Op-EXPLORER.EXE-*.pf`). These are SysMain operational files with a different internal structure, not standard Prefetch records. Person B's parser excludes them deliberately.

---

## Evidence destroyed by the log clear

The actor cleared the Security log only. The collection contains 118 .evtx
channels. 106 hold at least one pre-clear record, or 105 excluding Security
itself (whose single pre-clear record is the 67 ms write-ordering artefact
below). The convention used here is 106, including Security. The
anti-forensic action was therefore partial.

Microsoft-Windows-PowerShell/Operational holds 1,470 records predating the
clear, of which 1,231 are EventID 4104 script block logging. The 4104
records include the download commands, the Zone.Identifier inspection and
the `reg add` persistence command in plaintext. Application holds 3,927
pre-clear records; System holds 2,579.

Cited EventID 4104 records from
`Microsoft-Windows-PowerShell%4Operational.evtx` in `collection_s1_v2`:

| EventRecordID | TimeCreated | Command |
|---|---|---|
| 1597 | 2026-08-23T22:38:27.274684Z | Get-Contetn ... -Stream Zone.Identifier (typo in original) |
| 1602 | 2026-08-23T22:38:44.710217Z | Get-Content C:\Users\janed\Downloads\invoice_scan.exe -Stream Zone.Identifier |
| 1604 | 2026-08-23T22:59:48.314316Z | reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /V SecurityUpdate ... |

Facts from `collection_s1_v2` Security.evtx: 584 records, EventRecordID range
28,201 to 28,784. The EID 1102 log clear is first by EventRecordID
(28,201), 2026-08-23T23:05:06.682356Z, SubjectUserName `admin_local`. One
further record carries a TimeCreated of 2026-08-23T23:05:06.614816Z, 67 ms
earlier - a sub-second write-ordering artefact. No record predates the clear
by any meaningful interval. janed has zero EID 4624 and zero EID 4688 in this
collection.

janed's download, execution and persistence all predate the Security log
clear. They leave no trace in Security.evtx, while remaining evidenced in
other EVTX channels (see the 4104 records above) and elsewhere in the
collection:

- `C\Users\janed\AppData\Local\Microsoft\Edge\User Data\Default\History`
- `C\Windows\prefetch\INVOICE_SCAN.EXE-A345C2FE.pf`

Post-clear EID 4688 SubjectUserName breakdown:

| EID 4688 SubjectUserName | Count |
|---|---|
| `WINDOWS10$` | 247 |
| `admin_local` | 39 |
| `-` | 11 |
| `LOCAL SERVICE` | 2 |

EID 4624 post-clear totals 58 records, entirely SYSTEM and service accounts
plus `admin_local` twice. janed appears in neither.

### Why this matters

A single `wevtutil cl Security` at 2026-08-23T23:05:12.794670Z destroyed the
entire Security-log record of initial access, execution and persistence: the
4688 for `invoice_scan.exe` is gone, and the 359 records that survive are the
post-clear collection window, in which `janed` does not appear at all. Every one
of those actions nonetheless remains recoverable from other artefact families --
arrival from Edge `History` at 22:20:06.710763Z, identity and size from the
`downloads` record, execution from Prefetch at 22:57:15.832787Z with a run count
of 1, and effect from the Prefetch referenced-file list naming
`INVOICE_SCAN_MARKER.TXT` -- which is the case for multi-artefact triage made on
collected evidence rather than asserted: an adversary who clears one log has
cleared one log, not the record.

Two honest qualifications. The clear was Security-only, not a destruction of the
EVTX record as such; 106 of the 118 collected channels retain pre-clear entries,
and `Microsoft-Windows-PowerShell/Operational` alone holds 1,470 of them. And
Week 1 parses none of the families that carried the reconstruction, so those
ground-truth rows are marked `NOT-PARSED` and the chain above was rebuilt by
hand on 2026-08-26. The pipeline does not yet demonstrate this; the evidence
does, and Week 2 adds the parsers that would let the pipeline show it.

---

## Collection scope and artefact evaluability

`Zone.Identifier` is recorded in this file as verified at ZoneId=3. It is not
present in the collection. Verified by search:

| Claimed artefact | In collection_s1_v2? |
|---|---|
| Edge browser history (janed) | Yes |
| Prefetch INVOICE_SCAN.EXE-A345C2FE.pf | Yes |
| invoice_scan.exe binary | No |
| Zone.Identifier alternate data stream | No - zero ADS found under C\Users |
| Download LNK | No |

Cause: `C\Users\janed\Downloads` is absent from the collection tree entirely.
KapeTriage targets declared artefact paths, not user data directories, so the
binary and its alternate data stream were verified live in the guest but never
entered the collection.

`$MFT` is present in this collection (`C\$MFT`). Alternate data streams are
recorded in MFT attributes, so Zone.Identifier may remain recoverable from
`$MFT` even though the file itself was not collected. This is a possibility to
be confirmed by the Week 2 MFT parser, not an established fact.

---

