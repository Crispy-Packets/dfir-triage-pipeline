# Scenario 1 ground truth

**Collection:** `collection_s1_v2` — HTTP delivery, recollected 2026-08-23.
**Where this file lives:** HOST. Never edited inside the victim VM.

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

`wevtutil cl security` wipes the Security log. The process-creation **4688** for `invoice_scan.exe`, and everything else in that log, is **not** present in `Security.evtx` afterwards.

Browser history, `Zone.Identifier`, Prefetch, the registry Run key, MFT and USN all survive.

**A missing 4688 is not a parser fault.** It is the intended outcome and the reason cross-artifact correlation matters: Prefetch and Amcache still prove execution after the log is gone.

---

## Operator log (UTC)

Timestamps captured on the **host** with:
```powershell
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
```

| # | UTC | Machine | Actor | Action |
|---|-----|---------|-------|--------|
| 1 | `2026-08-23T22:45:32.274977Z` | victim VM | `janed` | **Download** `http://192.168.50.2:8000/invoice_scan.exe` in Edge → `C:\Users\janed\Downloads\invoice_scan.exe` |
| 2 | `2026-08-23T22:57:22.536771Z` | victim VM | `janed` | **Execute** by double-clicking in Explorer |
| 3 | `2026-08-23T22:59:54.543367Z` | victim VM | `janed` | **Persist** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate` |
| 4 | `2026-08-23T23:05:12.794670Z` | victim VM | `admin_local` | **Log clear** — `wevtutil cl security` |

**Intervals:** download → execute 11m 50s · execute → persist 2m 32s · persist → log clear 5m 18s. Total span 19m 40s.

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

`ZoneId=3` is the Internet zone. This is the artifact whose absence caused the first collection to be discarded, and its presence is the reason this collection exists.

`HostUrl` additionally records the source URL, which independently corroborates the delivery method.

The download was performed in **Edge**, not via PowerShell. `WebClient.DownloadFile` and `Invoke-WebRequest` are .NET calls that leave no browser history and no UserAssist entry.

---

## Expected artifacts

| Step | Actor | Path / locator | Expected artifacts |
|------|-------|----------------|--------------------|
| download | `janed` | `C:\Users\janed\Downloads\invoice_scan.exe` | Edge History, MFT, `Zone.Identifier` (ZoneId=3) |
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

| | |
|---|---|
| KAPE version | 1.3.0.2 |
| Target set | `KapeTriage` (identical across all three collections) |
| Output format | plain directory, no `--vhdx` |
| Session account | `admin_local`, elevated |
| Files found | 1,127 |
| Files copied | 814 (313 deduplicated) |
| Duration | 293.68 seconds |
| **Files on disk** | **793** |
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

