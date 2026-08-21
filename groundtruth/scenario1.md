# Scenario 1 ground truth

**Where this file lives:** HOST (this PC). Do not edit it inside the victim VM.

**Victim VM accounts**

| Account | Role in Scenario 1 |
|---------|--------------------|
| `janed` | Login, copy notepad to share, browser download, double-click, HKCU Run `SecurityUpdate` |
| `admin_local` | `wevtutil cl Security`, Admin PowerShell for KAPE |
| `youssef` | Do **not** use for Scenario 1 |

**Decoy:** `notepad.exe` renamed `invoice_scan.exe` (not `calc.exe`). Persistence is **HKCU** as `janed`, not HKLM.

## Log-clear consequence (write this before you act)

`wevtutil cl Security` wipes the Security log. Process-creation **4688** for `invoice_scan.exe` (and everything else in that log) will **not** be in `Security.evtx` after this. Persistence, Prefetch, USN, and other artifacts remain. Do not treat a missing 4688 as a parser bug.

## UTC clock (host PowerShell)

```powershell
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
```

Or: `scripts\day2-stamp-utc.ps1` on the host. Fill the UTC column **as you perform** each row. Do not reconstruct times later.

## Operator log (UTC)

| UTC | Machine | Actor | Action | Notes |
|-----|---------|-------|--------|-------|
|  | host | operator | Restore `BASELINE-CLEAN+TOOLS` | VM was off |
|  | victim VM | `janed` | Boot / login | Not `youssef`, not `admin_local` |
|  | victim VM | `janed` | Copy `C:\Windows\System32\notepad.exe` → `Z:\invoice_scan.exe` | Confirm on host share |
|  | host | operator | `python -m http.server 8000` from the shared-folder path | Not inside the VM. Not `cd Z:\` unless the host also has Z: |
|  | victim VM | `janed` | Browser download `http://<HOST-ONLY-IP>:8000/invoice_scan.exe` | Dest: `C:\Users\janed\Downloads\invoice_scan.exe`. Not 127.0.0.1, not 10.0.2.2 |
|  | victim VM | `janed` | Wait ~2 min | Timeline gap: download vs execute |
|  | victim VM | `janed` | Double-click Downloads copy in Explorer | Not `Z:\`. Notepad opens; close it |
|  | victim VM | `janed` | Wait ~1 min | |
|  | victim VM | `janed` | HKCU Run `SecurityUpdate` → Downloads path | Not HKLM |
|  | victim VM | `janed` | Wait ~1 min | |
|  | victim VM | `admin_local` | `wevtutil cl Security` | **Destroys 4688.** Expected remaining: 1102 + later events |
|  | victim VM | `admin_local` | KAPE start `Z:\collection_s1` | Same dirty session. No restore before this |
|  | victim VM | `admin_local` | KAPE end | Confirm host `collection_s1` not empty |
|  | host + VM | operator | Shutdown VM; stop Python | |

## Deviations (tell Person B)

- No VirtualBox shared folder; `Z:` is guest-only. Host FYP is not `Z:`.
- Decoy transferred **USB** (host → USB → VM), not a reliable host-only HTTP download. Python on the host was optional; stopping it does not undo USB/execute/persist/log-clear.
- Guest sometimes on **NAT** so `http://192.168.50.5:8000/invoice_scan.exe` would open. Host host-only address is **`192.168.50.5`**, not `192.168.56.1`.
- Clean B KAPE session used **`admin_local`** (lab text said `janed` for benign work).

## Expected artifacts (for Person B)

| Action | Actor | Path / locator | Expected |
|--------|-------|----------------|----------|
| download | `janed` | `C:\Users\janed\Downloads\invoice_scan.exe` | browser history, MFT, Zone.Identifier |
| execute | `janed` | `C:\Users\janed\Downloads\invoice_scan.exe` | Prefetch `INVOICE_SCAN.EXE-*`, Amcache, 4688 **then destroyed** |
| persist | `janed` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate` | registry Run |
| logclear | `admin_local` | `Security.evtx` | 1102; destroys prior 4688 |

## Real KAPE path shapes (from host trees 2026-08-21)

Layout is **flat `C\`**, no hostname/timestamp prefix. `winevt\logs` and `prefetch` are lowercase.

```text
collection_clean_a\C\Windows\System32\winevt\logs\Security.evtx
collection_clean_a\C\Windows\System32\winevt\logs\System.evtx
collection_clean_b\C\Windows\System32\winevt\logs\Security.evtx
collection_clean_b\C\Windows\System32\winevt\logs\System.evtx
collection_s1\C\Windows\System32\winevt\logs\Security.evtx
collection_s1\C\Windows\System32\winevt\logs\System.evtx
collection_s1\C\Windows\prefetch\INVOICE_SCAN.EXE-A345C2FE.pf
```

Also in `collection_s1` Prefetch (baseline / extra, not the decoy): `NOTEPAD.EXE-EB1B961A.pf`, `NOTEPAD++.EXE-A5D7A5DB.pf`.

Sizes: Clean A/B `Security.evtx` ~14–15 MB; Scenario 1 `Security.evtx` **69632 bytes** (log clear). Prefetch `INVOICE_SCAN.EXE-A345C2FE.pf` **9909 bytes**.
