# Person B — Day 2 metadata packet

**Sanity (host, 2026-08-21):** `Security.evtx` + `System.evtx` in all three trees. Scenario 1 Security log **69632 bytes** (clear). Prefetch **`INVOICE_SCAN.EXE-A345C2FE.pf` present.** Packet may be sent.

Do **not** attach evtx/pf. Do **not** `git add` the collection trees (Day 3 hashes). Commit **groundtruth markdown** only.

## Collections

| Dest (VM `Z:\` / now on host) | Independent restore? | Approx files / bytes |
|------------------------------|----------------------|----------------------|
| `collection_clean_a` | Yes — `BASELINE-CLEAN+TOOLS` | 835 files, ~840 MB |
| `collection_clean_b` | Yes — `BASELINE-CLEAN+TOOLS` again | 875 files, ~871 MB |
| `collection_s1` | Restore, act, KAPE **without** second restore | 836 files, ~927 MB |

- KAPE target: `KapeTriage`
- `--vhdx`: not used
- KAPE left on `Z:\kape\KAPE\`
- No vbox shared folder; trees copied **USB** host ← VM `Z:`

**Caveat (Clean A):** dest folder contains **two** KAPE log sets (`2026-08-19T19_27_26_*` and `2026-08-20T14_31_43_*`). Treat `C\` as the later (20 Aug) run unless Person A confirms otherwise. Not a second independent clean; it is a **merged dest**.

## Machines and accounts

| Collection | Login / session | Elevate |
|------------|-----------------|---------|
| Clean A | `youssef` | Admin PowerShell KAPE |
| Clean B | KAPE as **`admin_local`** (lab default was `janed` for benign work) | `admin_local` |
| Scenario 1 | `janed` execute + HKCU Run | `admin_local` `wevtutil` + KAPE |

VM: VirtualBox `windows10`. Snapshot: `BASELINE-CLEAN+TOOLS`.

## Network (actual)

- Host-only NIC on PC: **`192.168.50.5/24`** (`VirtualBox Host-Only Ethernet Adapter #3`)
- Run used **NAT** for some HTTP tests; decoy entered the VM by **USB**, not a completed host-only browser download
- No Guest Additions

## Versions

- Windows: *(Person A: `winver` on guest)*
- KAPE: `KapeTriage` via `Z:\kape\KAPE\kape.exe`
- Browser: n/a for USB copy

## Scenario 1 story

Notepad renamed `invoice_scan.exe`, **USB** into the guest, executed as `janed`, HKCU Run **`SecurityUpdate`**, `wevtutil cl Security` as `admin_local` (**destroys 4688**). Ground truth: `groundtruth/scenario1.md`.

## Sanity

| Check | clean_a | clean_b | s1 |
|-------|---------|---------|----|
| `Security.evtx` | yes 14749696 B | yes 15798272 B | yes **69632 B** (clear — expected) |
| `System.evtx` | yes 1118208 B | yes 1118208 B | yes 2166784 B |
| Prefetch `INVOICE_SCAN.EXE-` | none (correct) | none (correct) | **yes** `INVOICE_SCAN.EXE-A345C2FE.pf` |

## Real relative path shapes

```text
collection_s1\C\Windows\System32\winevt\logs\Security.evtx
collection_s1\C\Windows\System32\winevt\logs\System.evtx
collection_s1\C\Windows\prefetch\INVOICE_SCAN.EXE-A345C2FE.pf
collection_clean_a\C\Windows\System32\winevt\logs\Security.evtx
collection_clean_a\C\Windows\System32\winevt\logs\System.evtx
collection_clean_b\C\Windows\System32\winevt\logs\Security.evtx
collection_clean_b\C\Windows\System32\winevt\logs\System.evtx
```

No hostname/timestamp prefix. Paths use `logs` and `prefetch` lowercase.
