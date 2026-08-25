# Collection manifest

Three triage collections, each taken from an independent restore of
`BASELINE-CLEAN+TOOLS`.

Common parameters across all three:

| | |
|---|---|
| KAPE version | 1.3.0.2 |
| Target set | `KapeTriage` |
| Source | `C:` |
| Output format | plain directory, no `--vhdx` |
| Destination on guest | `Z:\collection_*` |
| Transfer to host | USB, into the repository at `collections/` |

The target set is identical across all three. A different target set between a
clean collection and the scenario would make every downstream comparison
invalid, and the difference would appear in the evaluation as a detection
result.

Collections are directories rather than VHDX containers because the pipeline
walks a directory tree; a VHDX is a single opaque file it cannot enter.

---

## The three collections

| ID | Guest folder | Session | Collected (UTC) | Files | Notes |
|----|--------------|---------|-----------------|-------|-------|
| `clean_a` | `collection_clean_a` | `admin_local`, elevated | 2026-08-24T17:44:56Z | 876 | Boot and settle. No user activity |
| `clean_b` | `collection_clean_b` | `admin_local`, elevated | 2026-08-24T18:58:05Z | 900 | Benign user workload |
| `scenario1` | `collection_s1_v2` | `janed`, then `admin_local` | 2026-08-23T23:31:48Z | 793 | HTTP delivery, execute, persist, log clear |

### clean_a

```
--tsource C: --target KapeTriage --tdest Z:\collection_clean_a
```

| | |
|---|---|
| Files found / copied | 1,017 / 889 (128 deduplicated) |
| Duration | 325.77 seconds |
| Files on disk | 876 |
| Total size | 950,656,516 bytes |
| Zero-byte files | 0 |
| Console log | 72,294 bytes, readable |
| CopyLog | `2026-08-24T17_21_01_6584538_CopyLog.csv` |

Purpose: minimal reference state. The machine was restored, booted, and left to
settle with no user interaction.

### clean_b

```
--tsource C: --target KapeTriage --tdest Z:\collection_clean_b
```

| | |
|---|---|
| Files found / copied | 1,052 / 913 (139 deduplicated) |
| Duration | 365.30 seconds |
| Files on disk | 900 |
| Zero-byte files | 0 |
| CopyLog | `2026-08-24T18_56_49_883*_CopyLog.csv` |

Purpose: threshold setting and false-positive measurement against realistic user
activity. Taken from an **independent restore**, a separate boot from clean_a's
— not a reuse of the same session. Two collections from one boot would not be
independent samples, and the Week 4 evaluation depends on their independence.

The 24-file difference against clean_a is consistent with the benign workload
that distinguishes the two baselines: browsing, application launches and file
operations.

**clean_b is the Week 4 anomaly-model baseline.**

### scenario1

```
--tsource C: --target KapeTriage --tdest Z:\collection_s1_v2
```

| | |
|---|---|
| Files found / copied | 1,127 / 814 (313 deduplicated) |
| Duration | 293.68 seconds |
| Files on disk | 793 |
| CopyLog | `2026-08-23T23_31_48_7980143_CopyLog.csv` |

Commodity infection chain: browser download over HTTP, execution, autorun
persistence, Security log clear. Full operator log with UTC timestamps and the
`Zone.Identifier` verification is in `groundtruth/scenario1.md`.

Prefetch decoy: `INVOICE_SCAN.EXE-A345C2FE.pf`.

---

## Recollection record

All three collections were retaken on 23–24 August. The originals are superseded
and are not retained. The reasons are recorded here because the detection method
forms part of the methodology.

### clean_a — merged runs, then a more serious fault

The original clean_a contained two KAPE runs written to the same destination
directory (2026-08-19T19:27:26 and 2026-08-20T14:31:43), so it was not a single
point-in-time collection.

Investigation established that the merge was less damaging than it appeared. The
two CopyLogs recorded 768 and 767 files with 766 in common, of which **713 were
byte-identical**. The 53 differences were confined to system service prefetch
entries (`svchost`, `RuntimeBroker`, `dllhost`) and telemetry event channels;
`NTUSER.DAT`, `SOFTWARE` and all user-relevant artifacts were identical across
both runs.

The merge was therefore not the reason for recollection. Direct filesystem
inspection established a more serious fault: of 101 `.evtx` files collected,
`Application.evtx` was present but **`Security.evtx` and `System.evtx` were
absent from both runs**.

The KAPE `EventLogs` target was inspected and found intact
(`Path: C:\Windows\System32\winevt\logs\`, `FileMask: '*.evtx'`), and a
verification collection using that target on the same machine collected both
files successfully. **The root cause of the original omission was not the target
definition and has not been determined.**

Separately, the console log from the 20 August run
(`2026-08-20T14_31_43_4265270_ConsoleLog.txt`) is 62,365 bytes containing no
non-zero data, indicating file size was allocated in the filesystem metadata but
contents were never flushed to disk. Whether this is related to the missing
event logs is not established. The recollection's console log is readable and
the condition did not recur.

**Detection method: hash comparison of the collection tool's own CopyLog
output.** No error was raised by KAPE, no SkipLog entry was written, and the run
was reported as successful.

### clean_b

Recollected from an independent restore, as described above.

### scenario1 — delivery method

The original scenario1 delivered `invoice_scan.exe` by USB, because the host
HTTP server could not be reached from the guest.

Root cause was a VirtualBox host-only misconfiguration: the DHCP pool issued
`192.168.56.x` addresses while the host adapter was configured on
`192.168.50.x`, so the guest received a valid-looking address with no route to
the host. No error was raised at any layer; the failure presented as an
application fault in the Python HTTP server.

USB delivery produced no browser history and no `Zone.Identifier`, so the
`download → execution` chain could not be reconstructed from artifacts within
the project's declared scope. USB-based initial access is out of scope
(CD-013) and is recorded in Future Work.

The recollection delivers the binary over HTTP through Edge. `Zone.Identifier`
was verified as `ZoneId=3` before the scenario continued.

## Manifest completeness

The scenario1 collection-time manifest (`clean-s1-v2-sha256.csv`) covers 793 of
the 817 files present in the collection. The 24 uncovered files are registry
hives (`NTUSER.DAT`, `UsrClass.dat`), their transaction logs, DPAPI `Protect`
blobs and `desktop.ini` entries — files carrying hidden or system attributes on
the collecting host, which the hashing command did not enumerate. The `clean_a`
and `clean_b` manifests are complete: 892 and 916 rows against 892 and 916
files.

The omission was found on 2026-08-25, after the lab VM had been decommissioned,
so collection-time hashes for these files cannot be produced.
`groundtruth/clean-s1-v2-sha256-supplement.csv` was generated from the host copy
on that date and establishes integrity from receipt onward rather than from
collection. No file named in the collection-time manifest is missing from disk.

Files covered by the collection-time manifest are unaffected: five randomly
sampled hashes per collection verified on receipt.

`janed`'s `NTUSER.DAT` — the hive holding the Run-key persistence artifact — is
among the 24. It is present and readable; only its collection-time hash is
unavailable.

---

## What enters git

**Tracked:**
- `groundtruth/scenario1.md`
- `groundtruth/clean-a-sha256.csv`
- `groundtruth/clean-b-sha256.csv`
- `groundtruth/scenario1-sha256.csv`
- `docs/lab-setup.md`, `docs/collection-manifest.md`
- `docs/evidence/*.txt`

**Never tracked:**
- The three collection trees
- `invoice_scan.exe`
- Any `.evtx`, `.pf` or `.hve` blob

`.gitignore` blocks `collections/`, `outputs/`, `*.evtx`, `*.pf`, `*.hve` and
`*.csv`. The SHA-256 manifests survive only through an explicit
`!groundtruth/**/*.csv` negation — confirm with `git check-ignore -v` that the
matching rule starts with `!`, because `git add` skips ignored files silently.

Reproducibility is provided by the manifests together with the procedure
documented here and in `docs/lab-setup.md`.

---

## Verification checks applied to every collection

- File count and total byte size recorded at collection time
- Zero-byte file count checked
- KAPE console log confirmed readable, not null-filled
- `Command line` echo in the console log confirms `--tsource C:` took effect
- Collection written to a fresh destination directory, never on top of an
  existing one
- VM shut down cleanly after each collection so the volume flushes
