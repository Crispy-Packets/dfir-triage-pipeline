# Collection manifest

`clean_a` and `clean_b` were each taken from an independent restore of
`BASELINE-CLEAN+TOOLS`. `collection_s1_v2` was taken from the live session in
which Scenario 1 had just been executed, with no restore beforehand.

Path convention. This manifest quotes filesystem paths from two
different machines. Paths beginning `C:\Users\janed\`, `Z:\`,
`\Device\HarddiskVolume`, `C:\kape\` and `C:\Windows\` refer to the
lab guest, which was decommissioned on 2026-08-25 and on which no
path can now be tested. Every absolute filesystem path in this manifest
refers to the guest; the manifest records no host paths. An automated
existence check run against the analysis host will therefore report every
path in this manifest as absent. That is the expected result and is not a
defect in this manifest.

Common parameters across all three:

| | |
|---|---|
| KAPE version | 1.3.0.2 |
| Target set | `KapeTriage` |
| Source | `C:` |
| Output format | plain directory, no `--vhdx` |
| Destination on guest | `Z:\collection_*` |
| Transfer to host | USB, to `C:\Users\SK_FA\dfir-evidence` -- OUTSIDE the repository (CD-016) |

The target set is identical across all three. A different target set between a
clean collection and the scenario would make every downstream comparison
invalid, and the difference would appear in the evaluation as a detection
result.

Collections are directories rather than VHDX containers because the pipeline
walks a directory tree; a VHDX is a single opaque file it cannot enter.

## Collection accounts and transfer

KAPE session account for every Week 1 collection is `admin_local`, established
from EID 4688 in each Security log (see docs/lab-setup.md, Investigator
activity). clean_b additionally retains earlier KAPE 4688 records under
`Youssef` (12 to 19 August) that predate the snapshot.

Collections were transferred from the guest to the host using removable media.
This is a chain-of-custody note rather than an evidence defect, since each
collection is a set of files accompanied by a manifest of SHA-256 hashes, and
the transport medium does not alter their content.

## Collection provenance

1. The machine ran from installation on 2026-06-20 through the lab build
   period, the Security log reaching approximately EventRecordID 28,200 by
   23 August.
2. On 2026-08-23 Scenario 1 ran from 22:45:32Z (download, per the operator
   log) to 23:05:12Z (log clear). The Security log clear is EID 1102,
   EventRecordID 28,201, 2026-08-23T23:05:06.682356Z. 23:05 to 23:31 is the
   post-clear window, during which 583 further records accrued and KAPE ran.
   EventRecordID 28,674 used `--tsource Z:`; the C: collection runs are
   EventRecordID 28,777 and 28,784. The scenario1 collection was
   acquired.
3. On 2026-08-24 the virtual machine was reverted to the clean snapshot. The
   Security log returned to its snapshot state near EventRecordID 15,600.
4. On 2026-08-24, up to 18:57, post-revert activity was performed, including
   the staged testuser create and delete at 18:44 and 18:45. The clean_b
   collection was acquired. clean_a was acquired from the same reverted
   snapshot state.

clean_a and clean_b are not pre-incident captures of the scenario1 machine.
They are the machine restored to its pre-attack snapshot after the incident,
run briefly, and then acquired.

The collections sit on divergent branches of one host's history. They share an
ancestor, not a timeline.

They are therefore never merged into a common timeline. Each collection is
processed independently.

EventRecordID 28,201 in scenario1 carries an earlier timestamp than
EventRecordID 15,707 in clean_b, which is impossible on a single unbroken
record sequence. This is what establishes the two collections as divergent
rather than sequential.

Because the VM was decommissioned on 2026-08-25, any future re-collection
requires rebuilding the environment from scratch. A rebuilt host would carry
different account SIDs, a different hostname history and a different
baseline, and would therefore not be directly comparable with these three
collections. Re-collection is consequently a rebuild, not a repeat.

---

## The three collections

| Collection | Guest folder | Scenario actor | KAPE session account | Collected (UTC) | Files (recorded at collection) | Notes |
|----|--------------|----------------|----------------------|-----------------|--------------------------------|-------|
| `clean_a` | `collection_clean_a` | (none) | `admin_local`, elevated | 2026-08-24T17:44:56Z | 876 | Boot and settle. No user activity |
| `clean_b` | `collection_clean_b` | (none) | `admin_local`, elevated | 2026-08-24T18:58:05Z | 900 | Benign user workload |
| `scenario1` | `collection_s1_v2` | `janed` (download, execute, persist); then `admin_local` (log clear) | `admin_local`, elevated | 2026-08-23T23:31:48Z | 793 | HTTP delivery, execute, persist, log clear |

What each file-count figure measures. No number below was changed; each is labelled.

| Collection | Recorded at collection ("Files on disk") | Full tree (host) | C\ evidence subtree (= CopyLog rows) | SHA-256 collection-time manifest rows |
|---|---|---|---|---|
| `clean_a` | 876 | 892 | 889 | 892 |
| `clean_b` | 900 | 916 | 913 | 916 |
| `scenario1` | 793 | 817 | 814 | 793 |

Full-tree counts are CopyLog rows plus three KAPE log files at the collection root, and match a recursive host listing with hidden/system files included (`docs/integrity-verification-day4.txt`).

On the host copy, Hidden and System attributes were preserved for
`collection_s1_v2` but not for `clean_a` or `clean_b`, where `Get-ChildItem`
returns the same count with and without `-Force`. This is a transfer artefact
of the host copy and does not affect file content, which verifies against
collection-time hashes.

876 and 900 were recorded at collection time. On the current host copy they do not equal the full tree, the C\ subtree, or the SHA-256 manifest row counts, because those two collections no longer carry Hidden or System attributes after transfer. They are retained as recorded, not recomputed. The 24-file difference between them (900 minus 876) equals the full-tree difference (916 minus 892).

793 equals both the SHA-256 collection-time manifest row count and the number of files visible on the current host without enumerating hidden/system attributes (`Get-ChildItem` without `-Force`: 817 minus 24). The full tree is 817.

### clean_a

```
--tsource C: --target KapeTriage --tdest Z:\collection_clean_a
```

| | |
|---|---|
| Files found / copied (KAPE; copied = CopyLog rows = C\ subtree) | 1,017 / 889 (128 deduplicated) |
| Duration | 325.77 seconds |
| Files on disk (recorded at collection; not the full tree) | 876 |
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
| Files found / copied (KAPE; copied = CopyLog rows = C\ subtree) | 1,052 / 913 (139 deduplicated) |
| Duration | 365.30 seconds |
| Files on disk (recorded at collection; not the full tree) | 900 |
| Zero-byte files | 0 |
| CopyLog | `2026-08-24T18_56_49_883*_CopyLog.csv` |

Purpose: threshold setting and false-positive measurement against realistic user
activity. Taken from an **independent restore**, a separate boot from clean_a's
— not a reuse of the same session. Two collections from one boot would not be
independent samples, and the Week 4 evaluation depends on their independence.

The 24-file difference against clean_a (900 minus 876 recorded at collection;
916 minus 892 in the full tree) is consistent with the benign workload
that distinguishes the two baselines: browsing, application launches and file
operations.

**clean_b is the reference baseline** for false-positive measurement and
anomaly-model training; clean_a is an ambient-noise control. CD-014.

### scenario1

```
--tsource C: --target KapeTriage --tdest Z:\collection_s1_v2
```

This is EventRecordID 28,777 and 28,784. EventRecordID 28,674 used `--tsource Z:`.

| | |
|---|---|
| Files found / copied (KAPE; copied = CopyLog rows = C\ subtree) | 1,127 / 814 (313 deduplicated) |
| Duration | 293.68 seconds |
| Files on disk (recorded at collection; equals SHA-256 manifest rows) | 793 |
| CopyLog | `2026-08-23T23_31_48_7980143_CopyLog.csv` |

Commodity infection chain: browser download over HTTP, execution, autorun
persistence, Security log clear. Full operator log with UTC timestamps and the
`Zone.Identifier` verification is in `groundtruth/Scenario1.md`.

Prefetch decoy: `INVOICE_SCAN.EXE-A345C2FE.pf`.

---

## Recollection record

All three collections were retaken on 23–24 August. The originals are superseded
and are not retained. The reasons are recorded here because the detection method
forms part of the methodology.

### clean_a - merged runs, then a more serious fault (SUPERSEDED COLLECTION)

**This section documents the ORIGINAL clean_a, which was discarded.** The
collection in use at `collection_clean_a` (892 files) is the recollection. The
history below is retained as methodology -- it records how the fault was found --
and is not a description of the evidence now in use. See CD-014 for the role
clean_a actually plays.

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

The same allocated-but-never-flushed condition appears in the collected Prefetch
files: five `.pf` files across the three collections are runs of zero bytes
(`DEFRAG.EXE-738093E8`, `SVCHOST.EXE-CE29B0F4`). They are present in their
SHA-256 manifests, so they were collected and transferred intact. The Prefetch
parser yields no records for them rather than raising. See CD-020 and D-024.

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

The scenario1 collection-time SHA-256 manifest (`clean-s1-v2-sha256.csv`)
covers 793 of the 817 files in the tree. Arithmetic: 817 minus 793 is 24
missing. All 24 carry the Hidden or System attribute (`NTUSER.DAT`,
`UsrClass.dat`, their transaction logs, DPAPI master keys, `desktop.ini`).
`Get-ChildItem` without `-Force` does not enumerate Hidden or System files.
The SHA-256 pass therefore never saw them.

This is a methodology note: a file enumeration without `-Force` silently
omits hidden and system files, which on a Windows triage collection means
omitting the registry hives. All 24 nonetheless carry collection-time SHA-1
in KAPE's CopyLog, which uses its own enumeration. The omission is not a
file lock, an in-use file, or an access error.

The `clean_a` and `clean_b` manifests are complete: 892 and 916 rows against
892 and 916 files.

The omission was found on 2026-08-25, after the lab VM had been decommissioned,
so a collection-time SHA-256 for these 24 files cannot be produced. No file
named in the collection-time SHA-256 manifest is missing from disk.

`groundtruth/clean-s1-v2-sha256-supplement.csv` now exists and covers those 24
paths. Its SHA-256 values were computed on 2026-08-25 from the host copy of the
collection. They are post-collection hashes, not collection-time hashes: they
establish integrity from the date of computation forward and cannot attest to
file state at acquisition. Files covered by the collection-time manifest are
unaffected: five randomly sampled hashes per collection verified on receipt.

`janed`'s `NTUSER.DAT` - the hive holding the Run-key persistence artefact - is
among the 24. It is present and readable. It has a collection-time SHA-1 in
KAPE's CopyLog; what is missing is a collection-time SHA-256 in
`clean-s1-v2-sha256.csv`. The supplement records a post-collection SHA-256 for
it, which does not attest to file state at acquisition.

---

## What enters git

**Tracked:**
- `groundtruth/Scenario1.md`
- `groundtruth/clean-a-sha256.csv`
- `groundtruth/clean-b-sha256.csv`
- `groundtruth/clean-s1-v2-sha256.csv`
- `groundtruth/clean-s1-v2-sha256-supplement.csv`
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
