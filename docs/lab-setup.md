# Lab setup

Environment in which all Week 1 evidence was collected. Every configuration
change below was verified by execution; the verification output is recorded
rather than asserted. Raw capture: docs/evidence/lab-verification.txt
Open questions remaining after Week 1 are recorded in docs/open-questions.md.

## Host

Hypervisor      : <VirtualBox 7.x | VMware Workstation Player 17.x>
Host OS         : <Windows 11 23H2>
Free disk       : <n> GB at collection time
Analysis path   : C:\Users\josep\fyp\dfir-triage-pipeline

## Virtual machine

Guest OS        : <from Win32_OperatingSystem Caption>
Version string  : <OSVersion.Version>
Build           : <BuildNumber>
RAM             : 4 GB
vCPU            : 2
System disk     : C: - <n> GB dynamic
Collection disk : Z: - <n> GB, added for KAPE output
Network         : Host-only

Host-only rather than NAT or bridged for two reasons: the VM holds
attack-simulation artifacts and must not reach the internet, and the Scenario 1
binary is served from a web server on the host, which host-only reaches
directly.

<If the adapter was switched to NAT to transfer evidence, record it here:
 "Adapter switched to NAT <UTC start> to <UTC end> for evidence transfer.
 All SHA-256 manifests were generated before the change; no collection was
 taken from the VM state that existed after it. Every collection begins from a
 restore of BASELINE-CLEAN+TOOLS.">

## Collection volume

KAPE output was written to Z:, a separate virtual disk, not to C:.

A collector writing to the volume it is collecting creates files on that volume
during collection - new MFT entries, updated directory timestamps, possible
Prefetch and USN activity - and so alters the evidence while acquiring it.
Writing to a separate volume avoids this. C: is read by KAPE and not written to.

Z: volume serial : <from vol Z:>
C: volume serial : <from vol C:>

The C: volume serial is recorded because Prefetch stores device paths of the
form \VOLUME{...}\ rather than drive letters. Resolving those to C:\ during
entity resolution requires this mapping, and it cannot be recovered once the VM
is discarded.

## Accounts

Three lab-created local user accounts (`Youssef`, `janed`, `admin_local`), plus
one staged test account (`testuser`) and one system built-in
(`WDAGUtilityAccount`). No Microsoft accounts. A Microsoft account changes the
profile path shape and introduces cloud-sync artifacts that would contaminate
the baseline.

Source of all creation times: EID 4720 records in the clean_b Security log.

| Account | Type | Created (UTC) | Evidence | Purpose |
|---|---|---|---|---|
| `Youssef` | Administrator | 2026-06-20T13:43:25Z | clean_b Security, EventRecordID 142 | Researcher account. Used for the VM build, tooling installation, snapshot management and KAPE collection. Not an actor in any attack scenario. |
| `janed` | Standard user | 2026-08-12T11:41:24Z | clean_b Security, EventRecordID 1498 | Simulated victim. Performs the HTTP download of invoice_scan.exe through Edge, its execution, and the establishment of persistence. |
| `admin_local` | Administrator | 2026-08-12T11:42:53Z | clean_b Security, EventRecordID 1530 | Simulated privileged account. Performs the anti-forensic Security log clear in Scenario 1. |
| `testuser` | Standard user | 2026-08-24T18:44:37Z | clean_b Security, EventRecordID 15707 | Staged test account. See "Staged events" below. |
| `WDAGUtilityAccount` | System built-in | 2026-06-20T23:41:33Z | clean_b Security, EventRecordID 33 | Windows Defender Application Guard built-in, created by the operating system during installation. Not lab-created. |

## Staged events

A test account `testuser` was created and deleted deliberately during the
clean_b collection window, under Week 1 runbook action 40, to provide EID
4720 coverage in real evidence. It was created as EID 4720, EventRecordID
15707, at 2026-08-24T18:44:37Z, and deleted as EID 4726, EventRecordID 15720,
at 2026-08-24T18:45:13Z, a lifetime of 36 seconds. It is identified as
synthetic wherever 4720 counts are reported in this project.

EID 4726 is not in the declared event vocabulary (CD-007), so the deletion is
present in the evidence but is not parsed by the pipeline. This is recorded as
an unexercised evidence source for Future Work.

## Post-revert activity

The final fifteen minutes of clean_b, immediately before acquisition:

| Time (UTC) | EventRecordID | Activity |
|---|---|---|
| 18:44:37 | 15,707 | testuser created (EID 4720, staged) |
| 18:45:13 | 15,720 | testuser deleted (EID 4726, staged) |
| 18:48:15 | 15,780 | 7z2602-x64.exe executed by admin_local |
| 18:56:13 | 15,887 | kape.exe executed by admin_local |
| 18:57:42 | 15,897 | final record |

This window contains a staged account lifecycle, a software installation and
the collection tooling. None of it represents baseline user behaviour.

### Investigator activity in the evidence - stated explicitly

KAPE collection operators, established from EID 4688 in each Security log:

- `collection_clean_a` was collected by `admin_local`. Evidence: EID 4688,
  EventRecordID 15461, 2026-08-24T17:21:00.773737Z, NewProcessName
  `\Device\HarddiskVolume2\kape\KAPE\kape.exe`, SubjectUserName `admin_local`.
- `collection_clean_b` was collected by `admin_local`. Evidence: EID 4688,
  EventRecordID 15887 and 15890, 2026-08-24T18:56, NewProcessName
  `\Device\HarddiskVolume2\kape\KAPE\kape.exe`, SubjectUserName `admin_local`.
- `collection_s1_v2` was collected by `admin_local`. Evidence: EID 4688,
  EventRecordID 28777 and 28784, `--tsource C:`, 2026-08-23T23:30 to 23:31,
  NewProcessName `Z:\kape\KAPE\kape.exe`, SubjectUserName `admin_local`.
  EventRecordID 28674 at 2026-08-23T23:19 used `--tsource Z:` and is not
  the C: collection.

clean_b additionally retains 4688 records of earlier KAPE runs under `Youssef`,
dated 12 to 19 August. These predate the snapshot and survive because clean_b's
Security log was never cleared. clean_b therefore contains collection artefacts
from two different operators, only one of which is its own collection run.

Consequence for analysis: `Youssef` remains excluded from the ground truth in
groundtruth/scenario1.md. Historical `Youssef` KAPE activity in clean_b, and
`admin_local` collection activity in every acquisition, are lab-operation
artefacts. If a detection rule fires on those accounts or on `kape.exe`, that
is a false positive caused by lab construction or collection method, and it is
reported as such rather than filtered away.

Consequence for the Week 4 anomaly layer: clean_a is described below as "no
user activity beyond boot". That means no *simulated* user activity. Collection
and residual lab-operator activity are present and are not zero activity; the
model will learn them as normal where they appear in the clean baselines.

## Host identity

The host was named `WIN-BQVKLIBL3LA` at installation and was renamed to
`windows10`. Both strings appear in the `System/Computer` field across clean_b
Security and clean_b System. scenario1 Security contains only `windows10`,
because its log was cleared after the rename. These denote one machine, not two.

`Event.host` is therefore not constant within a collection. The EVTX parser
reads `System/Computer` per record and is correct; any downstream logic that
assumes a single host per collection is not.

## Host clock integrity

clean_b Security contains 25 records of EID 4616 (the system time was changed).
`TimeCreated` is not monotonically non-decreasing when records are ordered by
`EventRecordID`: there are 26 inversions. The largest inversion is at
EventRecordID 139 -> 140, both dated 2026-06-20, where the clock moves back
approximately ten hours. This falls in the initial Windows installation window.
The remaining inversions range from under one second to approximately 47
minutes and are consistent with virtual-machine time synchronisation.
scenario1 Security contains zero records of EID 4616.

Record order is not chronological order. The timeline is therefore sorted by
timestamp and never by `EventRecordID`.

No system-time change occurs within the incident window. There is no evidence
of anti-forensic time manipulation by the actor. This is a documented negative
result, not an absence of investigation.

Collection span and power-off gap: clean_b Security first record is
EventRecordID 1, 2026-06-20T23:41:30.958795Z; last record is EventRecordID
15897, 2026-08-24T18:57:42.628249Z. The largest gap between consecutive records
is EventRecordID 1088 (2026-06-20T16:45:11Z) to 1089 (2026-08-12T11:26:32Z),
52 days 18 hours. The machine was built in June and left powered off until
August. Records 1 to 1088 are the operating system installing itself. Records
1089 to 15897, being 14809 records or 93.2 per cent of the log, are the August
lab construction period.

## Evidence locator uniqueness (CD-004)

CD-004 from docs/contract-decisions.md:

> CD-004  source_locator: MUST be unique within a source_file.
>         EVTX uses "EventRecordID=<n>". Prefetch uses "run_slot=<i>".
>         A loop counter is NOT acceptable: it is stable within a run but does not
>         resolve back to the evidence. CONSTRAINS PERSON A'S EVTX PARSER.
>
>         Day 3 confirmation against real evidence: no duplicate .pf basenames exist in
>         the scenario1 collection, so source_file plus source_locator is jointly unique
>         for Prefetch. EventRecordID uniqueness within each .evtx remains to be
>         confirmed by Person A.

| Collection | Records | Distinct EventRecordID |
|---|---|---|
| clean_b Security.evtx | 15,897 | 15,897 |
| clean_b System.evtx | 1,880 | 1,880 |
| scenario1 Security.evtx | 584 | 584 |

All three are contiguous with no gaps. This discharges the confirmation left
open in CD-004, converting it from an assumption into an observation. The
contract clause text still ends "remains to be confirmed by Person A"; the
clause update is pending with the contract owner.

## Declared EID coverage

All six declared EIDs have at least one record in real evidence. None is
unit-test-only.

| EID | Event | Source | Count |
|---|---|---|---|
| 4624 | logon | clean_b Security | 919 |
| 4625 | logon_failed | clean_b Security | 13 |
| 4688 | process_exec | clean_b Security | 9,502 |
| 4720 | account_created | clean_b Security | 5 (one staged) |
| 7045 | service_install | clean_b System | 16 |
| 1102 | log_cleared | scenario1 Security | 1 |

## Virtualisation tooling

VirtualBox Guest Additions are not installed in the virtual machine, and
consequently no `VBoxService` EID 7045 records exist in any collection. This is
stated explicitly so a reader familiar with VirtualBox does not read their
absence as a collection failure.

## Limitations of the clean_b collection

[PERSON A WRITES THIS: the clean_b limitation. Must cover - (1) what
clean_b is not: not a model of normal end-user behaviour, 93.2 per cent
of the log is lab construction, janed has one interactive logon and 103
of 9502 process-creation events; (2) what it is: a no-attack control
demonstrating the pipeline surfaces no attack-attributable indicators on
a host where the scenario did not run; (3) the argument: clean_b contains
five 4720 records and 4720 is a declared indicator, so the control set is
not free of indicator hits - this demonstrates that 4720 in isolation is
a high-false-positive indicator requiring contextualisation. Rest point
(3) on the FOUR genuine records, not the staged fifth.]

| EID 4688 SubjectUserName | Count | of 9,502 |
|---|---|---|
| `WINDOWS10$` (machine account) | 7,881 | |
| `Youssef` (investigator) | 1,176 | |
| `admin_local` | 179 | |
| `janed` | 103 | |

EID 4624 with `TargetUserName=janed` in clean_b: 1 record, LogonType 2. No
network logons.

## Audit configuration

Process creation auditing is disabled by default in Windows. Without it there
are no 4688 records at all.

Command:
    auditpol /set /subcategory:"Process Creation" /success:enable

Verification output:
    <paste from lab-verification.txt>

---

Command-line capture in 4688:
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
      /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

Verification output:
    <paste>

Without this, 4688 records carry a process name but nothing about how the
process was invoked. CommandLine is a field the Week 3 correlation rules read.

---

PowerShell script block logging (Week 2 needs EID 4104):
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
      /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

Verification output:
    <paste>

Enabled during the baseline build so clean and scenario collections are
configured identically. A setting differing between them would appear in the
evaluation as a detection result when it is really a configuration artifact.

---

Log sizes, 64 MB each so nothing rolls over mid-test:
    wevtutil sl Security /ms:67108864
    wevtutil sl System   /ms:67108864

Verification output:
    <paste the maxSize lines from wevtutil gl>

## Endpoint protection

Get-MpComputerStatus output was not captured at collection time and cannot be
filled from the collected evidence.

Microsoft-Windows-Windows Defender/Operational, EventID 5007, at
2026-08-20T15:52:33.593285Z records:

    HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\
    C:\Users\janed\Downloads\invoice_scan.exe = 0x0

PowerShell 4104 records the commands that created the exclusion:

    Add-MpPreference -ExclusionPath "C:\Users\janed\Downloads\invoice_scan.exe"
    at 2026-08-20T16:13:21.702204Z, and one for Invoice_Scan.exe at
    2026-08-20T18:46:53.833422Z

collection_s1_v2 was acquired from the live machine on 2026-08-23, so the
exclusion was in force throughout the scenario run.

Defender ran a scheduled Quick Scan from 2026-08-23T22:46:06.442689Z to
2026-08-23T22:47:59.072606Z (EventID 1000 then 1001, EventRecordID 976 and
977) with no detections. That result is uninformative given the exclusion.

No EventID 1116, 1117, 1006 or 1015 detection events exist in the scenario
window.

Microsoft-Windows-SmartScreen/Debug is absent from the collection, so whether
SmartScreen warned on the download is unrecorded.

No claim can be made about whether Defender would have detected the binary,
because its path was excluded from scanning.

### Identity of the Scenario 1 binary (OQ-001)

The identity of the binary present for the 2026-08-23 run is not established
by the collected evidence. See docs/open-questions.md, OQ-001.

PowerShell 4104 records in collection_s1_v2 show

    Copy-Item -Path C:\Windows\notepad.exe -Destination Z:\invoice_scan.exe
    at 2026-08-20T15:06:13, EventRecordID 855

    Copy-Item -Path C:\Windows\System32\notepad.exe -Destination Z:\invoice_scan.exe
    at 2026-08-20T15:11:08, EventRecordID 857, and again at 17:21:17,
    EventRecordID 1018

From 2026-08-21 a different artefact appears:

    Copy-Item E:\invoice_scan.exe C:\Users\janed\Downloads\invoice_scan.exe -Force
    at 01:00:43

    a two-byte header inspection at 00:28:18

    Test-Path "$env:LOCALAPPDATA\invoice_scan_marker.txt" at 00:29:00

The 2026-08-21 artefacts are consistent with the purpose-built binary
described in groundtruth/Scenario1.md. Which binary was present for the
2026-08-23 run is not established.

Resolution path: $MFT is present in the collection and records the file size
for C:\Users\janed\Downloads\invoice_scan.exe. A renamed notepad.exe carries
the size of the Windows binary. The Week 2 MFT parser settles it.

## Prefetch

Get-Service SysMain:
    <paste>

EnablePrefetcher:
    <paste>

Prefetch must be enabled for execution artifacts to exist. Confirmed running
before any collection was taken.

## Guest Additions / VMware Tools

<Record the true state. If they are absent or non-functional - which is why
 shared folders and clipboard are unavailable and all transfer is by USB or
 virtual-disk mount - say so, and note the consequence:

 "Guest integration tooling is not functional in this VM. Evidence was
 transferred by <route>. A side effect is that the guest carries fewer
 hypervisor-integration artifacts - no shared-folder redirector, no clipboard
 helper service, no drag-and-drop provider - than a VM with working integration
 tooling, so the collected artifact set is marginally closer to a physical
 endpoint than it would otherwise be.">

## Snapshots

BASELINE-CLEAN
    Windows installed and updated, all three accounts created, audit policy
    applied and verified, approximately 20 minutes of benign user activity
    under janed (web browsing, document creation, one small application
    install), one clean reboot. No forensic tooling installed.

    This is the clean image used for false-positive measurement.

    The benign activity is deliberate, not incidental: the Week 4 anomaly model
    learns "normal" from this material. A sterile installation would produce a
    model in which ordinary user behaviour appears anomalous.

BASELINE-CLEAN+TOOLS
    BASELINE-CLEAN plus KAPE and the Eric Zimmerman tool set, installed under
    youssef, plus the Z: collection volume attached.
    Every collection this week begins with a restore of this snapshot.

## Tooling

KAPE            : <version from lab-verification.txt>
KAPE location   : C:\kape\
Zimmerman tools : via get-zimmermantools.ps1 into C:\kape\Modules\bin\, <date>

## Known limitations

<Fill in honestly. Delete what does not apply:>
- <Collections taken from a single VM; no cross-host validation.>
- <Evaluation ISO rather than a licensed installation.>
- <Investigator session (youssef) present in all collections; see above.>
- <Evidence transferred by <route> rather than a verified forensic write-blocker
   path; integrity is established by SHA-256 manifests generated at source
   before transfer and verified after.>

## Deviations from the written procedure

Three deviations occurred during collection. Each was recorded at the time in
groundtruth/scenario1.md or docs/collection-manifest.md and is reproduced here
because it affects what the evaluation can claim.

### 1. scenario1 was collected without an intervening snapshot restore

The stated procedure is that every collection begins from a restore of
BASELINE-CLEAN+TOOLS. scenario1 was instead collected from the live session in
which the scenario had just been executed, with no restore beforehand.

Consequence: scenario1 and the clean baselines are not strictly comparable at
the filesystem level. Any artifact present in scenario1 and absent from the
clean collections may reflect accumulated session state rather than the attack
chain. Findings are therefore corroborated against the recorded operator log
in groundtruth/scenario1.md rather than against the clean baselines alone.

### 2. clean_a was recollected

The original clean_a contained two KAPE runs written to the same destination
directory (2026-08-19T19:27:26 and 2026-08-20T14:31:43), so it was not a single
point-in-time collection. Investigation of the merge established that it was
less damaging than it appeared: the two CopyLogs recorded 768 and 767 files with
766 in common, of which 713 were byte-identical. The 53 differences were
confined to system service prefetch entries (svchost, RuntimeBroker, dllhost)
and telemetry event channels; NTUSER.DAT, SOFTWARE and all user-relevant
artifacts were identical across both runs.

The merge was therefore not the reason for recollection. Direct filesystem
inspection established a more serious fault: of 101 .evtx files collected,
Application.evtx was present but **Security.evtx and System.evtx were absent
from both runs**. Those two channels are the sole source for all six EventIDs
declared in CD-007, so the collection would have produced zero events from the
EVTX parser — and the failure would have presented in Week 1 as a parser fault
rather than a collection fault.

The KAPE EventLogs target was inspected and found intact
(`Path: C:\Windows\System32\winevt\logs\`, `FileMask: '*.evtx'`), and a
verification collection using that target on the same machine collected both
files successfully. The root cause of the original omission was therefore not
the target definition and has not been determined.

clean_a was recollected on 2026-08-24 from a fresh restore of
BASELINE-CLEAN+TOOLS:

| | |
|---|---|
| Command | `--tsource C: --target KapeTriage --tdest Z:\collection_clean_a` |
| Session account | `admin_local`, elevated |
| Files found / copied (KAPE; copied = CopyLog rows = C\ subtree) | 1,017 / 889 (128 deduplicated) |
| Duration | 325.77 seconds |
| Files on disk (recorded at collection; not the full tree) | 876 |
| Total size | 950,656,516 bytes |
| Recorded at | 2026-08-24T17:44:56.723622Z |
| `Security.evtx` | 15,798,272 bytes |
| `System.evtx` | 1,118,208 bytes |
| Zero-byte files | 0 |
| Console log | 72,294 bytes, readable |

Single run, single destination, both event logs present. The merge and the
missing-log fault are both resolved; this entry is retained because the
detection method — hash-comparing the collection tool's own CopyLogs — is part
of the methodology.

### 3. clean_b was recollected

clean_b was recollected on 2026-08-24 from an independent restore of
BASELINE-CLEAN+TOOLS — a separate boot from clean_a's, not a reuse of the same
session, so that the two baselines remain independent samples.

| | |
|---|---|
| Command | `--tsource C: --target KapeTriage --tdest Z:\collection_clean_b` |
| Session account | `admin_local`, elevated |
| Files found / copied (KAPE; copied = CopyLog rows = C\ subtree) | 1,052 / 913 (139 deduplicated) |
| Duration | 365.30 seconds |
| Files on disk (recorded at collection; not the full tree) | 900 |
| Recorded at | 2026-08-24T18:58:05.095260Z |
| Zero-byte files | 0 |
| CopyLog | `2026-08-24T18_56_49_883*_CopyLog.csv` |

Post-collection verification confirmed the expected artifact families are
present, including the Windows event logs and browser history for `janed`.

clean_b contains 900 files against clean_a's 876 as recorded at collection.
The full-tree counts on the host are 916 against 892. The 24-file difference
is the same in both pairings and is consistent with the benign user activity
that distinguishes the two baselines:
clean_a is boot-and-settle with no user interaction, clean_b adds browsing,
application launches and file operations.

**clean_b is the Week 4 anomaly-model baseline.** clean_a supplies the minimal
reference state; clean_b supplies threshold-setting and false-positive
measurement against realistic user activity.

## Collection integrity verification

All three collections were re-verified on 2026-08-25 against KAPE
collection-time SHA-1 from each CopyLog. Full output:
docs/integrity-verification-day4.txt.

| Collection | Match | of CopyLog rows |
|---|---|---|
| clean_a | 885 | 889 |
| clean_b | 911 | 913 |
| collection_s1_v2 | 812 | 814 |

collection_s1_v2 was additionally verified against the host SHA-256 manifest
(`groundtruth/clean-s1-v2-sha256.csv`): 793 of 793 SHA-256 manifest rows match,
zero mismatches. The collection has not been altered since acquisition.

File counts reconcile in all three: CopyLog rows plus three KAPE log files at
the collection root equals the full tree (892, 916, 817). Those full-tree
figures are not the collection-time "Files on disk" figures (876, 900, 793);
see docs/collection-manifest.md for the labelled breakdown.

### Explained mismatches

`$MFT` and `$LogFile`, all three collections. KAPE's ConsoleLog records a
deferral followed by a deferred copy and a source hash after the copy. Example
from clean_a ConsoleLog:

```
Deferring C:\$MFT due to UnauthorizedAccessException...
Deferring C:\$LogFile due to UnauthorizedAccessException...
Copied deferred file C:\$MFT to Z:\collection_clean_a\C\$MFT. Hashing source file...
Copied deferred file C:\$LogFile to Z:\collection_clean_a\C\$LogFile. Hashing source file...
```

The source hash is computed after the copy completes, so on a live volume the
hashed state and the copied bytes describe different moments. Sizes are
identical in every case. This is an artefact of acquisition ordering, not of
alteration.

`$Extend\$J`, clean_a only. CopyLog FileSize 1,577,224,264 against 42,109,000
bytes on disk. The USN journal is a sparse file; only allocated extents were
copied. A different mechanism from the `$MFT` / `$LogFile` case, also expected.

`$LogFile` ModifiedOnUtc reads 1601-01-01, a null FILETIME. NTFS metadata files
do not carry meaningful timestamps.

### Unresolved mismatch

`janed`'s `WebCacheV01.dat` in clean_a. Equal size, differing SHA-1. Unlike the
NTFS files it was not deferred, has no ConsoleLog entry, and its mtime predates
the copy by seven days. The deferred-copy explanation does not account for it.
`WebCacheV01.dat` is a memory-mapped ESE database, and lazy page flushing
without an mtime update is a plausible mechanism, but the evidence does not
establish it. Recorded as unresolved. The equivalent files for `admin_local`
and `Youssef` were deferred and verified correctly. clean_a is not the primary
evidence collection.