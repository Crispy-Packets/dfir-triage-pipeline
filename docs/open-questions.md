# Open questions

Questions that remain after Week 1. None of these is settled by the collected
evidence as it stands. Each entry records what is open, why it cannot be
settled now, and what would settle it.

The lab virtual machine was decommissioned on 2026-08-25. The three
collections, their KAPE logs and the SHA-256 manifests are therefore the
complete and final evidentiary record. No further acquisition from that host
is possible, and every question below must be resolved from held evidence or
remain open permanently.

Held evidence, one line per question:

- OQ-001: **CLOSED 2026-08-26** from Edge `downloads` and Prefetch.
- OQ-002: `C/Users/janed/NTUSER.DAT` is present in `collection_s1_v2`.
- OQ-003: **CLOSED 2026-08-26** from Edge `downloads`.
- OQ-004: no further investigation planned; now permanently unresolvable.
- OQ-005: `$MFT` is present.
- OQ-006: closed for Prefetch (device paths embed the volume serial, both
  volumes resolved); narrowed for EVTX (`\Device\HarddiskVolume2` = Z:, C:
  unmapped).

## OQ-001 Identity of the Scenario 1 binary

**CLOSED 2026-08-26. The binary was the purpose-built .NET stand-in, 4,608
bytes.** Two independent measurements agree, neither of them host-side:

1. The guest's Edge `History` database, `downloads` row id 13, records the only
   download on 2026-08-23: `target_path`
   `C:\Users\janed\Downloads\invoice_scan.exe`, `tab_url`
   `http://192.168.50.2:8000/invoice_scan.exe`, `received_bytes` and
   `total_bytes` both **4,608**, `state` 1 (complete),
   `start_time` 2026-08-23T22:20:06.710763Z.
2. The Prefetch record `INVOICE_SCAN.EXE-A345C2FE.pf` shows the executed process
   referencing `...\USERS\JANED\APPDATA\LOCAL\INVOICE_SCAN_MARKER.TXT`, the
   marker file that only the stand-in writes.

4,608 bytes is the size of `C:\Users\Josep\invoice_scan.exe` on the analysis
host, the binary compiled from `C:\invoice_scan.cs` at 2026-08-20T23:46:43Z.
Windows Notepad is not a candidate: the two host-side Notepad copies are 360,448
bytes (Windows 11) and the 20 August downloads were 201,216 bytes.

The prediction recorded below, before either measurement was taken, named 4,608
bytes. It is left in place unedited so the prediction and its test can both be
read.

The `$MFT` size check remains available as a third measurement but is no longer
required to close the question.

### Original entry, retained


What is open: which binary was present at
`C:\Users\janed\Downloads\invoice_scan.exe` for the 2026-08-23 scenario run.

PowerShell 4104 records in `collection_s1_v2` show
`Copy-Item -Path C:\Windows\notepad.exe -Destination Z:\invoice_scan.exe`
at 2026-08-20T15:06:13, EventRecordID 855, then
`Copy-Item -Path C:\Windows\System32\notepad.exe -Destination Z:\invoice_scan.exe`
at 15:11:08, EventRecordID 857, and again at 17:21:17, EventRecordID 1018.
From 2026-08-21 a different
artefact appears: `Copy-Item E:\invoice_scan.exe
C:\Users\janed\Downloads\invoice_scan.exe -Force` at 01:00:43, a two-byte
header inspection at 00:28:18, and
`Test-Path "$env:LOCALAPPDATA\invoice_scan_marker.txt"` at 00:29:00,
consistent with the purpose-built binary described in
`groundtruth/Scenario1.md`.

Why it cannot be settled now: the collected evidence does not establish which
of those binaries was present for the 2026-08-23 run. The file itself was not
collected (`C\Users\janed\Downloads` is outside KAPE's collection scope).

Resolution path attempted, 2026-08-26: the analysis host was searched for a
surviving copy of the binary, on the reasoning that the file was served from the
host by `python -m http.server` and the host is still available. **Two distinct
executables were found, plus the source of one of them.**

| Host path | Size | SHA-256 | What it is |
|---|---|---|---|
| `FYP\invoice_scan.exe` | 360,448 | `3f543719...a55380` | Renamed Windows 11 Notepad (FileVersion 10.0.26100.8972) |
| `C:\Users\Josep\invoice_scan.exe` | 4,608 | `01c426d6...f436a0` | Purpose-built .NET stub, managed MSIL assembly |
| `C:\invoice_scan.cs` | 648 | `d429e2f5...2353fc` | C# source of the stub |

No two share a hash. The Notepad copy is a Windows 11 binary and the guest is
Windows 10 19045, so it is not the artefact produced by the guest-side
`Copy-Item C:\Windows\System32\notepad.exe` commands recorded in 4104.

The stub writes `%LOCALAPPDATA%\invoice_scan_marker.txt` with a line reading
`TRIAGEFORGE-STANDIN run=<ISO-8601 UTC>` and then sleeps 20 seconds. The
host-side copy of that marker file exists and contains two lines, dated
2026-08-21T00:46:19Z and 2026-08-21T00:47:08Z: the stub was executed twice on
the host, on the night it was compiled. This is the behaviour
`groundtruth/Scenario1.md` expects of the execution step on the guest.

The host's PowerShell console history records the build sequence in order: the
Notepad copy made in the FYP folder and served from there, then the C# source
written and compiled with `csc.exe`, then every subsequent `python -m
http.server 8000` issued from a working directory of `C:\Users\Josep\` - the
directory holding the 4,608-byte stub. That file has no per-line timestamps, so
it establishes sequence but not date.

**Prediction, recorded before the check that tests it:** the `$MFT` size for
`C:\Users\janed\Downloads\invoice_scan.exe` will be **4,608 bytes**. If it is
360,448 the reading above is wrong and the Notepad copy was served. If it is
neither, a third binary was involved. This prediction is recorded here, dated,
so that whichever answer the Week 2 MFT parser returns cannot afterwards be
presented as the one that was expected.

**Independent corroboration from collected evidence, 2026-08-26.** The
prediction above rests on host-side artefacts. The guest's own Prefetch record
supports it without reference to the host. `INVOICE_SCAN.EXE-A345C2FE.pf` in
`collection_s1_v2` records one execution, at 2026-08-23T22:57:15.832787Z, and
its referenced-file list contains two entries of interest:

    \VOLUME{01dd01162add2da6-a62af538}\USERS\JANED\DOWNLOADS\INVOICE_SCAN.EXE
    \VOLUME{01dd01162add2da6-a62af538}\USERS\JANED\APPDATA\LOCAL\INVOICE_SCAN_MARKER.TXT

Resolving the volume serial, those are
`C:\Users\janed\Downloads\invoice_scan.exe` and
`C:\Users\janed\AppData\Local\invoice_scan_marker.txt`. **The process that ran
touched the marker file.** Writing that marker is the defining behaviour of the
TriageForge stand-in, whose source is `C:\invoice_scan.cs`. Windows Notepad does
not write it, and the `NOTEPAD.EXE-EB1B961A.pf` record in the same collection
lists no such file among its 94 referenced entries.

The binary executed on the guest during Scenario 1 was therefore the
purpose-built stub, on the guest's own evidence. What the `$MFT` size adds is a
second, independent measurement of the same conclusion, which is what closes
OQ-001 properly rather than persuasively.

What would settle it: `$MFT` is present in the collection and records the file
size for `C:\Users\janed\Downloads\invoice_scan.exe`. The host-side candidate
now supplies two numbers to compare that size against, 4,608 and 360,448, which
name the two candidate binaries unambiguously. Two independent measurements
agreeing closes OQ-001; the Week 2 MFT parser supplies the second.

## OQ-002 Which hive received the HKCU Run key

What is open: which registry hive received the
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate` write.

Why it cannot be settled now: registry writes are not recorded in
`Security.evtx` without registry auditing.

What would settle it: `C\Users\janed\NTUSER.DAT` is present in the collection.
The Week 2 registry parser settles it. PowerShell 4104 EventRecordID 1604
carries a `System/Security/@UserID` which may settle it sooner.

## OQ-003 Operator log timeline versus evidence

**CLOSED 2026-08-26. The operator log's download entry is wrong by 25m 25.6s.**

The guest's Edge `History` contains exactly one download on 2026-08-23:
`downloads` id 13, starting 22:20:06.710763Z and completing 22:20:07.324360Z.
The operator log records 22:45:32.274977Z. The `Zone.Identifier` reads at
22:38:27Z and 22:38:44Z therefore fall eighteen minutes *after* the download,
not seven minutes before it, and the ordering contradiction disappears.

This is a transcription error on one entry, not a clock problem. Two other
operator-log entries can be checked against guest evidence:

| Entry | Operator log | Guest evidence | Late by |
|---|---|---|---|
| download | 22:45:32.274977Z | 22:20:06.710763Z, Edge `downloads` id 13 | **1,525.56 s** |
| execute | 22:57:22.536771Z | 22:57:15.832787Z, Prefetch slot 0 | 6.70 s |
| log clear | 23:05:12.794670Z | 23:05:06.682356Z, EID 1102 | 6.11 s |

Two entries sit inside the 6.1-6.7 s host-to-guest offset the +/-60 s tolerance
exists to absorb. One is out by a factor of roughly 250.

Against the three outcomes pre-registered before the query was run, this is
outcome 1 in substance - the operator log is in error and the ground truth is
corrected - but at a time none of the three named. Outcome 1 anticipated a
download at approximately 22:38; the measured time is 22:20:06.71. The mismatch
is recorded rather than smoothed over: the pre-registration bounded the shape of
the answer correctly and the value incorrectly.

`groundtruth/Scenario1.md` is corrected, with the original operator-log line
retained and annotated. The scenario's total span is 44m 59.97s, not the 19m 40s
originally recorded; see the amendment in `groundtruth/verification-method.md`.

### Original entry, retained


What is open: the operator log records the download at
2026-08-23T22:45:32.274977Z, while PowerShell 4104 EventRecordID 1597 and 1602
show the Zone.Identifier of the downloaded file being read at 22:38:27Z and
22:38:44Z, seven minutes earlier.

Why it cannot be settled now: the discrepancy is unresolved from the operator
log and the collected evidence as they stand.

What would settle it: not a Week 2 parser. `collection_s1_v2` contains
`C/Users/janed/AppData/Local/Microsoft/Edge/User Data/Default/History`, a
SQLite database whose `downloads` table records `start_time` and `end_time` in
microseconds since 1601-01-01 UTC. Reading one table of one collected file by
hand is Day 5 action 96 - resolving a ground-truth row to its source record -
not parser work, and it dates the download directly.

The +/-60 s tolerance recorded in `groundtruth/verification-method.md` does not
absorb this discrepancy and must not be used to. The log-clear delta is 6.1 s
and the download delta is 425 s; a single uncalibrated host-to-guest clock
offset cannot produce both. This is an ordering contradiction in the ground
truth, not a clock-skew artefact.

Three outcomes are possible and all three are recorded here before the query is
run, so that the one that occurs cannot be presented as the one that was
expected:

1. A download completing at approximately 22:38 - the operator log's 22:45:32
   entry is a transcription error, most likely `Get-Date` run after the fact
   rather than at the moment. Correct the operator log, mark the corrected
   entry as corrected, keep the original line visible, close OQ-003.
2. A download at approximately 22:45 and an earlier one at approximately 22:37 -
   there were two download attempts, the operator log records the second, and
   the ground truth needs the first added.
3. No `downloads` row for `invoice_scan.exe` at all - record that, and OQ-003
   stays open with a narrower question.

Affects Day 5 action 93.

## OQ-004 Unresolved hash mismatch: janed's WebCacheV01.dat in clean_a

What is open: `janed`'s `WebCacheV01.dat` in `clean_a` has equal size and
differing SHA-1. It was not deferred, has no ConsoleLog entry, and its mtime
is seven days before the copy. The deferred-copy explanation does not account
for it.

Why it cannot be settled now: lazy page flushing by a memory-mapped ESE
database is plausible but unestablished.

What would settle it: nothing further is planned. `clean_a` is not the primary
evidence collection. No further investigation planned.

## OQ-005 Zone.Identifier recoverability

What is open: whether the `Zone.Identifier` alternate data stream for
`invoice_scan.exe` can be recovered from collected artefacts.

Why it cannot be settled now: the stream was verified as `ZoneId=3` in the
live guest at collection time. The file and its alternate data stream fall
outside KAPE's collection scope, as `C\Users\janed\Downloads` was not
collected.

What would settle it: `$MFT` is present and alternate data streams are
recorded in MFT attributes. The Week 2 MFT parser settles it.

Note added 2026-08-26, for whoever runs that check: `C:\Users\janed\Downloads`
held more than one copy of the binary over the lab period. Edge `downloads`
records target paths `invoice_scan.exe`, `invoice_scan (1).exe` and
`invoice_scan (2).exe`, across eleven downloads of three different sizes -
201,216 bytes on 20 August, 360,448 bytes on 21 August, and 4,608 bytes for the
2026-08-23 scenario run. The MFT query must select the entry for
`invoice_scan.exe` and must check its size against 4,608, or it will resolve the
wrong file.

## OQ-006 Device path to drive letter mapping

**Status 2026-08-26: closed for Prefetch, narrowed for EVTX.**

What was open: how a device path recorded in an execution artefact resolves to a
drive letter, so that Week 3's download-to-execution rule can join EVTX and
Prefetch against ground truth written as
`C:\Users\janed\Downloads\invoice_scan.exe`. Unresolved, that join compares
different spellings of the same file, returns zero rows, and reports the result
as "no correlation found" rather than as a defect in the join.

### Closed: Prefetch

The volume information blocks of `INVOICE_SCAN.EXE-A345C2FE.pf` and
`NOTEPAD.EXE-EB1B961A.pf` in `collection_s1_v2` were read directly. Prefetch
uses neither the NT device-path form nor the mount-point GUID form. It uses a
form whose trailing field is the **volume serial number**:

| Prefetch device path | Serial | Resolves to |
|---|---|---|
| `\VOLUME{01dd01162add2da6-a62af538}` | `A62A-F538` | **C:** |
| `\VOLUME{01dd300c59a66956-5659c38d}` | `5659-C38D` | **Z:** |

Both serials were captured on the live guest before decommissioning and are held
in `docs/evidence/accounts-and-volumes.txt`. The mapping is complete for both
volumes, requires no further acquisition, and involves no inference.

### Narrowed: EVTX

EID 4688 records `NewProcessName` in the unrelated `\Device\HarddiskVolumeN`
form. One value is established: `\Device\HarddiskVolume2` is **Z:**, from
KAPE's ConsoleLog reporting `KAPE directory: Z:\kape\KAPE` 2.6 seconds after the
4688 that names the same process `\Device\HarddiskVolume2\kape\KAPE\kape.exe`.
An earlier revision of `docs/lab-setup.md` inferred that the same device path
was C:, from KAPE's recorded install location; that inference is discarded.

What remains open: no device path for C: has been observed in the surviving EVTX
evidence. Whether one exists at all is unknown, because the 4688 for
`invoice_scan.exe` was removed by the log clear.

What would settle it: a search of the three Security logs for any 4688 whose
`NewProcessName` begins `\Device\HarddiskVolume` and whose `CommandLine` names
the same executable in drive-letter form.
`ProcessCreationIncludeCmdLine_Enabled` is set (`0x1`,
`docs/evidence/lab-verification.txt`), so the pairing is present if any such
record survives. If none does, the honest outcome is that the EVTX half of the
mapping is unresolvable from this evidence, and Week 3's rule must either rely
on Prefetch for entity identity or normalise EVTX paths by basename with the
loss of precision that implies.

## FUTURE WORK

Recorded so these sources are not rediscovered late. None of these is a Week 1
change and none should be acted on now.

1. Microsoft-Windows-PowerShell/Operational, EventID 4104 script block
   logging. The channel holds 1,470 records predating the clear, of which
   1,231 are EventID 4104, including the full attack chain in plaintext. Not
   among the declared artefact families. The strongest available
   demonstration that a Security-only log clear does not remove the attack
   chain.

2. EID 4726, account deleted. Present in `clean_b`, not in CD-007.

3. EID 4616, system time changed. 25 records in `clean_b`, not in CD-007.
   Relevant to anti-forensic time manipulation.

4. `$LogFile` and `$Extend\$J`. Collected in all three collections, not
   parsed. `$J` records file creation and deletion and would evidence
   `invoice_scan.exe` arriving in `janed\Downloads` despite that directory
   not being collected.

5. 118 event channels are collected; 106 hold at least one pre-clear record
   (105 excluding Security, whose single pre-clear record is a 67 ms
   write-ordering artefact). The pipeline reads two.
