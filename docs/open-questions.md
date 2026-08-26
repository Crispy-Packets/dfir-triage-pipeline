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

- OQ-001: `$MFT` is present in all three collections.
- OQ-002: `C/Users/janed/NTUSER.DAT` is present in `collection_s1_v2`.
- OQ-003: Edge History for `janed` is present in `collection_s1_v2`.
- OQ-004: no further investigation planned; now permanently unresolvable.
- OQ-005: `$MFT` is present.
- OQ-006: `.pf` files are present in all three collections; the volume
  serial and GUID mappings are held in `docs/evidence/accounts-and-volumes.txt`.

## OQ-001 Identity of the Scenario 1 binary

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
host by `python -m http.server` and the host is still available. One was found,
at the root of the connected project folder:

    Size             : 360,448 bytes
    SHA-256          : 3f543719a819a9769d8f138a02544f93af8b53ef1779a96bc2403715d9a55380
    LastWriteTime    : 2026-07-29T21:58:57Z
    Version resource : CompanyName "Microsoft Corporation",
                       OriginalFilename "NOTEPAD.EXE",
                       FileDescription "Notepad"

It is a renamed copy of the Windows Notepad binary. This is corroborating
evidence and explicitly not a closure: nothing establishes that this host-side
copy is the file that was served to the guest on 2026-08-23, and the 2026-08-21
PowerShell artefacts above describe a binary with marker-file behaviour that
Notepad does not have. A second host-side artefact, a file named
`invoice_scan_marker.txt` in the host user's `AppData\Local`, was reported by a
path audit on the same date and has not yet been characterised; its timestamps
would date when the purpose-built binary last ran on the host.

What would settle it: `$MFT` is present in the collection and records the file
size for `C:\Users\janed\Downloads\invoice_scan.exe`. The host-side candidate
now supplies a number to compare that size against: 360,448 bytes means the
collected file was a renamed Notepad, any other size means it was not and the
2026-08-21 purpose-built binary becomes the candidate. Two independent
measurements agreeing closes OQ-001; the Week 2 MFT parser supplies the second.

## OQ-002 Which hive received the HKCU Run key

What is open: which registry hive received the
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate` write.

Why it cannot be settled now: registry writes are not recorded in
`Security.evtx` without registry auditing.

What would settle it: `C\Users\janed\NTUSER.DAT` is present in the collection.
The Week 2 registry parser settles it. PowerShell 4104 EventRecordID 1604
carries a `System/Security/@UserID` which may settle it sooner.

## OQ-003 Operator log timeline versus evidence

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

## OQ-006 NT device path to drive letter mapping

What is open: whether `\Device\HarddiskVolume2` is `C:` on the lab guest, as a
measurement rather than an inference.

Week 3's download-to-execution rule joins EVTX and Prefetch on the executable
path. EID 4688 records process paths in NT device-path form -
`\Device\HarddiskVolume2\kape\KAPE\kape.exe`, `docs/lab-setup.md` - while the
ground truth in `groundtruth/Scenario1.md` is written as
`C:\Users\janed\Downloads\invoice_scan.exe`. Unresolved, that join compares two
spellings of the same file, returns zero rows, and reports the result as "no
correlation found" rather than as a defect in the join.

The present basis for believing the mapping is that EID 4688 names the KAPE
binary by device path in `clean_a` and `clean_b`, and `docs/lab-setup.md` records
KAPE as installed at `C:\kape\` in the guest. That is two records agreeing, not
a measurement.

Not open, recorded here so it is not reopened: the volume serial and volume GUID
mappings for C: and Z: were captured on the live guest before decommissioning
and are held in `docs/evidence/accounts-and-volumes.txt` - C: `A62A-F538`,
`{b48fbbba-0000-0000-0000-100000000000}`; Z: `5659-C38D`,
`{b48fbbba-0000-0000-0000-f07f0c000000}`. `EnablePrefetcher` (`0x3`) and the
`SysMain` service state (`Automatic`, `Running`) were captured on
2026-08-21T17:22:37Z and are held in `docs/evidence/lab-verification.txt`. None
of these four values requires a parser or a further acquisition, and none of
them is what OQ-006 asks.

Why it cannot be settled directly now: `\Device\HarddiskVolumeN` is a symbolic
link assigned by the volume manager at run time. It is not stored under
`HKLM\SYSTEM\MountedDevices`, which records a disk signature and partition
offset against `\DosDevices\C:` and `\??\Volume{GUID}`; that key ties GUID to
drive letter, which is already held, and does not supply the device-path
numbering. The guest was decommissioned on 2026-08-25, so the live symbolic link
cannot be read.

What would settle it: the Prefetch volume information block records a volume
device path together with that volume's serial number in the same structure.
`A62A-F538` is already on record as C:, so the first `.pf` parsed from any of
the three collections pairs an unknown device path against a known serial and
resolves the mapping directly. This is a sequencing note rather than a hole: it
is settled by the Week 2 Prefetch parser reading evidence already collected.

Cheaper corroboration available before then, from held evidence and without a
parser: `ProcessCreationIncludeCmdLine_Enabled` is set (`0x1`,
`docs/evidence/lab-verification.txt`), so 4688 records carry `CommandLine`
alongside `NewProcessName`. Any single record whose `NewProcessName` is
`\Device\HarddiskVolume2\...` and whose `CommandLine` names the same executable
as `C:\...` establishes the mapping outright. Searching the three Security logs
for that pairing is a Day 5 task, not a Week 2 one.

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
