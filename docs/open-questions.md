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

What would settle it: `$MFT` is present in the collection and records the file
size for `C:\Users\janed\Downloads\invoice_scan.exe`. A renamed `notepad.exe`
carries the size of the Windows binary. The Week 2 MFT parser settles it.

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

What would settle it: Person A reconciling the operator log, and browser
history parsing in Week 2. Affects Day 5 action 93.

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
