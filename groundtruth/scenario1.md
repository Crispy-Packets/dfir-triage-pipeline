# Collection manifest

Three triage collections, each taken from an explicit restore of
BASELINE-CLEAN+TOOLS. Lab configuration is in docs/lab-setup.md.

## Common parameters

KAPE target set : KapeTriage
KAPE modules    : <none | list verbatim>
Output format   : plain directory (not --vhdx)
Source volume   : C:
Destination     : Z: (separate volume - see docs/lab-setup.md)
Collected by    : youssef (investigator account)

The target set is identical across all three. A different target set between a
clean collection and a scenario collection would make every downstream
comparison invalid, and the difference would appear in the evaluation as a
detection result.

Collections are directories rather than VHDX containers because the pipeline
walks a directory tree; a VHDX is a single opaque file it cannot enter.

## Integrity

SHA-256 manifests were generated inside the VM, against the collection as
written by KAPE, before any transfer. After transfer to the analysis host each
collection was re-hashed and compared row by row against the source manifest.
Mismatches: 0. Missing files: 0.

Transfer route: <USB | virtual-disk mount | file host>. This is not a
write-blocked forensic acquisition path; integrity is established by the
hash comparison above rather than by the transfer mechanism.

Path convention: manifest paths are collection-relative POSIX strings. Absolute
paths would be machine-specific and unverifiable on any other machine.
Encoding: UTF-8 with BOM (Windows PowerShell 5.1). Readers must use utf-8-sig.

## clean_a

Source snapshot : BASELINE-CLEAN+TOOLS
Restored at     : <UTC>
Activity        : none - booted and allowed to settle. See docs/lab-setup.md on
                  the investigator session present in all collections.
Collected at    : <UTC>
Command         : C:\kape\kape.exe --tsource C: --target KapeTriage --tdest Z:\collection_clean_a
Files           : <from counts.txt>
Bytes           : <from counts.txt>
Traversal errors: <from counts.txt>
Manifest        : groundtruth/clean-a-sha256.csv

Purpose: training data for the Week 4 anomaly model. Baseline system state with
no simulated user activity beyond boot.

## clean_b

Source snapshot : BASELINE-CLEAN+TOOLS (independent restore, not a reuse of clean_a)
Restored at     : <UTC>
Activity        : <web browsing, applications opened, files copied, PowerShell run>
                  <account each action was performed under - janed or local_admin>
                  <if a throwaway account was created and deleted, say so -
                   it produces a real 4720>
                  <if something was installed registering a service, say so -
                   it produces a real 7045>
Collected at    : <UTC>
Command         : C:\kape\kape.exe --tsource C: --target KapeTriage --tdest Z:\collection_clean_b
Files           : <n>
Bytes           : <n>
Traversal errors: <n>
Manifest        : groundtruth/clean-b-sha256.csv

Purpose: threshold setting and false-positive measurement. Independent of
clean_a by construction - a separate restore with a different benign workload.
If both came from the same run they would not be independent and the Week 4
evaluation would be invalid.

## scenario1

Source snapshot : BASELINE-CLEAN+TOOLS
Restored at     : <UTC>
Scenario        : commodity infection chain - browser download, execution,
                  autorun persistence, Security log clear
Run under       : janed (download, execution, persistence)
                  local_admin (Security log clear)
Staged binary   : C:\Windows\System32\notepad.exe renamed invoice_scan.exe,
                  served over the host-only network from the host
Executed at     : <UTC>
Collected at    : <UTC>
Command         : C:\kape\kape.exe --tsource C: --target KapeTriage --tdest Z:\collection_s1
Files           : <n>
Bytes           : <n>
Traversal errors: <n>
Ground truth    : groundtruth/scenario1.md
Manifest        : groundtruth/scenario1-sha256.csv

The staged binary is a genuine, signed, harmless Windows executable. From the
artifacts' point of view it is an unknown binary downloaded from a remote host
and executed out of Downloads\, which is the evidence pattern the project
targets. The claim in the report is narrow: it reproduces the download,
execution and persistence metadata. It is not claimed equivalent to real
malware.

notepad.exe rather than calc.exe: on Windows 10 and 11 the System32 calc.exe is
a stub that hands off to the Store Calculator app, so its execution artifacts
are unpredictable.

## Note on Security.evtx in scenario1

The scenario ends with `wevtutil cl Security`, which generates EID 1102 and
destroys the 4688 for the execution. Scenario 1's Security.evtx is therefore
nearly empty compared with clean_a and clean_b. This is intentional and is the
reason cross-artifact correlation matters: Prefetch and Amcache still prove
execution after the log is gone.

The missing 4688 is not a parser fault and must not be read as one.

Validate 4624 and 4688 against clean_a or clean_b; validate 1102 against
scenario1.

## Evidence handling

Collections are not committed to git. .gitignore blocks collections/, *.evtx,
*.pf and *.hve. Reproducibility is provided by the SHA-256 manifests above,
which are committed, together with the procedure documented here.