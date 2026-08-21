# Lab setup

Environment in which all Week 1 evidence was collected. Every configuration
change below was verified by execution; the verification output is recorded
rather than asserted. Raw capture: docs/evidence/lab-verification.txt

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

Three local accounts, no Microsoft accounts. A Microsoft account changes the
profile path shape and introduces cloud-sync artifacts that would contaminate
the baseline.

SUBJECT ACCOUNTS - the accounts whose behaviour the evidence represents

janed        - standard user, SID <S-1-5-21-...>
               Primary user for all scenarios. Downloads and executes the
               Scenario 1 binary.

admin_local  - local administrator, SID <S-1-5-21-...>
               Used for the Scenario 1 Security log clear, which requires
               administrative rights.

INVESTIGATOR ACCOUNT - lab operation, not part of the simulated behaviour

youssef      - local administrator, SID <S-1-5-21-...>
               Used to build the lab, install KAPE and the Zimmerman tools,
               and run every collection.

All three accounts were created during the BASELINE-CLEAN build, before any
snapshot was taken, so all three are present in the clean image. An account
created later would resemble attacker-created persistence (EID 4720) and would
appear in the evaluation as a detection when it is a lab artifact.

### Investigator activity in the evidence - stated explicitly

KAPE was run interactively under `youssef`, so every collection contains
artifacts of that session: a 4624 logon for `youssef`, Prefetch entries for
kape.exe and its child processes, and console history. This is unavoidable in a
live triage collection and is not concealed.

Consequence for analysis: `youssef` is excluded from the ground truth in
groundtruth/scenario1.md and is expected to appear in output as a benign
high-activity entity. If a detection rule ever fires on `youssef` or on
kape.exe, that is a false positive caused by the collection method, and it is
reported as such rather than filtered away.

Consequence for the Week 4 anomaly layer: clean_a is described below as "no
user activity beyond boot". That means no *simulated* user activity. The
`youssef` collection session is present in all three collections equally, so it
does not differentiate clean from scenario, but it is not zero activity and the
model will learn it as normal.

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

Microsoft Defender status at capture:
    <paste Get-MpComputerStatus block>

The Scenario 1 binary is a genuine signed Windows executable (notepad.exe,
renamed) and is not quarantined.

<If any protection setting was changed at any point, record it here with the
exact change and the UTC window it applied to. If nothing changed, say so
explicitly - "was AV running?" is a fair examiner question and "disabled
throughout" would weaken the realism claim for no gain.>

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

### 2. clean_a contains two merged KAPE runs

Two collections were written to the same destination directory:
2026-08-19T19:27:26 and 2026-08-20T14:31:43. The later run's files overlay the
earlier run's rather than replacing them.

Consequence: clean_a is not a single point-in-time collection. It is not used
as the sole training baseline for the Week 4 anomaly layer; clean_b, which is a
single run, is used instead, and clean_a is retained for comparison only.

### 3. clean_b's collection session ran under admin_local

The procedure specified janed for benign activity. The KAPE session itself was
run under admin_local.

Consequence: clean_b contains an admin_local logon and session artifacts not
anticipated in the procedure. This is investigator activity of the same class
as the youssef sessions documented above and is excluded from ground truth on
the same basis.