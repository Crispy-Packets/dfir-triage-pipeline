# atomic-evtx: what it can and cannot do for this pipeline — 2026-09-15

[`arniki/atomic-evtx`](https://github.com/arniki/atomic-evtx) is 21,281 EVTX
files from 4,244 Atomic Red Team technique executions, organised by ATT&CK
tactic. It was evaluated for two purposes: fixing `evtx.security` degeneracy,
and extending rule coverage.

**It does not help the first. It is the best available corpus for the second.**

---

## 1. Why it cannot fix degeneracy

`evtx.security` on host 2 has 740 rows and a distinct-vector ratio of 0.164,
below the 0.25 floor, so it is reported unscored. That is a VOLUME problem: the
same family with 10,439 rows in `clean_b` scores 0.909 and is one of the
healthiest in the project.

Fixing it needs a training baseline — thousands of Security rows from one
machine showing what normal looks like there.

**Measured: ~40,000 Security records across 4,244 files, a median of THREE
records per file.**

| event ID | occurrences in sample |
|---|---|
| 5379 (credential read) | 189 |
| 4798 (group enumeration) | 106 |
| 4799 | 106 |
| 4624 (logon) | 79 |
| **1102 (log cleared)** | **60** |
| 4616 (system time changed) | 54 |

Those three-record files are not a baseline; they are deliberately isolated
captures. **EID 1102 appears in roughly one file in four because the capture
tool clears the Security log before recording each technique.** A corpus that
clears the log before every capture is the opposite of what a baseline is.

And it is 4,244 different machine-states. Fitting a model across them is exactly
the cross-host failure `anomaly.baseline_warning` exists to catch — measured at
50.3% of rows flagged when host 2's model scored host 1.

**`evtx.security` degeneracy on host 2 is not fixable by any public dataset.**
It needs more Security activity on host 2 itself, and it is reported unscored
rather than fitted, which is the correct outcome.

---

## 2. Why it is the right corpus for rule coverage

Unlike sbousseaden's samples, where each file is one channel from one machine,
**every technique directory here holds Security and System from the SAME run**:

```
.../persistence/Service Installation PowerShell/
    T1543.003-1_Security.evtx
    T1543.003-1_System.evtx
    T1543.003-1_Windows PowerShell.evtx
```

That is what makes correlation rules testable at all: a rule joining two
artefact families finally has two families to join.

---

## 3. The run

```
10 rules
4244 technique directories, 4244 with 2+ parsed channels
running 250 techniques, spread across the corpus

250 techniques produced events, 0 produced none

=== RULE COVERAGE ===
A count is how many techniques contained the artifact, not how many
are about it: this corpus clears the Security log before most
captures, so R-ATOMIC-0002 matches real evidence throughout.

  R-ATOMIC-0001  no findings
  R-ATOMIC-0002  FIRED on 250 technique(s), 250 finding(s)
      ?/T1003-3
      ?/T1003.002-3
      ?/T1003.004-2
      ... 247 more
  R-ATOMIC-0003  no findings
  R-ATOMIC-0004  FIRED on 1 technique(s), 1 finding(s)
      privilege-escalation/Service Installation PowerShell
  R-ATOMIC-0005  no findings
  R-ATOMIC-0006  no findings
  R-CORR-0001  no findings
  R-CORR-0002  no findings
  R-CORR-0003  no findings
  R-CORR-0004  no findings

=== FINDINGS BY ATT&CK TACTIC ===
     69  defense-evasion
     51  ?
     34  discovery
     23  privilege-escalation
     21  credential-access
     11  command-and-control
     11  execution
     11  persistence
      6  impact
      5  collection
      4  lateral-movement
      3  exfiltration
      2  initial-access
```

---

## 4. What this establishes, and what it does not

**R-ATOMIC-0002 fired on all 250 techniques.** That is not broad detection and
the harness says so in its own output: this corpus clears the Security log
before most captures, so the rule is matching real EID 1102 evidence in
recordings named for something else entirely. The count measures how many
captures contain the artefact.

**R-ATOMIC-0004 fired on one technique** — `privilege-escalation/Service
Installation PowerShell`, an EID 7045 service install from
`C:\Users\ADMIN_~1\AppData\Local\Temp\AtomicRedTeam`. Independent
confirmation of a rule that fires on nothing in this project's own five
collections.

### Why the other eight did not fire, each for a structural reason

| rule | why |
|---|---|
| R-ATOMIC-0001 suspicious location | reads 4688 process creation; **EID 4688 is absent from this corpus entirely** |
| R-ATOMIC-0003 encoded PowerShell | reads 4104 on `Microsoft-Windows-PowerShell/Operational`. This corpus carries the LEGACY `Windows PowerShell` channel (400/403/600/800), which the parser does not read — see section 5 |
| R-ATOMIC-0005 external RDP | needs Security 4624 with a network logon type; present as 4624 but not of that type |
| R-ATOMIC-0006 autorun | reads the registry, which an EVTX corpus cannot supply |
| R-CORR-0001, -0003 | join browser or registry to execution; neither family exists here |
| R-CORR-0002 failed→success logon | needs 4625 then 4624 for one principal; 4625 does not appear |
| **R-CORR-0004 service→log clear** | **the evidence is present and the ORDER is wrong** — see below |

### R-CORR-0004 is the interesting one

The `Service Installation PowerShell` technique carries both halves:

```
12:51:58  evtx.security  log_cleared
12:52:00  evtx.system    service_install   C:\Users\ADMIN_~1\...\AtomicRedTeam
```

The rule requires a service installation **followed by** a log clear — an
adversary covering their tracks. Here the clear came **two seconds before** the
install, because the capture tool cleared the log to isolate the technique.

**The rule correctly refused to fire.** Reporting a chain whose steps occurred
in the opposite order would be a fabricated finding, and `order: strict` is what
prevents it. This is the rule's ordering constraint demonstrated on evidence
nobody here produced.

---

## 5. What a rule could read here and currently cannot

EID 800 on the legacy `Windows PowerShell` channel carries the command text:

```
<Data>Add-type -TypeDefinition $source -Language CSharp</Data>
<Data>... HostApplication=powershell.exe &amp; {IEX (New-Object System.Net.Webclient).Do...
```

`IEX (New-Object System.Net.Webclient).DownloadString` is precisely what
R-ATOMIC-0003 detects — and the pipeline cannot see it, because
`parsers/evtx_windows.py` reads only the Operational channel.

That exclusion is deliberate and documented: *"Windows PowerShell.evtx is the
legacy classic log and carries no script blocks."* The comment is right about
4104, but EID 800's `HostApplication` field does carry a command line, and on a
host without script-block logging enabled it is the only PowerShell evidence
available.

**This is a parser gap with a named consequence**, recorded here rather than
fixed: adding the legacy channel means a new artefact family, a
`details-schema.md` entry, and a measured base rate on all five collections —
Person A's lane and a decision rather than an implementation.

It is also directly relevant to this project's own history. `clean_c` had to be
re-collected because script-block logging was disabled and `evtx.powershell`
carried 5 rows; a legacy-channel parser would have salvaged that collection.

---

## 6. How to re-run it

```
python tools/atomic_harness.py <path to atomic-evtx> --limit 250
```

**Files are read from git rather than from the working tree.** The repository
contains directory names with colons (`Brute Force:Credential Stuffing using
Kerbrute Tool`), which are illegal on Windows: `git checkout` fails partway and
leaves an empty tree. `git show HEAD:<path>` reads the blob regardless.

The corpus is not vendored — 21,281 binary files under a separate licence, and
the gate does not need them.
