# Rule coverage against an independent public corpus — 2026-09-14

Four of the ten rules fired on nothing in this project's own five collections.
They were reported as untested code paths rather than as passing checks, which
left an obvious question: **do they work at all?**

This answers it for five of them, using
[`evtx-attack-samples`](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) —
278 EVTX files captured from real technique executions and named by ATT&CK
tactic. Nothing in the corpus was written by this project.

---

## 1. The run

```
10 rules loaded

278 samples, 60 in a channel this pipeline parses
channels present:
   192  Microsoft-Windows-Sysmon/Operational
    51  Security  <- parsed
     7  Application
     6  System  <- parsed
     4  Windows PowerShell
     3  Microsoft-Windows-Bits-Client/Operational
     3  Microsoft-Windows-PowerShell/Operational  <- parsed
     3  Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

37 samples produced events

=== RULE COVERAGE ===
A rule firing on many samples is not broad detection. Several of
these captures begin with a genuine EID 1102 because the collector
cleared the log before recording the technique it was isolating, so
R-ATOMIC-0002 matches real evidence in files named for something
else. The count says how many samples contain the artifact, not how
many are about the technique.

  R-ATOMIC-0001  FIRED on 1 sample(s), 2 finding(s)
      Credential Access/tutto_malseclogon.evtx
  R-ATOMIC-0002  FIRED on 24 sample(s), 24 finding(s)
      Command and Control/DE_RDP_Tunnel_5156.evtx
      Credential Access/ACL_ForcePwd_SPNAdd_User_Computer_Accounts.evtx
      Credential Access/CA_chrome_firefox_opera_4663.evtx
      Credential Access/Zerologon_VoidSec_CVE-2020-1472_4626_LT3_Anonym_follwedby_4742_DC_Anony_DC.evtx
      ... 20 more
  R-ATOMIC-0003  FIRED on 1 sample(s), 1 finding(s)
      emotet/exec_emotet_ps_4104.evtx
  R-ATOMIC-0004  FIRED on 1 sample(s), 2 finding(s)
      Lateral Movement/LM_Remote_Service02_7045.evtx
  R-ATOMIC-0005  no findings  (no sample in a parsed channel carries this technique)
  R-ATOMIC-0006  no findings  (no sample in a parsed channel carries this technique)
  R-CORR-0001  no findings  (correlation rule: one channel per sample, nothing to join)
  R-CORR-0002  FIRED on 1 sample(s), 1 finding(s)
      Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx
  R-CORR-0003  no findings  (correlation rule: one channel per sample, nothing to join)
  R-CORR-0004  no findings  (correlation rule: one channel per sample, nothing to join)
```

---

## 2. What this establishes

**Six of ten rules fire on evidence nobody here produced**, up from six that
fire on this project's own collections — but a different six, and that is the
point:

| rule | own corpus | public corpus |
|---|---|---|
| R-ATOMIC-0001 suspicious location | 42-48 (host 1) | ✅ 1 sample |
| R-ATOMIC-0002 log clear | 1 (s1_v3) | ✅ 24 samples |
| R-ATOMIC-0003 encoded PowerShell | 3-8 (host 1 only) | ✅ 1 sample |
| **R-ATOMIC-0004 services** | **0 everywhere** | ✅ **1 sample** |
| R-ATOMIC-0005 RDP | 0 everywhere | ✗ no parsed sample |
| R-ATOMIC-0006 autorun | 1-8 | ✗ registry, not EVTX |
| R-CORR-0001 download→exec | 1-4 | ✗ needs two channels |
| **R-CORR-0002 failed→success logon** | **0 on host 2** | ✅ **1 sample** |
| R-CORR-0003 exec→Run key | 1-2 | ✗ needs two channels |
| R-CORR-0004 service→log clear | **0 everywhere** | ✗ needs two channels |

**R-ATOMIC-0004 and R-CORR-0002 moved from "never fired anywhere" to "verified
against independent evidence."** That is the result this harness existed to
produce.

---

## 3. What it does NOT establish

Stated here because a coverage table invites being read as more than it is.

**It is not a detection rate.** A rule firing on a sample proves the rule
matches evidence of that technique. It says nothing about how many instances of
the technique it would catch, and nothing at all about false positives — that
needs a labelled corpus with negatives, and this is not one.

**R-ATOMIC-0002's 24 samples are not broad detection.** Several of these
captures begin with a genuine EID 1102, because the collector cleared the log
before recording the technique being isolated. The rule is matching real
evidence in files named for something else. The count says how many samples
contain the artifact, not how many are about the technique.

**Four rules remain unexercised**, and the reasons are structural rather than
faults:

- **R-ATOMIC-0005 (RDP)** — the corpus has three
  `RemoteDesktopServices-RdpCoreTS/Operational` samples, a channel this
  pipeline does not parse. The rule reads Security 4624 with a network logon
  type, and no sample carries one.
- **R-ATOMIC-0006 (autorun)** — reads the registry. An EVTX corpus cannot
  exercise it by construction.
- **R-CORR-0001, R-CORR-0003, R-CORR-0004** — each joins two artifact families,
  and every sample here is one channel from one machine. There is nothing to
  join. These are verified on this project's own collections instead, where
  R-CORR-0001 and R-CORR-0003 both fire on the scenario.

---

## 4. Why the anomaly layer is not involved

The samples come from **dozens of different machines with no clean baseline
between them**. Fitting a model on one and scoring another is precisely the
cross-host failure `anomaly.baseline_warning` exists to catch — measured at
50.3% of rows flagged against a 5% setting when host 2's model scored host 1.

A public EVTX corpus cannot supply a baseline for a machine it did not come
from, so nothing here touches the anomaly layer. It is a rule test.

---

## 5. One thing the harness got wrong first

The first version read each file as raw bytes and searched for `<Channel>`. It
found **zero** channels in all 278 files and reported every rule as unfired —
which looked exactly like a real result.

EVTX stores records as **binary XML**. The channel name does not exist as
readable bytes on disk; it appears only after `PyEvtxParser` renders a record.
The fix is to parse one record per file, and it is recorded here because the
failure mode is the one this project keeps meeting: code that runs, returns a
plausible answer, and is wrong.

---

## 6. How to re-run it

```
python tools/rule_harness.py <path to evtx-attack-samples>
```

The corpus is not vendored into this repository: it is 278 binary files under a
separate licence, and a checkout of this project does not need them to run the
gate. The harness is a tool, not a test — it requires an external corpus and is
therefore not part of `pytest`.

Each sample is copied to a temporary tree under the filename its channel
requires, because the parser matches on filename (`Security.evtx`,
`System.evtx`, `Microsoft-Windows-PowerShell%4Operational.evtx`) and these files
are named by scenario. **That copy is the only accommodation made. No sample is
edited.**
