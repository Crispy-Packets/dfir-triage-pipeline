# Family signal survey — 2026-09-18

**Do any of the parsed families no rule reads carry signal that separates the
scenario collections from the clean ones?**

Run as the "what am I missing" pass before writing rules for the 31 uncovered
families. 38 named families and 98 generic EVTX channels, across all five
collections.

**Result: one family survives. Three apparent candidates were disqualified on
inspection, and one of the disqualifications is a corpus-leakage finding that
matters more than the survivor.**

---

## 1. The first measurement was wrong, and how it failed

The first pass asked, per family, *is the scenario count different from the
clean count*. By that test **72 of 98 generic channels "separated both
hosts"**, along with `$MFT` (456,061 vs 419,396) and the Windows Store
telemetry channel (27,010 vs 26,494).

That is not signal. A scenario collection ran longer and did more, so nearly
every count rises a little. The test measured collection volume and reported
it as detection — the same failure `hour_of_day` produced for the anomaly
layer, where 86% "accuracy" was collection identity.

**Corrected test**, and it is the one the figures below use:

1. **Normalise by collection size** — compare each family's rows per 100,000
   events, not its raw count.
2. **Require both hosts to move the same way by at least 2x.** Host 1 is
   `clean_a`/`clean_b`/`s1_v2`; host 2 is `clean_c`/`s1_v3`. A family that
   rises on one host and falls on the other is noise, whatever a pooled
   statistic would say. Pooling the hosts is what the project's own
   train-and-score-within-one-host rule forbids.

Normalising cut the generic channels from 72 to 18 and reordered the named
families completely.

---

## 2. Named families, normalised (rows per 100,000 events)

| family | h1 clean | h1 scen | h2 clean | h2 scen | r1 | r2 | verdict |
|---|---|---|---|---|---|---|---|
| **recyclebin** | 0.3 | 2.1 | 0.0 | 0.2 | 6.54 | ∞ | **candidate** |
| ps_history | 7.9 | 27.1 | 6.7 | 19.9 | 3.43 | 2.95 | candidate → **excluded, leakage §3.1** |
| evtx.winlogon | 46.5 | 118.2 | 33.8 | 135.7 | 2.54 | 4.02 | candidate → **parser-blocked, D-057 §3.2** |
| ntfs_logfile | 18618.0 | 1008.8 | 33102.9 | 3760.5 | 0.05 | 0.11 | inverted → **structurally unable to attest §3.3** |
| recentdocs | 7.1 | 13.4 | 6.6 | 10.2 | 1.88 | 1.55 | weak |
| webcache | 15.7 | 28.3 | 9.1 | 18.3 | 1.81 | 2.00 | weak |
| timeline | 26.9 | 46.0 | 18.6 | 33.8 | 1.71 | 1.81 | weak |
| jumplist | 8.9 | 13.5 | 5.5 | 7.5 | 1.52 | 1.36 | weak |
| lnk | 5.4 | 8.1 | 5.9 | 8.2 | 1.50 | 1.39 | weak |
| evtx.defender | 62.1 | 91.4 | 45.2 | 73.7 | 1.47 | 1.63 | weak |
| shellbags | 3.9 | 5.6 | 1.2 | 3.1 | 1.44 | 2.56 | weak |
| bam | 8.2 | 11.7 | 6.4 | 10.4 | 1.42 | 1.63 | weak |
| srum | 909.7 | 1256.2 | 183.5 | 382.3 | 1.38 | 2.08 | weak |
| evtx.bits | 77.8 | 106.6 | 32.8 | 49.7 | 1.37 | 1.52 | weak |
| userassist | 14.2 | 18.6 | 7.8 | 12.1 | 1.31 | 1.56 | weak |
| **usn** | 7579.5 | 17566.7 | 11030.7 | 6545.2 | 2.32 | **0.59** | **no signal — opposite directions** |
| mft | 61674.5 | 68584.4 | 49668.5 | 77488.8 | 1.11 | 1.56 | no signal |
| shimcache | 56.1 | 62.3 | 35.7 | 48.1 | 1.11 | 1.35 | no signal |
| amcache | 122.5 | 132.0 | 69.0 | 115.2 | 1.08 | 1.67 | no signal |
| defender_mplog | 379.5 | 406.6 | 15.7 | 47.7 | 1.07 | 3.04 | no signal |
| **evtx.firewall** | 28.0 | 29.9 | 11.9 | 74.8 | **1.07** | **6.29** | **no signal — one host only** |
| scheduled_task | 30.9 | 31.6 | 35.4 | 49.0 | 1.02 | 1.39 | no signal |
| sam | 1.0 | 1.1 | 0.9 | 1.1 | 1.02 | 1.28 | no signal |
| lsa_policy | 2.5 | 2.6 | 2.2 | 2.9 | 1.02 | 1.28 | no signal |
| services | 94.2 | 91.4 | 106.9 | 137.1 | 0.97 | 1.28 | no signal |
| evtx.ps_classic | 111.3 | 107.7 | 23.1 | 44.8 | 0.97 | 1.94 | no signal |
| txf_pending | 0.0 | 0.0 | 0.0 | 11.0 | 1.00 | ∞ | no signal — one collection only |

**`usn` and `evtx.firewall` independently confirm two earlier findings.** USN
volume moves in *opposite directions* on the two hosts (2.32 vs 0.59), which is
the same conclusion the T1070.004 anchor analysis reached from a different
direction. Firewall is 1.07 on host 1 and 6.29 on host 2 — one host
disagreeing is the definition of noise, and it matches the flat 4/4/12/10/17
already recorded in the technique grid.

---

## 3. Why three candidates did not survive inspection

A family whose count rises is not a rule. A rule must name **which rows**
matter. Each candidate was read row by row.

### 3.1 `ps_history` — disqualified, and it is a corpus-leakage finding

The scenario's extra commands are **the operator building the scenario**:

    Copy-Item -Path C:\Windows\System32\notepad.exe -Destination Z:\invoice_scan.exe
    Test-Path Z:\invoice_scan.exe
    python -m http.server 8000
    sc.exe create DummyLabSvc binPath= "C:\Windows\System32\svchost.exe"
    sc.exe delete DummyLabSvc

And, decisively, **`clean_c` — a CLEAN collection — contains:**

    Get-Item C:\staging\invoice_scan.exe | Select-Object Name, Length
    Get-FileHash C:\staging\invoice_scan.exe
    $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'

The payload is named in a clean collection's PowerShell history, together with
the commands that configured the logging the scenario depends on. A rule keyed
on `ps_history` content would learn the shape of **lab construction**, and
would score a clean collection as compromised for the same reason.

`clean_b` carries the same problem in a milder form:
`net user testuser temppass1123 /addddddddddddddddddddddddddd` — a typo'd
account-creation command, retried, which is why `testuser` appears in the
grid's T1136.001 discussion at all.

This belongs with the corpus limitations already recorded for `hour_of_day`
and the artifact-mix result. **`ps_history` is excluded from rule authorship**
— not because it lacks signal, but because its signal is the operator.

### 3.2 `evtx.winlogon` — PARSER-BLOCKED, not disqualified (D-057)

    clean_b  316 rows   all logon_ui   details {}
    s1_v2    786 rows   all logon_ui   details {}
    clean_c  196 rows   all logon_ui   details {}
    s1_v3    615 rows   all logon_ui   details {}

`details` is empty on every row of all four collections — 1,913 rows. **The
first draft of this survey called that "disqualified: nothing in a row to
match". That was wrong, and it was hiding a bug.** Reading the raw record
instead of concluding from the parsed one:

    <EventData>
      <Data Name="Event">0</Data>
      <Data Name="SubscriberName">GPClient</Data>
    </EventData>

The fields are there. `_details_for()` has no branch for 811 or 812 and drops
both — structurally the same defect as D-055 in `evtx.ps_classic`. The same
raw read also found **EIDs 1 and 2 present (21 each on `clean_b`) and absent
from the curated map**, so they are discarded without ever being seen; the
generic `evtx.x.*` fallback does not catch an unmapped EID inside a curated
channel.

**A family cannot be said to lack discriminating content while its content is
being discarded.** The correct state is `parser-blocked`: whether
`SubscriberName` discriminates is unknown and unmeasurable until the parser
emits it. Filed as **D-057**.

This is the survey's own instance of the rule it was written to apply — check
the reading method before believing a negative result (D-053).

### 3.3 `ntfs_logfile` — structurally unable to attest to a time range

    clean_b  169,570 rows   89,317 distinct names
    s1_v2      6,708 rows    2,304 distinct names
    clean_c  191,934 rows   44,338 distinct names
    s1_v3     17,038 rows    5,961 distinct names

A 20x DROP on the scenario hosts, in the opposite direction to every other
family.

**`$LogFile` is a fixed-size circular buffer.** NTFS wraps it and overwrites
the oldest records; the file does not grow. The more filesystem activity a
host sees between the events of interest and the collection, the less of that
history survives. This is a property of NTFS journalling in post-mortem
analysis — **it is true of every Windows host, not of this corpus** — and it
belongs with the evidence-class statements in
`docs/technique-coverage-grid.md` rather than with the per-family
measurements here.

Two consequences, both permanent:

* **The family's reach is a function of host activity, not of time.** "No
  record of X in `$LogFile`" is never evidence that X did not happen, and the
  window it covers cannot be stated in hours without knowing the write rate.
* **The drop is not a detectable signal.** A busy machine and an adversarial
  one produce the same turnover, and this corpus contains the benign case:
  both drops here are scenario *activity*, not scenario *evasion*.

The parser's docstring already records the related limit — a recovered name
may be a truncated suffix — so the family was never authoritative. This adds
the temporal half of the same statement.

---

## 4. The one survivor: `recyclebin`

The ratio understates it, because the signal is in the rows rather than the
count.

    clean_b   5 rows    all SID ...-1000 (Youssef), installers and a .md file
    s1_v2    14 rows    the same 5, PLUS 9 rows under SID ...-1002 (janed):
                          invoice_scan.exe, invoice_scan (1).exe x3,
                          Invoice_Scan.exe, invoice_scan.exe x4
    clean_c   0 rows
    s1_v3     1 row     C:\Users\vboxuser\Desktop\invoice_scan.exe

Every scenario-only row is the payload, and on host 1 they belong to a
**different SID** from every benign row. The family carries the original full
path, which `usn` cannot supply.

This is the anchor the technique grid identified for T1070.004 by a separate
route, and the two analyses agree. It remains `observable-unwritten`: the
survey establishes that the rows are there and are discriminating, not that a
written rule discriminates. `clean_b`'s 5 benign deletions are the base rate a
rule must survive, and all five are installers in a Downloads folder — which
is the same shape as the payload, minus the execution.

---

## 5. What this survey establishes, and what it does not

**Establishes:**

- Of 31 uncovered named families, exactly one carries volume signal that
  survives inspection.
- Two families no rule reads (`usn`, `evtx.firewall`) independently confirm
  earlier "no discriminator" verdicts reached by other means.
- `ps_history` must be excluded from rule authorship on leakage grounds, which
  was not known before this survey.
- The 18 generic EVTX channels reaching the 2x bar are **not** investigated
  further and no rule is proposed for any of them: per CD-007 the pipeline
  declines to invent semantics for EIDs it has not studied, and a volume ratio
  is not a reason to break that.

**Does not establish:**

- That `recyclebin` will discriminate as a *written rule*. Volume signal and a
  rule that fires correctly are different claims; the firewall EID and the
  timestomp indicator both looked writable until measured.
- That the "weak" families are useless. A 1.5x volume ratio says nothing about
  whether a *predicate* over those rows discriminates — `lnk` at 1.50 carries
  the removable-media evidence CD-013 depends on, and that is a shape claim,
  not a volume one.
- Anything about families a rule already reads.
