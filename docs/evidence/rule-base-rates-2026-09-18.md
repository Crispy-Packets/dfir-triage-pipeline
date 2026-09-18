# Rule base rates across five collections — 2026-09-18

Run after adding the acquisition-directory predicate to `R-CORR-0003`'s
persistence step (D-056). Real command output.

Supersedes `rule-base-rates-2026-09-13.md`, which is kept: the change is only
defensible against the measurement it replaced.

**The event counts are ~50-200x the 2026-09-13 figures** because the parser
work between the two dates took the pipeline from 7 named families to 38. The
finding counts are not comparably inflated, and that is the point of section 3.

---

## 1. The measurement

```
collection_clean_a: 63 findings over 603532 events
collection_clean_b: 71 findings over 776724 events
collection_s1_v2:   19 findings over 664963 events
collection_clean_c:  5 findings over 579810 events
collection_s1_v3:    6 findings over 453082 events

rule               clean_a   clean_b     s1_v2   clean_c     s1_v3
------------------------------------------------------------------
R-ATOMIC-0001           42        48         1         0         0
R-ATOMIC-0002            0         0         1         0         1
R-ATOMIC-0003            3         3         8         0         0
R-ATOMIC-0004            0         0         0         0         0
R-ATOMIC-0005            0         0         0         0         0
R-ATOMIC-0006            8         8         4         1         2
R-ATOMIC-0007            0         0         0         0         0
R-ATOMIC-0008            0         0         0         0         0
R-ATOMIC-0009            4         5         0         2         0
R-CORR-0001              3         4         3         1         1
R-CORR-0002              2         2         0         0         0
R-CORR-0003              0         0         1         0         1
R-CORR-0004              0         0         0         0         0
R-CORR-0005              1         1         0         1         0
R-CORR-0006              0         0         1         0         1
```

`R-CORR-0006` is new on 2026-09-18 — the first rule of the coverage phase.
See section 7.

---

## 2. What changed since 2026-09-13

**One rule: `R-CORR-0003`.**

    before   1  1  2  1  2
    after    0  0  1  0  1

Zero on every clean host. One on each scenario host, and on both it is
`invoice_scan.exe`. No other rule's counts moved — `R-ATOMIC-0006` is
unchanged at 8/8/4/1/2, deliberately (see D-056 and the rule's own note).

---

## 3. The finding that motivated it

Running the pipeline end to end on `s1_v3` and reading the **entity table**
rather than the finding list:

    94 (from 145 across 2 rules)  [critical] entity.exe_name=invoice_scan.exe
    94 (from 145 across 2 rules)  [critical] entity.exe_name=onedrive.exe

A benign autorun tied with the payload at critical severity, at the top of the
ranked output. Both matched `R-CORR-0003` (85) and `R-ATOMIC-0006` (60), and
equal rule sets produce equal scores by construction — no combination function
separates them. The distinction had to be made in a rule, and was. See D-056.

After:

    94 (from 145 across 2 rules)  [critical] entity.exe_name=invoice_scan.exe
    88 (from 130 across 2 rules)  [high] entity.user=vboxuser
    75  [high] entity.exe_name=npp.8.9.8.installer.x64.exe
    70  [high] entity.host=winvm
    60  [high] entity.exe_name=onedrive.exe

`invoice_scan.exe` is the sole critical entity. On `s1_v2` it scores 98 and
tops the table.

---

## 4. Rules that still fire on nothing

`R-ATOMIC-0004` (services), `R-ATOMIC-0005` (RDP), `R-ATOMIC-0007` (WMI),
`R-ATOMIC-0008` (remote session) and `R-CORR-0004` (service then log clear)
measure zero on all five, as on 2026-09-13. There is no RDP in either lab, no
service installation, no WMI execution consumer, and no encoded PowerShell in
the scenario. They are untested code paths on this corpus and are reported as
such rather than as passing checks. `tools/rule_harness.py` exercises them
against an independent public EVTX corpus for that reason.

`R-ATOMIC-0003` fires 3/3/8/0/0 — zero on BOTH host-2 collections, including
the scenario. Host 2's PowerShell activity does not include the download
primitives the rule matches.

---

## 5. What the attack triggers on s1_v3

- **R-CORR-0003** `critical` — executed and registered at logon, and now the
  only rule at critical severity on this collection
- **R-ATOMIC-0006** `high` — autorun pointing at a user-writable path
- **R-ATOMIC-0002** `high` — Security log cleared, `EventRecordID=15568`

`R-CORR-0001` fires once, on `npp.8.9.8.installer.x64.exe` rather than on the
payload, because the payload's download and execution fall outside that rule's
window on this collection.

---

## 6. What this measurement does NOT establish

The `R-CORR-0003` predicate was derived from these five collections and
evaluated on the same five. Its positive class is **two rows** — one staged
scenario, one operator. The 0-of-53 benign figure describes the corpus the
rule was fitted against, not a held-out test. Both limits are written into the
rule's own `expected:` note rather than left to be inferred from this table.

---

## 7. R-CORR-0006, added 2026-09-18

**An autorun-registered executable was deleted to the Recycle Bin.** 0/0/1/0/1
— zero on every clean host, `invoice_scan.exe` on both scenario hosts.

Effect on the entity tables, measured through the engine rather than predicted:

    s1_v2   invoice_scan.exe  94 -> 99 critical, now named by 4 rules
    s1_v3   invoice_scan.exe  94 -> 99 critical, now named by 3 rules
    onedrive.exe              60, UNCHANGED on both hosts
    every clean-host rule count            UNCHANGED

`onedrive.exe` was checked specifically: OneDrive is autorun-registered but
was never deleted to the bin, so it does not re-enter through the new rule.
That was the risk D-056 established — a benign entity accumulating weight
from a third rule — and it did not materialise.

The rule adds a third independent claim about the same entity rather than a
new entity: R-ATOMIC-0006 says an autorun points somewhere user-writable,
R-CORR-0003 says a binary that ran is registered to run again, R-CORR-0006
says the file behind that registration was deleted.

Derivation and the three rejected predicates:
`docs/evidence/recyclebin-predicate-2026-09-18.md`.
