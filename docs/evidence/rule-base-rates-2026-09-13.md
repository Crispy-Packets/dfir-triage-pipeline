# Rule base rates across five collections — 2026-09-13

Run after adding `is_user_writable` to R-CORR-0003's persistence step. Real
command output.

---

## 1. The measurement

```
collection_clean_a: 59 findings over 13210 events
collection_clean_b: 66 findings over 13556 events
collection_s1_v2: 19 findings over 3429 events
collection_clean_c: 3 findings over 2444 events
collection_s1_v3: 6 findings over 2304 events

rule            clean_a  clean_b   s1_v2  clean_c   s1_v3
----------------------------------------------------------
R-ATOMIC-0001        42       48       1        0       0
R-ATOMIC-0002         0        0       1        0       1
R-ATOMIC-0003         3        3       8        0       0
R-ATOMIC-0004         0        0       0        0       0
R-ATOMIC-0005         0        0       0        0       0
R-ATOMIC-0006         8        8       4        1       2
R-CORR-0001           3        4       3        1       1
R-CORR-0002           2        2       0        0       0
R-CORR-0003           1        1       2        1       2
R-CORR-0004           0        0       0        0       0
```

---

## 2. What changed, and what did not

**One rule changed: R-CORR-0003.** Its persistence step now requires the autorun
target to be user-writable.

| rule | clean_a | clean_b | s1_v2 | | |
|---|---|---|---|---|---|
| R-CORR-0003 before | 5 | 5 | 5 | | fired on msedge, onedrive, securityhealthsystray |
| R-CORR-0003 after | **1** | **1** | **2** | | `invoice_scan.exe` retained |

No other rule was touched. The remaining nine carry the same conditions they had
on 2026-08-30; only their `expected:` blocks gained the host-2 figures.

---

## 3. Why a shape predicate rather than a name list

R-CORR-0003's own `expected:` note, written 2026-08-30, had already identified
the problem and rejected the obvious fix:

> Nothing here is a fault in the rule. Software that runs and is also registered
> to run at logon is exactly what the rule describes, and most such software is
> legitimate.

and, on R-ATOMIC-0006:

> Suppressing OneDrive by name would improve the numbers and would be exactly
> the kind of corpus-fitting that does not survive contact with a different
> estate, so it is not done here.

That rejection stands and is not overturned here. `is_user_writable` does not
name a binary; it asks **where the binary lives**, which is a property of the
finding rather than of this lab. `invoice_scan.exe` sits in `Downloads\` and
matches; `msedge.exe` sits in `Program Files` and does not. The predicate would
behave identically on an estate this corpus has never seen.

It is the same reasoning `features.py` already uses for
`path_is_user_writable`, and the two layers deliberately share the marker list
so the rule engine and the anomaly layer cannot disagree about what
user-writable means for the same path.

**System locations are tested first.** `C:\Program Files\Common Files\Users
Guide\` contains the substring `users` and is not user-writable; checking the
writable markers first would call it writable. `tests/test_shape_operators.py`
pins that ordering.

---

## 4. What the numbers still say

**The rule is better, not fixed.** One finding per clean host at `critical`
severity is a substantially better claim than five, but it is not zero. The
survivor is per-user OneDrive under `AppData\Local` — a genuine user-writable
autorun, structurally identical to the attack, and the honest limit of this
indicator.

**`s1_v3` carries 6 findings against `clean_c`'s 4.** The attack contributes two
net findings: R-ATOMIC-0002 (the log clear) and one R-CORR-0003 / R-ATOMIC-0006
pair naming `invoice_scan.exe`.

**Host 1 and host 2 base rates differ by a factor of ten**, and the reason is
collection size rather than rule behaviour: `clean_a` holds 13,210 events against
`clean_c`'s 2,444. R-ATOMIC-0001's 42-48 findings on host 1 and 0 on host 2 is
the clearest case — host 1 ran binaries from user-writable locations routinely,
host 2 did not.

**Four rules fire on nothing in any collection.** R-ATOMIC-0004 (services),
R-ATOMIC-0005 (RDP), R-CORR-0004 (service then log clear), and on host 2 also
R-ATOMIC-0003 (encoded PowerShell). Three of those are legitimately absent — no
RDP in either lab, no service installation, no encoded PowerShell in the
scenario. They are untested code paths on this corpus and are reported as such
rather than as passing checks.

---

## 5. What the attack still triggers

On `s1_v3`, `invoice_scan.exe` is named by:

- **R-CORR-0003** `critical` — executed and registered at logon
- **R-ATOMIC-0006** `high` — autorun value pointing at a user-writable path

and the anti-forensic step by:

- **R-ATOMIC-0002** `high` — Security log cleared, `EventRecordID=15568`

Each names its source file and locator. R-CORR-0001 fires once, on
`npp.8.9.8.installer.x64.exe` rather than on the payload, because the payload's
download and execution fall outside that rule's window on this collection.
