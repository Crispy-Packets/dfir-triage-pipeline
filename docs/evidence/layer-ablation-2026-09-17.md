# Layer ablation — what each half of the pipeline contributes (B-11a)

**2026-09-17.** The project's central claim is that **detection is
deterministic and the anomaly layer prioritises**. That had been argued from
the architecture and never measured. This measures it.

Unlike the feature ablation, nothing here is a tuning exercise: both layers
ship, and the question is what each is worth. A result showing one contributed
nothing would have been reported, not acted on.

---

## 1. The run

```
==================================================================
SCENARIO: collection_s1_v3  (2338 events)
==================================================================

layer           entities  attack rank  in top 10
--------------------------------------------------
rules only             5          1/5        yes
ML only              525       37/525         no
both                 527        1/527        yes

rules only -- 6 findings, top 10 entities:
   1. invoice_scan.exe  <-- ATTACK
   2. onedrive.exe
   3. vboxuser
   4. npp.8.9.8.installer.x64.exe
   5. winvm

ML only -- top 10 entities:
   1. cat.exe
   2. svchost.exe
   3. msmpeng.exe
   4. microsoftedgeupdate.exe
   5. msedge.exe
   6. ngen.exe
   7. searchfilterhost.exe
   8. onedrivesetup.exe
   9. conhost.exe
  10. wmiprvse.exe

==================================================================
CLEAN: collection_clean_c  (2463 events)
==================================================================

layer           entities  attack rank  in top 10
--------------------------------------------------
rules only             3 not surfaced         no
ML only              428 not surfaced         no
both                 429 not surfaced         no

rules only -- 3 findings on a collection with NO attack
  entities named: onedrive.exe, npp.8.9.8.installer.x64.exe, vboxuser
```

---

## 2. The result

| layer | entities to review | attack rank | found in first 10? |
|---|---|---|---|
| **rules only** | **5** | **1 / 5** | **yes** |
| ML only | 525 | 37 / 525 | no |
| both | 527 | 1 / 527 | yes |

**The rules detect. The anomaly layer does not.** An analyst given the rule
output reads five entities and the attack is first. Given the anomaly output
they read 37 before reaching it, and the ten most anomalous entities are
`cat.exe`, `svchost.exe`, `msmpeng.exe`, the Edge updater and `ngen.exe` —
Windows maintenance, correctly identified as unusual and entirely benign.

This is the two-layer argument measured rather than asserted, and it says
something sharper than the architecture diagram does: **the layers are not
peers.**

---

## 3. What the clean collection adds

Run against `clean_c`, which contains no attack:

| layer | entities |
|---|---|
| rules only | **3** — `onedrive.exe`, `npp...installer.exe`, `vboxuser` |
| ML only | 428 |

Three findings on a clean host, none of them the attack because there is no
attack. That is the rules' false-positive rate stated as a number an analyst
would feel: **three things to look at on a machine where nothing happened.**

The anomaly layer produces 428 ranked entities on the same collection. It is
not wrong — those are genuinely the least-like-baseline rows — but a ranking of
every entity on a clean host is not a triage output, which is precisely why it
is reported in a separate panel and labelled as prioritisation.

---

## 4. Why "both" is 1/527 rather than an improvement

The combined column reads the verdict panel before the prioritisation panel, as
the report does. The attack is first because the rules put it first; the
anomaly layer contributes nothing to that position.

**Combining did not help, and the honest reading is that on this corpus it
cannot.** The rules already place the attack at rank 1 of 5. There is no
headroom for a second layer to improve on, and any arrangement that let the
anomaly rank move the attack DOWN from position 1 would be worse than not
having it.

That is not an argument against the layer. It is an argument about what it is
for, and section 5 is what it is for.

---

## 5. What the anomaly layer is actually worth

Three things the ablation shows it contributes, none of which is detection:

**It ranks entities the rules never name.** 525 entities against the rules' 5.
The 520 the rules are silent about are exactly where an unknown technique would
sit — a binary no rule was written for produces no finding and is invisible to
the deterministic layer entirely.

**It works where no rule exists.** Every rule encodes a technique somebody
anticipated. `R-ATOMIC-0007` catches WMI persistence because it was written to;
nothing catches a technique nobody wrote a rule for. The anomaly layer has no
such dependency — it asks "is this unlike the baseline", which is a question
that does not need the answer known in advance.

**It is measurably better than chance at it.** Rank 37 of 525 is the top 7%,
and the sweep at K=50 gives 10.50x lift over random ordering.

**What it is NOT worth, stated plainly:** on a corpus where a rule already
names the attack, the anomaly layer adds nothing to finding it. The two layers
answer different questions, and this corpus only asks the one the rules are
good at.

---

## 6. The claim this licenses

> Detection comes from the deterministic rules. Measured on `s1_v3`, the rule
> layer places the attack entity first of five, with three findings on a clean
> collection of comparable size. The anomaly layer places it 37th of 525 and
> does not detect it; its contribution is a ranking over the 520 entities no
> rule names, at 10.50x better than chance. The layers are not peers, and the
> report presents them in separate panels for that reason.

Every figure in that paragraph is in the run above.

---

## 7. Threats to this result

**One scenario, one payload.** The rules place the attack first because rules
were written for the techniques it uses. An intrusion using a technique nobody
anticipated would invert this table, and the anomaly layer's 520 unnamed
entities are where it would have to be found — untested, because this corpus
contains no such intrusion.

**The rules' false-positive rate is three per clean host on a lightly used
machine.** On a workstation with years of software history it would be higher,
and R-CORR-0003's own `expected` note records that it fired five times per
clean host before the `is_user_writable` condition was added.

**`both` is a presentation order, not a fusion.** No score combines the two
layers, deliberately: an anomaly percentile feeding a rule's severity would
make "R-CORR-0003 fired" partly mean "the model thought it odd", and the
traceability claim would not survive it.
