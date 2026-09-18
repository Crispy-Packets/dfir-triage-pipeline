# Choosing the Recycle Bin predicate — 2026-09-18

How R-CORR-0006 was arrived at, including the two predicates that were
measured and rejected. The rejections are the substance: both would have
produced a rule that fires correctly on this corpus and fails elsewhere.

---

## 1. The starting point

`docs/evidence/family-signal-survey-2026-09-18.md` found `recyclebin` to be
the only one of 31 uncovered families carrying volume signal that survived
inspection: 6.54x on host 1, and 1 row against 0 on host 2.

The obvious rule follows the technique: **execution followed by deletion of
the same executable** — T1070.004, and the payload's own behaviour.

---

## 2. Predicate 1: "executed, then deleted" — REJECTED

Row inspection, `clean_b`, the benign population:

| deleted file | size | executed? |
|---|---|---|
| `SQL2025-SSEI-StdDev.exe` | 4,569,136 | **yes** — shimcache, userassist |
| `VSCodeUserSetup-x64-1.125.1.exe` | 192,417,872 | **yes** — shimcache, userassist |
| `SSMS-Setup-ENU.exe` | 495,847,104 | **yes** — amcache, prefetch, shimcache, userassist |
| `vs_community__647585806.1617625018.exe` | 1,650,112 | **yes** — shimcache, userassist |
| `dfir pipeline project - Copy.md` | 29,884 | no (not an executable) |

**Four of five benign deletions were also executed.** Download an installer,
run it, delete it — that is how software gets installed, and it is the modal
benign pattern in this evidence. The payload does the same thing. Adding
"was executed" to a deletion anchor narrows nothing.

This is the same failure the `usn` analysis found from the other direction:
`.exe` deletions run 0 / 293 / 169 / 0 / 16, with a CLEAN host holding the
most.

---

## 3. Predicate 2: "deleted file ≤ 512 KB" — REJECTED as corpus-fitting

This one **measured well**, which is why it is written up rather than
discarded quietly.

    collection        matches   payload   benign
    clean_a                 0         0        0
    clean_b                 1         0        1
    s1_v2                  10         9        1
    clean_c                 0         0        0
    s1_v3                   1         1        0

10 payload against 2 benign, and the two benign matches are the same
29,884-byte `.md` file.

**It works for the wrong reason.** The sizes:

    payload   4,608 / 201,216 / 360,448 bytes   (a copied notepad.exe)
    benign    1,650,112 - 495,847,104 bytes     (software installers)

The threshold separates *this lab's payload* from *this lab's benign
deletions*. A real payload can be 50 MB; a real user deletes small files
constantly. The test it fails is the one R-CORR-0003's note applies to vendor
names, applied to a number: **could an examiner who has never seen this corpus
derive `512 KB` from reasoning about the technique?** No — only from reading
these five collections.

A numeric threshold is easier to slip past this test than a name list,
because it looks principled. D-040's rule covers both.

---

## 4. Also rejected: the SID, and the repetition count

**The SID separates perfectly and must not be used.** On `s1_v2` every payload
deletion belongs to `S-1-5-21-…-1002` (janed) and every benign one to
`…-1000` (Youssef). janed is the scenario user. On another estate the attacker
and a benign user may share an account, and a SID-anchored rule has learned
the lab rather than the attack.

**The repetition count is scenario construction.** `invoice_scan.exe` is
deleted **nine times on `s1_v2`**, at three different sizes (201,216 → 360,448
→ 4,608) over four days. That is the operator retrying the scenario, not an
actor's behaviour — and `s1_v3`, the other scenario host, holds exactly **one**
deletion. A rule keyed on repetition would fire on host 1 and miss host 2.

This is milder than the `ps_history` leakage but the same category, and
`deleted_size` and repetition are recorded together with it in
`docs/feature-decisions.md`.

---

## 5. What survived: persistence joined to deletion

The discriminator was never in the Recycle Bin row. It is in what the deleted
file was *registered to do*.

**An installer does not register itself to run at logon.** It is downloaded,
run once, and deleted. A payload is downloaded, run, **registered for
autostart**, and deleted. Persistence pointing at a file that has been deleted
is anti-forensic by construction: the Run value survives to launch whatever
later occupies that path, and the file that would explain it is gone.

Derivable from the technique, with no reference to this corpus.

Measured as the engine would join it — `persistence_autorun` (registry) to
`file_deleted` (recyclebin) on `entity.exe_name`:

    collection        autoruns   deleted   JOINED
    clean_a                  5         0        0
    clean_b                  5         4        0
    s1_v2                    6         6        1   invoice_scan.exe
    clean_c                  5         0        0
    s1_v3                    6         1        1   invoice_scan.exe

**The control matters more than the result.** On `clean_b` there are 5
autoruns and 4 deleted executables and **zero** joins — the benign installers
fall out because none of them is autorun-registered, which is exactly what the
shape argument predicts. The rule is not excluding them by a threshold; they
were never the shape.

---

## 6. What this does not establish

* **The positive class is two findings**, one per scenario host, from one
  staged scenario by one operator. Clean calibration, not a validated
  discriminator.
* **No held-out collection** — all five were used to derive the shape and to
  evaluate it.
* **`recyclebin` is empty on `clean_a` and `clean_c`.** The zero on those two
  says the family held nothing, not that the rule discriminated. Only
  `clean_b` — 4 deleted executables, 5 autoruns, no join — is a real negative.
* **A deletion that bypassed the Recycle Bin is invisible.** `usn` sees those
  and is deliberately not selected: its volume moves in opposite directions on
  the two hosts, so it carries no collection-level signal, and it cannot
  supply the original full path.
