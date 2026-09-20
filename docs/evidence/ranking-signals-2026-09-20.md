# Ranking-signal evaluation — 2026-09-20

Four candidate ranking signals plus an execution gate, measured across all five
collections before any implementation. **Nothing here was implemented.**

Prior expectation, stated before measuring: most will die on inspection. Four
of the last five "obvious" signals this session did — `ps_history`, the
firewall channel, T1052.001 USB, T1059.001 `-ExecutionPolicy`.

**Result: one survives with a caveat, one survives as preventive-only, two
die.** Plus three premise corrections that were found before measuring and
would have invalidated the acceptance tests.

---

## Premise corrections (found before measuring)

**P1. "The anomaly rank" and the D-058 entity tables are different pools.**
The anomaly layer's `Scored` carries `(family, percentile_in_family)` and
scores ROWS inside a per-family Isolation Forest. It has no entity concept at
all. The 86/86/75 baseline the gate is to be judged against is **rules-side**
`entity_score`. Signal 0 is therefore measured against the rules-side pool,
and the anomaly pool is reported as not-applicable rather than measured.

**P2. `youssef` is not in 3 of 3 clean collections.** The two hosts have
different users. Measured, `youssef` appears on `clean_a` and `clean_b` only —
host 1. Host 2's user is `vboxuser`. By the proposed rarity criterion, a real
user of host 1 is *rarer* than a Windows binary, which inverts the acceptance
test's first half before it is run. Cross-host comparison is also the 27.4%
artifact-mix failure the project already recorded, so rarity is additionally
computed **within host**.

**P3. `invoice_scan.exe` is not absent from all three clean collections.**
`clean_c` names it — the C-02 `ps_history` leakage (`Get-Item
C:\staging\invoice_scan.exe`). Whether the payload meets the "0 of 3 clean"
premise therefore **depends on which family set defines presence**, which is
why signal 0 had to be measured first.

**P4 (incidental).** `docs/collection-manifest.md` documents only the three
host-1 collections. `clean_c` and `s1_v3` appear nowhere in it. Separate
finding, not a ranking signal.

---

## Signal 0 — execution-evidence gate

**Rule proposed:** an entity is scoreable iff it appears in ≥1 execution family
(prefetch, amcache, shimcache, srum, bam, userassist, evtx 4688/7045).

### Base rate

| collection | scored binaries | with ZERO execution presence | any above baseline |
|---|---|---|---|
| clean_a | 20 | **0** | 0 |
| clean_b | 21 | **0** | 0 |
| s1_v2 | 5 | **0** | 0 |
| clean_c | 2 | **0** | 0 |
| s1_v3 | 3 | **0** | 0 |

### Row-level

There is nothing to inspect: **every** rules-side scored binary on **every**
collection already has execution-family presence. The gate removes zero
entities from the current ranking, on all five.

### Verdict: **ACCEPT as preventive-only, and say so**

It removes no current false positive. It is worth having because a
download-only entity *can* be scored today (`R-CORR-0001`'s download step
selects browser rows), and nothing prevents it — the corpus simply does not
contain the case. That is a statement about this corpus, not about the rule.

**State it as preventive, never as a measured improvement.** A changelog line
reading "gate removes non-executed entities from the rank" would imply a
correction that did not occur here.

**Scope statement to carry with it, as specified:** *a file whose execution
evidence was removed is invisible to the anomaly layer, by design.* This is a
real trade: it makes the ranking blind to exactly the anti-forensic case
`docs/artifact-attestation-matrix.md` §2.6 exists to cover. The findings
remain in `findings.csv`; only the rank drops them.

---

## Signal 1 — cross-collection rarity

**Rule proposed:** 0 of 3 clean and ≥1 scenario ⇒ rare ⇒ rank up.
**Acceptance test as given:** must flip `youssef` down and `invoice_scan.exe`
up, or the signal dies.

### Base rate

Payload presence, and the dependency on signal 0's family set:

| family set | `invoice_scan.exe` present in | clean count | meets 0/3? |
|---|---|---|---|
| ALL families | clean_c, s1_v2, s1_v3 | **1 / 3** | **no** |
| EXEC families only | s1_v2, s1_v3 | 0 / 3 | yes |

Population of "rare" entities under the ALL-families reading:

| scope | entities scoring as rare |
|---|---|
| across all five | **43,844** |
| within host 1 | **29,034** |
| within host 2 | **20,670** |

### Row-level

The rare set is not a shortlist. Reading it:

    $$_boot_efi_ex_bg-bg_0d0c35b328a6e44f.cdf-ms
    $$_boot_efi_ex_cs-cz_0d0c4c7d28a7c26c.cdf-ms
    $$_boot_dvd_ex_efi_en-us_91aa4a0627c21b4a.cdf-ms
    $i4k0au4.exe   $i6i3yjl.exe   $i9kwvcq.exe   ...
    -directory | select-object name

Windows servicing catalogue files, per-locale boot resources, temporary
installer names, and — because entity extraction reads basenames wherever they
appear — fragments of PowerShell command lines. These are rare because they
are *generated*, not because they are suspicious. Two collections of the same
machine days apart do not share their transient filenames.

**And the acceptance test fails on its own terms.** Of the eight user entities
present, **every one is in 3/3 clean and 2/2 scenario** (`default`, `public`,
`localservice`, `networkservice`, `administrator`, `guest`, `defaultaccount`,
`wdagutilityaccount`) — these are the normalised system contexts. `youssef`
resolves on host 1 only, so the test's premise (3/3 clean) is false for the
one entity it names.

Two known false positives are also promoted by rarity, both already recorded:
`clean_b`'s staged `testuser` (a clean-host event), and `s1_v2`'s VirtualBox
Guest Additions binaries (D-026 — installed on `s1_v2` only, so `vboxdrvinst.exe`
is 0-clean/1-scenario and rises beside the payload; the memory says explicitly
not to suppress it by name).

### Verdict: **REJECT**

The acceptance criterion was binary and it is not met: the ordering does not
flip, because `youssef` is not 3/3-clean and the payload is not 0/3-clean under
the family set that includes `ps_history`. Restricting to execution families
rescues the payload's half only — at the cost of making the signal a
restatement of signal 0 — and still leaves a rare set of 20,000–29,000
entities per host dominated by generated filenames.

"Rare across siblings" is a real fleet signal. **Three collections of two
machines is not a fleet**, and the difference is not scale: the clean
collections were taken minutes apart from a restored snapshot, so their shared
set is a snapshot identity rather than a population norm. This is the corpus
constraint, not a flaw in the idea.

---

## Signal 2 — first-seen relative to baseline

**Rule proposed:** entities first seen after the clean-collection baseline
window are more suspicious than entities present since install.

### Base rate

The collection dates make the proposed anchor degenerate
(`docs/collection-manifest.md`):

| collection | collected (UTC) |
|---|---|
| **s1_v2 (scenario)** | **2026-08-23T23:31Z** |
| clean_a | 2026-08-24T17:44Z |
| clean_b | 2026-08-24T18:58Z |

**The scenario was collected ~18 hours BEFORE both host-1 clean baselines.**
clean_a and clean_b are the machine restored to its pre-attack snapshot *after*
the incident (manifest, Collection provenance). So "first seen after the clean
baseline" is anchored to a timestamp later than the attack, and every attack
entity is *before* the baseline, not after.

Payload first-seen where recorded: `2026-08-20T15:15Z` (s1_v2) and
`2026-09-12T10:30Z` (s1_v3). The s1_v2 value is **attempt 1**, three days
before the run under test — D-027's three attempts again.

### Row-level

Not reached. The anchor cannot be constructed from this corpus in the direction
the signal requires.

### Verdict: **REJECT for this corpus** — and note it is *structurally* sound

Unlike signal 1, nothing here says the idea is wrong. A baseline captured
before the incident would support it. This corpus has no such baseline, and the
predicted secondary failure stands untested but likely: the clean hosts' own
top binaries (`cursorusersetup-x64`, `7z2602-x64`, `npp.8.9.8.installer`) are
all post-install user software, so "new since install" would fire on them.

**This belongs in `docs/scenario-design-constraints.md`** as a collection
requirement: *the clean baseline must be collected before the scenario runs,
not after a restore.* Filed as a candidate, not written — the user asked for
evaluation only.

---

## Signal 3 — cross-family corroboration count

**Rule proposed:** an entity named in many families is more corroborated than
one named in few.

### Base rate

| collection | top entity | its count | payload count | payload rank |
|---|---|---|---|---|
| clean_a | `powershell.exe` | 11 | — | — |
| clean_b | `msedge.exe` | 11 | — | — |
| clean_c | `powershell.exe` | 10 | 1 | 156,050 |
| **s1_v2** | **`invoice_scan.exe`** | **13** | 13 | **1 of 218,629** |
| **s1_v3** | **`invoice_scan.exe`** | **10** | 10 | **1 of ~232,000** |

Entities reaching 13 families: **1 across the whole corpus**, the payload on
`s1_v2`. Zero on every clean collection.

### Row-level

The payload's 13 families on `s1_v2` are not a count — they are the attack
chain written down:

    browser      the download
    prefetch     the execution
    bam          the execution, per-user
    userassist   the execution, attributed to janed
    shimcache    the execution, kernel-side
    registry     the Run-key persistence
    runmru       the operator's own typing
    recyclebin   the deletion
    mft/usn/ntfs_logfile   the filesystem record of all of it
    ps_history   the typed commands
    timeline     the session

A Windows binary reaches 10–11 through a different and duller set —
`amcache, bam, evtx.security, mft, prefetch, shimcache, srum, timeline,
userassist, usn` — which is *one behaviour* (a program ran) recorded by ten
families that all record program execution. The payload's set spans
**download → execute → persist → delete**, which is four behaviours.

> **CORRECTION, 2026-09-20 — the "one behaviour" claim above is wrong.**
> Re-read at row level (`phase-span-2026-09-20.md`), clean `powershell.exe`
> spans **two** phases, not one: `scheduled_task/task_registered` is
> persistence, on all four collections where it appears. The family list
> quoted above is also not the measured set — that contains `defender_mplog`
> and `scheduled_task`, and no `usn`.
>
> The signal-3 verdict is unaffected: the count still ties at 10 on `s1_v3`.
> The justification was wrong, not the conclusion. Recorded because the error
> is the class the verification-coverage pattern names — a claim carried
> forward from a document rather than re-read against the evidence.

**The caveat that decides how this may be used.** On `s1_v2` the payload leads
by 2 (13 vs 11). On `s1_v3` it **ties at 10** with `msedge.exe`,
`powershell.exe` and `vboxtray.exe`, and wins only on the alphabetical
tie-break. A count-based rank is therefore a real separator on one scenario
host and a coin-toss on the other. Host 2's collection is smaller and its
`ps_history`/`registry` corroboration for the payload is thinner.

### Verdict: **ACCEPT the shape, REJECT the count**

The count alone does not survive: it ties on `s1_v3`, and its clean-host
leaders (10–11) overlap the scenario's range entirely.

What separates is **which** families corroborate — specifically whether they
span distinct phases of a chain rather than restating one behaviour. That is a
different signal from the one proposed, it is closer to what the correlation
rules already encode, and **it has not been measured**. It should not be
implemented on the strength of this document.

> **Followed up 2026-09-20: measured as "phase-span", and it survives.**
> See `phase-span-2026-09-20.md`. Under the adopted mapping the payload is the
> unique four-phase entity on each scenario host (1 of 218,629 on `s1_v2`,
> 1 of 194,694 on `s1_v3`), and no clean collection has an entity above three
> (max 3 on each of 233,918 / 294,639 / 232,508). Per-collection figures, not
> summed: `clean_a` and `clean_b` are one host restored from snapshot minutes
> apart, which is the same constraint signal 1's verdict recorded.
>
> Accepted with scope, **not implemented** — it ranks a four-step intrusion
> and is confirmatory rather than corrective on the rules-side pool. The "one
> behaviour" premise this section used to motivate it was itself wrong; see
> the correction above.

---

## Summary

| # | signal | verdict | reason |
|---|---|---|---|
| 0 | execution gate | **accept, preventive-only** | removes 0 of 51 currently scored entities; nothing above baseline; the case does not occur in this corpus |
| 1 | cross-collection rarity | **reject** | acceptance test not met on its own terms; 43,844 "rare" entities are generated filenames; 3 collections of 2 machines is not a fleet |
| 2 | first-seen vs baseline | **reject here, structurally sound** | the scenario was collected 18h BEFORE both clean baselines; the anchor cannot be built |
| 3 | corroboration count | **shape accepted, count rejected** | payload ranks 1 on both scenario hosts, but TIES at 10 on s1_v3; what separates is which families, not how many |

**Signals 4 (kill-chain position, temporal density, signed/unsigned, recency)
were not measured**, per instruction, since 0 and 3 did not both fail.

**No implementation follows from this document.** Two survivors mean a
composition decision, which is explicitly deferred. The honest one-line
summary: *the execution gate is free and preventive; corroboration is the only
candidate with real signal, and the version with signal is not the version
proposed.*

## Method note

Signal 1's result depended on signal 0's family set, and signal 1's acceptance
test contained two factual errors about the corpus (`youssef` 3/3, payload
0/3). Both were caught by checking the premises against the evidence before
writing the measurement, not by the measurement itself. See the
verification-coverage pattern at the top of `docs/defect-log.md`: an acceptance
test is a check, and a check stated against a wrong premise cannot fail
correctly.
