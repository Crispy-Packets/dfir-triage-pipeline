# Layer ablation — 2026-09-18

Run after the rules-coverage phase froze the deterministic layer (15 rules).
Supersedes `layer-ablation-2026-09-17.md` as the current measurement and does
not replace it: the two describe different rule sets and different family
counts.

**Headline: this is a BASELINE of the anomaly layer before any ML work, not a
ranking result.** The layer is scoped to the original 7 families;
`FAMILY_FEATURES` was never extended to the 31 the parser work added. The
entity denominator grew with the event pool while the model stayed where it
was, so the attack entity's percentile fell without anything about the model
changing. Dilution, not damage. See D-062.

**Superseded when D-058 lands.** The rules-side ranks below were measured
against the current entity scoring, in which a clean-host user scores 97
against the attack binary's 99. Any of D-058's candidate fixes changes what
"rank 1 of 5" means, so these figures describe pre-D-058 scoring and must be
re-measured after that decision.

---

## 0. State of the pipeline at the time of this run

**Rules:** 15, including R-CORR-0006 added the same day.

**Curated-channel EID coverage is PARTIALLY fixed.** EID 800 was mapped and
committed (`f9e7254`) before this run, so `evtx.ps_classic` drops zero EIDs.
Every other curated channel is unchanged: **34,526 of 70,873 curated-channel
records are still discarded**, 188 distinct EIDs, each now *declared* in
`tests/test_curated_eid_coverage.py` with a reason but not parsed. A later run
after mapping more EIDs is not comparable to this one.

**D-058 is open and affects every rules-side figure below.** Entity scoring
places a clean-host *user* beside the attack *binary*:
`entity.user=youssef` scores 97 on `clean_a` and `clean_b` against
`invoice_scan.exe` at 99, and until R-CORR-0006 landed earlier the same day
the attack scored 94 and `youssef` outranked it outright. A rules-only rank of
1 below means "first among entities scored on a scale that mixes users, hosts
and binaries", **not** "cleanly separated from the clean baseline".

---

## 1. The measurement

Train and score within one host, per `CLAUDE.md`.

### Host 1 — train `clean_b`, score `s1_v2`

    layer           entities   attack rank   in top 10
    rules only             9           1/9         yes
    ML only             1189      298/1189          no
    both                1193        1/1193         yes

### Host 2 — train `clean_c`, score `s1_v3`

    layer           entities   attack rank   in top 10
    rules only             5           1/5         yes
    ML only              892       134/892          no
    both                 894         1/894         yes

**`both` is the rules layer.** The combination is rules-first with the anomaly
ranking appended, so rank 1 is R-ATOMIC-0006, R-CORR-0003 and R-CORR-0006
naming the payload. ML alone places it at 298/1189 and 134/892 — outside any
review budget on either host.

---

## 2. Requirement 1 — clean beside scenario

The rules-only rank is only interpretable next to the clean baseline.

| collection | rank | score | entity |
|---|---|---|---|
| clean_a | 1 | **97** | `entity.user=youssef` |
| clean_a | 2 | 92 | `entity.user=admin_local` |
| clean_a | 3 | 88 | `entity.host=windows10` |
| clean_b | 1 | **97** | `entity.user=youssef` |
| clean_b | 2 | 92 | `entity.user=admin_local` |
| clean_b | 3 | 88 | `entity.host=windows10` |
| **s1_v2** | 1 | **99** | `entity.exe_name=invoice_scan.exe` ← attack |
| s1_v2 | 2 | 94 | `entity.host=windows10` |
| s1_v2 | 3 | 93 | `entity.user=admin_local` |
| clean_c | 1 | **92** | `entity.user=vboxuser` |
| clean_c | 2 | 75 | `npp.8.9.8.installer.x64.exe` |
| clean_c | 3 | 60 | `onedrive.exe` |
| **s1_v3** | 1 | **99** | `entity.exe_name=invoice_scan.exe` ← attack |
| s1_v3 | 2 | 88 | `entity.user=vboxuser` |
| s1_v3 | 3 | 75 | `npp.8.9.8.installer.x64.exe` |

**The margin between the payload and an ordinary user of a clean machine is
two points (99 vs 97).** `entity.host=windows10` reaching 94 on `s1_v2` —
second place on the scenario host — is the same defect: one host per
collection, so a host entity aggregates every finding in the run. D-058.

---

## 3. Requirement 2 — which families carry the attack entity

Rank of `invoice_scan.exe` within each family's own scored rows:

| host | family | rank | percentile |
|---|---|---|---|
| host 1 | `bam` | 26 / 78 | 33.3% |
| host 1 | `prefetch` | 356 / 868 | 41.0% |
| host 1 | `shimcache` | 328 / 414 | 79.2% |
| host 1 | `userassist` | 107 / 124 | 86.3% |
| host 2 | `prefetch` | 641 / 1014 | 63.2% |
| host 2 | `amcache` | 466 / 522 | 89.3% |

**No family places the attack entity in its own top decile.** The signal is
not carried by one family and is therefore not fragile in the way a
single-family dependency would be — it is *absent* from all of them. Four of
eight scored families carry the entity at all on host 1; two of five on host 2.

---

## 4. The delta: 7 families vs 38

The headline question, and the reason this run was ordered after the parser
work rather than before.

| host | 7 families | 38 families |
|---|---|---|
| host 1 | 420 / 616 (68.2%) | 298 / 1189 (25.1%) |
| host 2 | 73 / 443 (16.5%) | 134 / 892 (15.0%) |

Host 1 improved. **Host 2 — the collection built specifically so the model
could see the attack — did not move**: 16.5% to 15.0% is noise.

Against the recorded 2026-09-13 figure:

    2026-09-13,  7 declared,  7 parsed    40 of 525   (top 7.6%)
    2026-09-18,  7 declared, 38 parsed   134 of 892   (top 15.0%)

### Why: the layer was never extended, and that is the baseline being recorded

`features.FAMILY_FEATURES` contains exactly seven entries — `amcache`,
`browser`, `evtx.powershell`, `evtx.security`, `evtx.system`, `prefetch`,
`registry`. The original seven. **Not one of the 31 families added since has a
feature set**, because extending the anomaly layer is a separate workstream
that has not been started.

**The parser work did not damage the ranking.** The model stayed fitted on
seven families while the event pool — and therefore the entity denominator —
grew with everything the parsers added. The percentile fell by dilution. That
is a workstream-sequencing fact, and recording it before any ML work begins is
the point of running the ablation now.

At the time of the run above, `features_for()` fell back to the full
`FEATURE_NAMES` for undeclared families, so `services` and `shimcache` were
being modelled on columns nobody had chosen for them — measured at **5
families modelled out of 126 present, 3,019 scored rows of 453,082 events**.
That fallback was a real defect independent of the ML workstream and was fixed
the same day (**D-063**).

**Re-measured on `s1_v3` after D-063**, skipping undeclared families instead
of defaulting them:

    modelled families   5 -> 3   (amcache, evtx.powershell, prefetch)
    scored rows     3,019 -> 2,180
    entities          892 -> 443
    attack rank       134 -> 81   (15.0% -> 18.3%)

**The percentile barely moved**, which confirms the diagnosis: the denominator
was carrying the change, not the model. 81/443 is the figure that describes
the pipeline as it now stands — 7 declared families, 38 parsed, undeclared
families skipped and reported. Full write-up in D-062.

---

## 5. What this run does not settle

* **Whether the anomaly layer should cover the new families at all.** Several
  have no obvious numeric feature — `recyclebin` carries a size and a path,
  `txf_pending` carries neither. Explicitly scoping the layer to
  execution-shaped families and saying so is a legitimate answer; adding 31
  feature sets without a leakage test each is not.
* **Anything about D-058.** The rules-side scores above inherit it and the
  ablation was run with it open, deliberately, so that the decision is taken
  with this measurement in hand.
* **A false-positive rate.** Nothing is flagged as an outlier in either
  scenario, so the ~5% clean-host floor recorded elsewhere is unchanged by
  this run and was not re-derived here.
