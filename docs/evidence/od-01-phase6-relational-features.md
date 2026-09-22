# OD-01 Phase 6 — relational / cross-family features (2026-09-22)

**Pre-registered before the run.** The anomaly layer has never seen the entity's
*chain* signal — how many families it appears in, how long its activity spans,
whether a download precedes execution. This is the one feature family left
untried. It was deferred three times with a consistent reason: the deterministic
rules already encode that signal (the R-CORR correlation rules and the verdict
panel), so feeding it to the ML is re-deriving what the rules already prove. This
probe measures whether the ML sees it *independently* or merely re-derives it.

The "both" layer is already 1/444; this probe changes only the **ML-only** rank
and answers "does the anomaly layer independently rank the chain." It does not
change the headline — the layer ranks, the rules detect.

## Provenance discipline (why three features, not four)

`phase_span` is **excluded**. It is computed from `rule.phase` on `Finding`
objects — the verdict panel piped back into the ML. Any hand-built
artifact→phase map is the same rule taxonomy re-encoded. It cannot be an input
under any framing.

The three admitted features are computed from **raw events only**, one row per
entity, over all 38 parsed families:

| feature | definition | provenance |
|---|---|---|
| `family_count` | distinct `source_artifact` over the entity's events | raw |
| `activity_span_hours` | last − first event timestamp | raw (difference, not wall-clock — D-074 safe by construction, still leak-tested) |
| `download_precedes_exec` | 1 if a browser row ts < min exec-family ts | raw, but *is* the R-CORR download→exec check from raw events |

If `download_precedes_exec` is the column that moves the rank, the finding is
stated plainly: **the ML re-derived the rule.**

## Pre-registered outcomes

- rank improves **and** payload's feature values are shared with the installers
  (npp, onedrivesetup) → rule re-derived, not independent signal.
- rank improves **and** payload is isolated on the relational columns →
  independent signal (the interesting case).
- flat → relational signal is not rank-bearing for the ML.
- any column fails the +6.0pp leak bar → dropped, named.
- fails distinct-ratio (0.25) or row-floor (50) guard → that is the result;
  guard not relaxed.

## Result

**Outcome 1 (pre-registered): the rank improves, but by re-deriving the rule.**
The relational pseudo-family ranks the payload **2/443** (raw) and **1/443**
once a timestamp confound is removed — but the improvement is not independent
chain signal. It is the download→exec rule, re-encoded.

### The rank is carried by `download_precedes_exec`, which is the R-CORR set

Exactly **three** entities in s1_v3 have `download_precedes_exec = 1`:

    invoice_scan.exe            [11 families, 46.8 h, dl<exec 1]   <-- payload
    npp.8.9.8.installer.x64.exe [ 9 families, 81.4 h, dl<exec 1]
    vlc-3.0.23-win64.exe        [ 8 families, 34.8 h, dl<exec 1]

That is the set surfaced by **`R-CORR-0001` ("A downloaded file was executed",
`rules/correlation/R-CORR-0001-download-to-execution.yml`)** — the ML feature is
that exact rule recomputed from raw events. The rule's own file already records
this population: "Every clean-host hit is a benign installer downloaded and then
executed … [the signal comes] from WHAT was downloaded, not from the shape of the
chain." A rare binary value is anomalous to any scorer (IF and MODA agree: both
rank the payload 2/443), so the ML is not seeing the chain; it is re-deriving
R-CORR-0001, the one rule that already fires on it. `family_count` does not
isolate the payload either — `vboxtray.exe` spans 10 families and is benign, and
the payload's `[11, 46.8, 1]` sits beside npp's `[9, 81.4, 1]`, not apart from
it.

**Extending the pseudo-family to the full chain would re-derive more rules, not
fewer.** The rules separate the payload (rank 1) from npp (rank 3) because the
payload's chain is *longer* — download→exec→persist→log-clear, each step another
rule hit (R-CORR-0001, then R-CORR-0003 exec→runkey, then R-CORR-0006
persistence→deletion). The relational features encode only the first two steps.
Any raw-event version of "touched a Run key" or "cleared an event log" *is* one
of those rules. So capturing the rest of the chain adds rules to the ML layer; it
does not give the ML independent signal. The lever is closed, not paused.

### The payload is tied with the installers, not separated from them

Removing the timestamp confound (below) lifts the payload to rank 1/443, but the
top three share **one identical anomaly score** (0.98357): invoice_scan, npp and
vlc are indistinguishable to the model. Rank 1 is a tie-break by name, not
separation. An analyst handed this ranking sees the attack tied with two
legitimate installers — which is the deferral's point: the relational features
carry the download→exec signal and nothing that distinguishes a malicious
download from a benign one. That distinction is what the *rules* provide
(R-CORR + the verdict panel), and it is why the "both" layer is 1/444 while this
ML-only view is a 3-way tie.

### Sensitivity 1 — the timestamp confound (labelled, not the headline)

The raw run put `vlc` at rank 1 on a 3.73-million-hour activity span. That value
is the **FILETIME zero sentinel** (`1601-01-01`), emitted by `browser_profile`
and `ntfs_logfile` rows and confirmed by inspection, not chosen by rank. Excluding
timestamps before `2000-01-01` (justified as pre-XP, a value filter not a rank
filter) removes it; the payload then ranks 1/443 as the tie above. Either way the
finding is unchanged — the confound moved *other* rows, never the payload's
membership in the download→exec trio.

### Sensitivity 2 — the pre-registered drop path fails the guard

With `activity_span_hours` dropped (the leakiest by construction), the two
remaining columns — `family_count` (int) and `download_precedes_exec` (binary) —
collapse to **12 distinct vectors over 368 training rows, ratio 0.033**, far
below the 0.25 distinct-ratio floor. Not modellable. This is a pre-registered
outcome, reported, not worked around: two low-cardinality columns cannot support
a per-entity forest.

### Leakage and guards (full 3-column set)

    column                    baseline  best    delta   verdict
    family_count               54.6      55.5   +0.9    clean (< +6.0)
    activity_span_hours        54.6      56.7   +2.1    clean (< +6.0)
    download_precedes_exec     54.6      54.6   +0.0    clean

    distinct-ratio 0.886 (368 rows, 326 distinct)  PASS
    row floor 50                                    PASS
    clean_c self-outlier rate (IF)  0.052           in band

No column trips the +6.0pp leak bar, so the rank is not a collection-identity
artifact — it is genuine signal, that genuine signal just being the rule.

## What Phase 6 settles

The relational / cross-family lever — the one feature family the ML had never
seen — was built, leak-tested, guarded, and measured. It ranks the payload
1–2/443, higher than any single artifact family (amcache 1.0% was the prior
best). But the rank is carried entirely by `download_precedes_exec`, which
selects exactly the R-CORR download→exec set, and the payload lands in a 3-way
tie with two benign installers it cannot be told apart from. The ML re-derives
the rule; it does not see the chain independently. This is the reason the lever
was deferred three times, now measured rather than asserted.

It is **not** a shipping candidate, and not because it failed — because it
succeeded at the wrong thing. Adding it would feed the verdict panel's own output
back into the triage ranking and report a rank the rules already produce (and
produce *better*: the rules separate the payload from the installers; the ML ties
them). No flag is added for this lever. (The default scorer became MODA*-G on
2026-09-22; that is orthogonal to this finding — relational stays declined under
either scorer.) The
headline is unchanged: the anomaly layer ranks, the rules detect, and the "both"
layer at 1/444 is the deterministic rules doing the separating.

## Closing check — does the feature fire on clean hosts? (the decisive test)

The tie with the installers raised the one question that settles shipping: does
`download_precedes_exec` fire on collections with **no attack**? If it names
installers as anomalies on a clean host, it is not a chain detector — it is a
"download happened" detector, and it manufactures false positives on any host
where software was installed.

Measured on all three clean collections, each trained and scored within its own
host, restricted to that host's scored entity universe:

    collection   scored   browser rows   download_precedes_exec == 1
    clean_a       671       336           cursorusersetup-x64, npp.8.9.6.2.installer, ssms-setup-enu   (3)
    clean_b       670       363           7z2602-x64, cursorusersetup-x64, npp.8.9.6.2.installer, ssms-setup-enu   (4)
    clean_c       368       633           npp.8.9.8.installer, vlc-3.0.23-win64   (2)

**The feature fires on every clean host, and every firer is a legitimate
installer.** clean_a and clean_b contain no attack; the flag still lights up 3
and 4 entities, all ordinary software installs (Notepad++, Cursor, SSMS, 7-Zip).
This is the "download happened" detector, not the chain detector: any host where
someone downloaded and ran an installer produces the same top-ranked relational
"anomalies" as the attack host. Browser rows are plentiful on all three
collections (336 / 363 / 633), so this is not host-1 browser sparsity — the
signal genuinely fires everywhere. The result is decisive on its own: a feature
that ranks benign installers first on clean hosts is a false-positive generator,
and that alone is a reason not to ship, independent of the tie.

## Verdict panel is unchanged (structural, not re-run)

Adding relational to the ML layer cannot change the report the judges see. The
verdict panel is rules-only: `entity_score.aggregate` takes `Finding` objects and
scores them by rule weight; a grep of `core/entity_score.py` and `core/findings.py`
for `percentile_in_family`, `EntityRank` and `rank_entities` returns nothing — no
ML percentile enters the verdict score. The payload is 99/critical from the rules
and stays 99/critical. This is the same boundary the multi-key entity-table sort
already respected (commit `f29a884` deliberately omitted the ML percentile from
the entity-table key because the verdict panel is rules-only and ML lives in the
prioritisation panel). No pipeline variant was built to "prove" a non-effect;
the non-effect is structural.

## Bottom line

The decision was made by the measurement, and the closing check confirms it from
both directions. On the shipped default (Isolation Forest) the payload ranks
40/443 **alone**; under the measured MODA*-G alternative it ranks 14/443 **alone**.
The relational lever ranks it 1–2/443 but in a **3-way tie with two benign
installers**, on a feature that fires on every clean host — a ranking that is both
confused (tied) and noisy (false positives on clean hosts). Rank-alone beats
rank-tied-with-false-positives. Relational is not shipped and gets no flag.

This closes the untried-lever list. Every lever has now been measured — coverage,
scorer, categorical engine, ensemble, and relational — and the headline is
unchanged by all of them: **the anomaly layer ranks, the rules detect.**
