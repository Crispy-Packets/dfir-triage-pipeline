# OD-01 Phase 4 — the 38-family model, built behind a flag and measured

Measured 2026-09-20. Phases 1–3 concluded that extending the anomaly layer to
more families would dilute the attack entity's rank rather than raise it, but
that conclusion rested on the D-062 denominator effect and Phase 2 drop tests —
it was *inferred*, never run end to end. This phase builds the extension behind
an off-by-default flag (`DFIR_EXTENDED_FAMILIES`, `features._EXTENDED_FAMILY_FEATURES`)
and measures it both ways, so the result is measured rather than assumed and the
committed 7-family headline cannot be silently overwritten.

## 1. Survey: of 31 undeclared families, 27 carry no key a column needs

Every parsed family above `MIN_TRAINING_ROWS` (50) on host 2 was surveyed for
the details keys `features.build()` can turn into a column (`run_count`,
`bytes`, `mime_type`, `path_*`, `script_block_text`, `publisher`). Beyond the
7 already declared, **only four families carry any such key at all**:

| family | numeric/shape key carried | attack rows (s1_v2 / s1_v3) |
|---|---|---|
| `services` | `path_*` (paths on ~60% of rows) | 0 / 0 |
| `shimcache` | `path_*` | 1 / 0 |
| `evtx.bits` | `path_*` (paths on ~25% of rows) | 0 / 0 |
| `userassist` | `run_count` | 2 / 1 |

The other 27 undeclared families above the row floor carry **zero** behavioural
keys — `{}`. A column over them would be constant across every row, and the
distinct-vector guard would reject it. Declaring them would assert coverage the
data cannot support. **That is the honest form of "38 families in the ML": all
38 were evaluated; 7 are declared; of the 31 undeclared, 27 have nothing a
forest column can be computed from, and 4 carry a single key.**

## 2. Leakage test rejects the snapshot families' usable columns

Declaring a family requires a leakage test (the `is_declared` contract). For
each candidate, the best single-threshold accuracy separating clean_c from
s1_v3 on each proposed column, against a majority-class baseline. Rarity uses
the **training profile** `build_rarity_index(clean_c)` applied to both
collections — the pipeline's real semantics (a per-collection rarity, used in a
first pass, was a measurement bug and is corrected here). Leak bar +6.0pp, the
project's own precedent (`exec_location_rarity` rejected on amcache at +6.0).

| family | column | base | acc | verdict |
|---|---|---|---|---|
| services | `executable_rarity` | 0.500 | 0.502 | ok |
| services | `events_in_same_hour` | 0.500 | 0.841 | **LEAKS** |
| services | `distinct_executables_in_same_hour` | 0.500 | 0.841 | **LEAKS** |
| services | `path_depth` | 0.500 | 0.500 | ok (varies) |
| shimcache | `events_in_same_hour` | 0.513 | 1.000 | **LEAKS** |
| shimcache | `distinct_executables_in_same_hour` | 0.513 | 1.000 | **LEAKS** |
| shimcache | `path_depth` | 0.513 | 0.513 | ok (varies) |
| shimcache | `executable_rarity` | 0.513 | 0.513 | ok (varies) |
| evtx.bits | `events_in_same_hour` | 0.546 | 0.546 | ok |
| evtx.bits | `distinct_executables_in_same_hour` | 0.546 | 0.546 | ok |
| evtx.bits | (all columns) | 0.546 | 0.546 | ok |
| userassist | `events_in_same_hour` | 0.550 | 0.670 | **LEAKS** |
| userassist | `run_count` | 0.550 | 0.550 | ok |

The temporal-density columns encode collection identity on the inventory-
snapshot families: services/shimcache rows cluster in time by *when each
collection was taken*, not by behaviour. They are dropped from those families'
extended sets. What is left (`path_depth`, `executable_rarity`, an interval
column) both varies and does not leak — but is too few columns to survive the
distinct-vector guard, as §4 shows.

## 3. The naive declaration — why the leakage gate exists (D-063 shape)

Declaring the four families with the untested `_SHARED + _PATH_AND_INTERVAL`
set — i.e. skipping the leakage gate — moved the ML-only attack rank from
**79/443 to 81/443**, worse, with **no new entities**. Even with the leaking
columns present, services/shimcache/userassist still failed the distinct-vector
and row-floor guards, so the one family that changed the result is the same one
that does in the pruned run (§4): `evtx.bits`. The leaking columns bought
nothing except the risk of ranking on collection identity — the exact
configuration D-063 hardened the codebase against: coverage that looks like
progress and ranks nothing. Reported here as the reason the gate exists, not as
the dilution figure.

## 4. Guards fit exactly one new family, and it has no attack row

With the pruned, leakage-tested sets and the flag ON, `PerFamilyModel.fit` on
clean_c fits:

    FITTED (flag OFF): amcache, evtx.powershell, prefetch          (3 of 7 declared)
    FITTED (flag ON):  amcache, evtx.powershell, prefetch, evtx.bits

    UNSCORED, extended families, with the recorded reason:
      services:   21 distinct vectors in 620 rows (ratio 0.034, floor 0.25)
      shimcache:  41 distinct vectors in 207 rows (ratio 0.198, floor 0.25)
      userassist: below MIN_TRAINING_ROWS (45 rows on clean_c)

(Note: of the 7 *declared* families, only 3 fit on clean_c — `browser` and
`evtx.security` are rejected by the distinct-ratio guard on this training
collection, `registry`/`evtx.system` by the row floor. "7 families" is the
declared count; 3 is the fitted count on this host.)

The flag adds exactly **one** fitted family, `evtx.bits`, and it carries **zero
attack rows** in either scenario collection. It cannot raise the attack
entity's rank; it can only enlarge the scored pool. The direct denominator
measurement:

| configuration | attack rank (ML-only, s1_v3) | scored entities |
|---|---|---|
| flag OFF (committed) | 79/443 | 443 |
| flag ON (pruned, evtx.bits fits) | 81/443 | 443 |

The rank moves **79 → 81, worse**, and the entity count is **unchanged at 443**:
`evtx.bits`'s entities were already in the scored pool (its executable basenames
appear in other families too), so it adds no new entity — it only perturbs the
ordering, and downward. The pruned ON figure equals the naive ON figure (§3) for
the same reason: `evtx.bits` is the only family that ever cleared the guards in
either configuration, so pruning the leaking columns off services/shimcache
changed nothing about what got fitted. On the clean host, ON is inert (368 → 368,
attack absent by construction). The measured cost of the extension is a two-place
loss for the entity we care about and no gain anywhere.

## 5. A pre-existing leak this test surfaced — D-074, not fixed here

The temporal-density leak is **not confined to the candidate families.** The
same columns were measured on the committed families as a control:

| family | `events_in_same_hour` acc | baseline | verdict |
|---|---|---|---|
| amcache (committed, fits) | 0.828 | 0.566 | **LEAKS** |
| prefetch (committed, fits) | 0.706 | 0.576 | **LEAKS** |
| browser (committed) | 0.547 | 0.547 | ok |

`amcache` and `prefetch` are committed families that **do** fit and that carry
the attack entity, and their per-hour density columns encode collection
identity. This predates and is independent of the flag. Logged as **D-074**;
not fixed in this commit, because removing columns from the committed config is
a change to the shipped ML result and belongs in its own measured change.

## What Phase 4 settles

The 38-family extension was built and run, not predicted. The measured result:

- 27 of 31 undeclared families carry no key a column could be computed from.
- Of the 4 that do, the columns that vary encode collection identity and the
  columns that don't are constant; the leakage gate and the distinct-vector
  guard reject three of the four outright.
- The one family that fits (`evtx.bits`) has no attack row, so it moves the
  denominator, not the entity — confirming OD-01(b) directly.

This is a stronger statement than the Phase 3 dilution inference: it is not
that more families *would* dilute, it is that the data does not contain a
declarable family that carries the attack entity with non-leaking signal. The
flag stays OFF by default; the committed headline is unchanged.
