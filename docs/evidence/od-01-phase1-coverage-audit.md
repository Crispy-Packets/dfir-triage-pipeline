# OD-01 reopened — Phase 1: coverage audit of the 31 unmodelled families

Measured 2026-09-20, five collections. No modelling. The question: of the 31
families the anomaly layer does not model, how many are even candidates for an
Isolation Forest feature set?

`FAMILY_FEATURES` covers 7 (`prefetch`, `browser`, `amcache`, `registry`,
`evtx.security`, `evtx.system`, `evtx.powershell`). The `evtx.x.*` generic
channels are excluded as a catch-all handler, leaving 31 curated families to
audit.

## Candidacy bar

A family is a candidate only if **all** of:

1. **rows ≥ MIN_TRAINING_ROWS (50)** — `anomaly.py:158`.
2. **≥ 2 numeric/ordinal detail keys** — from the `details-schema.md` type
   column (`int`, `float`, `str(int)`), intersected with the keys actually
   measured on disk.
3. **the attack entity appears in the family at all.**
4. **those numeric keys have non-trivial variance and are not row identifiers**
   — the principle-4.1 pre-filter, pulled forward from Phase 2 because it is
   cheap and it settles candidacy.

Not a bar, disqualified separately: **known-leak families.** `ps_history` is
the C-02 contamination case (the operator's own lab-construction commands);
it clears 1–4 mechanically but is a documented leak and is not sent to Phase 3
to rediscover that.

### Why the attack-entity filter, precisely

It is **question-specific, not a model critique.** OD-01 asks whether the
attack entity *ranks better* with more families. A family the entity has no
rows in cannot change the entity's rank — it only enlarges the denominator,
which the ablation already showed worsens the percentile. If the question were
instead "does the model flag anything anomalous at all," this filter would not
apply. It is here because of what is being measured, not because the model
fails on those families.

(Caveat on the presence column: it is a substring match for `invoice_scan.exe`
across each row's details and path. It over-reports on `mft`/`ntfs_logfile`/
`usn`, which carry the filename as metadata for every file operation — but none
of those reach the numeric-key bar, so it does not affect the candidate set.)

## Result

Of 31 families: **2 candidates.**

| family | rows | numeric keys | verdict |
|---|---|---|---|
| `userassist` | 418 | `run_count`, `focus_count`, `focus_seconds` | **CANDIDATE** — behavioural counts, real range, low uniqueness |
| `defender_mplog` | 8,168 | `scan_count`, `scan_time_ms` | **CANDIDATE** — `pid`/`mplog_line` are not row IDs (uniq 0.05/0.35); scan metrics have range |
| `timeline` | 934 | `active_seconds` only | rejected — `activity_type` is 2 distinct values (near-zero variance), leaving one numeric, below the 2-key bar |
| `ps_history` | 417 | `commands_in_file`, `history_line` | rejected — C-02 contamination, a known leak |
| other 27 | — | 0–1 numeric keys, or no attack row, or < 50 rows | rejected structurally |

The 27 structural rejections are the substance: most curated families are
text (`command`, `url`, `file_name`), categorical (`hive_type`, `drive_type`,
`usn_reason`), or thin (`sam` 31 rows, `runmru` 6). None of that is fixable by
feature engineering — an Isolation Forest needs numeric variance, and these
families do not carry it.

## What this already says about OD-01

OD-01(b) held that coverage was not the limiting factor on the attack entity's
rank. Phase 1 does not yet confirm or overturn that — Phase 3 does — but it
bounds the test sharply: the "31 further families" is really **2** once the
requirement to carry numeric behavioural variance *and* an attack-entity row is
applied. Whatever Phase 3 measures, it measures the effect of adding two
families, not thirty-one. The coverage that sounded large was mostly families
an anomaly model structurally cannot use.

Next: Phase 2 designs numeric feature sets for `userassist` and
`defender_mplog` only, each with variance asserted (done above) and each
gated in Phase 3 by the three leakage tests — collection-identity,
contamination, and snapshot-identity (clean_a vs clean_b).
