# Per-family feature sets — the decision, made before it is measured

**Written 2026-09-13, before any code was changed and before any rank was
remeasured.** This ordering is the point of the document. The change argued for
below is one the 2026-09-13 ablation also happens to favour, and a reader is
entitled to ask whether the ablation caused the decision. It did not, and the
only way to show that is to state the structural argument on its own terms, in
its own commit, before the result exists.

---

## 1. The argument, without reference to any result

`features.build()` emits one fixed 13-column vector for every event, whatever
artefact family produced it. That is wrong by construction, and it would be
wrong on a corpus that contained no attack at all.

**A browser download has never run.** There is no run count, no previous
execution, no interval since a previous execution. Six of the thirteen columns
are therefore not "missing" for a download — they are *undefined*, and the
builder emits 0.0 for each:

    run_count                                      0.0
    run_count_is_known                             0.0
    seconds_since_previous_run_of_same_executable  0.0
    previous_run_is_known                          0.0

Two more are constant rather than undefined, because every download in a Windows
profile lands in the same directory:

    path_depth              4.0   (C:\Users\<user>\Downloads\<file>)
    path_is_user_writable   1.0   (Downloads is always user-writable)

**A Prefetch record has no MIME type and no byte count.** The artefact records
that a binary ran and how often; it carries nothing about how the file arrived.
So the three columns added on 2026-09-13 are undefined for Prefetch in exactly
the way `run_count` is undefined for a download:

    download_size_log10       0.0
    download_size_is_known    0.0
    mime_type_is_executable   0.0

**Amcache and the EVTX families have their own subsets**, on the same reasoning.

## 2. Why a constant column is not merely useless

If a constant column were simply ignored, this would be a tidiness argument and
not worth a document. It is not ignored.

Isolation Forest builds each tree by selecting a feature **uniformly at random**
and then a split point uniformly at random within that feature's observed range.
A feature whose value is identical across every row in the population offers no
split that separates anything: the tree spends a node and partitions nothing.

With thirteen columns of which six are constant for a family, roughly **46% of
split attempts in that family's forest are structurally incapable of isolating
anything**. The informative columns are not damaged, but they are selected less
often, and isolation depth — which is what the anomaly score is computed from —
is diluted accordingly.

This is a property of the algorithm and of the artefact schema. It does not
depend on which collection is being scored, whether the collection contains an
attack, or where any particular row ranks.

## 3. The same reasoning already decided `PerFamilyModel`

This is not a new principle on this project. `docs/feature-decisions.md` §4
records why one model per `source_artifact` replaced a single mixed model:

> The feature vector has columns that only one family can populate — `run_count`
> is non-zero only for Prefetch — so a mixed model spends its splits separating
> artefact types instead of behaviours.

That argument was accepted, implemented, and measured: a single model put
`s1_v2` at 27.4% outliers against `clean_a`'s 5.5%, almost entirely artefact
mix; per-family scoring took it to 7.7%.

**The present change is the second half of the same idea, left undone.** Fitting
a separate forest per family stopped families from being compared against each
other. It did not stop each family's forest from being handed columns that
family cannot populate. Splitting the models without splitting the feature sets
was an incomplete application of the principle, not a separate design.

## 4. What is deliberately NOT the argument

The 2026-09-13 ablation (`docs/evidence/evaluation-host2-2026-09-13.md` §5)
measured that removing any one of ten features *improves* the attack entity's
rank, and that dropping the six execution-only columns would likely place it
around rank 25-30.

**That table is not a reason to make this change, and it is not being used as
one.** Selecting features by which removal improves a known answer is tuning the
corpus to the test — the process behind the 27.4% result, closed in
`shared/DECIDED.md`. If the ablation had shown the opposite, the argument in §1
and §2 would be unchanged, because it is about what an artefact records rather
than about what any row scored.

The correct relationship is the other way round: **§1 predicts the ablation's
shape.** Constant columns dilute; the ablation shows constant columns diluting.
That is a confirmed prediction, which is evidence *for* the model of the
problem, not the source of the decision.

## 5. What is predicted, recorded before measuring

Stated now so that whatever happens is reportable rather than selectable:

- **`browser` gains most.** Six of thirteen columns are constant for it, the
  highest proportion of any family.
- **`prefetch` gains least, and may lose slightly.** It populates the original
  ten columns properly; it only sheds the three download columns, so there is
  less dilution to remove.
- **The attack entity's rank should improve**, because its best score comes from
  the browser row. A rank in the 20s-30s would match the ablation's arithmetic.
- **The B-12 acceptance test must still pass.** If restricting feature sets
  makes the two clean baselines score differently from each other, the change is
  wrong regardless of what it does to the attack's rank.

**If the rank does not improve, the change still stands** on the §1-§2 argument,
and the result is reported as a prediction that failed. A structural argument
that is only kept when it pays is not a structural argument.

## 6. The feature sets

Derived from what each artefact records, not from what scored well.

| feature | browser | prefetch | amcache | evtx.* |
|---|:--:|:--:|:--:|:--:|
| `executable_rarity` | + | + | + | + |
| `executable_is_unseen` | + | + | + | + |
| `events_in_same_hour` | + | + | + | + |
| `distinct_executables_in_same_hour` | + | + | + | + |
| `run_count` | | + | | |
| `run_count_is_known` | | + | | |
| `seconds_since_previous_run_of_same_executable` | | + | + | + |
| `previous_run_is_known` | | + | + | + |
| `path_depth` | | + | + | + |
| `path_is_user_writable` | | + | + | + |
| `download_size_log10` | + | | | |
| `download_size_is_known` | + | | | |
| `mime_type_is_executable` | + | | | |

Notes on the judgement calls:

- **The four shared features apply everywhere.** Rarity and hourly density are
  computed from the event stream rather than from artefact-specific fields, so
  every family can populate them.
- **`path_depth` and `path_is_user_writable` are excluded for `browser` only.**
  Every download lands in `Downloads\`, so both are constant *for that family*.
  They vary properly for Prefetch, Amcache and the EVTX channels.
- **Interval features stay for `amcache` and `evtx.*`.** Those families do
  record repeated observations of the same executable, so "time since this
  binary was last seen" is defined for them even though `run_count` is not.
- **`evtx.*` families share one set.** They are separate forests but the same
  schema shape: a path, a principal, a time, no run count and no byte count.

## 7. Implementation constraint

`FEATURE_NAMES` is contractual — `AnomalyModel.score` compares the incoming
table's names against the fitted model's and refuses a mismatch, because the
forest scores by column position and a shifted layout would be scored silently
and wrongly.

Per-family sets must preserve that guarantee: each family's names tuple is fixed
and ordered, and the check still runs. The change makes the contract per-family
rather than global; it does not weaken it.
