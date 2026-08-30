# Rule schema

    schema_version: 1.3.0
    Frozen:         2026-08-29 (compressed week, Day 1, step A-1/A-2)
    Revised:        2026-08-29, against week2/parsers-registry-browser @ 0994251
    1.2.0:          2026-08-29, when the six atomic rules were written
    1.3.0:          2026-08-30, when the correlation engine was written
    Owner:          Person A (rules/** per shared/CONTRACT-RULES.md section 5)
    Applies to:     every file under rules/atomic/ and rules/correlation/

This document is frozen before any rule is written, so that the rules written on
Day 2 are not rewritten on Day 3. A change to anything in sections 2 to 6 is a
schema version bump and a re-validation of every rule file, not an edit.

Every rule file declares `schema_version`. The loader rejects a rule whose major
version differs from this document's.

---

## 0. What this document fixes, and what it does not

**It fixes** the shape of a rule file, how a condition names a field, what a join
field is, what happens when a field is missing, and whether an event whose
timestamp is not a recorded time may enter a time window.

**It does not fix** the content of any individual rule, the correlation engine's
implementation, or the `Event` class. `Event` is Person B's (`CD-005`); this
document only says how rules read one.

**What changed in 1.1.0.** Version 1.0.0 was written against a checkout where
`docs/contract-decisions.md` ended at `CD-013`, and it marked six dependencies
**PENDING-B**. Reading `origin/week2/parsers-registry-browser` at `0994251`
resolved all six: `CD-019`, `CD-020`, `CD-021` and `CD-022` exist,
`docs/details-schema.md` exists, `timestamp_type` is a required `Event` field
and column 2 of the CSV, and all five parsers are landed and registered. Only
`pyyaml` is still outstanding (section 11).

**What changed in 1.3.0.** Writing the engine found three things the document
had wrong or missing, and one of them was a bug in this document rather than in
the code: section 4.2 said the image token is the **longest** leading prefix
ending in an executable extension. It is the **shortest**. Section 4.2 now says
so and a test pins it. Section 3.5 is new and holds the truncated-key clause,
which had been living in section 11 where a rule author would never look for it.
Section 4.2 also absorbs D-032's sixth ImagePath form.

Two entries in `docs/defect-log.md` change this schema rather than merely
informing it, and both are written up here as clauses:

- **D-027** — the scenario's persistence artifact predates the scenario's own
  download by two days. Sections 4.7 and 5.4.
- **D-028** — Amcache holds no entry for the binary that executed. Section 6.2.

---

## 1. Rule files: layout and identity

    rules/
      schema.md                      this document
      validate_rules.py              the validator (section 10)
      atomic/                        one file per atomic rule
      correlation/                   one file per correlation rule
      blocked/                       specified but not loadable; see below

One rule per file. Filename is `<id>-<slug>.yml`, lowercase slug, hyphens only.

`rules/blocked/` holds rules that are fully specified but cannot load, because
something they depend on does not exist yet. Their filenames end `.yml.draft`,
which keeps them out of the validator's glob **by design, not by accident**: a
blocked rule left in `atomic/` would fail every run, and one written against a
field that does not exist would match nothing and report that as a clean
negative. Parking it visibly is the third option, and it is the right one. Each
draft states its blocker, who owns it, and what would clear it.

`id` is stable and never reused, even after a rule is deleted. Reserved blocks:

| Block | Meaning |
|---|---|
| `R-ATOMIC-0001` .. `R-ATOMIC-0006` | the six atomic rules required by the plan, in plan order |
| `R-ATOMIC-0007` onward | additional atomic rules |
| `R-CORR-0001` .. `R-CORR-0004` | the four required chains, in plan order |
| `R-CORR-0005` onward | additional chains |
| `R-TEST-*` | fixtures that exist only to exercise the engine; never loaded by the CLI |

Plan order for the atomic block, fixed here so Day 2 does not renumber:

    R-ATOMIC-0001  suspicious execution location
    R-ATOMIC-0002  log clearing
    R-ATOMIC-0003  encoded / download PowerShell
    R-ATOMIC-0004  suspicious services
    R-ATOMIC-0005  external RDP
    R-ATOMIC-0006  autorun persistence

Plan order for the correlation block:

    R-CORR-0001  download -> execution
    R-CORR-0002  failed-logon burst -> success
    R-CORR-0003  execution -> Run key
    R-CORR-0004  service creation -> log clear

Files are UTF-8. YAML 1.2 core schema only: no anchors, no aliases, no tags, no
multi-document files. The validator rejects all four, because each of them makes
a rule file mean something different depending on which loader reads it.

**PyYAML implements YAML 1.1, not 1.2**, and in 1.1 the bare words `on`, `off`,
`yes`, `no`, `y` and `n` are booleans. `join:` `{on: [entity.exe_name]}` parses
as the key `True`, and the join then silently does not exist. The validator
overrides the resolver so only `true`/`false` are booleans, which makes the
YAML-1.2 claim above true rather than aspirational. This was found by a negative
fixture during Day 1, not by reading the document.

---

## 2. Required fields

Every rule file carries all of these. There is no default for any of them; an
omitted field is a load-time error, not an implied value.

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | must match this document's major version |
| `id` | string | matches `^R-(ATOMIC\|CORR\|TEST)-\d{4}$` |
| `type` | enum | `atomic` \| `correlation` |
| `title` | string | one line, human-readable |
| `description` | string | what the rule claims, and what it does not claim |
| `severity` | enum | `informational` \| `low` \| `medium` \| `high` \| `critical` |
| `weight` | integer | 0..100, the rule's contribution to an entity score |
| `attack` | mapping | `technique` (e.g. `T1070.001`) and `name` |
| `select` | mapping | the event types the rule considers; section 3.1 |
| `conditions` | mapping | section 3 |
| `enabled` | boolean | a disabled rule is still loaded and still validated |

Atomic rules additionally carry:

| Field | Type | Notes |
|---|---|---|
| `expected` | mapping | measured base rate per collection; section 8 |

Correlation rules additionally carry `steps`, `join`, `window` and `order`;
section 6.

`severity` is **not** derived from `weight` and `weight` is not derived from
`severity`. Severity is what an analyst is told; weight is what the score
arithmetic uses. Deriving one from the other means a tuning change to the score
silently rewrites the report's language.

Optional fields, defined here so Day 2 does not invent them: `references` (list
of strings), `notes` (string), `false_positive_notes` (string).

---

## 3. Conditions

### 3.1 `select` comes first

    select:
      event_type: [log_cleared]
      source_artifact: [evtx.security]      # optional

`select` is a pre-filter on the fixed vocabulary of `CD-007`. It is separate
from `conditions` for one reason: the validator can check a `select` value
against `CD-007` and reject a typo at load time. `log_clear` instead of
`log_cleared` inside a free-form condition would simply match nothing.

`event_type` is required in `select` and must be a non-empty list. Every value
must appear in `CD-007`.

### 3.2 How a condition names a field

A condition's `field` is one of exactly two things:

**Top-level `Event` attributes**, by bare name:

    timestamp  timestamp_type  source_artifact  event_type  action
    source_file  source_locator  host  user  path  confidence

All eleven exist on `Event` as of `0994251`; `timestamp_type` is a required
constructor argument validated in `__post_init__` against `CD-019`'s closed set.

**Keys of `details`**, always prefixed:

    details.<key>

The prefix is mandatory. A bare name that is not in the list above is a
load-time error, not a `details` lookup. Rationale: `details` is free-form and
excluded from the `event_id` hash (`CD-005`), so a typo in a bare name would
resolve to a `details` key that no parser emits and the rule would match nothing
without complaint.

Only one level of nesting. `details.a.b` is a load-time error in 1.0.0. If a
parser emits nested mappings, that is a schema revision, not a rule that reaches
into them.

**A rule may only name a `details` key that is declared in
`docs/details-schema.md` for at least one of the event types in its `select`.**
This is `CD-012` enforced at the rule layer rather than trusted. The validator
reads that document and fails the rule if the key is not there.

`docs/details-schema.md` now exists and declares 40 keys across six artifact
families, so this check is live rather than deferred. The validator reads the
document, takes every back-quoted key cell in its tables as declared, and fails
any rule naming a key that is not there. If the document ever goes missing the
check reports **NOT PERFORMED** and names it, and fails any rule that references
a `details` key — it never passes silently. See section 10.

### 3.3 Operators

Closed set. An unknown operator is a load-time error.

| Operator | Applies to | Notes |
|---|---|---|
| `equals`, `not_equals` | string, number, bool | case-sensitive unless `ci: true` |
| `in`, `not_in` | string against a list | `ci` allowed |
| `contains`, `not_contains` | substring | `ci` allowed |
| `starts_with`, `ends_with` | string | `ci` allowed |
| `matches` | regex | Python `re`; must compile at load or the rule is rejected |
| `present`, `absent` | any | takes no `value` |
| `gt`, `gte`, `lt`, `lte` | number or timestamp | both sides must be the same kind |

`ci: true` case-folds both sides before comparing. It exists because `CD-010`
forbids the parser from case-folding anything, so folding belongs in the rule,
where it is visible, and not in the parser, where it would destroy provenance.

Structure:

    conditions:
      all:  [ ... ]     # every one must hold
      any:  [ ... ]     # at least one must hold
      none: [ ... ]     # none may hold

At least one of the three must be present and non-empty. `all` and `none` on the
same rule is allowed; `none` is not a synonym for negated operators (see 3.4).

### 3.4 Missing fields: fail or skip

This has two answers because there are two different failures, and conflating
them is how a rule engine ends up either brittle or silent.

**An unknown field name is a load-time error.** The rule is rejected, the run
aborts, nothing is scored. This covers a bare name that is not an `Event`
attribute, a `details.<key>` not declared in `docs/details-schema.md`, an
unknown operator, and a regex that does not compile. Loud, before any evidence
is read.

**A field that is declared but absent on a particular event makes the condition
false.** The event does not match. No error, no exception, and the engine
increments a per-rule counter `absent_field_skips`, which is reported in the run
summary. A rule whose counter equals the number of events it selected is doing
nothing, and the summary is where that becomes visible.

**Negative operators do not match an absent field.** `not_equals`,
`not_contains` and `not_in` are all **false** when the field is absent, exactly
as their positive forms are. This is the clause that matters most, and it
follows from `CONTRACT-RULES` section 3: an absent key means the artifact did
not record the value, not that the value is something else. If `not_equals` were
true on absence, then every event from a parser that does not emit the key would
match, and absence would become evidence.

To assert absence, say so: `op: absent`. To assert presence with any value:
`op: present`.

`none:` differs from a negative operator. `none` requires the listed conditions
to be false; a condition on an absent field is already false, so it satisfies
`none`. That is deliberate and it is the only place where absence contributes to
a match — and it does so visibly, because the rule author wrote `none`.

### 3.5 Declared-truncated keys

A `details` key may be declared as holding only the first N bytes of a longer
original. `script_block_text` is the first: capped at 4096 UTF-8 bytes, with
`script_block_text_bytes` carrying the full original length and
`script_block_truncated` present when the cap was hit (D-031).

**A declared-truncated key may be read by positive operators only.**

A rule can prove that what was recorded contains something. It can never prove
that the whole original did not, because the part that was cut off is not in
evidence. `not_contains` against the first 4 KB of a 40 KB script asserts an
absence the evidence cannot support, and it would read as a clean negative.

The validator enforces this in two ways, and the second is the one that
matters:

1. `absent`, `not_equals`, `not_in` and `not_contains` are rejected against a
   truncated key wherever they appear.
2. **Any operator at all is rejected inside a `none:` block**, including a
   positive one. `none: [{op: contains}]` reads "does not contain" however
   positively the operator itself is spelled. Restricting the operator set
   alone would have left the hole open.

The second rule is wider than the clause this schema first wrote, and the
widening is the point: what is being protected is the assertion, not the
keyword. Credit where due — the clause was specified here and the gap in it was
found by Person B while implementing it.

---

## 4. Join fields

### 4.1 A join field is a derived entity key, never a raw `Event` attribute

`CD-010` settles this: entity identity is derived, `path` is provenance and is
never normalised. So a rule joins on an **entity key**, computed by a documented
derivation, and written into the Finding — never back onto the `Event`
(`CD-005`).

Version 1.0.0 defines exactly three entity keys. Adding a fourth is a schema
bump.

| Key | Definition |
|---|---|
| `entity.exe_name` | the case-folded basename of the executable image. The primary join key (`CD-010`). |
| `entity.user` | the normalised principal; section 4.4 |
| `entity.host` | `Event.host` verbatim. **Not joinable in 1.0.0**; section 4.5 |

### 4.2 Deriving `entity.exe_name`

The same executable is recorded in incompatible forms across artifact families,
so the derivation is per family and it is allowed to fail.

| `source_artifact` / `event_type` | Source of the image token |
|---|---|
| `evtx.security` / `process_exec` (4688) | `path`, which is a plain path in 9,771 of 9,782 measured rows |
| `prefetch` / `process_exec` | **`details.executable`** — the name as the Prefetch record stores it, uppercase. `details-schema.md` states outright that the case-folded form of this value is `CD-010`'s primary join key. Do **not** use `path` here: for Prefetch, `path` holds a bare executable name, not a path, and says so in `details.path_source` |
| `evtx.system` / `service_install` (7045) | `path`, which holds an **ImagePath command line**, not a path (`CD-021`) |
| `registry` / `persistence_autorun` | `path`, which holds the Run value data verbatim: may be quoted, may carry arguments, may contain an unexpanded `%APPDATA%` |
| `browser` / `file_download` | `path`, the download `target_path`. See 4.7 — the name alone is not enough |
| `amcache` / `program_inventoried` | `details.name`, the file name as inventoried |
| `evtx.powershell` / `script_block` | no executable; this family yields no `entity.exe_name` |

Extraction, applied to whichever token the table names:

1. If the string begins with `"`, the image token is the text up to the next `"`.
2. Otherwise, if the string contains whitespace, the image token is the
   **shortest** leading prefix that ends, at a token boundary, in `.exe`,
   `.com`, `.sys`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.scr`, `.msi`, `.vbs` or
   `.js`, matched case-insensitively. If there is no such prefix the key is
   **absent** — it is not guessed.
3. Take the text after the last `\` or `/`.
4. Case-fold.
5. If the result contains whitespace and does not itself end in one of those
   extensions, the key is **absent**: a sentence is not a file name, and two
   unrelated events carrying the same prose would otherwise join on it.
6. If the result is empty, the key is **absent**.

**Shortest, not longest — corrected in 1.3.0, and the difference is not
academic.** Given

    C:\Program Files\App\run.exe -config C:\other\thing.exe

the longest such prefix runs to `thing.exe`, which is an argument. The shortest
is `run.exe`, which is the image. Versions 1.0.0 to 1.2.0 of this document said
longest and were wrong. Pinned by
`tests/test_entity.py::test_shortest_leading_prefix_not_longest`.

Step 5 was added for the same reason and found the same way: by a test, not by
reading. A registry autorun value is free text, so `run this thing please` was
becoming an `entity.exe_name` of `run this thing please`.

An absent entity key never joins. It does not join to another absent key, and it
does not join to the empty string. `CONTRACT-RULES` section 3 again: absent is
not a value.

Step 2 is written to be conservative on purpose. `CD-021`, measured across all
three collections on 2026-08-28, records **54 of 55** `service_install` rows as
something other than a bare filesystem path, in five forms: quoted executable
with arguments (27), unquoted drive path with arguments (6), `\SystemRoot` or
UNC device path (7), environment-variable form such as `%SystemRoot%` (14), and
bare drive path (1). Emitting no key is a `NOT-PARSED` outcome that Day 5 can
count. Emitting a wrong key is a fabricated join that Day 5 cannot see.

**D-032 splits the fourth of those into two, and the split matters here.** Of
the fourteen "environment-variable form" rows, only four carry an explicit
variable (`%SystemRoot%\system32\svchost.exe -k print`). The other ten are
root-relative driver images with no prefix at all —
`system32\DRIVERS\RsFx0800.sys` and similar — which the Service Control Manager
resolves against `%SystemRoot%` implicitly. A canonicaliser written from the
clause as it originally stood would look for a variable, find none in those ten,
and either pass them through as already-canonical or invent a root; both are
wrong under `CD-010`. The extraction above is unaffected, because it takes a
basename and never roots anything — but it is unaffected by accident rather than
by design, and saying so is the difference between a fact and a coincidence.
Both forms are pinned in `tests/test_entity.py`.

`CD-021` assigns the implementation of this extraction to Week 3's
`core/entity.py`. That module now exists, written by Person A, and it sits under
`dfir_triage_pipeline/` because `CD-021` put it there — the one place the
ownership table's boundary is crossed, by the contract's own instruction rather
than by drift. This section is the specification it implements.

It is a thin module on purpose. `paths.derive` (B-9) already emits
`path_basename_canonical` for every value it can canonicalise, and
`core/entity.py` prefers that declared key over anything it computes itself. It
adds only the case `paths.py` deliberately declines: a command line, where the
executable has to be extracted before a basename means anything.

### 4.3 Joining on `path` is forbidden

    join:
      on: [path]        # load-time error

The validator rejects `path`, `source_file`, `source_locator` and `action` as
join fields. `path` is rejected because the same binary appears as

    C:\Windows\System32\svchost.exe              (process_exec)
    %SystemRoot%\system32\svchost.exe -k print   (service_install)

and an equality join over those returns nothing while reporting "no correlation
found" rather than "the join compared two different kinds of string".

### 4.4 `entity.user`

`CD-022` fixes `Event.user` as the account exactly as the artifact recorded it —
no folding, no domain stripping, no SID mapping — and defers normalisation to
Week 3 on the grounds that the mapping is a forensic claim about identity. This
section is that Week 3 decision. It applies in entity derivation only, and never
writes back onto `Event`.

Case-folded `Event.user`, with one fold and one exclusion:

- **`""` and `-` are both non-principals, and they are not the same thing.**
  `CD-022` is explicit: `-` is a value the log wrote, whereas empty is a field
  the parser found missing. Measured on `clean_b`: 134 rows of `-` and 6 empty,
  across 24 distinct recorded spellings. Neither yields an `entity.user` key,
  and a rule may still distinguish them with `op: equals value: "-"` against
  `op: absent` when the difference matters.
- `NT AUTHORITY\LOCALSERVICE` folds to `local service`; the domain-qualified and
  bare forms of the same well-known principal are one key.
- `SYSTEM`, `LocalSystem`, `LOCAL SERVICE`, `NETWORK SERVICE`, `DWM-*` and
  `UMFD-*` are **system contexts and are not joinable principals**. A
  correlation joined on `system` correlates the whole machine to itself. Rules
  needing them must say `entity.exe_name` instead.

### 4.5 `entity.host` is not a join key

`Event.host` is read per record and is correct per record, but it is not
constant within a collection: `clean_b` carries both `WIN-BQVKLIBL3LA` and
`windows10` for one machine, before and after a rename. Any join on host would
split that collection in two. Recorded in `docs/lab-setup.md`.

### 4.6 Volume serial is not a join field and not a classifier

A volume serial is per-record provenance. It is not a tool-noise classifier:
`KAPE.EXE` appears under both `A62A-F538` (C:) and `5659-C38D` (Z:). A rule that
excluded rows by serial to suppress collection-tool noise would suppress real
rows and keep tool rows. Serial is usable only to resolve a `\VOLUME{...}` form
to a drive letter during `exe_name` extraction, which is a lookup, not a join.
Prefetch declares it as `details.volume_serial` for exactly that purpose.

### 4.7 A filename is not enough to identify a download

New in 1.1.0, and it comes from measurement rather than caution. **D-027**
records that Scenario 1 was attempted three times, and that
`collection_s1_v2`'s Edge history holds **nine `invoice_scan.exe` downloads
before the real one**:

| Attempt | Download ids | Host | Size | Status |
|---|---|---|---|---|
| 1 | 4, 5, 7, 8, 9 | `192.168.50.5:8000` | 201,216 B | transfer faults |
| 2 | 10, 11, 12 | `192.168.50.5:8000` | 360,448 B | transfer faults |
| **3** | **13** | **`192.168.50.2:8000`** | **4,608 B** | **the scenario under test** |

All ten share a filename and a target path. `entity.exe_name` therefore joins
every one of them, and three distinct binaries are involved, not one file
fetched repeatedly. What separates them is **size and source host**, both of
which are declared: `details.bytes` and `details.url`.

**So a correlation step selecting `file_download` must constrain at least one of
`details.bytes` or `details.url`.** The validator rejects a step that does not,
unless the step carries `ambiguity_ack` citing D-027 — an explicit statement
that the rule is meant to match any download, not an omission.

This is not a Scenario-1 quirk to be worked around. A real intrusion produces
repeated fetches of the same name far more often than a lab does, and a chain
built on the first matching download is a chain built on the wrong one.

---

## 5. `timestamp_type` — what a rule may do with a time

This is A-2, and it is the single most likely source of a fabricated join.

### 5.1 The three values

| Value | The claim the artifact makes | Emitted by |
|---|---|---|
| `recorded` | the log wrote this as it happened | EVTX, browser |
| `last_run` | the most recent occurrence, as summarised | Prefetch |
| `presence` | this exists now; when it appeared is unknown | registry |

### 5.2 The decision

**`recorded`** — may be either endpoint of a window, may establish ordering, may
carry a time claim in a finding. No restriction.

**`last_run`** — may be an endpoint of a window and may establish ordering. A
Prefetch slot timestamp is a real execution that really happened at that time,
and each of the up-to-eight slots is a separate real execution, so as a point in
time it is sound. What it may **not** support is a claim about *completeness*: a
rule may not use `last_run` to assert that a binary did **not** run in some
interval, and may not use slot count as a run count. A finding containing a
`last_run` event carries `time_claim: observed_occurrence`, not
`time_claim: only_occurrence`.

`4688` process creation and a Prefetch slot are different claims about the same
executable (close-out 2.3). Ordering them against each other is permitted;
treating them as duplicates of one event is not, and deduplication across
artifact families is out of scope for 1.0.0.

**`presence`** — **does not participate in a sliding window at all.**

A `presence` event joins on entity only. It is admitted to a finding as an
unordered member, it contributes its `weight`, and it is reported with

    time_claim: none

and the note that its timestamp is the containing key's last-write time, which
is not the moment the value was written and which is shared by every sibling
value under that key.

This is the answer to the question A-2 asks. The reason is in the artifact: a
Run key's last-write time can be hours from the moment a value was added, and
several values share it. Admitting it to a 45-minute window as if it were
`recorded` produces a chain that reads as evidence and is not one — and it would
do so on `s1_v2`, where the HKCU Run entry is the persistence step of the
scenario and would look perfect.

The consequence for `R-CORR-0003` (`execution -> Run key`) is stated now so it
is not discovered on Day 3: that chain **joins on `entity.exe_name` and reports
no interval between the two steps.** It is a correct finding. It is not a
timeline.

### 5.3 The static table

`timestamp_type` is now a real field: required on `Event`, validated in
`__post_init__`, part of the `event_id` hash, and column 2 of the CSV beside
`timestamp_utc` because it qualifies it. **At run time the field is
authoritative and nothing is derived.**

A rule file, however, is checked before any evidence is read, so the validator
needs to know what a step's selected artifacts will emit. This table is that
static map. It is not a fallback and it is not consulted at run time; it exists
so that `in_window: false` can be enforced at load time rather than discovered
in a finding.

| `source_artifact` | `timestamp_type` emitted | Verified at |
|---|---|---|
| `evtx.security` | `recorded` | `evtx_windows.py:190` |
| `evtx.system` | `recorded` | `evtx_windows.py:190` |
| `evtx.powershell` | `recorded` | `evtx_windows.py:190` |
| `browser` | `recorded` | `browser.py:129` |
| `prefetch` | `last_run` | `prefetch.py:175` |
| `registry` | `presence` | `registry.py:138` |
| `amcache` | `presence` | `amcache.py:126` |

A `source_artifact` not in this table is a **load-time error**, not a default.
Defaulting an unknown artifact to `recorded` would silently grant a time claim
to whatever parser lands next. When a parser is added, this table and `CD-007`
are updated together or the rule layer stops loading — which is the intended
failure.

### 5.4 The measured case, so this is not treated as theory

**D-027.** The `SecurityUpdate` autorun in `collection_s1_v2` carries a key
last-write time of `2026-08-21T01:34:07.976260Z`. The download it points at is
`2026-08-23T22:20:06.710763Z`. **The persistence appears, on timestamps alone,
to have been established two days before the file it launches was delivered.**

The explanation is in D-027 and is not recoverable from the timestamps: the Run
value was written during attempt 2, the baseline restore before attempt 3 did
not clear it, and because every attempt wrote the payload to the same path the
stale value stayed valid for the new binary and was never rewritten. The
artifact is genuine persistence pointing at the genuine payload. Only its
timestamp belongs to an earlier attempt.

A sliding window over `[download, persistence]` on this evidence does one of two
things, and both are wrong: it finds nothing, or — with a window wide enough to
span two days — it reports persistence **preceding** its own delivery. That is
what section 5.2 prevents, and D-027 names it as the concrete case `CD-019`'s
third value exists for.

`R-CORR-0003` (`execution -> Run key`) therefore joins on `entity.exe_name`,
sets `in_window: false` on the Run-key step, and reports no interval. The
finding says the persistence exists and points at the binary that ran. It does
not say when it was established, because the artifact does not know.

---

## 6. Correlation rules

### 6.1 Shape

    type: correlation
    steps:
      - name: download
        select:      { event_type: [file_download], source_artifact: [browser] }
        conditions:  { all: [ ... ] }
        in_window:   true
        optional:    false
      - name: execution
        select:      { event_type: [process_exec], source_artifact: [prefetch] }
        conditions:  { all: [ ... ] }
        in_window:   true
        optional:    false
    join:
      on: [entity.exe_name]
    window:
      from: download
      to:   execution
      min:  PT0S
      max:  PT45M
      justification: >
        Measured, not chosen. ...
    order: strict

**`join.on` is required and must be non-empty.** A correlation rule that cannot
name a shared entity cannot be loaded. This is the schema-level half of the
anti-fabricated-join guarantee; the test-level half is A-9 on Day 4.

`in_window` is required on every step. It must be `false` for any step whose
selected events are `presence`-typed, and the validator enforces that against
the section 5.3 table. A `presence` step is joined on entity and excluded from
the interval arithmetic.

`select.source_artifact` is therefore **required on every correlation step**,
although it is optional on an atomic rule. Without it the presence check is not
decidable at load time, and a check that cannot be made is a check that is not
being made.

`window.max` and `window.min` are ISO-8601 durations. **`justification` is a
required string** and must cite a measurement rather than a round number. This
field exists because the one interval we have measured is not round: the
scenario's arrival at `2026-08-23T22:20:06.710763Z` and its execution at
`2026-08-23T22:57:15.832787Z` are **37 m 09.122 s** apart, so a `PT30M` window
chosen because it looks tidy misses the only download-to-execution chain in the
corpus.

`order: strict` requires each windowed step's timestamp to be greater than or
equal to the previous one. `order: any` permits any ordering within the window.
`presence` steps are outside the ordering either way.

Ties are broken by the `Event` sort already used for the timeline: timestamp,
`source_artifact`, `source_file`, `source_locator`, `event_id`.

### 6.2 `optional`, and why Amcache must always be optional

`optional` is required on every step. A required step that matches nothing kills
the finding; an optional one that matches nothing is simply absent from it, and
its weight does not contribute.

**A step selecting `amcache` must be `optional: true`.** The validator rejects a
required one. This is **D-028**: `invoice_scan.exe` executed at
`2026-08-23T22:57:15.832788Z`, is recorded in Prefetch, and has **no Amcache
entry at all** — searched exhaustively by key name and by every value, not only
by path. The hive is not stale; its newest entries are the Guest Additions
binaries at `23:15:02.514594Z`, eighteen minutes after the execution.

Amcache is populated by the Compatibility Appraiser scheduled task, not at
process start, so a binary that runs once and is collected 34 minutes later can
miss the inventory pass entirely. That is normal behaviour, not a gap in the
evidence — and it is why `amcache` emits `presence`.

The consequence is blunt: **a rule requiring Prefetch and Amcache to agree
before raising a finding would miss the only real detection in the corpus.**
Amcache's value here is the 878 inventoried binaries per collection as baseline
material and SHA-1 where present, not as a second witness to the scenario. The
absence is pinned by
`tests/test_amcache.py::test_scenario_binary_is_absent_from_amcache` so it is
never later mistaken for a parser regression.

---

## 7. What a finding must carry

Fixed here so Day 3 implements to it rather than around it. A finding is
immutable once constructed, and it is keyed by `event_id`, never by a mutated
`Event` (`CD-005`).

| Field | Notes |
|---|---|
| `finding_id` | deterministic; a content hash over rule id plus the sorted matched `event_id`s |
| `rule_id`, `rule_version`, `schema_version` | which rule, at which version |
| `severity`, `weight`, `score_contribution` | |
| `matched_events` | for **every** matched event: `event_id`, `source_file`, `source_locator`, `timestamp`, `timestamp_type` |
| `entity_keys` | the derived keys the join used, and their derivation source |
| `window_observed` | actual interval between the windowed steps, or `null` when every step is `presence` |
| `time_claim` | `observed_interval` \| `observed_occurrence` \| `none` |
| `reason` | one human-readable sentence naming the artifacts, not the rule internals |

A finding that cannot name the `source_file` and `source_locator` of every event
it matched is not acceptable output. That is the acceptance gate's word
"traceable", made checkable.

---

## 8. `expected`: measured base rates, declared with the rule

Every atomic rule declares what it is expected to fire on, per collection:

    expected:
      clean_a: 4
      clean_b: 5
      s1_v2:   0
      note: >
        ...

This is not a test assertion; it is the measured base rate of the indicator,
recorded next to the rule that uses it. The reason it is a required field is
`EID 4720`: `clean_b` holds 5 and `clean_a` holds 4 account-creation records in
collections containing no attack, four of which are genuine lab construction
(`Youssef`, `WDAGUtilityAccount`, `janed`, `admin_local`) and the fifth is
`testuser`, staged twelve minutes before collection. A rule firing on those is
not a false positive of the pipeline — it is the indicator's base rate. A Week 4
false-positive figure that counts them as detections measures the indicator, not
the pipeline, and `expected` is where that distinction is written down before
the number is computed.

Two rules where the field carries most of the weight:

- **Log clearing.** Exactly one `1102` exists in the whole corpus, so the rule
  has one positive case across all three collections and its negative tests
  matter more than its positive one.
- **External RDP.** `s1_v2` has 58 logon rows after the clear, entirely SYSTEM
  and service accounts plus `admin_local` twice. There is no RDP in the
  scenario. `expected` is 0 everywhere, and that is a negative test, not a
  failure to detect.

`expected` values are recorded as measured; where a count has not yet been
measured the value is the string `unmeasured`, which the validator accepts and
Day 5 reports. It is never guessed and never silently `0`.

---

## 9. Determinism

Same input, same findings, same order, every run.

- Rules load in `id` order, not directory order.
- Findings sort by earliest matched timestamp, then `rule_id`, then the sorted
  matched `event_id` list.
- No rule may depend on wall-clock time, on the host locale, on set or dict
  iteration order, or on the order in which files were walked.
- `finding_id` is a content hash for the same reason `event_id` is (`CD-002`):
  a random id would make two runs over one collection produce different output
  and break diffing and regression tests.

---

## 10. Validation

    python rules/validate_rules.py rules/

Checks, in order: YAML loads under the restricted subset; required fields
present and well-typed; `id` matches its filename and its reserved block;
`select.event_type` values exist in `CD-007`; every `field` resolves to an
`Event` attribute or a `details.<key>`; every `details.<key>` is declared in
`docs/details-schema.md`; every operator is in the closed set and every regex
compiles; no forbidden join field; `join.on` non-empty for correlation rules;
`in_window: false` on every `presence`-typed step; `optional: true` on every
`amcache` step (6.2); a `file_download` step constrains `details.bytes` or
`details.url`, or acknowledges D-027 (4.7); `window.justification` present and
citing a number; `expected` present on atomic rules.

`CD-007` and `docs/details-schema.md` are read from the repository rather than
copied into the validator, so a clause changed on Person B's side changes what
passes here. If either document is missing the validator reports it as
**NOT PERFORMED**, names the file, and fails any rule that depended on it. It
does not pass silently and it does not skip quietly.

Exit status is 0 only when every rule passes every check that could be run.

---

## 11. What this schema needs from Person B

Nothing here is a change to a Person A file, so none of it is done unilaterally
(`CONTRACT-RULES` section 5).

| # | Item | State at `0994251` |
|---|---|---|
| 1 | `CD-019` — the three `timestamp_type` values | **landed**, and 5.2 matches it clause for clause |
| 2 | `timestamp_type` as a field on `Event` | **landed**, required, validated, in the `event_id` hash |
| 3 | `timestamp_type` as a CSV column | **landed** as column 2, beside `timestamp_utc` |
| 4 | `CD-021` — the `service_install` ImagePath decision | **landed**, with all five forms counted |
| 5 | `docs/details-schema.md` | **landed**, 40 keys across six families |
| 6 | the Prefetch executable-name key | **landed** as `details.executable` |
| 7 | `pyyaml` in `pyproject.toml` | **outstanding** — the validator cannot read a rule file without it |

Two items opened by writing the atomic rules on Day 2:

**The EID 4104 script text is carried under a cap.** *(Resolved 2026-08-30.)*
It was originally dropped, which blocked rule 3 of the six outright: `path` is
null for a script block, `action` is a fixed string, and no declared key held
what the script said. Option 1 of the three in the draft was taken.
`details.script_block_text` now carries the text capped at 4096 UTF-8 bytes,
with `script_block_text_bytes` holding the full original length and
`script_block_truncated` present when the cap was hit. The cap was chosen by
measurement: the corpus is bimodal, median 339 bytes and p90 about 15 KB, and
the blocks a rule needs to read are 112 bytes. See D-031.

The clause this schema promised to add with it is now **enforced by the
validator**, not merely stated:

> A declared-truncated key may be read by positive operators only.

`validate_rules.py` carries the set of truncated keys in `TRUNCATED_KEYS` and
rejects two things against them:

1. Any of `absent`, `not_equals`, `not_in`, `not_contains`, wherever it appears.
2. **Any operator at all inside a `none:` block** — including a positive one.
   `none: contains` reads "does not contain" however positively the operator
   itself is spelled, so restricting the operator set alone would have left the
   hole open. This goes beyond the clause as first written, and the extension is
   the point: the property being protected is the assertion, not the keyword.

Both rejections are verified against the validator rather than assumed, and a
legitimate positive `matches` on the same field is confirmed to still pass.

**`regipy` was not in `pyproject.toml`.** *(Resolved 2026-08-30.)* Both
`parsers/registry.py` and `parsers/amcache.py` import it lazily inside a
function, so nothing failed at import time and the failure arrived when a
parser ran -- the worse of the two failure modes. `regipy==6.3.0` and
`pyyaml==6.0.3` are both now pinned in `pyproject.toml`; pyyaml had been absent
from the working venv entirely, so the rule validator could not run there.

**The schema has no aggregation operator, and one required chain needs it.**
*(Opened 2026-08-30 by writing R-CORR-0002.)* The plan's second chain is
"failed-logon **burst** -> success". A burst is a count over a window — N
failures for one principal inside T — and the condition grammar in section 3
evaluates one event at a time. There is no `count`, no `within`, no grouping
aggregate.

`R-CORR-0002` is therefore written as *one* failure followed by a success,
which is a weaker claim than the plan asked for, and its description says so
rather than implying otherwise. It is not faked with a threshold the engine
cannot enforce. Closing this properly means either a `count` operator in 2.0.0
or a documented limitation in Week 4; the second is honest and the first is
better, and the choice is not urgent because `collection_s1_v2` contains exactly
one EID 4625 in the whole post-clear log, so no burst exists to detect.

One coordination item, not a blocker:

`CD-021` assigns executable extraction to Week 3's `core/entity.py`, which sits
in Person B's tree, while section 4.2 of this document specifies what that
extraction must produce. Neither placement is wrong; they simply have to stay in
step. The concrete request is that `core/entity.py` cite this section, and that
a change to either one is raised before it is made.

---

## 12. Version history

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-08-29 | First frozen version. Field addressing, join fields, missing-field behaviour, and the `timestamp_type` rule (A-1, A-2). |
| 1.3.0 | 2026-08-30 | Written alongside the correlation engine. **Corrects a bug in this document**: 4.2 said the image token is the longest leading prefix ending in an executable extension; it is the shortest, and an argument that is itself a path was being taken for the image. Adds step 5 to the same extraction, so a sentence cannot become an executable name. Moves the truncated-key clause into new section 3.5, where a rule author will find it, and records the `none:`-block extension Person B added in enforcing it. Absorbs D-032's sixth ImagePath form. Opens the aggregation gap in section 11. No change to any rule field, so 1.0.0, 1.1.0 and 1.2.0 files still load. |
| 1.2.0 | 2026-08-29 | Written while the six atomic rules were being drafted. Adds the `rules/blocked/` convention and the `.yml.draft` exclusion (section 1), and two items to section 11: the EID 4104 script-text gap that blocks `R-ATOMIC-0003`, and `regipy` missing from `pyproject.toml`. No change to any rule field, so 1.0.0 and 1.1.0 files still load. |
| 1.1.0 | 2026-08-29 | Reconciled against `week2/parsers-registry-browser` @ `0994251`. Six PENDING-B dependencies resolved and the shim table replaced by a verified static map including `evtx.powershell`. Added 4.7 (a filename does not identify a download, D-027), 5.4 (the measured presence-before-download case, D-027) and 6.2 (`optional`, and Amcache never required, D-028). Aligned 4.4 with `CD-022`, which distinguishes a recorded `-` from an absent field. Minor version, not major: every 1.0.0 rule file still loads. |
