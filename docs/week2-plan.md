# Week 2 plan

Ordered by what unblocks the most downstream work. Items carried from Week 1
limitations keep their reference so nothing is silently dropped.

---

## 1. Toolchain smoke tests -- do this FIRST

**Ninety minutes, before Week 4 depends on any of them.** Hayabusa, Plaso and
dftpl. The only question to answer per tool: does it install, run against one of
our collections, and produce parseable output on this host?

Rationale for going first: a tool that cannot be made to work is a Week 4
schedule problem, and finding that out in Week 4 leaves no room to replace it.
Ninety minutes now buys the option to change course.

Record the result either way in `docs/evidence/`, including versions.

---

## 2. `clean_c` decision

With one realistic clean collection, false-positive measurement and
anomaly-model training draw on the same data (CD-014). Either collect a third
clean collection with a differing benign workload, or state explicitly in the
evaluation that the two draws are not independent and accept the weaker claim.

**This is a decision, not a task.** It needs making early because collecting
`clean_c` requires lab time that must be scheduled, and the lab VM used for the
scenario has already been decommissioned once.

---

## 3. Count downloads in `collection_s1_v2` browser history

Deferred from Week 1 because no browser parser existed. The ground truth records
one download; whether the history holds others is unmeasured, and an unmeasured
count cannot support a false-positive claim about download-to-execution rules.

Depends on the browser downloads parser below.

---

## 4. Parsers

In dependency order, not preference order:

| parser | why this order |
|---|---|
| **Amcache** | `presence` timestamp_type, already in the CD-019 vocabulary. Gives execution evidence where Prefetch is absent |
| **Shimcache** | Same `presence` semantics; pairs with Amcache for the same question |
| **Registry autoruns** | Directly evaluable against the scenario's `HKCU\...\Run\SecurityUpdate` persistence |
| **Browser downloads** | Unblocks item 3 and the download-to-execution sequence rule |
| **MFT (narrow mode)** | Largest and least constrained; last so the pattern is settled first |

Each parser follows the Week 1 shape that held up under real evidence:

- a `_records()` adapter that is the **only** library-coupled code
- a pure `record_to_events()` transform taking a dict and returning Events
- `can_handle()` tested against the **real directory listing**, not invented paths
- every `details` key declared in `docs/details-schema.md` **before** emission

**Read `03-findings-for-you.md` before writing any of them.** Three of Week 1's
four defects produced wrong output without raising an exception. Assume the same
class of fault exists in every new library until checked against raw bytes or
ground truth.

---

## 5. `core/entity.py`

Entity identity across artifact families (CD-010). The volume-serial to
drive-letter map is read from the collection manifest.

**Two constraints established in Week 1 that this must respect:**

- The volume serial is **per-record**, and marks which volume a binary ran from
  -- not whether it is tool noise. `KAPE.EXE` appears under both serials in
  `clean_b`. Do not use the serial as a noise classifier.
- Basename joining is the primary key and **will** join distinct binaries
  sharing a name. That cost must be measured against the clean baselines and
  reported, not estimated.

---

## 6. Freeze and tag the YAML rule schema

Once the rule engine has a shape, freeze the schema and tag it. Week 3 and Week 4
both write rules against it, and an unfrozen schema means every rule written
early gets rewritten late.

---

## Carried from Week 1, unresolved

- **D-019** -- 24 files in `collection_s1_v2` covered only from receipt onward.
  Cannot be resolved; the lab VM is decommissioned. Stays recorded.
- **D-014** -- ruff `I001` on parser registration imports. Resolved by `,I001` on
  the first import line each time a parser is added. Will recur with every new
  parser in item 4.
- **CD-014 7045 counts** -- the only knowingly incomplete clause in the
  contract. Filled at step 191 once EVTX merges.
