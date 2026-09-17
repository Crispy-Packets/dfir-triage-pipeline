# SAM hive parser — measured record, 2026-09-17

Thirteenth artifact family. Measured across all five collections through
`ingest.collect_events`, not through the parser in isolation.

## What SAM adds that nothing else in the pipeline has

The Security log records account *events*. SAM records *accounts*. After
`wevtutil cl security` — which `s1_v2` and `s1_v3` both perform — the log holds
neither 4720 nor 4624, and SAM holds both facts intact because it is not a log.

`collection_s1_v3` is the demonstration: **12 Security events survive** the
clear, and SAM still names all five accounts with their logon counts.

## Measured account counts

| collection | accounts | real | built-in |
|---|---|---|---|
| clean_a | 7 | 3 | 4 |
| clean_b | 7 | 3 | 4 |
| s1_v2 | 7 | 3 | 4 |
| clean_c | 5 | 1 | 4 |
| s1_v3 | 5 | 1 | 4 |

Built-ins are the same four everywhere: Administrator (500), Guest (501),
DefaultAccount (503), WDAGUtilityAccount (504). All four are `disabled` on both
hosts and all four have a logon count of **zero**.

## Logon counts, which SAM maintains itself

| account | RID | clean_a | clean_b | s1_v2 | clean_c | s1_v3 |
|---|---|---|---|---|---|---|
| Youssef | 1000 | 13 | 13 | 17 | — | — |
| janed | 1002 | 1 | 1 | 12 | — | — |
| admin_local | 1003 | 5 | 5 | 29 | — | — |
| vboxuser | 1000 | — | — | — | 9 | 15 |
| built-ins | 500/501/503/504 | 0 | 0 | 0 | 0 | 0 |

The scenario collections show higher counts than their baselines on every real
account, which is the scenario session being performed. Nothing here is a
detection — it is corroboration available after the log is gone.

## Two bugs found by measuring, both of which produced plausible output

**1. Every account resolved as `RID-1000`.** `_names_to_rid` checked
`isinstance(rid, int)`; regipy returns the RID as a **decimal string**, because
it is not a `REG_*` constant the library can name and it falls back to `str()`.
The map came out empty on every hive. The output was well-formed, correct as
far as it went, and useless to any rule wanting a name. Guarded by
`TestCoerceRid` and by `test_accounts_are_named_not_numbered`.

**2. The event was timestamped by the key's last write.** Measured, the user
key's last-write time is **exactly** the last-logon FILETIME on every account
with a non-zero logon count, across all five collections, because Windows
rewrites the key on logon. The event restated one fact twice and labelled it
`presence`, which understates what the artefact knows. Now an account that has
logged on carries the logon time as `last_run`; one that never has falls back
to the key write as `presence`.

## The `testuser` result

`testuser` was created in `clean_b` on 2026-08-24 18:44 (R-CORR-0005's negative
case) and **does not appear in SAM at all**.

That separates two situations the Security log cannot distinguish, because 4720
fires identically for both:

- an account created and **never used** — present in SAM, logon count 0
- an account created and **deleted** — absent from SAM entirely

WDAGUtilityAccount is the first; testuser is the second. The earlier C4
measurement reported testuser as "NEVER", derived from the absence of a logon
event. SAM shows the account is gone, which is a different and stronger claim.

## Contract consequences

**CD-019 amended, not extended.** SAM's last-logon takes `last_run` rather than
a new `last_logon` term. The vocabulary is defined by *shape* — "the artifact
records only the most recent occurrence" — and one overwritten slot behind a
count of 13 logons is exactly that shape, despite recording an authentication
rather than an execution. A separate term would split one concept in two and
break every rule reasoning over recency.

**SAM is the first family whose `timestamp_type` varies by record.** The static
`TIMESTAMP_TYPE_BY_ARTIFACT` map can only state the dominant case, so
`MIXED_TIMESTAMP_TYPE` now names such families and the validator rejects a
windowed step selecting one unless it excludes the never-logged-on records
(`details.last_logon not_equals never`, or the same in a `none` group). Without
that guard a `sam` step would pass the presence check on the strength of the
dominant mapping while still admitting records timestamped at image-build time.

**`local_account` is a new event_type**, not a reuse of `account_created`, for
the same reason `service_registered` is distinct from `service_install`: one is
an event, the other is a state.

## What this parser does not read

No password hash, no decryption. The `V` value holds the NT hash and
`SupplementalCredentials` holds more; neither is touched. A triage pipeline
that extracted credential material would be a different tool with different
handling requirements, and `test_no_credential_material_is_emitted` asserts it
stays that way.

## Gate at this commit

    ruff              All checks passed!
    pytest            477 passed, 20 skipped
    validate_rules    schema 2.0.0   rules 14   errors 0   warnings 0

    families          13 (was 12)
