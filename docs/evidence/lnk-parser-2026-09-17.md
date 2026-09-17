# Shell link parser — measured record, 2026-09-17

Twentieth artifact family, and the one that reopens **CD-013**. Measured across
all five collections through `ingest.collect_events`.

## The result: a device that is not in the image

```
s1_v2   E:\Camera\2020-10-09-171406379.mp4   removable   serial 18334A83   label "JOE"
        E:\Camera                            removable   serial 18334A83   label "JOE"
```

Two Recent links, written under `Youssef`'s profile, naming a **removable volume
labelled `JOE`** carrying a 14.7 MB video last modified 2020-10-09.

**Zero other families in the entire pipeline mention that volume or serial.**
Verified by scanning every event of every other family in `s1_v2` for the
string, and by checking all four remaining collections: the serial appears
nowhere else. Asserted in `test_no_other_family_names_that_volume` and
`test_the_volume_appears_in_no_other_collection`.

A device touched this machine, a file was opened from it, and the only record is
a 1 KB shell link. That is the CD-013 case, measured rather than argued.

## Why a LNK is stronger than the RecentDocs entry beside it

Both record that a file was opened through the shell, and both emit
`file_opened` — the same event_type deliberately, so a chain joined on it does
not break. The difference is in the details:

| | recentdocs | lnk |
|---|---|---|
| identity | a **name** | the **full path** |
| when | the containing key's last write, **shared by every sibling** (D-027) | three FILETIMEs **copied from the target file** |
| volume | — | serial, label, drive type |
| size | — | the target's size in bytes |

The LNK's timestamps describe the **target**, not the link, so they survive the
target's deletion. A shell link is a record of a file that may no longer exist.

## Measured counts

| collection | files | events | recent | installed | volumes seen |
|---|---|---|---|---|---|
| clean_a | 49 | 36 | 21 | 15 | A62AF538, 5659C38D |
| clean_b | 51 | 38 | 22 | 16 | A62AF538, 5659C38D |
| s1_v2 | 69 | 54 | 38 | 16 | A62AF538, 5659C38D, **18334A83** |
| clean_c | 41 | 34 | 18 | 16 | 60620DF0 |
| s1_v3 | 46 | 37 | 21 | 16 | 60620DF0 |

**Zero parse failures.** Families per collection: **19**.

Events are fewer than files because protocol links (`ms-settings:`,
`ms-gamingoverlay:`) name a URI handler rather than a file and carry no path at
all — nothing to attribute, so nothing is emitted.

`lnk_location` separates the two populations: a Start Menu or Desktop link was
installed by software and is **not evidence anyone used anything**. Every
collection carries 15–16 installed links regardless of activity, which is the
figure that would otherwise inflate a rule's base rate.

## Two parsing traps, both bounds-checked

Every section after the 76-byte header is length-prefixed and positioned
relative to the one before it. One mis-sized field shifts everything after it,
and the parser then emits **plausible strings read out of the middle of other
structures — without raising**.

**1. StringData counts CHARACTERS, not bytes.** All 256 links in this corpus are
Unicode, so the byte length is `count * 2`. Read as bytes, every later section
starts mid-string. `test_two_consecutive_sections_stay_in_step` is the assertion
that catches this: if the first section's width is wrong, the second is garbage.

**2. LinkInfo offsets are relative to the LinkInfo structure**, not to the file.
Treated as absolute they read from inside the header and assemble paths from
unrelated bytes.

A section that would run past the end of the file **ends the parse**, keeping
the fields already read — a truncated link still attests to its header, and
discarding it would lose a real record because its tail is damaged.

Measured: **256 files across five collections, 0 raised, 0 overran.**

## `timestamp_type` is `presence`, not `recorded`

The three FILETIMEs describe the target file, copied into the link. The OS
logged no event at that instant; it copied a property of a file. `recorded`
would claim an observation the artefact did not make.

The honest claim is *this file existed, with this timestamp, when the link was
written* — which is precisely why the link outlives its target.

## What is not parsed here

**JumpLists.** `*.automaticDestinations-ms` (6–18 per collection) and
`*.customDestinations-ms` (6–12) are OLE compound files containing embedded
shell links plus an application id. They would add the **application that opened
each file**, which no family currently carries. Left for later: the container
format is a second parser's worth of work, and the LNK decoding it would reuse
is now in place.

## Gate at this commit

    ruff              All checks passed!
    pytest            625 passed, 20 skipped
    validate_rules    schema 2.0.0   rules 14   errors 0   warnings 0

    families          19 present in any collection (was 18)
