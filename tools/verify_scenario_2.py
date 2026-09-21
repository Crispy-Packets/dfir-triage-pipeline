"""Pre-collection verification for scenario 2.

DESIGN ONLY -- scenario 2 was never collected and no collection is planned; the
corpus is final at five collections. This script is retained as the record of
what a row-level pre-collection check would have asserted. It was never run
against a live collection.

Run on the LIVE VM, after the scenario and BEFORE KAPE.

C-05 says the scenario must produce the indicator the rule set is meant to
detect -- not merely that the family which would record it is parsed. This
enforces that at the row level: for each step, it asserts the specific
`details` field the rule reads, through the pipeline's own parsers.

Reading the artifacts with independent logic would be the "wrong target"
failure of principles.md 4.1: a check that parses a .lnk its own way can pass
while the pipeline's `lnk` parser extracts something else, and the rule still
cannot fire. So this ingests exactly as the pipeline does and asserts on
`Event.details`.

Why before KAPE: a step that wrote the right technique with the wrong field is
seconds to re-run while the VM is live, and unrecoverable once the snapshot is
gone.

    python tools/verify_scenario_2.py --live
    python tools/verify_scenario_2.py --collection <path>   (dry-run a KAPE dir)

Exit 0 = every required check passed. Exit 1 = at least one failed; do not
collect yet.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from dfir_triage_pipeline.ingest import collect_events  # noqa: E402

# --- What each step must have written, expressed as the rule reads it. -------
#
# `family`/`event_type` mirror the rule's `select:`; `require` mirrors its
# conditions. A check passes when at least one row satisfies every clause.
# `rule` names the rule that would fire, so a failure says what is lost.

CHECKS = [
    {
        "id": "S1-DELIVERY",
        "step": "BITS background transfer",
        "rule": "(T1071.001 -- no rule yet; gives evtx.bits its first positive class)",
        "family": "evtx.bits",
        "event_type": None,
        "require": [("url", "present"), ("jobOwner", "present")],
        "reject_value": [("url", ("windowsupdate.com", "microsoft.com", "msedge"))],
        "note": "The url must be ATTACKER-controlled. Every BITS transfer in the "
                "existing corpus is Windows servicing, which is why T1071.001 is "
                "measured-no-discriminator. A servicing URL here buys nothing.",
    },
    {
        "id": "S2-EXECUTE-LNK",
        "step": ".lnk carrying arguments, in Recent Items",
        "rule": "R-ATOMIC-0012",
        "family": "lnk",
        "event_type": "file_opened",
        "require": [("arguments", "present"), ("lnk_location", "equals:recent")],
        "note": "BOTH clauses. A .lnk with arguments outside Recent Items does not "
                "match: the rule reads details.lnk_location == recent.",
    },
    {
        "id": "S3-PERSIST-TASK",
        "step": "scheduled task created by the scenario",
        "rule": "(T1053.005 -- currently measured-no-discriminator)",
        "family": "scheduled_task",
        "event_type": None,
        "require": [("command", "contains:invoice_scan")],
        "note": "Asserts the task's command names the scenario payload, NOT that "
                "task_author names the scenario user. Measured on scenario 1: "
                "task_author is ABSENT on 79 of 210 tasks and is 'Microsoft "
                "Corporation' or a MUI resource string on the rest -- it never "
                "carries a username, so requiring it would fail a correct run. "
                "The principal lives in the task XML's <UserId> element, which "
                "the parser does not currently extract; until it does, C-04 "
                "(scenario user, not provisioning account) must be enforced by "
                "procedure -- see the runbook -- not asserted here.",
    },
    {
        "id": "S3-PERSIST-RUNKEY",
        "step": "autorun value in the per-user hive (optional, if used)",
        "rule": "R-ATOMIC-0017",
        "family": "registry",
        "event_type": "persistence_autorun",
        "require": [("hive_type", "equals:ntuser"), ("value_data", "present")],
        "optional": True,
        "note": "Only required if the persist step writes a per-user Run key "
                "instead of, or as well as, the scheduled task.",
    },
    {
        "id": "S4-DESTROY-EVTX",
        "step": "the .evtx file itself deleted (not wevtutil cl)",
        "rule": "(the case EID 1102 cannot record -- grid 3.8, OD-02)",
        "family": "usn",
        "event_type": None,
        "require": [("file_name", "contains:.evtx")],
        "note": "Deleting the file rather than clearing the log is the whole point "
                "of this step. If this fails, the scenario cleared the log the way "
                "scenario 1 did and R-ATOMIC-0002 already covers it.",
    },
    {
        "id": "S5-EXFIL-LNK",
        "step": "payload opened from removable media",
        "rule": "R-ATOMIC-0010",
        "family": "lnk",
        "event_type": "file_opened",
        "require": [("drive_type", "in:removable,remote")],
        "note": "C-01: this must NOT be the volume the collections are carried on. "
                "Check the volume_serial reported below against the collection "
                "media before accepting it.",
    },
    {
        "id": "S5-EXFIL-JUMPLIST",
        "step": "the same access recorded in a jump list",
        "rule": "R-ATOMIC-0013",
        "family": "jumplist",
        "event_type": "file_opened",
        "require": [("drive_type", "in:removable,remote")],
        "optional": True,
        "note": "Jump lists lag; this may legitimately be empty if the app was not "
                "closed. Optional so it does not block a collection on its own.",
    },
    {
        "id": "S5-EXFIL-SRUM",
        "step": "measurable network egress by the payload",
        "rule": "R-ATOMIC-0014",
        "family": "srum",
        "event_type": "network_usage",
        "require": [("bytes_sent", "present")],
        "optional": True,
        "note": "SRUM flushes on a timer -- typically up to an hour. If this is "
                "empty, WAIT and re-run rather than re-running the scenario.",
    },
    {
        "id": "S6-RECYCLE",
        "step": "payload sent to the Recycle Bin (optional)",
        "rule": "R-ATOMIC-0015",
        "family": "recyclebin",
        "event_type": "file_deleted",
        "require": [("original_path", "present")],
        "optional": True,
    },
    {
        "id": "S6-AMCACHE",
        "step": "unsigned payload inventoried by Amcache (optional)",
        "rule": "R-ATOMIC-0018",
        "family": "amcache",
        "event_type": "program_inventoried",
        "require": [("publisher", "absent")],
        "optional": True,
        "note": "Amcache updates on a schedule; absence here is a timing artifact "
                "as often as a failure.",
    },
]


def _clause_holds(details: dict, key: str, spec: str) -> bool:
    value = details.get(key)
    if spec == "present":
        return value not in (None, "")
    if spec == "absent":
        return value in (None, "")
    if spec.startswith("equals:"):
        return str(value).lower() == spec.split(":", 1)[1].lower()
    if spec.startswith("contains:"):
        return spec.split(":", 1)[1].lower() in str(value or "").lower()
    if spec.startswith("in:"):
        allowed = {v.strip().lower() for v in spec.split(":", 1)[1].split(",")}
        return str(value or "").lower() in allowed
    raise ValueError(f"unknown clause spec {spec!r}")


def run(root: Path) -> int:
    print(f"Ingesting {root} through the pipeline's own parsers ...", flush=True)
    events, _stats = collect_events(root)
    print(f"  {len(events)} events\n")

    by_family: dict[str, list] = {}
    for e in events:
        by_family.setdefault(e.source_artifact, []).append(e)

    failed_required = 0
    failed_optional = 0

    for check in CHECKS:
        rows = by_family.get(check["family"], [])
        if check["event_type"]:
            rows = [r for r in rows if r.event_type == check["event_type"]]

        hits = [
            r for r in rows
            if all(_clause_holds(r.details or {}, k, s) for k, s in check["require"])
        ]

        # A value-level reject: the field is populated but with the wrong thing.
        rejected = []
        for key, bad_substrings in check.get("reject_value", []):
            for r in hits:
                val = str((r.details or {}).get(key, "")).lower()
                if any(b in val for b in bad_substrings):
                    rejected.append(val)
        clean_hits = [
            r for r in hits
            if not any(
                any(b in str((r.details or {}).get(key, "")).lower() for b in bad)
                for key, bad in check.get("reject_value", [])
            )
        ]

        optional = check.get("optional", False)
        ok = bool(clean_hits)
        tag = "PASS" if ok else ("WARN" if optional else "FAIL")
        if not ok:
            if optional:
                failed_optional += 1
            else:
                failed_required += 1

        clauses = ", ".join(f"details.{k} {s}" for k, s in check["require"])
        print(f"[{tag}] {check['id']}  {check['step']}")
        print(f"       rule      {check['rule']}")
        print(f"       family    {check['family']}"
              f"{' / ' + check['event_type'] if check['event_type'] else ''}"
              f"   rows={len(rows)}")
        print(f"       asserts   {clauses}")
        print(f"       matching  {len(clean_hits)}")
        if rejected:
            print(f"       REJECTED  {len(rejected)} row(s) matched but the value "
                  f"looks like vendor traffic, e.g. {rejected[0][:60]}")
        if clean_hits:
            sample = clean_hits[0]
            shown = {k: (sample.details or {}).get(k) for k, _ in check["require"]}
            print(f"       sample    {shown}")
            if "volume_serial" in (sample.details or {}):
                print(f"       volume    serial={sample.details.get('volume_serial')} "
                      f"label={sample.details.get('volume_label')}  <-- C-01: must "
                      f"NOT be the collection media")
        if not ok and check.get("note"):
            print(f"       why       {check['note']}")
        print()

    print("=" * 68)
    if failed_required:
        print(f"{failed_required} REQUIRED check(s) failed. DO NOT COLLECT YET.")
        print("Re-run the failing step on the live VM and run this again.")
    else:
        print("All required checks passed.")
    if failed_optional:
        print(f"{failed_optional} optional check(s) empty -- see notes; several are "
              f"timing artifacts that resolve by waiting, not by re-running.")
    print("=" * 68)
    return 1 if failed_required else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--live", action="store_true",
                   help="verify the running system (C: as its own root)")
    g.add_argument("--collection", type=Path,
                   help="verify an already-taken KAPE collection instead")
    args = ap.parse_args(argv)
    root = Path("C:/") if args.live else args.collection
    if not root.exists():
        print(f"no such path: {root}", file=sys.stderr)
        return 2
    return run(root)


if __name__ == "__main__":
    raise SystemExit(main())
