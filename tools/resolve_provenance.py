"""Resolve the three provenance rows of Day 5 step 2 straight from Security.evtx.

Deliberately does NOT go through the timeline CSV: the point of the check is to
confirm the CSV against the source, so reading the CSV would be circular. Uses
the evtx library and raw XML only.
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from evtx import PyEvtxParser

EVTX = Path(
    r"%USERPROFILE%\dfir-evidence\collection_s1_v2"
    r"\C\Windows\System32\winevt\logs\Security.evtx"
)

EXPECT = {
    28674: {
        "timestamp": "2026-08-23T23:19:36.095131Z",
        "event_type": "process_exec",
        "user": "admin_local",
        "path": r"Z:\kape\KAPE\kape.exe",
        "index": 330,
    },
    28364: {
        "timestamp": "2026-08-23T23:15:31.058684Z",
        "event_type": "process_exec",
        "user": "WINDOWS10$",
        "path": r"C:\Windows\System32\svchost.exe",
        "index": 131,
    },
    28640: {
        "timestamp": "2026-08-23T23:17:45.468579Z",
        "event_type": "logon",
        "user": "SYSTEM",
        "path": "",
        "index": 303,
    },
}

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
EID_TYPE = {4624: "logon", 4625: "logon_failed", 4688: "process_exec",
            4720: "account_created", 1102: "log_cleared"}

found = {}
parser = PyEvtxParser(str(EVTX))
for rec in parser.records():
    rid = rec["event_record_id"]
    if rid in EXPECT:
        found[rid] = rec["data"]
    if len(found) == len(EXPECT):
        break

print(f"source: {EVTX}")
print(f"records located: {len(found)} of {len(EXPECT)}\n")

ok_all = True
for rid, exp in EXPECT.items():
    print("=" * 72)
    print(f"index {exp['index']}   EventRecordID={rid}")
    print("=" * 72)
    if rid not in found:
        print("  NOT FOUND -- record does not exist in this log")
        ok_all = False
        continue

    root = ET.fromstring(found[rid])
    system = root.find("e:System", NS)
    eid = int(system.findtext("e:EventID", default="0", namespaces=NS))
    tnode = system.find("e:TimeCreated", NS)
    raw_ts = tnode.get("SystemTime")

    data = {}
    ed = root.find("e:EventData", NS)
    if ed is not None:
        for d in ed.findall("e:Data", NS):
            data[d.get("Name")] = (d.text or "").strip()

    # match the parser's own field selection
    if eid == 4688:
        user = data.get("SubjectUserName", "")
        path = data.get("NewProcessName", "")
    elif eid in (4624, 4625):
        user = data.get("TargetUserName", "")
        path = ""
    else:
        user = data.get("SubjectUserName", "")
        path = ""

    # normalise the timestamp to the Z form the timeline writes
    ts = raw_ts
    if "." in ts:
        head, frac = ts.split(".", 1)
        frac = re.sub(r"[^0-9]", "", frac)[:6].ljust(6, "0")
        ts = f"{head}.{frac}Z"

    checks = [
        ("timestamp", ts, exp["timestamp"]),
        ("event_type", EID_TYPE.get(eid, f"EID{eid}"), exp["event_type"]),
        ("user", user, exp["user"]),
        ("path", path, exp["path"]),
    ]
    for label, got, want in checks:
        mark = "OK  " if got == want else "FAIL"
        if got != want:
            ok_all = False
        shown_got = repr(got) if got == "" else got
        shown_want = repr(want) if want == "" else want
        print(f"  [{mark}] {label:11} got {shown_got}")
        if got != want:
            print(f"              want {shown_want}")
    print(f"         (EID {eid})")
    print()

print("=" * 72)
print("ALL THREE RESOLVE AS DOCUMENTED" if ok_all else "MISMATCH -- see FAIL above")
print("=" * 72)
