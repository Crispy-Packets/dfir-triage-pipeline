"""EVTX library spike -- throwaway diagnostic, NOT part of the package.

Run on the HOST, from the repository root, with (.venv) active:

    python tools\\evtx_spike.py "<path to a real .evtx under collections\\>"

Answers every question the Day 3 spike is supposed to answer, two the
runbook forgot to ask, and one this lab needs because it has three accounts:

  1. Which library, and its exact version      -> the string Person B pins
  2. How records are iterated, and their type
  3. Whether the XML carries XML NAMESPACES    -> decides whether the parser
                                                  works at all
  4. Where EventRecordID comes from
  5. The exact shape of TimeCreated/@SystemTime, and its fractional digits
  6. Whether EventRecordID is UNIQUE in the file -> CD-004, Day 3 action 73
  7. Which EventIDs are actually present       -> which integration tests can
                                                  exist, and whether 4720/7045
                                                  have real coverage
  8. WHICH ACCOUNTS appear per declared EID    -> answers "which account
                                                  performed the benign
                                                  baseline" from evidence
                                                  instead of from memory

Q8 is the only change from the version in the Day 3 closeout document.
Nothing else in this file was touched.

Keep the output. Paste it into docs/lab-setup.md and push it; send Person B
the commit hash rather than the text.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from importlib import metadata

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
DECLARED_EIDS = {4624, 4625, 4688, 4720, 1102, 7045}

# Q8. Which EventData field names the acting or affected account, per EID.
# Matches _user_for() in the parser, so the spike reports what the parser
# will actually put in Event.user -- not a second opinion about it.
USER_FIELD = {
    4624: "TargetUserName",
    4625: "TargetUserName",
    4720: "TargetUserName",
    4688: "SubjectUserName",
    1102: "SubjectUserName",  # lives under UserData/LogFileCleared, not EventData
    7045: "AccountName",
}


def load_library() -> tuple[str, str, object]:
    """Return (library name, version, a records(path) -> Iterator callable)."""
    try:
        from evtx import PyEvtxParser

        def records(path: str):
            yield from PyEvtxParser(path).records()

        return "evtx", metadata.version("evtx"), records
    except ImportError:
        pass

    try:
        import Evtx.Evtx as pyevtx

        def records(path: str):
            with pyevtx.Evtx(path) as log:
                for rec in log.records():
                    yield {"event_record_id": rec.record_num(), "data": rec.xml()}

        return "python-evtx", metadata.version("python-evtx"), records
    except ImportError:
        sys.exit("Neither 'evtx' nor 'python-evtx' is installed in this interpreter.")


def _fields(root: ET.Element) -> dict[str, str]:
    """EventData/Data[@Name] pairs, plus UserData/LogFileCleared children for 1102.

    Namespaced first, un-namespaced as a fallback, so the spike still reports
    something useful on a library that strips namespaces -- which is exactly
    the case Q3 exists to detect.
    """
    out: dict[str, str] = {}
    nodes = root.findall("e:EventData/e:Data", NS) or root.findall("EventData/Data")
    for node in nodes:
        name = node.get("Name")
        if name:
            out[name] = node.text or ""
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] == "LogFileCleared":
            for child in node:
                out[child.tag.rsplit("}", 1)[-1]] = child.text or ""
    return out


def main(path: str) -> None:
    name, version, records = load_library()

    print("=" * 70)
    print("Q1  LIBRARY")
    print(f"    pin string for Person B:  {name}=={version}")
    print(f"    interpreter:              {sys.version.split()[0]}")
    print(f"    file:                     {path}")

    first_shown = False
    record_ids: list[str] = []
    eids: Counter[str] = Counter()
    systemtimes: list[str] = []
    users: dict[int, Counter[str]] = defaultdict(Counter)
    parse_failures = 0
    total = 0

    for rec in records(path):
        total += 1
        xml_text = rec["data"] if isinstance(rec, dict) else str(rec)

        if not first_shown:
            first_shown = True
            print("=" * 70)
            print("Q2  RECORD SHAPE")
            print(f"    type(record):             {type(rec).__name__}")
            if isinstance(rec, dict):
                print(f"    keys:                     {sorted(rec.keys())}")
            print("=" * 70)
            print("Q3  NAMESPACES  <-- the one that decides everything")
            head = xml_text[:300].replace("\n", " ")
            print(f"    first 300 chars: {head}")
            if "xmlns=" in xml_text[:400]:
                print("    VERDICT: namespaced. NS + findall('e:...') is CORRECT.")
            else:
                print("    VERDICT: NO NAMESPACE FOUND.")
                print("    STOP. Every findall('e:...', NS) in the parser will")
                print("    return nothing and the parser will silently yield ZERO")
                print("    events with no error. Report this before writing code.")

        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            parse_failures += 1
            continue

        system = root.find("e:System", NS)
        if system is None:
            system = root.find("System")  # un-namespaced fallback
        if system is None:
            continue

        rid = system.findtext("e:EventRecordID", default="", namespaces=NS) or (
            system.findtext("EventRecordID", default="") or ""
        )
        if rid:
            record_ids.append(rid)

        eid = system.findtext("e:EventID", default="", namespaces=NS) or (
            system.findtext("EventID", default="") or ""
        )
        if eid:
            eids[eid] += 1

        node = system.find("e:TimeCreated", NS)
        if node is None:
            node = system.find("TimeCreated")
        if node is not None and len(systemtimes) < 3:
            st = node.get("SystemTime")
            if st:
                systemtimes.append(st)

        # Q8 -- account attribution, declared EIDs only.
        if eid.isdigit() and int(eid) in DECLARED_EIDS:
            field = USER_FIELD[int(eid)]
            value = _fields(root).get(field, "")
            users[int(eid)][value or "(empty)"] += 1

    print("=" * 70)
    print("Q4  EventRecordID SOURCE")
    print("    Read from the XML System/EventRecordID element (works on both")
    print("    libraries and keeps record_to_event a pure string transform).")
    print(f"    records with an EventRecordID: {len(record_ids)} of {total}")

    print("=" * 70)
    print("Q5  TimeCreated/@SystemTime SHAPE")
    for st in systemtimes:
        # Count fractional digits only. Anything after them is an offset, and
        # counting it as fraction (".000000+03:00" -> 12) misreports the shape.
        frac = ""
        if "." in st:
            tail = st.split(".", 1)[1]
            for ch in tail:
                if ch.isdigit():
                    frac += ch
                else:
                    break
        offset = "Z" if st.endswith("Z") else "EXPLICIT OFFSET -- see Defect 3"
        print(f"    {st}   fractional digits={len(frac)}   suffix={offset}")
    if not systemtimes:
        print("    none captured")

    print("=" * 70)
    print("Q6  EventRecordID UNIQUENESS  (CD-004, Day 3 action 73)")
    unique = len(set(record_ids))
    print(f"    total records:  {total}")
    print(f"    with an ID:     {len(record_ids)}")
    print(f"    distinct IDs:   {unique}")
    if record_ids and unique == len(record_ids):
        print("    VERDICT: unique. CD-004 is now an observation, not an assumption.")
    else:
        dupes = [k for k, v in Counter(record_ids).items() if v > 1][:10]
        print(f"    VERDICT: DUPLICATES FOUND -> {dupes}")
        print("    CD-004 does not hold on this file. Raise with Person B.")

    print("=" * 70)
    print("Q7  EventIDs PRESENT")
    print(f"    malformed records skipped: {parse_failures}")
    print("    declared EIDs (CD-007) found in this file:")
    for eid_num in sorted(DECLARED_EIDS):
        n = eids.get(str(eid_num), 0)
        mark = "yes" if n else " NO"
        print(f"      {mark}  {eid_num}: {n}")
    print("    top 10 EIDs overall:")
    for eid_str, n in eids.most_common(10):
        print(f"      {eid_str}: {n}")

    print("=" * 70)
    print("Q8  ACCOUNTS PER DECLARED EID")
    print("    This lab has three accounts: youssef and admin_local (admins)")
    print("    and janed (standard user). Read this against the ground truth.")
    print("    An '(empty)' user on 1102 means UserData was not read -- a")
    print("    parser bug, not an evidence gap.")
    if not users:
        print("    no declared EIDs in this file")
    for eid_num in sorted(users):
        print(f"    EID {eid_num} ({USER_FIELD[eid_num]}):")
        for value, n in users[eid_num].most_common(8):
            print(f"      {value}: {n}")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])