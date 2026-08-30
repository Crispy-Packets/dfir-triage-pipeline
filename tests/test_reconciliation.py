"""B-13: the written CSV must reproduce every independently recorded figure.

These assert against the serialised output rather than the in-memory events,
because the CSV is the deliverable and a serialisation fault would not show up
any other way.

The Security-channel arithmetic and the ground-truth chain were derived by
Person A by hand from the evidence, before this pipeline could produce them.
That independence is what makes them worth asserting: they are not this code
checking its own homework.
"""

import csv
import os
from collections import Counter
from pathlib import Path

import pytest

COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")
OUTPUTS = Path(__file__).resolve().parent.parent / "outputs"

# Produced by `python -m dfir_triage_pipeline <collection> --output ...`.
EXPECTED = {
    "clean_a": {"total": 13210, "evtx.security": 10142, "prefetch": 1212},
    "clean_b": {"total": 13556, "evtx.security": 10439, "prefetch": 1248},
    "s1_v2": {"total": 3429, "evtx.security": 359, "prefetch": 868},
}


def _rows(name):
    path = OUTPUTS / name / "timeline.csv"
    if not path.is_file():
        pytest.skip(f"{path} not generated; run the pipeline first")
    with path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_event_counts_reproduce(name):
    rows = _rows(name)
    expected = EXPECTED[name]
    assert len(rows) == expected["total"]
    artifacts = Counter(r["source_artifact"] for r in rows)
    for artifact in ("evtx.security", "prefetch"):
        assert artifacts[artifact] == expected[artifact]


def test_security_arithmetic_matches_person_a():
    """Person A derived this by hand from the evidence: 4688(299) + 4624(58) +
    1102(1) + 4625(1) = 359. Two independent routes to the same numbers is the
    strongest check available here."""
    sec = [r for r in _rows("s1_v2") if r["source_artifact"] == "evtx.security"]
    counts = Counter(r["event_type"] for r in sec)
    assert counts["process_exec"] == 299
    assert counts["logon"] == 58
    assert counts["log_cleared"] == 1
    assert counts["logon_failed"] == 1
    assert len(sec) == 359


def test_ground_truth_chain_is_present_in_the_output():
    """The three steps Person A fixed by hand on 2026-08-26.

    The execution timestamp is shared with CONHOST.EXE -- Prefetch writes a
    batch of records at the same instant -- so the binary has to be named as
    well as the time. Matching on timestamp alone would pass on the wrong row.
    """
    rows = _rows("s1_v2")

    arrival = [
        r for r in rows
        if r["timestamp_utc"] == "2026-08-23T22:20:06.710763Z"
        and r["source_artifact"] == "browser"
        and "invoice_scan.exe" in r["path"]
    ]
    assert len(arrival) == 1

    execution = [
        r for r in rows
        if r["timestamp_utc"] == "2026-08-23T22:57:15.832788Z"
        and r["source_artifact"] == "prefetch"
        and r["path"].upper() == "INVOICE_SCAN.EXE"
    ]
    assert len(execution) == 1

    clears = [r for r in rows if r["event_type"] == "log_cleared"]
    assert len(clears) == 1

    # Arrival must precede execution, and execution the clear. If a future
    # change broke timestamp handling this ordering would invert.
    assert arrival[0]["timestamp_utc"] < execution[0]["timestamp_utc"]
    assert execution[0]["timestamp_utc"] < clears[0]["timestamp_utc"]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_contract_invariants_hold_in_the_written_csv(name):
    """CD-004 and CD-019, checked after serialisation rather than before."""
    rows = _rows(name)

    ids = Counter(r["event_id"] for r in rows)
    assert [k for k, v in ids.items() if v > 1] == []

    locators = Counter((r["source_file"], r["source_locator"]) for r in rows)
    assert [k for k, v in locators.items() if v > 1] == []

    vocabulary = {"recorded", "last_run", "presence"}
    assert {r["timestamp_type"] for r in rows} <= vocabulary

    timestamps = [r["timestamp_utc"] for r in rows]
    assert timestamps == sorted(timestamps)


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_a_fresh_run_reproduces_the_committed_output():
    """Determinism at the file level.

    The in-memory determinism check lives in test_ingest. This one runs the CLI
    end to end and compares bytes, which also covers CSV quoting, field order
    and line endings -- the parts a later change is most likely to alter without
    anyone noticing.
    """
    import subprocess
    import sys
    import tempfile

    name = Path(COLLECTION).name.replace("collection_", "")
    if name not in EXPECTED:
        pytest.skip(f"no committed output for {name}")

    committed = OUTPUTS / name / "timeline.csv"
    if not committed.is_file():
        pytest.skip("committed output not generated")

    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "timeline.csv"
        result = subprocess.run(
            [sys.executable, "-m", "dfir_triage_pipeline", COLLECTION,
             "--output", str(fresh)],
            capture_output=True,
            cwd=OUTPUTS.parent,
        )
        assert result.returncode == 0, result.stderr.decode()
        assert fresh.read_bytes() == committed.read_bytes()
