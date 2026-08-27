from datetime import UTC, datetime
from pathlib import Path

from dfir_triage_pipeline.model import Event
from dfir_triage_pipeline.timeline import sort_events, write_csv


def ev(minute: int, locator: str) -> Event:
    return Event(
        timestamp=datetime(2026, 8, 10, 10, minute, 0, tzinfo=UTC),
        source_artifact="prefetch",
        event_type="process_exec",
        action="executed",
        source_file="Windows/Prefetch/NOTEPAD.EXE-A1B2C3D4.pf",
        source_locator=locator,
        timestamp_type="last_run",
        path=r"C:\Windows\System32\notepad.exe",
    )


def test_header_is_the_eleven_declared_columns(tmp_path: Path):
    """The CSV header is a contract. Column order is fixed, and
    timestamp_type sits beside timestamp_utc because it qualifies it."""
    out = tmp_path / "header.csv"
    write_csv([ev(10, "a")], out)
    header = out.read_text(encoding="utf-8").splitlines()[0]
    assert header == (
        "timestamp_utc,timestamp_type,source_artifact,event_type,user,path,"
        "action,event_id,source_file,source_locator,confidence"
    )
    assert len(header.split(",")) == 11


def test_sort_events_chronological():
    events = [ev(30, "c"), ev(10, "a"), ev(20, "b")]
    sorted_ = sort_events(events)
    assert [e.source_locator for e in sorted_] == ["a", "b", "c"]
    assert [e.timestamp.minute for e in sorted_] == [10, 20, 30]


def test_identical_sorted_events_write_byte_identical_files(tmp_path: Path):
    events = sort_events([ev(10, "a"), ev(20, "b")])
    path_a = tmp_path / "a.csv"
    path_b = tmp_path / "b.csv"
    write_csv(events, path_a)
    write_csv(events, path_b)
    assert path_a.read_bytes() == path_b.read_bytes()


def test_differently_ordered_inputs_produce_byte_identical_exports(tmp_path: Path):
    a = [ev(30, "c"), ev(10, "a"), ev(20, "b")]
    b = [ev(20, "b"), ev(30, "c"), ev(10, "a")]
    path_a = tmp_path / "order_a.csv"
    path_b = tmp_path / "order_b.csv"
    write_csv(sort_events(a), path_a)
    write_csv(sort_events(b), path_b)
    assert path_a.read_bytes() == path_b.read_bytes()
