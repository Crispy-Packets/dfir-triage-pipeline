from datetime import UTC, datetime, timedelta, timezone

import pytest

from dfir_triage_pipeline.model import Event


def make(**overrides) -> Event:
    defaults = {
        "timestamp": datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC),
        "source_artifact": "prefetch",
        "event_type": "process_exec",
        "action": "executed",
        "source_file": "Windows/Prefetch/NOTEPAD.EXE-A1B2C3D4.pf",
        "source_locator": "run_0",
        "timestamp_type": "last_run",
        "path": r"C:\Windows\System32\notepad.exe",
    }
    defaults.update(overrides)
    return Event(**defaults)


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        make(timestamp=datetime(2024, 1, 15, 12, 0, 0))


def test_offset_timestamp_rejected():
    plus3 = timezone(timedelta(hours=3))
    with pytest.raises(ValueError, match="UTC"):
        make(timestamp=datetime(2024, 1, 15, 12, 0, 0, tzinfo=plus3))


def test_invalid_confidence_rejected():
    with pytest.raises(ValueError, match="confidence"):
        make(confidence="certain")


def test_empty_source_locator_rejected():
    with pytest.raises(ValueError, match="provenance"):
        make(source_locator="")


def test_invalid_timestamp_type_rejected():
    with pytest.raises(ValueError, match="timestamp_type"):
        make(timestamp_type="observed")


def test_event_id_differs_when_timestamp_type_differs():
    """timestamp_type participates in the content hash: the same observation
    claimed as 'recorded' and as 'last_run' is not the same event."""
    assert make(timestamp_type="recorded").event_id != make(
        timestamp_type="last_run"
    ).event_id


def test_event_id_identical_for_identical_inputs():
    assert make().event_id == make().event_id


def test_event_id_differs_when_source_locator_differs():
    assert make(source_locator="run_0").event_id != make(source_locator="run_1").event_id


def test_event_id_unchanged_when_only_details_differ():
    a = make(details={"a": 1})
    b = make(details={"b": 2})
    assert a.event_id == b.event_id


def test_set_collapses_events_differing_only_in_details():
    a = make(details={"a": 1})
    b = make(details={"b": 2})
    assert len({a, b}) == 1
