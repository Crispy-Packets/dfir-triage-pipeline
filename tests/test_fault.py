from collections.abc import Iterator
from pathlib import Path

import pytest

from dfir_triage_pipeline import parsers
from dfir_triage_pipeline.ingest import collect_events
from dfir_triage_pipeline.model import Event


@pytest.fixture
def raising_parser():
    """Inject a parser that always raises, then remove it.

    The registry is module-level global state. Without the teardown, this parser
    leaks into every test that runs afterwards.
    """

    class RaisingParser:
        name = "raiser"

        def can_handle(self, relative_path: str) -> bool:
            return relative_path.endswith(".boom")

        def parse(self, abs_path: Path, relative_path: str) -> Iterator[Event]:
            raise EOFError("truncated")
            yield  # unreachable, but makes this a generator function

    injected = RaisingParser()
    parsers._REGISTRY.append(injected)
    yield
    # Remove only what was injected. clear() emptied the whole registry, so
    # every collection-backed test running afterwards saw zero parsers and
    # silently produced zero events -- a passing test that asserted nothing.
    parsers._REGISTRY.remove(injected)


def test_raising_parser_does_not_end_the_run(tmp_path, raising_parser):
    (tmp_path / "good.txt").write_text("x")
    (tmp_path / "bad.boom").write_text("x")

    events, stats = collect_events(tmp_path)

    assert stats.files_seen == 2
    assert stats.files_failed == 1
    assert stats.files_skipped == 1
    assert events == []

    name, rel, err = stats.failures[0]
    assert name == "raiser"
    assert rel == "bad.boom"
    assert "EOFError" in err