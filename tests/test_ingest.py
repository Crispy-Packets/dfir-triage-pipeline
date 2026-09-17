from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline.ingest import relative_posix


def test_relative_posix_uses_forward_slashes(tmp_path):
    target = tmp_path / "C" / "Windows" / "Prefetch" / "X.pf"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"")
    assert relative_posix(target, tmp_path) == "C/Windows/Prefetch/X.pf"


def test_unknown_files_are_skipped_not_failed(tmp_path):
    (tmp_path / "readme.txt").write_text("hello")
    events, stats = collect_events(tmp_path)
    assert events == []
    assert (stats.files_seen, stats.files_skipped, stats.files_failed) == (1, 1, 0)


def test_directories_are_not_counted_as_files(tmp_path):
    (tmp_path / "empty_dir").mkdir()
    _, stats = collect_events(tmp_path)
    assert stats.files_seen == 0