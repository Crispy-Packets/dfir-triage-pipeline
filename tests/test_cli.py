from dfir_triage_pipeline.__main__ import main


def test_rejects_non_directory(tmp_path, capsys):
    bad = tmp_path / "nope"
    assert main([str(bad), "--output", str(tmp_path / "t.csv")]) == 2
    assert "not a directory" in capsys.readouterr().err


def test_empty_collection_still_writes_header(tmp_path):
    out = tmp_path / "out" / "timeline.csv"
    assert main([str(tmp_path), "--output", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("timestamp_utc,")