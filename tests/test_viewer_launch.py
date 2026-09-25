"""`--view`: the pipeline opens the viewer on the run it just wrote.

Nothing here starts Streamlit. The command is built and checked; launching with
no viewer environment must report, not raise, because the run is already
written and hashed by then.
"""

from __future__ import annotations

import pytest

from dfir_triage_pipeline import viewer_launch
from dfir_triage_pipeline.__main__ import build_parser, main


def test_command_opens_the_given_run(tmp_path):
    run = tmp_path / "run.json"
    run.write_text("{}", encoding="utf-8")
    py = tmp_path / "python.exe"
    cmd = viewer_launch.viewer_command(run, py, viewer_dir=tmp_path)
    assert cmd[:4] == [str(py), "-m", "streamlit", "run"]
    assert cmd[4] == str(tmp_path / "app.py")
    assert cmd[-3:] == ["--", "--run", str(run.resolve())]


def test_missing_viewer_environment_is_reported_not_raised(tmp_path):
    assert viewer_launch.viewer_python(tmp_path) is None
    status = viewer_launch.launch(tmp_path / "run.json", viewer_dir=tmp_path)
    assert "viewer environment not found" in status
    assert "Start-Viewer.bat" in status


def test_viewer_python_is_found_when_the_venv_exists(tmp_path):
    exe = tmp_path / ".venv" / "Scripts" / "python.exe"
    exe.parent.mkdir(parents=True)
    exe.write_text("", encoding="utf-8")
    assert viewer_launch.viewer_python(tmp_path) == exe


def test_view_flag_defaults_off():
    args = build_parser().parse_args(["somewhere", "--output", "t.csv"])
    assert args.view is False


def test_view_without_run_json_is_refused(tmp_path, capsys):
    with pytest.raises(SystemExit):
        main([str(tmp_path), "--output", str(tmp_path / "t.csv"), "--view"])
    assert "--view needs --run-json" in capsys.readouterr().err


def test_the_launcher_script_ships_with_the_viewer():
    bat = viewer_launch.VIEWER_DIR / "Start-Viewer.bat"
    assert bat.is_file()
    text = bat.read_text(encoding="utf-8")
    assert "py -3.11 -m venv .venv" in text
    assert "requirements.txt" in text
