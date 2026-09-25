"""Open Person A's viewer on a finished run (`--view`).

The viewer is a separate component with its own venv (viewer/.venv, Streamlit
only) and imports nothing from this package; this module only starts it as a
separate process pointed at the run.json just written. The pipeline never
imports Streamlit, and a missing viewer never fails a run -- the run's outputs
are already on disk and hashed by the time this is called.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

VIEWER_DIR = Path(__file__).resolve().parent.parent / "viewer"


def viewer_python(viewer_dir: Path = VIEWER_DIR) -> Path | None:
    """The viewer venv's interpreter, or None if the venv was never created."""
    for rel in (Path(".venv") / "Scripts" / "python.exe", Path(".venv") / "bin" / "python"):
        candidate = viewer_dir / rel
        if candidate.is_file():
            return candidate
    return None


def viewer_command(run_json: Path, python: Path, viewer_dir: Path = VIEWER_DIR) -> list[str]:
    """`streamlit run app.py -- --run <run.json>`, as the viewer's README runs it."""
    return [
        str(python), "-m", "streamlit", "run", str(viewer_dir / "app.py"),
        "--", "--run", str(Path(run_json).resolve()),
    ]


def setup_hint(viewer_dir: Path = VIEWER_DIR) -> str:
    return (
        "viewer environment not found -- set it up once (needs internet, ~100 MB):\n"
        f"      double-click {viewer_dir / 'Start-Viewer.bat'}\n"
        "    then re-run with --view, or open the run from the viewer's sidebar."
    )


def launch(run_json: Path, viewer_dir: Path = VIEWER_DIR) -> str:
    """Start the viewer on `run_json` in its own console and return a status line.

    Never raises: a viewer that cannot start is reported, and the run -- already
    written and hashed -- stands.
    """
    python = viewer_python(viewer_dir)
    if python is None:
        return setup_hint(viewer_dir)
    kwargs: dict = {"cwd": str(viewer_dir)}
    if sys.platform == "win32":
        # Its own console window, so the viewer keeps serving after the pipeline
        # exits and Ctrl+C in the pipeline's window does not reach it.
        kwargs["creationflags"] = subprocess.CREATE_NEW_CONSOLE  # type: ignore[attr-defined]
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen(viewer_command(run_json, python, viewer_dir), **kwargs)
    except OSError as exc:
        return f"viewer could not start: {exc}"
    return "viewer starting in its own window -- http://localhost:8501 opens in your browser"
