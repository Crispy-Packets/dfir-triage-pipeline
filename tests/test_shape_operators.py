"""The `is_user_writable` shape operator (2026-09-13).

Added because a rule could previously only ask whether a path matched a regex,
which forced R-CORR-0003 to treat `C:\\Users\\...\\Downloads\\invoice_scan.exe`
and `C:\\Program Files (x86)\\...\\msedge.exe` identically -- firing five times
at critical severity on a collection containing no attack.

The property that matters most here is the ORDERING: system locations are
tested before user-writable ones, so a Program Files path that happens to
contain the substring "users" is not called user-writable. Get that backwards
and the operator returns a plausible answer on every path while quietly
promoting system binaries.
"""

from __future__ import annotations

import pytest

from dfir_triage_pipeline.core.engine import _is_user_writable, evaluate_condition
from dfir_triage_pipeline.core.ruleset import Condition


class _Event:
    def __init__(self, path: str | None) -> None:
        self.path = path
        self.details: dict[str, str] = {}


def _cond(value: bool = True, field: str = "path") -> Condition:
    return Condition(field=field, op="is_user_writable", value=value)


class TestIsUserWritable:
    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Users\vboxuser\Downloads\invoice_scan.exe",
            r"C:\Users\vboxuser\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
            r"C:\ProgramData\vendor\updater.exe",
            r"C:\Users\Public\shared.exe",
            r"%APPDATA%\thing.exe",
            r"%LOCALAPPDATA%\thing.exe",
            r"%TEMP%\thing.exe",
            r"%USERPROFILE%\thing.exe",
        ],
    )
    def test_user_writable_locations(self, path: str) -> None:
        assert _is_user_writable(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\VideoLAN\VLC\vlc.exe",
            r"C:\Windows\System32\svchost.exe",
            r"%SystemRoot%\system32\SecurityHealthSystray.exe",
            r"%ProgramFiles%\vendor\app.exe",
            r"%windir%\system32\cmd.exe",
        ],
    )
    def test_system_locations(self, path: str) -> None:
        assert _is_user_writable(path) is False

    def test_system_wins_over_a_users_substring(self) -> None:
        """The ordering test. `Common Files\\Users Guide\\` contains "users"
        but the path is under Program Files and only an administrator can write
        there. Checking user-writable markers first would call this writable."""
        assert _is_user_writable(r"C:\Program Files\Common Files\Users Guide\x.exe") is False

    def test_forward_slashes_are_normalised(self) -> None:
        assert _is_user_writable("C:/Users/vboxuser/Downloads/x.exe") is True

    def test_case_is_folded(self) -> None:
        assert _is_user_writable(r"C:\USERS\VBOXUSER\DOWNLOADS\X.EXE") is True

    def test_empty_is_not_writable(self) -> None:
        """An absent path is not evidence of a writable location."""
        assert _is_user_writable("") is False

    def test_a_bare_command_line_is_not_writable(self) -> None:
        """Autorun values are often command lines with no directory at all."""
        assert _is_user_writable("rundll32.exe shell32.dll,Control_RunDLL") is False


class TestOperatorInConditions:
    def test_true_matches_a_writable_path(self) -> None:
        event = _Event(r"C:\Users\vboxuser\Downloads\invoice_scan.exe")
        assert evaluate_condition(event, _cond(True)) is True

    def test_true_rejects_a_system_path(self) -> None:
        event = _Event(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
        assert evaluate_condition(event, _cond(True)) is False

    def test_false_inverts(self) -> None:
        """`value: false` asserts the path is NOT user-writable, which is how a
        rule would look for something running from a system location."""
        system = _Event(r"C:\Windows\System32\svchost.exe")
        user = _Event(r"C:\Users\vboxuser\Downloads\x.exe")
        assert evaluate_condition(system, _cond(False)) is True
        assert evaluate_condition(user, _cond(False)) is False

    def test_absent_field_is_false_not_an_error(self) -> None:
        """Consistent with every other operator: an absent field does not match.

        If this returned True for `value: false`, a parser that emits no path
        would satisfy "not user-writable" and absence would become evidence.
        """
        event = _Event(None)
        assert evaluate_condition(event, _cond(True)) is False
        assert evaluate_condition(event, _cond(False)) is False


class TestValidatorAcceptsIt:
    def test_operator_is_declared(self) -> None:
        import importlib.util
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "validate_rules", Path(__file__).resolve().parent.parent / "rules" / "validate_rules.py"
        )
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)

        assert "is_user_writable" in mod.OPERATORS
        assert "is_user_writable" in mod.SHAPE_OPS
        # Not case-insensitive: it folds internally, so `ci` would be meaningless.
        assert "is_user_writable" not in mod.CI_OPS
        # Both host-2 collections must be declarable in an expected: block.
        assert "clean_c" in mod.COLLECTIONS
        assert "s1_v3" in mod.COLLECTIONS
