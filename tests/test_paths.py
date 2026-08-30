"""Derived path fields (B-9).

The rule under test throughout: a derived field is emitted only when it can be
computed from what the artifact recorded. Where it cannot, the field is absent
rather than guessed -- a consumer can detect an absent field and fall back to
`path`, but has no way to detect a wrong one.
"""

import os
from pathlib import Path

import pytest

from dfir_triage_pipeline.ingest import collect_events
from dfir_triage_pipeline.paths import (
    derive,
    looks_like_command_line,
    path_basename,
    path_canonical,
)


class TestCanonical:
    def test_case_is_folded(self):
        """The reason B-9 exists: Amcache lowercases what it stores, the EVTX
        channels keep the OS casing, and 86 paths in the corpus differ from
        another path by case alone."""
        a = path_canonical(r"C:\Program Files\7-Zip\7z.exe")
        b = path_canonical(r"c:\program files\7-zip\7z.exe")
        assert a == b == r"c:\program files\7-zip\7z.exe"

    def test_forward_slashes_normalised(self):
        """Registry values are written by hand and are not guaranteed to use
        the Windows separator."""
        assert path_canonical("C:/Windows/System32/cmd.exe") == r"c:\windows\system32\cmd.exe"

    @pytest.mark.parametrize(
        "value,why",
        [
            (r"C:\Windows\system32\cmd.exe /q /c del", "command line"),
            (r'"C:\Program Files\App\a.exe" -background', "quoted command line"),
            (r"\Device\HarddiskVolume2\kape\kape.exe", "drive unknown without the volume serial"),
            (r"%SystemRoot%\system32\svchost.exe", "expansion is not recorded by the artifact"),
        ],
    )
    def test_omitted_when_it_would_have_to_be_invented(self, value, why):
        assert path_canonical(value) is None, why


class TestBasename:
    def test_case_preserved(self):
        """path_basename keeps what the artifact recorded; the lowercased form
        is a separate field, so both are available."""
        assert path_basename(r"C:\Users\janed\Downloads\Invoice_Scan.exe") == "Invoice_Scan.exe"

    def test_absent_when_there_is_nothing_to_extract(self):
        """Prefetch stores a bare name, which is already its own basename.
        Emitting a derived field identical to the input would imply a
        normalisation step that did not happen."""
        assert path_basename("INVOICE_SCAN.EXE") is None

    def test_trailing_separator_does_not_produce_an_empty_name(self):
        assert path_basename(r"C:\Windows\System32\\") == "System32"


class TestCommandLineDetection:
    @pytest.mark.parametrize(
        "value",
        [
            r'"C:\Program Files\Microsoft\OneDrive\OneDrive.exe" /background',
            r"C:\Windows\system32\cmd.exe /q /c del /q file",
            r"%SystemRoot%\system32\svchost.exe -k print",
        ],
    )
    def test_command_lines_recognised(self, value):
        assert looks_like_command_line(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            r"C:\Program Files\7-Zip\7z.exe",
            r"c:\program files (x86)\microsoft sdks\windows\bin\netfx 4.8 tools\al.exe",
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            "INVOICE_SCAN.EXE",
            r"system32\DRIVERS\RsFx0800.sys",
        ],
    )
    def test_paths_with_spaces_are_not_command_lines(self, value):
        """The hard case. "Program Files" contains a space and is a path;
        "cmd.exe /q" contains a space and is not. Getting this wrong would
        discard derived fields for the 965 evtx.security and 743 amcache rows
        whose paths merely live under Program Files."""
        assert looks_like_command_line(value) is False


class TestDerive:
    def test_command_line_gets_nothing_at_all(self):
        """Not even a basename: the trailing token of a command line is an
        argument, not a filename. CD-021 and D-032."""
        assert derive(r"C:\Windows\system32\cmd.exe /q /c del /q x") == {}

    def test_bare_name_still_gets_a_join_key(self):
        """Prefetch carries no path, so this is the only field by which an
        execution recorded there can be matched to a full path recorded
        elsewhere. Gating it on path_basename would defeat B-9 for the one
        artifact that needs it most."""
        out = derive("INVOICE_SCAN.EXE")
        assert out["path_basename_canonical"] == "invoice_scan.exe"
        assert "path_basename" not in out

    def test_device_path_keeps_the_basename_it_can_prove(self):
        """The drive is unknown, but the filename is not. Withholding the
        basename because the full path is unresolvable would discard a fact the
        artifact did record."""
        out = derive(r"\Device\HarddiskVolume2\kape\KAPE\kape.exe")
        assert out["path_basename"] == "kape.exe"
        assert "path_canonical" not in out

    def test_empty_and_none_are_safe(self):
        assert derive(None) == {}
        assert derive("") == {}
        assert derive("   ") == {}

    @pytest.mark.parametrize("root", ["C:\\", "C:", "\\", "\\\\", "/", "c:/"])
    def test_root_only_paths_yield_nothing(self, root):
        """A root names a directory, not a file, and every consumer of these
        fields is asking about a binary. Without this a drive root would enter
        the pipeline as a canonical path carrying no join key.

        Found by probing inputs the corpus does not contain -- zero occurrences
        in all three collections -- but a Startup folder entry or a directory
        ImagePath would produce one, and the failure would be silent."""
        assert derive(root) == {}

    def test_unc_paths_are_handled(self):
        """No drive letter, but a real resolvable location. Not in this
        corpus; a domain-joined host would produce them constantly.
        """
        unc = r"\\fileserver\share\tool.exe"
        out = derive(unc)
        assert out["path_basename"] == "tool.exe"
        assert out["path_canonical"] == unc.lower()

    def test_unicode_paths_survive_canonicalisation(self):
        """Amcache lowercases with OS rules and Python with its own. They
        need not agree on every script, but neither may raise nor corrupt.
        """
        name = "Str\u00f6m.exe"
        out = derive(f"C:\\Users\\\u00dcn\u00efcode\\{name}")
        assert out["path_basename"] == name
        assert out["path_basename_canonical"] == name.lower()


COLLECTION = os.environ.get("DFIR_TEST_COLLECTION")


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
class TestAgainstRealEvidence:
    @staticmethod
    def _events():
        return collect_events(Path(COLLECTION))[0]

    def test_original_path_is_never_modified(self):
        """CD-010 is the contract B-9 must not break. The derived fields are
        additions; if any parser had overwritten `path` with its canonical form
        this would catch it."""
        checked = 0
        for e in self._events():
            if e.path and "path_canonical" in e.details:
                if e.path != e.path.lower():
                    assert e.details["path_canonical"] != e.path
                    checked += 1
        # Without this the test passes when the parsers emit nothing, which is
        # how D-035 hid a broken registry behind a green suite.
        assert checked > 100, (
            f"only {checked} mixed-case paths examined; the parsers are not "
            "producing what this test claims to check"
        )

    def test_derived_fields_are_present_on_almost_every_path(self):
        """Coverage should be near-total. If it drops sharply, either a parser
        stopped calling derive() or the command-line heuristic became too
        eager and started discarding real paths."""
        events = self._events()
        with_path = [e for e in events if e.path]
        if not with_path:
            pytest.skip("no paths in this collection")
        canonical = [e for e in with_path if "path_canonical" in e.details]
        assert len(canonical) / len(with_path) > 0.98

    def test_no_canonical_field_for_any_service_install(self):
        """CD-021: these carry command lines, not paths. Emitting a canonical
        form for them would join unrelated records."""
        checked = 0
        for e in self._events():
            if e.event_type == "service_install" and e.path:
                if looks_like_command_line(e.path):
                    assert "path_canonical" not in e.details
                    checked += 1
        # Every collection carries exactly ten command-line service rows
        # (CD-021, D-032). A drop to zero means the parser stopped, not that
        # the contract started holding.
        assert checked == 10, (
            f"expected 10 command-line service_install rows, examined {checked}"
        )


@pytest.mark.skipif(not COLLECTION, reason="DFIR_TEST_COLLECTION not set")
def test_scenario_chain_joins_on_one_key():
    """What B-9 is for, end to end.

    The Scenario 1 binary is recorded by three artifact families that describe
    it three different ways: Edge history holds a full path, Prefetch holds a
    bare uppercase name and no path at all, and the registry holds an autorun
    value. Before B-9 no single field joined them. After it, one does.
    """
    if "s1_v2" not in str(COLLECTION):
        pytest.skip("assertion is about the scenario collection")

    hits = [
        e
        for e in collect_events(Path(COLLECTION))[0]
        if e.details.get("path_basename_canonical") == "invoice_scan.exe"
    ]
    families = {e.source_artifact for e in hits}
    assert {"browser", "prefetch", "registry"} <= families

    # The execution and the persistence must both be reachable by this key.
    assert any(e.event_type == "process_exec" for e in hits)
    assert any(e.event_type == "persistence_autorun" for e in hits)
