r"""`$LogFile` and `$T` -- the two files I called unparseable without testing.

Both were dismissed on the strength of their first few bytes. Measured, both
hold evidence:

* `$LogFile` has 16,382 valid RCRD pages and names `invoice_scan_marker.txt`
* `$T` is Component Based Servicing XML naming a pending KB

What both tests pin hardest is the STATED LIMIT of each recovery, because both
parsers recover fragments rather than parsing structures, and a recovered
fragment presented as a parsed record would be a fabrication.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline.parsers.ntfs_logfile import (
    NtfsLogFileParser,
    _drop_suffix_fragments,
    apply_fixup,
    names_in_page,
)
from dfir_triage_pipeline.parsers.txf_pending import (
    TxfPendingParser,
    recoverable_text,
)

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")
LOGFILE_REL = "C/$LogFile"
TXF_REL = "C/$Extend/$RmMetadata/$TxfLog/$T"

needs_s1v3 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / LOGFILE_REL).is_file(),
    reason="s1_v3 $LogFile required",
)


def _page(name: str = "notes.txt", *, usn: bytes = b"\x07\x00", tear: bool = False) -> bytes:
    """A 4096-byte RCRD page carrying one $FILE_NAME-shaped record."""
    page = bytearray(4096)
    page[0:4] = b"RCRD"
    struct.pack_into("<HH", page, 4, 40, 9)  # usa offset, count
    struct.pack_into("<Q", page, 8, 1_987_906_640)  # lsn
    encoded = name.encode("utf-16-le")
    at = 100
    page[at] = len(name)
    page[at + 1] = 1  # WIN32 namespace
    page[at + 2 : at + 2 + len(encoded)] = encoded
    page[40:42] = usn
    for i in range(1, 9):
        end = i * 512 - 2
        page[40 + i * 2 : 42 + i * 2] = b"\xcc\xdd"
        page[end : end + 2] = b"\x00\x00" if tear else usn
    return bytes(page)


class TestLogFileFixup:
    def test_the_stashed_bytes_are_restored(self):
        fixed = apply_fixup(_page())
        assert fixed is not None
        assert fixed[510:512] == b"\xcc\xdd"

    def test_a_torn_page_is_rejected(self):
        """Captured mid-write: the sector's real contents are unknown, and
        guessing would fabricate a filename."""
        assert apply_fixup(_page(tear=True)) is None

    def test_short_input(self):
        assert apply_fixup(b"") is None
        assert apply_fixup(b"RCRD") is None


class TestNamesInPage:
    def test_a_name_is_found(self):
        assert "notes.txt" in names_in_page(apply_fixup(_page("notes.txt")))

    def test_a_run_without_an_extension_is_rejected(self):
        """A bare token with no dot and no separator is more often a
        coincidence than a filename."""
        assert names_in_page(apply_fixup(_page("plaintoken"))) == set()

    def test_a_page_of_zeros_yields_nothing(self):
        assert names_in_page(bytes(4096)) == set()


class TestSuffixFragments:
    def test_a_strict_suffix_is_dropped(self):
        """The length/namespace pair matches at many offsets inside a long
        name, so scanning one package name yields a dozen suffixes."""
        names = {
            "S-1-5-21-1591430865-807086247-2139423957-1000.pckgdep",
            "5-21-1591430865-807086247-2139423957-1000.pckgdep",
            "1000.pckgdep",
        }
        assert _drop_suffix_fragments(names) == {
            "S-1-5-21-1591430865-807086247-2139423957-1000.pckgdep"
        }

    def test_unrelated_names_all_survive(self):
        names = {"notes.txt", "todo.txt", "invoice_scan.exe"}
        assert _drop_suffix_fragments(names) == names

    def test_the_longest_wins_not_the_first(self):
        assert _drop_suffix_fragments({"b.txt", "ab.txt"}) == {"ab.txt"}

    def test_empty_input(self):
        assert _drop_suffix_fragments(set()) == set()


class TestLogFileCanHandle:
    def test_accepts_the_log(self):
        parser = NtfsLogFileParser()
        assert parser.can_handle("C/$LogFile")
        assert parser.can_handle("c\\$logfile")

    def test_rejects_other_metafiles(self):
        parser = NtfsLogFileParser()
        for name in ("C/$MFT", "C/$Boot", "C/$Extend/$J"):
            assert not parser.can_handle(name)


@needs_s1v3
class TestLogFileAgainstEvidence:
    @pytest.fixture(scope="class")
    def events(self):
        path = EVIDENCE / "collection_s1_v3" / LOGFILE_REL
        result = list(NtfsLogFileParser().parse(path, LOGFILE_REL))
        assert result, "parser produced no events"
        return result

    def test_the_scenario_files_are_recovered(self, events):
        """What made the dismissal wrong: the payload's marker file and its
        Prefetch record are both in the log."""
        names = {e.path for e in events}
        assert "invoice_scan_marker.txt" in names
        assert any("INVOICE_SCAN" in n for n in names)

    def test_every_event_carries_an_lsn(self, events):
        """The only ordering the log provides. Higher is more recent, and that
        is all it means."""
        assert all(e.details["lsn"].isdigit() for e in events)

    def test_timestamp_type_is_presence(self, events):
        """The log carries no wall-clock time at all -- only LSNs. Deriving a
        time from an LSN would be a fabrication."""
        assert all(e.timestamp_type == "presence" for e in events[:2000])

    def test_locators_are_unique(self, events):
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_the_fragment_limit_is_real_and_stated(self, events):
        """The parser's docstring states that a name MAY be a suffix of the
        real filename, because cross-page fragments survive. This asserts the
        limit still exists rather than pretending it was solved -- if it is
        ever genuinely fixed, this test should fail and be removed."""
        names = {e.path for e in events}
        suspicious = [n for n in names if n.startswith(("-", "1-5-", "5-21-"))]
        assert suspicious, "fragments are gone; update the docstring and this test"


class TestTxfRecovery:
    def test_framing_bytes_are_stripped(self):
        r"""TxF interleaves \x01\x00 mid-attribute: `Proces` + `rArchitecture`.
        290 pairs measured on s1_v3."""
        blob = b"<?xml version='1.0'?><a b=\"Proces\x01\x00rArchitecture\"/>"
        assert "ProcessorArchitecture" not in recoverable_text(blob)
        assert "ProcesrArchitecture" in recoverable_text(blob)

    def test_tabs_and_newlines_survive(self):
        blob = b"<?xml ?>\n\t<a/>"
        text = recoverable_text(blob)
        assert "\n" in text and "\t" in text

    def test_a_file_with_no_xml_yields_nothing(self):
        assert recoverable_text(b"\x00" * 500) == ""

    def test_can_handle(self):
        parser = TxfPendingParser()
        assert parser.can_handle(TXF_REL)
        assert not parser.can_handle("C/$Extend/$J")
        assert not parser.can_handle("C/$MFT")


@needs_s1v3
class TestTxfAgainstEvidence:
    def test_the_pending_update_is_recovered(self):
        """Measured: 1 transaction, 47 component changes, 2 installs on
        s1_v3 -- and ZERO on every other collection, so the family
        discriminates rather than firing everywhere."""
        path = EVIDENCE / "collection_s1_v3" / TXF_REL
        if not path.is_file():
            pytest.skip("$T absent")
        events = list(TxfPendingParser().parse(path, TXF_REL))
        assert events
        kinds = Counter_of(events)
        assert kinds["servicing_pending"] >= 1
        assert kinds["component_version_change"] >= 10
        assert any("KB" in str(e.path) for e in events)

    def test_version_changes_carry_both_versions(self):
        path = EVIDENCE / "collection_s1_v3" / TXF_REL
        if not path.is_file():
            pytest.skip("$T absent")
        changes = [
            e
            for e in TxfPendingParser().parse(path, TXF_REL)
            if e.event_type == "component_version_change"
        ]
        assert changes
        for event in changes:
            assert event.details["version_old"]
            assert event.details["version_new"]

    @pytest.mark.parametrize(
        "collection", ["collection_clean_a", "collection_clean_b", "collection_clean_c"]
    )
    def test_clean_collections_have_no_pending_servicing(self, collection):
        """The discrimination, stated as a measurement rather than assumed."""
        path = EVIDENCE / collection / TXF_REL
        if not path.is_file():
            pytest.skip(f"{collection} $T absent")
        assert list(TxfPendingParser().parse(path, TXF_REL)) == []

    def test_no_parse_failures_in_a_full_run(self):
        _, stats = collect_events(EVIDENCE / "collection_s1_v3")
        offenders = [
            f for f in stats.failures if f[0] in ("ntfs_logfile", "txf_pending")
        ]
        assert offenders == []


def Counter_of(events):
    from collections import Counter

    return Counter(e.event_type for e in events)
