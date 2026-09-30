"""JumpLists: which application opened a file.

The property that would silently produce an empty family: the two extensions
sitting in one directory are DIFFERENT FILE FORMATS. automaticDestinations is
an OLE compound file; customDestinations is not one, despite the neighbouring
files and the similar extension. A parser that assumes OLE for both finds no
header on the second and yields nothing, with no error.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.jumplist import (
    JumpListParser,
    _embedded_links,
    app_id_of,
)

EVIDENCE = Path.home() / "dfir-evidence"
RECENT = "C/Users/vboxuser/AppData/Roaming/Microsoft/Windows/Recent"

needs_collection = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / RECENT).is_dir(),
    reason="s1_v3 Recent directory required",
)

LINK_CLSID = bytes(
    (
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    )
)


def _link(path: str) -> bytes:
    """A minimal valid shell link with a relative path."""
    blob = bytearray(76)
    struct.pack_into("<I", blob, 0, 0x4C)
    blob[4:20] = LINK_CLSID
    struct.pack_into("<II", blob, 20, 0x80 | 0x08, 0)
    encoded = path.encode("utf-16-le")
    return bytes(blob) + struct.pack("<H", len(path)) + encoded


class TestAppId:
    def test_the_stem_is_the_app_id(self):
        name = "5f7b5f1e01b83767.automaticDestinations-ms"
        assert app_id_of(f"{RECENT}/AutomaticDestinations/{name}") == "5f7b5f1e01b83767"

    def test_backslash_paths(self):
        assert app_id_of("a\\b\\ccba5a5986c77e43.customDestinations-ms") == (
            "ccba5a5986c77e43"
        )


class TestEmbeddedLinks:
    def test_finds_concatenated_links(self):
        """The customDestinations format: links one after another with no
        container structure."""
        blob = b"\x02\x00\x00\x00" + _link("..\\a.txt") + _link("..\\b.txt")
        found = list(_embedded_links(blob))
        assert len(found) == 2
        assert found[0][1]["relative_path"] == "..\\a.txt"
        assert found[1][1]["relative_path"] == "..\\b.txt"

    def test_a_bare_signature_is_not_accepted(self):
        """Four bytes of `4C 00 00 00` occur in ordinary data. The candidate
        must also carry the 16-byte link CLSID, which parse_lnk verifies."""
        blob = b"\x00" * 32 + b"\x4c\x00\x00\x00" + b"\xff" * 80
        assert list(_embedded_links(blob)) == []

    def test_offsets_are_where_the_links_start(self):
        prefix = b"\x02\x00\x00\x00"
        first = _link("..\\a.txt")
        blob = prefix + first + _link("..\\b.txt")
        found = list(_embedded_links(blob))
        assert found[0][0] == len(prefix)
        assert found[1][0] == len(prefix) + len(first)

    def test_empty_and_garbage_input(self):
        assert list(_embedded_links(b"")) == []
        assert list(_embedded_links(b"\x00" * 500)) == []

    def test_a_truncated_trailing_link_is_skipped(self):
        """parse_lnk bounds-checks, so a fragment yields no event rather than
        a wrong one."""
        blob = b"\x02\x00\x00\x00" + _link("..\\a.txt") + b"\x4c\x00\x00\x00" + b"\x01"
        found = list(_embedded_links(blob))
        assert len(found) == 1


class TestCanHandle:
    def test_accepts_both_formats(self):
        parser = JumpListParser()
        assert parser.can_handle("x/5f7b5f1e01b83767.automaticDestinations-ms")
        assert parser.can_handle("x/590aee7bdd69b59b.customDestinations-ms")
        assert parser.can_handle("X/ABC.AUTOMATICDESTINATIONS-MS")

    def test_rejects_plain_links_and_others(self):
        parser = JumpListParser()
        assert not parser.can_handle("x/foo.lnk")
        assert not parser.can_handle("C/Windows/System32/config/SAM")


@needs_collection
class TestAgainstRealJumpLists:
    @pytest.fixture(scope="class")
    def events(self):
        parser = JumpListParser()
        root = EVIDENCE / "collection_s1_v3"
        result = []
        for path in sorted(root.rglob("*Destinations-ms")):
            rel = path.relative_to(root).as_posix()
            result.extend(parser.parse(path, rel))
        assert result, "parser produced no events; tests would pass vacuously"
        return result

    def test_both_container_formats_produce_events(self, events):
        """The regression guard for the OLE assumption. If customDestinations
        were treated as OLE, this set would hold only 'automatic'."""
        kinds = {e.details["jumplist_type"] for e in events}
        assert kinds == {"automatic", "custom"}

    def test_every_event_names_an_application(self, events):
        """The family's reason to exist."""
        assert all(e.details["app_id"] for e in events)
        assert len({e.details["app_id"] for e in events}) >= 3

    def test_locators_are_unique_within_each_file(self, events):
        by_file: dict[str, list[str]] = {}
        for event in events:
            by_file.setdefault(event.source_file, []).append(event.source_locator)
        for locators in by_file.values():
            assert len(locators) == len(set(locators))

    def test_timestamp_type_is_presence(self, events):
        assert all(e.timestamp_type == "presence" for e in events)

    def test_family_and_event_type(self, events):
        assert {e.source_artifact for e in events} == {"jumplist"}
        assert {e.event_type for e in events} == {"file_opened"}

    def test_paths_are_never_empty(self, events):
        assert all(e.path and e.path.strip() for e in events)


class TestAcrossCollections:
    @pytest.mark.parametrize(
        "collection,minimum",
        [
            ("collection_clean_a", 40),
            ("collection_clean_b", 40),
            ("collection_s1_v2", 70),
            ("collection_clean_c", 25),
            ("collection_s1_v3", 25),
        ],
    )
    def test_each_collection_yields_events(self, collection, minimum):
        """Measured 2026-09-17 as 59/62/90/32/34; lower bounds because these
        change with ordinary use."""
        root = EVIDENCE / collection
        if not root.is_dir():
            pytest.skip(f"{collection} not present")
        parser = JumpListParser()
        events = []
        for path in root.rglob("*Destinations-ms"):
            events.extend(parser.parse(path, path.relative_to(root).as_posix()))
        assert len(events) >= minimum

    def test_s1v2_jumplists_carry_removable_media(self):
        """JumpLists record the transfer volume independently of the Recent
        LNKs -- a second family attesting to a device not in the image."""
        root = EVIDENCE / "collection_s1_v2"
        if not root.is_dir():
            pytest.skip("collection_s1_v2 not present")
        parser = JumpListParser()
        removable = []
        for path in root.rglob("*Destinations-ms"):
            for event in parser.parse(path, path.relative_to(root).as_posix()):
                if event.details.get("drive_type") == "removable":
                    removable.append(event)
        assert removable
