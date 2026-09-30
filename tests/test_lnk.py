"""Shell links: a path, a volume, and the target's own timestamps.

Every section after the 76-byte header is length-prefixed and positioned
relative to the one before it, so a single mis-sized field shifts everything
after it and the parser emits plausible strings read out of the middle of other
structures -- without raising. The two specific traps are pinned here:

* StringData counts CHARACTERS, not bytes;
* LinkInfo offsets are relative to the LinkInfo structure, not to the file.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.lnk import (
    LnkParser,
    filetime_to_utc,
    is_shell_link,
    parse_lnk,
)

EVIDENCE = Path.home() / "dfir-evidence"
LINK_CLSID = bytes(
    (
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    )
)

needs_host1 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v2").is_dir(),
    reason="collection_s1_v2 is required",
)
needs_host2 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3").is_dir(),
    reason="collection_s1_v3 is required",
)


def _ticks(when: datetime) -> int:
    return 116444736000000000 + int(when.timestamp() * 10_000_000)


def _header(*, flags: int = 0x80, created: int = 0, modified: int = 0, size: int = 0) -> bytes:
    blob = bytearray(76)
    struct.pack_into("<I", blob, 0, 0x4C)
    blob[4:20] = LINK_CLSID
    struct.pack_into("<II", blob, 20, flags, 0)
    struct.pack_into("<QQQ", blob, 28, created, 0, modified)
    struct.pack_into("<I", blob, 52, size)
    return bytes(blob)


def _string_data(text: str, *, wide: bool = True) -> bytes:
    """A StringData section: a CHARACTER count, then that many code units."""
    encoded = text.encode("utf-16-le" if wide else "latin-1")
    return struct.pack("<H", len(text)) + encoded


class TestIsShellLink:
    def test_accepts_a_real_header(self):
        assert is_shell_link(_header())

    def test_rejects_a_wrong_clsid(self):
        """Header size 76 is not enough; the CLSID is constant for every shell
        link ever written and a different one is a different format."""
        blob = bytearray(_header())
        blob[4] = 0xFF
        assert not is_shell_link(bytes(blob))

    def test_rejects_a_wrong_signature(self):
        blob = bytearray(_header())
        struct.pack_into("<I", blob, 0, 0x50)
        assert not is_shell_link(bytes(blob))

    def test_rejects_short_input(self):
        assert not is_shell_link(b"")
        assert not is_shell_link(_header()[:75])


class TestFiletime:
    def test_zero_is_not_a_time(self):
        """A LNK writes zero for 'not recorded', measured on Recent links whose
        targets were already gone."""
        assert filetime_to_utc(0) is None

    def test_real_value_converts(self):
        when = datetime(2026, 8, 23, 23, 19, 52, tzinfo=UTC)
        result = filetime_to_utc(_ticks(when))
        assert result is not None
        assert (result.year, result.month, result.day) == (2026, 8, 23)

    def test_negative_and_absurd_do_not_raise(self):
        assert filetime_to_utc(-1) is None
        assert filetime_to_utc(2**63 - 1) is None

    def test_bool_is_not_a_time(self):
        assert filetime_to_utc(True) is None


class TestStringDataWidth:
    def test_character_count_is_doubled_for_unicode(self):
        """THE trap. A count of 5 means 10 bytes on a Unicode link; reading it
        as 5 leaves every later section starting mid-string."""
        blob = _header(flags=0x80 | 0x08) + _string_data("..\\abc")
        record = parse_lnk(blob)
        assert record["relative_path"] == "..\\abc"

    def test_two_consecutive_sections_stay_in_step(self):
        """If the first section's width is wrong, the second is garbage. This
        is the assertion that would catch it."""
        flags = 0x80 | 0x08 | 0x10 | 0x20
        blob = (
            _header(flags=flags)
            + _string_data("..\\Downloads\\Files.zip")
            + _string_data("C:\\Users\\janed")
            + _string_data("-silent -x")
        )
        record = parse_lnk(blob)
        assert record["relative_path"] == "..\\Downloads\\Files.zip"
        assert record["working_dir"] == "C:\\Users\\janed"
        assert record["arguments"] == "-silent -x"

    def test_a_section_running_past_the_end_stops_the_parse(self):
        """Rather than decoding whatever follows. The header fields already
        read are kept: a truncated link still attests to its header."""
        blob = _header(flags=0x80 | 0x08, size=4096) + struct.pack("<H", 500) + b"AB"
        record = parse_lnk(blob)
        assert record is not None
        assert "relative_path" not in record
        assert record["target_size"] == 4096


class TestHeaderFields:
    def test_timestamps_and_size(self):
        created = datetime(2026, 8, 20, 15, 31, 9, tzinfo=UTC)
        modified = datetime(2026, 8, 23, 23, 19, 52, tzinfo=UTC)
        record = parse_lnk(
            _header(created=_ticks(created), modified=_ticks(modified), size=13354)
        )
        assert record["target_created"].day == 20
        assert record["target_modified"].day == 23
        assert record["target_size"] == 13354

    def test_zero_timestamps_become_none_not_1601(self):
        record = parse_lnk(_header(created=0, modified=0))
        assert record["target_created"] is None
        assert record["target_modified"] is None

    def test_a_non_link_returns_none(self):
        assert parse_lnk(b"not a link") is None
        assert parse_lnk(b"") is None


class TestCanHandle:
    def test_accepts_lnk_files(self):
        parser = LnkParser()
        assert parser.can_handle("C/Users/janed/AppData/Roaming/Microsoft/Windows/Recent/x.lnk")
        assert parser.can_handle("C/Users/Public/Desktop/VLC media player.LNK")

    def test_rejects_other_extensions(self):
        parser = LnkParser()
        assert not parser.can_handle("C/Windows/System32/config/SAM")
        assert not parser.can_handle("x.automaticDestinations-ms")


@needs_host1
class TestAgainstRealLinks:
    @pytest.fixture(scope="class")
    def events(self):
        parser = LnkParser()
        root = EVIDENCE / "collection_s1_v2"
        result = []
        for path in sorted(root.rglob("*.lnk")):
            rel = path.relative_to(root).as_posix()
            result.extend(parser.parse(path, rel))
        assert result, "parser produced no events; the tests would pass vacuously"
        return result

    def test_no_file_raises_across_every_collection(self):
        """256 links, five collections. The offset arithmetic must stay in
        bounds on all of them, because an overrun yields strings rather than
        an exception."""
        parser = LnkParser()
        total = 0
        for collection in (
            "collection_clean_a",
            "collection_clean_b",
            "collection_s1_v2",
            "collection_clean_c",
            "collection_s1_v3",
        ):
            root = EVIDENCE / collection
            if not root.is_dir():
                continue
            for path in root.rglob("*.lnk"):
                total += 1
                list(parser.parse(path, path.relative_to(root).as_posix()))
        assert total >= 250

    def test_recent_and_installed_are_distinguished(self, events):
        """An installed Start Menu link is not evidence anyone used anything."""
        locations = {e.details["lnk_location"] for e in events}
        assert locations == {"recent", "installed"}

    def test_paths_are_absolute_or_relative_never_empty(self, events):
        for event in events:
            assert event.path
            assert event.path.strip()

    def test_volume_serials_are_eight_hex_digits(self, events):
        serials = {e.details["volume_serial"] for e in events if "volume_serial" in e.details}
        assert serials
        for serial in serials:
            assert len(serial) == 8
            int(serial, 16)

    def test_timestamp_type_is_presence(self, events):
        """The times describe the TARGET, copied into the link. The OS logged
        no event at that instant."""
        assert all(e.timestamp_type == "presence" for e in events)

    def test_target_times_are_details_not_only_the_timestamp(self, events):
        dated = [e for e in events if "target_modified" in e.details]
        assert dated
        for event in dated:
            assert event.details["target_modified"].endswith("Z")

    def test_every_event_carries_provenance(self, events):
        for event in events:
            assert event.source_file.lower().endswith(".lnk")
            assert event.source_locator

    def test_family_and_event_type(self, events):
        assert {e.source_artifact for e in events} == {"lnk"}
        assert {e.event_type for e in events} == {"file_opened"}

    def test_protocol_links_yield_nothing(self):
        """`ms-settings:` and `ms-gamingoverlay:` links name a URI handler
        rather than a file, and carry no path at all."""
        parser = LnkParser()
        root = EVIDENCE / "collection_s1_v2"
        protocol = [p for p in root.rglob("*.lnk") if p.name.startswith("ms-")]
        if not protocol:
            pytest.skip("no protocol links in this collection")
        for path in protocol:
            assert list(parser.parse(path, path.relative_to(root).as_posix())) == []


@needs_host1
class TestTheRemovableMediaResult:
    """CD-013 reopened, and measured: a volume named by LNK and by nothing
    else in the entire pipeline."""

    def test_a_removable_volume_is_recorded_on_s1v2(self):
        parser = LnkParser()
        root = EVIDENCE / "collection_s1_v2"
        events = []
        for path in root.rglob("*.lnk"):
            events.extend(parser.parse(path, path.relative_to(root).as_posix()))

        removable = [e for e in events if e.details.get("drive_type") == "removable"]
        assert removable, "no removable-media link found"
        assert {e.details["volume_serial"] for e in removable} == {"18334A83"}
        assert {e.details.get("volume_label") for e in removable} == {"JOE"}

    def test_only_the_link_families_name_that_volume(self):
        """The claim that makes this worth parsing.

        AMENDED 2026-09-17: when this test was written `lnk` was the sole
        record, and the assertion was that NO other family named the volume.
        The JumpList parser landed the same day and reads embedded shell links,
        so it names it too -- and this test caught that, which is why it is
        corrected rather than deleted.

        The claim that survives is the one that mattered: only artefacts built
        from shell links carry the volume at all. Every OTHER family in the
        pipeline -- prefetch, amcache, srum, the event logs, the hives -- is
        silent about a device that was attached to this machine.
        """
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v2")
        naming = {
            e.source_artifact
            for e in events
            if "18334a83" in str(e.details).lower()
        }
        assert naming == {"lnk", "jumplist"}

    def test_jumplists_reveal_paths_the_recent_links_do_not(self):
        """Measured: the LNKs record two paths on that volume, the JumpLists
        six. `E:\collection_s1`, `E:\collection_clean_a`,
        `E:\collection_clean_b` and `E:\handoff` appear in no Recent link --
        the removable drive held earlier collection data, and only the
        application's own history records it."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v2")
        on_volume = [
            e for e in events if "18334a83" in str(e.details).lower()
        ]
        lnk_paths = {e.path for e in on_volume if e.source_artifact == "lnk"}
        jl_paths = {e.path for e in on_volume if e.source_artifact == "jumplist"}
        assert jl_paths - lnk_paths

    @pytest.mark.parametrize(
        "collection",
        ["collection_clean_a", "collection_clean_b", "collection_clean_c", "collection_s1_v3"],
    )
    def test_the_volume_appears_in_no_other_collection(self, collection):
        root = EVIDENCE / collection
        if not root.is_dir():
            pytest.skip(f"{collection} not present")
        parser = LnkParser()
        for path in root.rglob("*.lnk"):
            for event in parser.parse(path, path.relative_to(root).as_posix()):
                assert event.details.get("volume_serial") != "18334A83"


@needs_host2
class TestAcrossCollections:
    @pytest.mark.parametrize(
        "collection,minimum",
        [
            ("collection_clean_a", 30),
            ("collection_clean_b", 30),
            ("collection_s1_v2", 45),
            ("collection_clean_c", 28),
            ("collection_s1_v3", 30),
        ],
    )
    def test_each_collection_yields_events(self, collection, minimum):
        """Lower bounds: Recent links come and go with ordinary use, and an
        exact count would pin the corpus rather than the parser."""
        root = EVIDENCE / collection
        if not root.is_dir():
            pytest.skip(f"{collection} not present")
        parser = LnkParser()
        events = []
        for path in root.rglob("*.lnk"):
            events.extend(parser.parse(path, path.relative_to(root).as_posix()))
        assert len(events) >= minimum
