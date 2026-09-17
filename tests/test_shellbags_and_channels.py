"""Shellbags, and the five EVTX channels added 2026-09-17.

The shellbag property pinned here is D-049: the long name is anchored to the
0xBEEF extension signature, not scanned for. The first version scanned and
produced `詆eKapeFiles-master` -- the DOS timestamps sitting before the name
decode as printable CJK, so a scan sweeps them up. Every result was well-formed
and wrong.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.shellbags import (
    ShellbagsParser,
    dos_datetime,
    parse_shell_item,
)

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")
USRCLASS = "C/Users/vboxuser/AppData/Local/Microsoft/Windows/UsrClass.dat"

needs_host2 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / USRCLASS).is_file(),
    reason="s1_v3 UsrClass.dat required",
)
needs_host1 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v2").is_dir(),
    reason="collection_s1_v2 required",
)


def _item(
    short: str, long_name: str | None = None, *, kind: int = 0x31,
    dos_date: int = 0, dos_time: int = 0,
) -> bytes:
    """A synthetic shell item with the measured layout."""
    body = bytearray(14)
    body[2] = kind
    struct.pack_into("<HH", body, 8, dos_date, dos_time)
    body += short.encode("latin-1") + b"\x00"
    if long_name is None:
        struct.pack_into("<H", body, 0, len(body))
        return bytes(body)
    # Pad to the signature, then 38 filler bytes so the name lands at +40.
    body += b"\x00" * 4
    body += b"\xef\xbe"
    body += b"\x11" * 38
    body += long_name.encode("utf-16-le") + b"\x00\x00"
    struct.pack_into("<H", body, 0, len(body))
    return bytes(body)


class TestDosDatetime:
    def test_a_real_value(self):
        # 2026-09-13 11:50:08 -> year offset 46, two-second resolution
        date_word = ((2026 - 1980) << 9) | (9 << 5) | 13
        time_word = (11 << 11) | (50 << 5) | 4
        result = dos_datetime(date_word, time_word)
        assert result == datetime(2026, 9, 13, 11, 50, 8, tzinfo=UTC)

    def test_zero_is_not_a_time(self):
        assert dos_datetime(0, 0) is None

    def test_an_impossible_date_does_not_raise(self):
        """Month 13, day 40: a corrupt item must not take the parser down."""
        assert dos_datetime((46 << 9) | (13 << 5) | 31, 0) is None

    def test_utc_is_attached_not_converted(self):
        """D-013: DOS times carry no zone, so converting would apply the
        analyst's zone to the subject's clock."""
        result = dos_datetime(((2026 - 1980) << 9) | (1 << 5) | 1, 0)
        assert result.tzinfo is UTC
        assert result.hour == 0


class TestParseShellItem:
    def test_a_folder_with_a_long_name(self):
        record = parse_shell_item(_item("DOWNLO~1", "Downloads"))
        assert record["kind"] == "folder"
        assert record["short_name"] == "DOWNLO~1"
        assert record["long_name"] == "Downloads"

    def test_a_file_item(self):
        record = parse_shell_item(_item("FILES~1.ZIP", "Files.zip", kind=0x32))
        assert record["kind"] == "file"

    def test_the_long_name_is_anchored_not_scanned(self):
        """D-049. The bytes before the name decode as printable CJK; a scan
        sweeps them into the result and the output still looks like a name."""
        record = parse_shell_item(_item("DESKTOP", "Desktop"))
        assert record["long_name"] == "Desktop"
        assert not record["long_name"].startswith("\u8a46")

    def test_the_anchor_holds_regardless_of_short_name_length(self):
        """The reason it is anchored to the signature rather than computed
        from the short name, whose length varies from 4 to 12 here."""
        for short in ("KAPE", "vboxuser", "SUPPLI~1.ZIP"):
            record = parse_shell_item(_item(short, "TheRealName"))
            assert record["long_name"] == "TheRealName"

    def test_the_resource_suffix_is_stripped(self):
        record = parse_shell_item(
            _item("DOWNLO~1", "Downloads@shell32.dll,-21798")
        )
        assert record["long_name"] == "Downloads"

    def test_an_item_with_no_extension_block_keeps_its_short_name(self):
        record = parse_shell_item(_item("KAPE"))
        assert record["short_name"] == "KAPE"
        assert record["long_name"] is None

    def test_undecoded_types_return_none(self):
        """0x1f, 0x2e and 0x2f hold CLSIDs and drive letters. Decoding them as
        names puts the UTF-16 misreading of a GUID into a path field."""
        for kind in (0x1F, 0x2E, 0x2F, 0x00, 0xFF):
            assert parse_shell_item(_item("X", "Y", kind=kind)) is None

    def test_short_and_non_bytes_input(self):
        assert parse_shell_item(b"") is None
        assert parse_shell_item(b"\x00\x00\x31") is None
        assert parse_shell_item(None) is None


class TestCanHandle:
    def test_accepts_usrclass(self):
        parser = ShellbagsParser()
        assert parser.can_handle(USRCLASS)
        assert parser.can_handle(USRCLASS.replace("/", "\\").lower())

    def test_rejects_transaction_logs_and_other_hives(self):
        parser = ShellbagsParser()
        for suffix in (".LOG", ".LOG1", ".LOG2"):
            assert not parser.can_handle(USRCLASS + suffix)
        assert not parser.can_handle("C/Users/vboxuser/NTUSER.DAT")
        assert not parser.can_handle("C/Windows/System32/config/SAM")


@needs_host2
class TestAgainstRealHive:
    @pytest.fixture(scope="class")
    def events(self):
        path = EVIDENCE / "collection_s1_v3" / USRCLASS
        result = list(ShellbagsParser().parse(path, USRCLASS))
        assert result, "parser produced no events; tests would pass vacuously"
        return result

    def test_paths_are_readable_not_mojibake(self, events):
        """The D-049 regression guard against real evidence. Before the anchor
        fix these read `剼Ùvboxuser` and `詆eKapeFiles-master`."""
        for event in events:
            for character in event.path:
                assert character.isprintable(), f"unreadable path: {event.path!r}"
            assert "\ufffd" not in event.path

    def test_a_known_folder_tree_is_reconstructed(self, events):
        """The ancestry is built from tree position, so a nested bag carries
        its whole path rather than just its own name."""
        paths = {e.path for e in events}
        assert any(p.startswith("Users\\vboxuser") for p in paths)

    def test_timestamp_type_is_presence(self, events):
        assert all(e.timestamp_type == "presence" for e in events)

    def test_locators_are_unique(self, events):
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_family_and_event_type(self, events):
        assert {e.source_artifact for e in events} == {"shellbags"}
        assert {e.event_type for e in events} == {"folder_browsed"}

    def test_every_event_names_the_hive_owner(self, events):
        assert all(e.user == "vboxuser" for e in events)


@needs_host1
class TestAcrossHosts:
    def test_host1_separates_three_users(self):
        """Each profile's UsrClass yields only its own owner's browsing."""
        seen = {}
        for user in ("Youssef", "janed", "admin_local"):
            rel = f"C/Users/{user}/AppData/Local/Microsoft/Windows/UsrClass.dat"
            path = EVIDENCE / "collection_s1_v2" / rel
            if not path.is_file():
                continue
            events = list(ShellbagsParser().parse(path, rel))
            if events:
                seen[user] = {e.user for e in events}
        assert seen
        for user, users in seen.items():
            assert users == {user}

    def test_no_collection_raises(self):
        from conftest import cached_collect_events as collect_events

        for collection in ("collection_clean_b", "collection_s1_v2", "collection_s1_v3"):
            root = EVIDENCE / collection
            if not root.is_dir():
                continue
            _, stats = collect_events(root)
            assert [f for f in stats.failures if f[0] == "shellbags"] == []


class TestTheNewChannels:
    """Five EVTX channels, selected by what they attest rather than by size."""

    @pytest.mark.parametrize(
        "family",
        [
            "evtx.ps_classic",
            "evtx.defender",
            "evtx.winlogon",
            "evtx.firewall",
            "evtx.bits",
        ],
    )
    def test_each_channel_produces_events(self, family):
        """Measured 2026-09-17 on every collection. A channel that parses to
        zero everywhere would mean the EID selection was wrong."""
        from conftest import cached_collect_events as collect_events

        root = EVIDENCE / "collection_s1_v3"
        if not root.is_dir():
            pytest.skip("collection_s1_v3 not present")
        events, _ = collect_events(root)
        assert [e for e in events if e.source_artifact == family]

    def test_the_legacy_powershell_channel_is_distinct_from_4104(self):
        """`evtx.ps_classic` exists because 4104 holds nothing when
        script-block logging is off. They are different families and must not
        be merged."""
        from conftest import cached_collect_events as collect_events

        root = EVIDENCE / "collection_s1_v3"
        if not root.is_dir():
            pytest.skip("collection_s1_v3 not present")
        events, _ = collect_events(root)
        classic = {e.event_type for e in events if e.source_artifact == "evtx.ps_classic"}
        modern = {e.event_type for e in events if e.source_artifact == "evtx.powershell"}
        assert classic and modern
        assert not (classic & modern)

    def test_firewall_rule_churn_is_high_on_clean_hosts(self):
        """A measured base rate, recorded so no rule is written against the
        assumption that a firewall deletion is rare. Windows churns rules
        constantly: 2006 carries a real RuleId and is written by S-1-5-19
        during ordinary policy refresh."""
        from conftest import cached_collect_events as collect_events

        root = EVIDENCE / "collection_clean_c"
        if not root.is_dir():
            pytest.skip("collection_clean_c not present")
        events, _ = collect_events(root)
        deletions = [
            e for e in events if e.event_type == "firewall_rule_deleted"
        ]
        assert len(deletions) > 10, "the churn this test documents has changed"

    def test_all_five_are_recorded_type(self):
        """They are logs: the channel writes the record as the event occurs."""
        from conftest import cached_collect_events as collect_events

        root = EVIDENCE / "collection_s1_v3"
        if not root.is_dir():
            pytest.skip("collection_s1_v3 not present")
        events, _ = collect_events(root)
        for family in (
            "evtx.ps_classic",
            "evtx.defender",
            "evtx.winlogon",
            "evtx.firewall",
            "evtx.bits",
        ):
            rows = [e for e in events if e.source_artifact == family]
            assert all(e.timestamp_type == "recorded" for e in rows)
