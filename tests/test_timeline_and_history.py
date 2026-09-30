"""Windows Timeline and PSReadLine history.

Two properties that would produce plausible wrong output:

* Timeline times are Unix epoch SECONDS -- not FILETIME, not OLE, both of which
  this pipeline uses elsewhere. Applying either places events decades away and
  raises nothing.
* `AppId` is a JSON platform array, and the FIRST member is usually
  `data_boundary`, whose application is the constant `microsoft.default.default`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.ps_history import (
    PsHistoryParser,
    join_continuations,
)
from dfir_triage_pipeline.parsers.timeline import (
    TimelineParser,
    decode_app_id,
    decode_payload,
    unix_to_utc,
)

EVIDENCE = Path.home() / "dfir-evidence"
TIMELINE_REL = (
    "C/Users/vboxuser/AppData/Local/ConnectedDevicesPlatform/"
    "L.vboxuser/ActivitiesCache.db"
)
HISTORY_REL = (
    "C/Users/vboxuser/AppData/Roaming/Microsoft/Windows/PowerShell/"
    "PSReadline/ConsoleHost_history.txt"
)

needs_timeline = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / TIMELINE_REL).is_file(),
    reason="s1_v3 ActivitiesCache.db required",
)
needs_history = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / HISTORY_REL).is_file(),
    reason="s1_v3 ConsoleHost_history.txt required",
)


class TestUnixTime:
    def test_the_measured_value(self):
        """Read out of s1_v3's Activity table."""
        result = unix_to_utc(1788916091)
        assert result is not None
        assert result.year == 2026

    def test_zero_and_negative_are_rejected(self):
        assert unix_to_utc(0) is None
        assert unix_to_utc(-1) is None

    def test_a_filetime_sized_value_is_rejected(self):
        """The guard against applying the wrong convention. A FILETIME read as
        Unix seconds lands far outside the band, and is refused rather than
        emitted."""
        assert unix_to_utc(134336826389520000) is None

    def test_bool_and_non_int_are_rejected(self):
        assert unix_to_utc(True) is None
        assert unix_to_utc("1788916091") is None
        assert unix_to_utc(None) is None


class TestDecodeAppId:
    def test_the_most_specific_platform_wins(self):
        """x_exe_path carries a full path, sometimes on another drive. It must
        outrank packageId, which holds the same thing less precisely."""
        raw = (
            '[{"application":"microsoft.default.default","platform":"data_boundary"},'
            '{"application":"D:\\\\VBoxWindowsAdditions-amd64.exe","platform":"x_exe_path"},'
            '{"application":"Something","platform":"packageId"}]'
        )
        assert decode_app_id(raw) == "D:\\VBoxWindowsAdditions-amd64.exe"

    def test_data_boundary_is_never_returned(self):
        """It is the FIRST member on most rows and its application is a
        constant naming nothing. Taking entry 0 blindly returns it."""
        raw = (
            '[{"application":"microsoft.default.default","platform":"data_boundary"},'
            '{"application":"Microsoft.Windows.Explorer","platform":"windows_win32"}]'
        )
        assert decode_app_id(raw) == "Microsoft.Windows.Explorer"

    def test_only_data_boundary_yields_none(self):
        raw = '[{"application":"microsoft.default.default","platform":"data_boundary"}]'
        assert decode_app_id(raw) is None

    def test_bytes_input_is_decoded(self):
        raw = b'[{"application":"MSEdge","platform":"windows_win32"}]'
        assert decode_app_id(raw) == "MSEdge"

    def test_a_bare_string_is_accepted(self):
        """The column is JSON on every row here, but the value is
        application-written and a future build could change it."""
        assert decode_app_id("notepad.exe") == "notepad.exe"

    def test_empty_and_malformed(self):
        assert decode_app_id(None) is None
        assert decode_app_id("") is None
        assert decode_app_id("[]") is None
        assert decode_app_id('[{"platform":"x_exe_path"}]') is None


class TestDecodePayload:
    def test_json_payload(self):
        raw = '{"displayText":"File Explorer","activeDurationSeconds":17}'
        assert decode_payload(raw)["activeDurationSeconds"] == 17

    def test_base64_protobuf_yields_empty(self):
        """Type 11 rows carry this. They are not parsed, but a malformed
        payload on a parsed row must not take the parser down."""
        assert decode_payload("Q0IBAMoUDhUAyh4OBwDKMgDKPAAA") == {}

    def test_non_dict_json_yields_empty(self):
        assert decode_payload("[1,2,3]") == {}
        assert decode_payload(None) == {}


class TestCanHandle:
    def test_timeline(self):
        parser = TimelineParser()
        assert parser.can_handle(TIMELINE_REL)
        assert not parser.can_handle(TIMELINE_REL + "-wal")
        assert not parser.can_handle(TIMELINE_REL + "-shm")

    def test_history(self):
        parser = PsHistoryParser()
        assert parser.can_handle(HISTORY_REL)
        assert parser.can_handle(HISTORY_REL.replace("/", "\\"))
        assert not parser.can_handle("C/Users/x/Documents/history.txt")


class TestJoinContinuations:
    def test_a_single_line_command(self):
        assert join_continuations(["Get-Process"]) == [(1, "Get-Process")]

    def test_backtick_continuations_are_joined(self):
        """Splitting on newlines would report `'HKCU:\\...\\RunOnce',` as a
        command in its own right."""
        lines = [
            "$k = 'HKCU:\\Software\\Run',`",
            "     'HKLM:\\Software\\Run'",
            "Get-Process",
        ]
        result = join_continuations(lines)
        assert len(result) == 2
        assert result[0][0] == 1
        assert "HKLM" in result[0][1]
        assert result[1] == (3, "Get-Process")

    def test_the_line_number_is_the_first_line(self):
        """So the locator points at where the command starts."""
        lines = ["a", "b`", "c", "d"]
        result = join_continuations(lines)
        assert [n for n, _ in result] == [1, 2, 4]

    def test_blank_lines_are_dropped(self):
        assert join_continuations(["", "  ", "Get-Date"]) == [(3, "Get-Date")]

    def test_a_trailing_continuation_still_emits(self):
        """A file ending mid-command must not lose the fragment."""
        result = join_continuations(["Get-Item x`"])
        assert len(result) == 1

    def test_runaway_continuations_are_capped(self):
        """A pathological file cannot build one unbounded string."""
        result = join_continuations(["x`"] * 500)
        assert len(result) >= 2

    def test_empty_input(self):
        assert join_continuations([]) == []


@needs_timeline
class TestTimelineAgainstRealDatabase:
    @pytest.fixture(scope="class")
    def events(self):
        path = EVIDENCE / "collection_s1_v3" / TIMELINE_REL
        result = list(TimelineParser().parse(path, TIMELINE_REL))
        assert result, "parser produced no events; tests would pass vacuously"
        return result

    def test_only_the_two_activity_types_are_emitted(self, events):
        """Types 11 (settings sync) and 16 (clipboard) name no program."""
        assert {e.details["activity_type"] for e in events} <= {"5", "6"}
        assert {e.event_type for e in events} <= {"app_opened", "app_engaged"}

    def test_engagement_rows_carry_a_duration(self, events):
        """The value no other family holds."""
        engaged = [e for e in events if e.event_type == "app_engaged"]
        assert engaged
        with_duration = [e for e in engaged if "active_seconds" in e.details]
        assert len(with_duration) / len(engaged) > 0.9
        assert all(int(e.details["active_seconds"]) >= 0 for e in with_duration)

    def test_timestamps_land_in_the_collection_window(self, events):
        """The regression guard for the epoch convention."""
        for event in events:
            assert datetime(2025, 1, 1, tzinfo=UTC) <= event.timestamp
            assert event.timestamp <= datetime(2027, 1, 1, tzinfo=UTC)

    def test_no_row_is_attributed_to_the_data_boundary_constant(self, events):
        assert not any("microsoft.default.default" in str(e.path) for e in events)

    def test_locators_are_unique(self, events):
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_provenance_and_user(self, events):
        for event in events:
            assert event.source_file == TIMELINE_REL
            assert event.user == "vboxuser"

    def test_the_wal_carries_activity_the_database_does_not(self):
        """AMENDED 2026-09-17, and the amendment is the point.

        This asserted that `admin_local`'s database yields NOTHING, and the
        docstring recorded the conclusion I drew from that: "an account that
        logged on but never used the Activity Feed". Both were wrong.

        The `.db` is 4,096 bytes and genuinely empty. Its `-wal` is 1.7 MB and
        holds **17 real activities**, MSEdge and notepad.exe among them. The
        account used the Activity Feed normally; none of it had been
        checkpointed into the database when the machine was collected.

        `immutable=1` was hiding all of it, and the absence looked like
        evidence. See D-053.
        """
        rel = (
            "C/Users/admin_local/AppData/Local/ConnectedDevicesPlatform/"
            "L.admin_local/ActivitiesCache.db"
        )
        path = EVIDENCE / "collection_clean_b" / rel
        if not path.is_file():
            pytest.skip("admin_local timeline database not present")
        events = list(TimelineParser().parse(path, rel))
        assert events, "the WAL rows are being dropped again"
        assert any("notepad" in str(e.path).lower() for e in events)

    def test_a_database_with_no_activity_table_still_yields_nothing(self, tmp_path):
        """The D-024 property the amended test above used to cover: a file
        that is not an Activity database must yield nothing rather than
        raising, and must not be mistaken for one."""
        import sqlite3

        path = tmp_path / "ActivitiesCache.db"
        connection = sqlite3.connect(str(path))
        connection.execute("CREATE TABLE Unrelated (x INTEGER)")
        connection.commit()
        connection.close()
        assert list(TimelineParser().parse(path, "x/ActivitiesCache.db")) == []


@needs_history
class TestHistoryAgainstRealFile:
    @pytest.fixture(scope="class")
    def events(self):
        path = EVIDENCE / "collection_s1_v3" / HISTORY_REL
        result = list(PsHistoryParser().parse(path, HISTORY_REL))
        assert result, "parser produced no events; tests would pass vacuously"
        return result

    def test_the_delivery_command_is_present(self, events):
        """What this family exists for: the typed line survives whether or not
        script-block logging was on."""
        commands = [e.path for e in events]
        assert any("Invoke-WebRequest" in c for c in commands)

    def test_timestamp_type_is_presence(self, events):
        """PSReadLine writes no timestamps at all."""
        assert all(e.timestamp_type == "presence" for e in events)

    def test_every_event_shares_the_file_mtime(self, events):
        """D-027's shape: one time, every sibling. Stated rather than hidden."""
        assert len({e.timestamp for e in events}) == 1

    def test_line_numbers_are_unique_and_ordered(self, events):
        numbers = [int(e.details["history_line"]) for e in events]
        assert len(numbers) == len(set(numbers))
        assert numbers == sorted(numbers)

    def test_locators_are_unique(self, events):
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_no_command_is_a_bare_continuation_fragment(self, events):
        """If joining failed, fragments appear as commands of their own."""
        for event in events:
            assert not event.path.rstrip().endswith("`")


class TestAcrossCollections:
    @pytest.mark.parametrize(
        "collection,timeline_min,history_min",
        [
            ("collection_clean_a", 100, 40),
            ("collection_clean_b", 100, 40),
            ("collection_s1_v2", 200, 150),
            ("collection_clean_c", 60, 30),
            ("collection_s1_v3", 100, 80),
        ],
    )
    def test_each_collection_yields_events(self, collection, timeline_min, history_min):
        """Lower bounds: both grow with ordinary use, and an exact count would
        pin the corpus rather than the parser. Measured 2026-09-17."""
        from conftest import cached_collect_events as collect_events

        root = EVIDENCE / collection
        if not root.is_dir():
            pytest.skip(f"{collection} not present")
        events, _ = collect_events(root)
        timeline = [e for e in events if e.source_artifact == "timeline"]
        history = [e for e in events if e.source_artifact == "ps_history"]
        assert len(timeline) >= timeline_min
        assert len(history) >= history_min

    def test_no_collection_produces_a_parser_failure(self):
        """The admin_local empty database raised until the table check landed."""
        from conftest import cached_collect_events as collect_events

        for collection in ("collection_clean_b", "collection_s1_v3"):
            root = EVIDENCE / collection
            if not root.is_dir():
                continue
            _, stats = collect_events(root)
            offenders = [
                f for f in stats.failures if f[0] in ("timeline", "ps_history")
            ]
            assert offenders == []
