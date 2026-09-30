"""Scheduled task definitions: persistence with no enabled-by-default event.

Two properties pinned here were wrong in the first draft and neither would have
raised in an obvious place:

* `can_handle` rejected any name containing a dot, on the theory that task
  definitions have no extension. Five of the 220 names on `s1_v3` contain one,
  including four whose names BEGIN with a dot (`.NET Framework NGEN ...`).
  They would have been dropped silently.
* `<Date>` carrying a UTC offset was passed through unconverted. CD-019's
  validation rejects a non-zero offset, so four tasks raised (D-045) -- the
  contract caught what the parser did not.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.scheduled_tasks import (
    ScheduledTasksParser,
    normalise_uri,
    parse_registration_date,
)

EVIDENCE = Path.home() / "dfir-evidence"
TASKS_REL = "C/Windows/System32/Tasks"

needs_collection = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / TASKS_REL).is_dir(),
    reason="collection_s1_v3 Tasks directory is required",
)


def _task_files(collection: str) -> list[Path]:
    root = EVIDENCE / collection / TASKS_REL
    return sorted(p for p in root.rglob("*") if p.is_file())


def _parse_collection(collection: str):
    parser = ScheduledTasksParser()
    root = EVIDENCE / collection / TASKS_REL
    events = []
    for path in _task_files(collection):
        rel = f"{TASKS_REL}/{path.relative_to(root).as_posix()}"
        if parser.can_handle(rel):
            events.extend(parser.parse(path, rel))
    return events


class TestNormaliseUri:
    def test_leading_backslash_is_made_consistent(self):
        """Measured: `<URI>` is inconsistent about it within one collection.
        Without normalising, one task reached two ways becomes two entities."""
        assert normalise_uri("\\Microsoft\\Windows\\Foo", "x") == "\\Microsoft\\Windows\\Foo"
        assert normalise_uri("Microsoft\\Windows\\Foo", "x") == "\\Microsoft\\Windows\\Foo"

    def test_repeated_separators_collapse_to_one(self):
        assert normalise_uri("\\\\\\Foo", "x") == "\\Foo"

    def test_forward_slashes_become_backslashes(self):
        assert normalise_uri("/Microsoft/Windows/Foo", "x") == "\\Microsoft\\Windows\\Foo"

    def test_missing_uri_falls_back_to_the_path_under_tasks(self):
        """The directory tree mirrors the task folder, so identity survives a
        missing element rather than becoming the whole collection path."""
        rel = "C/Windows/System32/Tasks/Microsoft/Windows/Foo/Bar"
        assert normalise_uri(None, rel) == "\\Microsoft\\Windows\\Foo\\Bar"

    def test_fallback_is_case_insensitive_about_the_tasks_segment(self):
        rel = "c/windows/system32/tasks/Microsoft/Foo"
        assert normalise_uri("", rel) == "\\Microsoft\\Foo"


class TestParseRegistrationDate:
    def test_naive_value_gets_utc_attached_not_converted(self):
        """D-013's decision. 86 of 90 dates in the corpus are naive; they are
        the subject machine's wall clock, and converting would apply the
        ANALYST's zone to the SUBJECT's."""
        result = parse_registration_date("2010-09-30T14:53:37.9516706")
        assert result == datetime(2010, 9, 30, 14, 53, 37, 951670, tzinfo=UTC)

    def test_offset_bearing_value_is_converted(self):
        """The measured counter-case, 4 of 90. Here the file DOES state a
        zone, so converting preserves the instant; attaching UTC would move
        the event eight hours."""
        result = parse_registration_date("2005-06-23T13:48:00-08:00")
        assert result == datetime(2005, 6, 23, 21, 48, tzinfo=UTC)
        assert result.utcoffset() == timedelta(0)

    def test_zulu_value(self):
        assert parse_registration_date("2026-09-13T11:48:00Z") == datetime(
            2026, 9, 13, 11, 48, tzinfo=UTC
        )

    def test_every_result_is_zero_offset(self):
        """CD-019 rejects a non-zero offset outright, which is what caught the
        original bug. No path through this function may return one."""
        for raw in (
            "2010-09-30T14:53:37.9516706",
            "2005-06-23T13:48:00-08:00",
            "2026-01-01T00:00:00+05:30",
            "2026-09-13T11:48:00Z",
        ):
            result = parse_registration_date(raw)
            assert result is not None
            assert result.utcoffset() == timedelta(0)

    def test_unparseable_and_empty_yield_none(self):
        for raw in (None, "", "   ", "not a date", "2026-13-45T99:99:99"):
            assert parse_registration_date(raw) is None


class TestCanHandle:
    def test_accepts_a_task_definition(self):
        parser = ScheduledTasksParser()
        assert parser.can_handle("C/Windows/System32/Tasks/Microsoft/Windows/AppID/PolicyConverter")
        assert parser.can_handle("c/windows/system32/tasks/OneDrive Startup Task-S-1-5-21-1")

    def test_accepts_names_containing_dots(self):
        """THE bug. Five of 220 task names on s1_v3 contain a dot, and four
        BEGIN with one. An extension test drops real tasks silently."""
        parser = ScheduledTasksParser()
        base = "C/Windows/System32/Tasks/Microsoft/Windows/.NET Framework"
        assert parser.can_handle(f"{base}/.NET Framework NGEN v4.0.30319")
        assert parser.can_handle(f"{base}/.NET Framework NGEN v4.0.30319 64 Critical")
        assert parser.can_handle(
            "C/Windows/System32/Tasks/GoogleSystem/GoogleUpdater/"
            "GoogleUpdaterTaskSystem152.0.7933.0{170F6A46-20AF-41F6-A7A8-8DA5C80A57D3}"
        )

    def test_accepts_backslash_paths(self):
        assert ScheduledTasksParser().can_handle(
            "C\\Windows\\System32\\Tasks\\Microsoft\\Windows\\AppID\\PolicyConverter"
        )

    def test_rejects_non_definitions_beside_the_tree(self):
        parser = ScheduledTasksParser()
        for name in ("SA.DAT", "desktop.ini", "Thumbs.db"):
            assert not parser.can_handle(f"C/Windows/System32/Tasks/{name}")

    def test_rejects_the_legacy_job_format(self):
        """A .job is the pre-Vista binary format, not XML."""
        assert not ScheduledTasksParser().can_handle("C/Windows/Tasks/At1.job")

    def test_rejects_files_outside_the_tasks_tree(self):
        parser = ScheduledTasksParser()
        assert not parser.can_handle("C/Windows/System32/config/SAM")
        assert not parser.can_handle("C/Users/vboxuser/Documents/PolicyConverter")


@needs_collection
class TestAgainstRealDefinitions:
    @pytest.fixture(scope="class")
    def events(self):
        result = _parse_collection("collection_s1_v3")
        assert result, "parser produced no events; the tests would pass vacuously"
        return result

    def test_every_file_on_disk_is_handled(self):
        """220 files, and can_handle must accept all of them. A silent drop is
        the failure mode this family is most prone to."""
        parser = ScheduledTasksParser()
        root = EVIDENCE / "collection_s1_v3" / TASKS_REL
        files = _task_files("collection_s1_v3")
        assert len(files) == 220
        rejected = [
            p.name
            for p in files
            if not parser.can_handle(f"{TASKS_REL}/{p.relative_to(root).as_posix()}")
        ]
        assert rejected == [], f"can_handle rejected real task files: {rejected}"

    def test_both_action_types_are_emitted(self, events):
        """ComHandler outnumbers Exec, 115 to 106. Reading only <Exec> drops
        over half the tasks -- and exactly the fileless shape."""
        kinds = {e.details["action_type"] for e in events}
        assert kinds == {"exec", "com_handler"}
        com = [e for e in events if e.details["action_type"] == "com_handler"]
        assert len(com) > len([e for e in events if e.details["action_type"] == "exec"])

    def test_com_actions_carry_a_class_id_and_no_command(self, events):
        """No command line exists for these. Emitting an empty path would
        suggest one was recorded and turned out blank."""
        for event in events:
            if event.details["action_type"] == "com_handler":
                assert event.details["com_class_id"]
                assert event.path is None
                assert "command" not in event.details

    def test_exec_actions_carry_a_command(self, events):
        for event in events:
            if event.details["action_type"] == "exec":
                assert event.details["command"]
                assert event.path == event.details["command"]

    def test_commands_are_recorded_unexpanded(self, events):
        """CD-010: as recorded. %windir% is what the file says, and expanding
        it would assert a resolution this parser did not verify."""
        commands = [e.path for e in events if e.path]
        assert any(c.lower().startswith("%windir%") for c in commands)

    def test_a_multi_action_task_yields_one_event_per_action(self, events):
        """MareBackup declares three Exec actions. Collapsing them would hide
        two things that would run."""
        mare = [e for e in events if e.details["task_uri"].endswith("MareBackup")]
        assert len(mare) == 3
        assert len({e.source_locator for e in mare}) == 3

    def test_locators_are_unique(self, events):
        """CD-004. The URI alone collides on multi-action tasks."""
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_every_event_carries_provenance(self, events):
        for event in events:
            assert event.source_file.startswith(TASKS_REL)
            assert event.source_locator
            assert event.details["task_uri"].startswith("\\")

    def test_family_and_event_type(self, events):
        assert {e.source_artifact for e in events} == {"scheduled_task"}
        assert {e.event_type for e in events} == {"task_registered"}

    def test_timestamp_type_is_presence(self, events):
        """The definition says a task EXISTS, not that it ever ran."""
        assert all(e.timestamp_type == "presence" for e in events)

    def test_principals_are_resolved_where_declared(self, events):
        """S-1-5-18 (SYSTEM) dominates; S-1-5-4 is INTERACTIVE."""
        users = [e.user for e in events if e.user]
        assert users
        assert any(u == "S-1-5-18" for u in users)

    def test_enabled_and_hidden_are_absent_rather_than_defaulted(self, events):
        """Both default to true when the element is missing. Writing the
        default would assert a value the file does not carry."""
        assert any("task_enabled" not in e.details for e in events)
        for event in events:
            for key in ("task_enabled", "task_hidden"):
                if key in event.details:
                    assert event.details[key] in {"true", "false"}

    def test_registration_dates_are_rare_and_all_utc(self, events):
        """Measured 26 of 222. Most tasks carry no date, which is why it is a
        detail rather than the event timestamp."""
        dated = [e for e in events if "registered_at" in e.details]
        assert 0 < len(dated) < len(events) / 2
        for event in dated:
            assert event.details["registered_at"].endswith("Z")


@needs_collection
class TestAcrossCollections:
    @pytest.mark.parametrize(
        "collection,files,events",
        [
            ("collection_clean_a", 210, 210),
            ("collection_clean_b", 210, 210),
            ("collection_s1_v2", 210, 210),
            ("collection_clean_c", 205, 205),
            ("collection_s1_v3", 220, 222),
        ],
    )
    def test_measured_counts(self, collection, files, events):
        """Measured 2026-09-17. Events exceed files only where a task declares
        several actions -- s1_v3's MareBackup, which has three."""
        root = EVIDENCE / collection / TASKS_REL
        if not root.is_dir():
            pytest.skip(f"{collection} not present")
        assert len(_task_files(collection)) == files
        assert len(_parse_collection(collection)) == events

    def test_no_collection_raises(self):
        """The offset-bearing <Date> raised on every collection until D-045 was
        fixed; SystemSoundsService is present in all five."""
        for collection in (
            "collection_clean_a",
            "collection_clean_b",
            "collection_s1_v2",
            "collection_clean_c",
            "collection_s1_v3",
        ):
            if not (EVIDENCE / collection / TASKS_REL).is_dir():
                continue
            assert _parse_collection(collection)


class TestOffsetRegression:
    def test_the_exact_failing_value_is_accepted(self):
        """`SystemSoundsService` carries this literal string in all five
        collections and raised `ValueError: timestamp must be UTC` until the
        conversion branch existed."""
        result = parse_registration_date("2005-06-23T13:48:00-08:00")
        assert result is not None
        assert result.tzinfo is not None
        assert result.utcoffset() == timedelta(0)
        # Not merely stripped: the instant must be preserved.
        assert result.hour == 21

    def test_a_positive_offset_is_also_converted(self):
        aware = datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
        assert parse_registration_date(aware.isoformat()) == datetime(
            2026, 1, 1, 6, 30, tzinfo=UTC
        )
