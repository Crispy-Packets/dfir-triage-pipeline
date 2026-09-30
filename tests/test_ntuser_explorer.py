"""NTUSER Explorer keys: what a user ran, and what they opened.

The properties pinned here are the ones that let a parser return plausible
output while being wrong:

* value names are ROT13, so skipping the decode emits garbage that looks like
  paths;
* the UserAssist FILETIME is at offset 60, the LAST field, so a truncated
  record yields a run count with a time read from the wrong bytes;
* RecentDocs values terminate on a null CODE UNIT, and splitting on a null
  BYTE truncates mid-character.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.ntuser_explorer import (
    decode_mru_name,
    explorer_events,
    filetime_to_utc,
    parse_userassist_record,
    rot13,
)

EVIDENCE = Path.home() / "dfir-evidence"

needs_host1 = pytest.mark.skipif(
    not (EVIDENCE / "collection_clean_b" / "C/Users/Youssef/NTUSER.DAT").is_file(),
    reason="collection_clean_b host-1 hives are required",
)
needs_host2 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / "C/Users/vboxuser/NTUSER.DAT").is_file(),
    reason="collection_s1_v3 vboxuser hive is required",
)


def _events(collection: str, user: str):
    rel = f"C/Users/{user}/NTUSER.DAT"
    return list(explorer_events(EVIDENCE / collection / rel, rel))


def _ua_record(
    *, run_count: int = 0, focus_count: int = 0, focus_ms: int = 0, ticks: int = 0
) -> bytes:
    blob = bytearray(72)
    struct.pack_into("<I", blob, 4, run_count)
    struct.pack_into("<I", blob, 8, focus_count)
    struct.pack_into("<I", blob, 12, focus_ms)
    struct.pack_into("<Q", blob, 60, ticks)
    return bytes(blob)


def _ticks(when: datetime) -> int:
    return 116444736000000000 + int(when.timestamp() * 10_000_000)


class TestRot13:
    def test_the_measured_session_marker(self):
        """The literal string in every hive in the corpus."""
        assert rot13("HRZR_PGYFRFFVBA") == "UEME_CTLSESSION"

    def test_a_measured_program_name(self):
        assert rot13("Zvpebfbsg.Trgfgnegrq_8jrxlo3q8oojr!Ncc") == (
            "Microsoft.Getstarted_8wekyb3d8bbwe!App"
        )

    def test_digits_and_punctuation_pass_through(self):
        """A GUID must survive: only letters rotate."""
        assert rot13("{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}") == (
            "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}"
        )

    def test_round_trip(self):
        assert rot13(rot13("C:\\Users\\janed\\Downloads\\invoice_scan.exe")) == (
            "C:\\Users\\janed\\Downloads\\invoice_scan.exe"
        )


class TestFiletime:
    def test_zero_is_not_a_time(self):
        assert filetime_to_utc(0) is None

    def test_negative_is_rejected(self):
        assert filetime_to_utc(-1) is None

    def test_real_value_converts(self):
        when = datetime(2026, 8, 23, 22, 57, 15, tzinfo=UTC)
        result = filetime_to_utc(_ticks(when))
        assert result is not None
        assert (result.year, result.month, result.day) == (2026, 8, 23)

    def test_absurd_value_does_not_raise(self):
        assert filetime_to_utc(2**63 - 1) is None

    def test_bool_is_not_a_time(self):
        assert filetime_to_utc(True) is None


class TestUserAssistRecord:
    def test_fields_land_at_the_measured_offsets(self):
        when = datetime(2026, 8, 23, 22, 57, 15, tzinfo=UTC)
        record = parse_userassist_record(
            _ua_record(run_count=28, focus_count=9, focus_ms=24000, ticks=_ticks(when))
        )
        assert record["run_count"] == 28
        assert record["focus_count"] == 9
        assert record["focus_ms"] == 24000
        assert record["last_run"].day == 23

    def test_short_record_is_rejected_not_partially_decoded(self):
        """THE property. The FILETIME is the LAST field, at offset 60, so a
        truncated record would yield a run count with a time read from
        whatever bytes happen to be there."""
        full = _ua_record(run_count=28, ticks=_ticks(datetime(2026, 1, 1, tzinfo=UTC)))
        for size in (0, 4, 16, 59, 67, 71):
            assert parse_userassist_record(full[:size]) is None

    def test_non_bytes_is_rejected(self):
        for raw in (None, "", 72, [0] * 72):
            assert parse_userassist_record(raw) is None

    def test_zero_filetime_yields_no_time_but_keeps_the_count(self):
        """Explorer records no time for some entries. That is an absence, not
        1601, and the run count is still evidence."""
        record = parse_userassist_record(_ua_record(run_count=5, ticks=0))
        assert record["run_count"] == 5
        assert record["last_run"] is None

    def test_oversized_record_still_parses(self):
        """Offsets are from the start; trailing bytes are not a reason to
        refuse a record."""
        blob = _ua_record(run_count=7) + b"\x00" * 40
        assert parse_userassist_record(blob)["run_count"] == 7


class TestDecodeMruName:
    def test_terminates_on_a_code_unit_not_a_byte(self):
        """`test_doc` came back as `test_doc\\ufffd` when split on a single
        null byte -- the low byte of the next UTF-16 unit was consumed."""
        blob = "test_doc".encode("utf-16-le") + b"\x00\x00" + b"\x01\x02\x03\x04"
        assert decode_mru_name(blob) == "test_doc"

    def test_the_shell_link_tail_is_discarded(self):
        blob = "notes.txt".encode("utf-16-le") + b"\x00\x00" + bytes(range(60))
        assert decode_mru_name(blob) == "notes.txt"

    def test_odd_length_does_not_raise(self):
        blob = "abc".encode("utf-16-le") + b"\x00"
        decode_mru_name(blob)  # must not raise

    def test_empty_and_too_short(self):
        assert decode_mru_name(b"") is None
        assert decode_mru_name(b"\x00") is None
        assert decode_mru_name(b"\x00\x00") is None
        assert decode_mru_name(None) is None


class TestDispatchContract:
    def test_a_non_ntuser_path_yields_nothing(self):
        """explorer_events is called by registry.parse for EVERY hive it
        handles, including SOFTWARE. It must decline quietly."""
        software = "C/Windows/System32/config/SOFTWARE"
        assert list(explorer_events(Path("nonexistent"), software)) == []

    def test_the_registry_parser_owns_the_file(self):
        """find_parser returns the FIRST match, and registry claims NTUSER.DAT.
        A separate registration for these keys would never run -- which is why
        this module is delegated to rather than registered."""
        from dfir_triage_pipeline.parsers import find_parser

        parser = find_parser("C/Users/vboxuser/NTUSER.DAT")
        assert parser is not None
        assert parser.name == "registry"


@needs_host2
class TestAgainstHost2:
    @pytest.fixture(scope="class")
    def events(self):
        result = _events("collection_s1_v3", "vboxuser")
        assert result, "parser produced no events; the tests would pass vacuously"
        return result

    def test_families_emitted(self, events):
        families = {e.source_artifact for e in events}
        assert "userassist" in families
        assert "recentdocs" in families
        assert families <= {"userassist", "recentdocs", "typedpaths", "runmru"}

    def test_every_event_names_the_hive_owner(self, events):
        """The reason this family exists: the principal is the hive's owner and
        needs no inference."""
        assert all(e.user == "vboxuser" for e in events)

    def test_no_session_aggregate_is_emitted_as_a_program(self, events):
        """UEME_CTLSESSION is a 1612-byte roll-up, not a binary. Emitting one
        invents a program with a run count of several hundred."""
        paths = {str(e.path) for e in events}
        assert not any(p.startswith("UEME_") for p in paths)

    def test_names_are_rot13_decoded(self, events):
        """Undecoded names are dense consonant runs. At least one path must be
        a recognisable Windows identifier."""
        paths = [str(e.path) for e in events if e.source_artifact == "userassist"]
        assert any("Microsoft" in p for p in paths)

    def test_userassist_timestamp_type_varies_by_record(self, events):
        """Why `userassist` is in MIXED_TIMESTAMP_TYPE: a real FILETIME gives
        last_run, a zero falls back to the key write and presence."""
        ua = [e for e in events if e.source_artifact == "userassist"]
        kinds = {e.timestamp_type for e in ua}
        assert kinds <= {"last_run", "presence"}
        assert "last_run" in kinds

    def test_mru_families_are_presence(self, events):
        """D-027: the timestamp is the containing key's, shared by siblings."""
        for event in events:
            if event.source_artifact in {"recentdocs", "typedpaths", "runmru"}:
                assert event.timestamp_type == "presence"
                assert int(event.details["value_count_in_key"]) >= 1

    def test_no_ordering_value_is_emitted_as_an_entry(self, events):
        """MRUList and MRUListEx order the list; they name nothing."""
        names = {e.details.get("value_name") for e in events}
        assert "MRUList" not in names
        assert "MRUListEx" not in names

    def test_locators_are_unique(self, events):
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_every_event_carries_provenance(self, events):
        for event in events:
            assert event.source_file.endswith("NTUSER.DAT")
            assert event.source_locator
            assert event.path


@needs_host1
class TestTheAttributionResult:
    """The strongest cross-family result in the corpus: on `s1_v2` the Security
    log was cleared, and three independent artefacts still converge on one
    account."""

    def test_userassist_names_the_account_that_ran_the_payload(self):
        events = _events("collection_s1_v2", "janed")
        hits = [
            e
            for e in events
            if e.source_artifact == "userassist"
            and "invoice_scan" in str(e.path).lower()
        ]
        assert hits, "UserAssist holds no entry for the scenario binary"
        assert all(e.user == "janed" for e in hits)
        assert max(int(e.details["run_count"]) for e in hits) >= 28

    def test_the_userassist_time_agrees_with_prefetch(self):
        """Two independent artefacts, one clock: both record 22:57:15."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v2")
        by_family = {}
        for event in events:
            blob = (
                str(event.path or "")
                + str(event.details.get("path_basename_canonical") or "")
            ).lower()
            if "invoice_scan" in blob and event.source_artifact in {
                "userassist",
                "prefetch",
            }:
                by_family.setdefault(event.source_artifact, []).append(event)

        assert "userassist" in by_family and "prefetch" in by_family
        ua = max(by_family["userassist"], key=lambda e: e.timestamp)
        pf = max(by_family["prefetch"], key=lambda e: e.timestamp)
        assert abs((ua.timestamp - pf.timestamp).total_seconds()) < 2

    def test_three_users_are_separated(self):
        """Host 1 has three accounts. Each hive yields only its own owner --
        the machine-wide families cannot make this distinction at all."""
        for user in ("Youssef", "janed", "admin_local"):
            events = _events("collection_clean_b", user)
            assert events, f"{user} yielded nothing"
            assert {e.user for e in events} == {user}


@needs_host1
class TestAcrossCollections:
    @pytest.mark.parametrize(
        "collection,user,minimum",
        [
            ("collection_clean_a", "Youssef", 40),
            ("collection_clean_b", "Youssef", 40),
            ("collection_s1_v2", "janed", 40),
            ("collection_clean_c", "vboxuser", 30),
            ("collection_s1_v3", "vboxuser", 30),
        ],
    )
    def test_each_collection_yields_events(self, collection, user, minimum):
        """Lower bounds rather than exact counts: these keys change with
        ordinary use, and an exact figure would pin the corpus rather than the
        parser. Measured 2026-09-17, all comfortably above."""
        rel = f"C/Users/{user}/NTUSER.DAT"
        if not (EVIDENCE / collection / rel).is_file():
            pytest.skip(f"{collection} has no {user} hive")
        assert len(_events(collection, user)) >= minimum

    def test_the_default_profile_yields_nothing(self):
        """C:\\Users\\Default has none of these keys. It must not raise."""
        rel = "C/Users/Default/NTUSER.DAT"
        if not (EVIDENCE / "collection_s1_v3" / rel).is_file():
            pytest.skip("Default profile absent")
        assert _events("collection_s1_v3", "Default") == []
