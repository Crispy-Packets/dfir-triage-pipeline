"""The SAM hive parser: local accounts independent of the Security log.

Two bugs found during development motivate most of what is pinned here, and
both produced output that looked entirely plausible:

* `_names_to_rid` checked `isinstance(rid, int)`. regipy hands the RID back as
  a DECIMAL STRING, so the map came out empty and every account was reported as
  `RID-1000` -- true, well-formed, and useless to any rule wanting a name.
* The event was timestamped by the key's last write. Measured, that is EXACTLY
  the last-logon FILETIME on every account with logons, so the event restated
  one fact twice and labelled it `presence`.

Neither would have raised. That is the failure mode the suite is aimed at.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.sam_hive import (
    SamHiveParser,
    _coerce_rid,
    filetime_to_utc,
    parse_f_value,
)

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")
SAM_REL = "C/Windows/System32/config/SAM"

needs_collection = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / SAM_REL).is_file(),
    reason="collection_s1_v3 SAM hive is required",
)


def _f_value(
    *,
    rid: int = 1000,
    last_logon: int = 0,
    password_set: int = 0,
    password_failed: int = 0,
    flags: int = 0x0010,
    logon_count: int = 0,
    size: int = 80,
) -> bytes:
    """A synthetic 80-byte F value at the offsets the parser reads."""
    blob = bytearray(size)
    struct.pack_into("<Q", blob, 8, last_logon)
    struct.pack_into("<Q", blob, 24, password_set)
    struct.pack_into("<Q", blob, 40, password_failed)
    struct.pack_into("<I", blob, 48, rid)
    struct.pack_into("<H", blob, 56, flags)
    struct.pack_into("<H", blob, 66, logon_count)
    return bytes(blob)


def _ticks(when: datetime) -> int:
    return 116444736000000000 + int(when.timestamp() * 10_000_000)


class TestFiletime:
    def test_zero_is_never_not_1601(self):
        """SAM writes zero for 'never logged on'. Converting it would place an
        account's logon at the start of the timeline with no evidence."""
        assert filetime_to_utc(0) is None

    def test_epoch_itself_is_rejected(self):
        assert filetime_to_utc(116444736000000000) is None

    def test_real_value_converts(self):
        result = filetime_to_utc(_ticks(datetime(2026, 9, 13, 12, 8, 33, tzinfo=UTC)))
        assert result is not None
        assert (result.year, result.month, result.day) == (2026, 9, 13)

    def test_absurd_value_does_not_raise(self):
        assert filetime_to_utc(2**63 - 1) is None


class TestCoerceRid:
    def test_decimal_string_is_accepted(self):
        """THE bug. regipy returns the RID as text because it is not a REG_*
        constant it can name, and an int-only check mapped nothing at all."""
        assert _coerce_rid("500") == 500
        assert _coerce_rid("1000") == 1000

    def test_plain_int_is_accepted(self):
        """Which form arrives is a library detail; both must work."""
        assert _coerce_rid(1000) == 1000

    def test_zero_is_not_a_rid(self):
        assert _coerce_rid(0) is None
        assert _coerce_rid("0") is None

    def test_non_numeric_is_rejected(self):
        for raw in ("REG_SZ", "", "  ", None, b"500", 3.5):
            assert _coerce_rid(raw) is None

    def test_bool_is_not_a_rid(self):
        """bool subclasses int, so True would otherwise coerce to RID 1."""
        assert _coerce_rid(True) is None


class TestParseFValue:
    def test_fields_land_at_the_expected_offsets(self):
        when = datetime(2026, 9, 13, 12, 8, 33, tzinfo=UTC)
        record = parse_f_value(
            _f_value(rid=1000, last_logon=_ticks(when), logon_count=15, flags=0x0010)
        )
        assert record["rid"] == 1000
        assert record["logon_count"] == 15
        assert record["last_logon"].day == 13

    def test_short_blob_yields_nothing(self):
        """A partial decode reads FILETIMEs from the wrong offsets and emits
        plausible times. No record is better than a confident wrong one."""
        full = _f_value(rid=1000, logon_count=15)
        for size in (0, 8, 40, 65, 79):
            assert parse_f_value(full[:size]) == {}

    def test_non_bytes_yields_nothing(self):
        assert parse_f_value(None) == {}
        assert parse_f_value("F") == {}

    def test_never_logged_on_reports_none_not_a_time(self):
        record = parse_f_value(_f_value(last_logon=0, logon_count=0))
        assert record["last_logon"] is None
        assert record["logon_count"] == 0

    def test_oversized_blob_still_parses(self):
        """Longer F values exist on other builds; the fields read are at fixed
        offsets from the start, so extra trailing bytes are not a reason to
        refuse the record."""
        assert parse_f_value(_f_value(rid=1000, size=120))["rid"] == 1000


class TestCanHandle:
    def test_accepts_the_sam_hive(self):
        parser = SamHiveParser()
        assert parser.can_handle("C/Windows/System32/config/SAM")
        assert parser.can_handle("c/windows/system32/config/sam")

    def test_rejects_transaction_logs(self):
        """They share the basename and hold no committed values."""
        parser = SamHiveParser()
        for suffix in (".LOG", ".LOG1", ".LOG2"):
            assert not parser.can_handle(f"C/Windows/System32/config/SAM{suffix}")

    def test_rejects_other_hives(self):
        parser = SamHiveParser()
        assert not parser.can_handle("C/Windows/System32/config/SYSTEM")
        assert not parser.can_handle("C/Windows/System32/config/SECURITY")
        assert not parser.can_handle("C/Users/x/NTUSER.DAT")

    def test_rejects_a_stray_file_named_sam(self):
        """Only the hive in config/ is the SAM. A user's file called `sam`
        would otherwise be parsed as a registry hive."""
        parser = SamHiveParser()
        assert not parser.can_handle("C/Users/youssef/Documents/sam")


@needs_collection
class TestAgainstRealHive:
    @pytest.fixture(scope="class")
    def events(self):
        parser = SamHiveParser()
        path = EVIDENCE / "collection_s1_v3" / SAM_REL
        result = list(parser.parse(path, SAM_REL))
        assert result, "parser produced no events; the tests would pass vacuously"
        return result

    def test_accounts_are_named_not_numbered(self, events):
        """The regression guard for the RID-as-string bug. Every account
        resolved to `RID-nnnn` and nothing raised."""
        users = {e.user for e in events}
        assert "Administrator" in users
        assert not any(u.startswith("RID-") for u in users), (
            f"unresolved RIDs: {sorted(u for u in users if u.startswith('RID-'))}"
        )

    def test_the_interactive_account_is_present_and_used(self, events):
        """vboxuser is host 2's only real account. SAM counts its logons
        itself, which is the claim the Security log cannot make after a clear."""
        rows = [e for e in events if e.user == "vboxuser"]
        assert len(rows) == 1
        assert int(rows[0].details["logon_count"]) > 0
        assert rows[0].details["last_logon"] != "never"

    def test_never_used_accounts_say_never_explicitly(self, events):
        """Omitting the key would make 'never logged on' indistinguishable
        from 'this parser failed to read the field'."""
        rows = [e for e in events if e.details["logon_count"] == "0"]
        assert rows
        assert all(e.details["last_logon"] == "never" for e in rows)

    def test_used_accounts_are_timestamped_by_the_logon(self, events):
        """Not by the key's last write. Measured, the two are identical on
        every used account, so the key write is a restatement rather than
        corroboration -- and `presence` would understate the artefact."""
        for event in events:
            if event.details["last_logon"] == "never":
                assert event.timestamp_type == "presence"
            else:
                assert event.timestamp_type == "last_run"
                assert event.timestamp.isoformat().startswith(
                    event.details["last_logon"][:19]
                )

    def test_builtin_accounts_are_labelled_not_hidden(self, events):
        """Named rather than suppressed: that Guest is enabled, or that
        Administrator has logged on, is evidence."""
        by_rid = {e.details["rid"]: e for e in events}
        assert by_rid["500"].details["well_known"] == "administrator"
        assert by_rid["501"].details["well_known"] == "guest"

    def test_builtin_accounts_are_disabled_on_this_host(self, events):
        """The measured baseline. A collection where this fails is one where
        a built-in account was enabled, which is the finding."""
        by_rid = {e.details["rid"]: e for e in events}
        for rid in ("500", "501", "503"):
            assert "disabled" in by_rid[rid].details["account_flags"]

    def test_no_credential_material_is_emitted(self, events):
        """The V value holds the NT hash. This parser reads account metadata
        and a triage pipeline that carried hashes would be a different tool."""
        for event in events:
            for key, value in event.details.items():
                assert "hash" not in key.lower()
                assert "password" not in key.lower() or key.startswith("password_last")
                assert len(value) < 200

    def test_every_event_carries_provenance(self, events):
        """CD-003/CD-004. A finding that cannot name its source is not
        acceptable output."""
        for event in events:
            assert event.source_file == SAM_REL
            assert event.source_locator.startswith("Users\\")

    def test_locators_are_unique_within_the_hive(self, events):
        """CD-004. The RID key name is the identifier; it must not collide."""
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_family_and_event_type_are_the_declared_ones(self, events):
        """CD-007: `local_account`, not `account_created`. 4720 records a
        creation EVENT; SAM records that an account EXISTS."""
        assert {e.source_artifact for e in events} == {"sam"}
        assert {e.event_type for e in events} == {"local_account"}


@needs_collection
class TestAcrossHosts:
    """SAM is the same on both hosts in structure and different in content.
    A parser that silently returned nothing on one would pass every test above.
    """

    @pytest.mark.parametrize(
        "collection,expected_accounts",
        [
            ("collection_clean_a", 7),
            ("collection_clean_b", 7),
            ("collection_s1_v2", 7),
            ("collection_clean_c", 5),
            ("collection_s1_v3", 5),
        ],
    )
    def test_measured_account_counts(self, collection, expected_accounts):
        """Measured 2026-09-17, not assumed. Host 1 carries three real accounts
        plus four built-ins; host 2 carries one plus the same four."""
        path = EVIDENCE / collection / SAM_REL
        if not path.is_file():
            pytest.skip(f"{collection} not present")
        events = list(SamHiveParser().parse(path, SAM_REL))
        assert len(events) == expected_accounts

    def test_host1_accounts_resolve_by_name(self):
        """The RID-as-string bug was found on host 2 and would have been
        equally invisible here."""
        path = EVIDENCE / "collection_clean_b" / SAM_REL
        if not path.is_file():
            pytest.skip("collection_clean_b not present")
        users = {e.user for e in SamHiveParser().parse(path, SAM_REL)}
        assert {"Youssef", "janed", "admin_local"} <= users

    def test_deleted_accounts_are_absent_rather_than_idle(self):
        """testuser was created in clean_b on 2026-08-24 and does not appear in
        SAM. An account created and deleted is a different situation from one
        created and never used, and the Security log alone cannot separate
        them -- 4720 fires for both. This is the distinction SAM adds."""
        path = EVIDENCE / "collection_clean_b" / SAM_REL
        if not path.is_file():
            pytest.skip("collection_clean_b not present")
        users = {e.user.lower() for e in SamHiveParser().parse(path, SAM_REL)}
        assert "testuser" not in users
