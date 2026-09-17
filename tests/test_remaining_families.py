"""Defender text logs, LSA policy, registry transaction logs, browser profiles.

The property that matters most here is the transaction-log one: these files
were dismissed earlier in this project as holding "no committed values", and
the measurement showed 21 of 27 logs on `clean_b` are AHEAD of their hive, one
by 933 KB of pending writes. A dismissal is a claim like any other.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.browser_profile import (
    profile_database,
    webkit_to_utc,
)
from dfir_triage_pipeline.parsers.defender_mplog import (
    DefenderMpLogParser,
    parse_timestamp,
)
from dfir_triage_pipeline.parsers.registry_txlog import (
    RegistryTxLogParser,
    hive_sequence,
    parse_log_header,
)
from dfir_triage_pipeline.parsers.security_hive import SecurityHiveParser, hive_kind

EVIDENCE = Path(r"%USERPROFILE%\dfir-evidence")

needs_s1v3 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3").is_dir(), reason="s1_v3 required"
)
needs_cleanb = pytest.mark.skipif(
    not (EVIDENCE / "collection_clean_b").is_dir(), reason="clean_b required"
)


def _log_blob(*, sequence: int = 428, entry_size: int = 32256, file_type: int = 6) -> bytes:
    blob = bytearray(512 + 32)
    blob[0:4] = b"regf"
    struct.pack_into("<II", blob, 4, sequence, sequence)
    struct.pack_into("<Q", blob, 12, 133000000000000000)
    struct.pack_into("<II", blob, 20, 1, 5)
    struct.pack_into("<I", blob, 28, file_type)
    blob[512:516] = b"HvLE"
    struct.pack_into("<III", blob, 516, entry_size, 0, sequence)
    return bytes(blob)


class TestDefenderTimestamps:
    def test_utc_is_attached_not_converted(self):
        """D-013: the log writes no zone, so the value is the subject's wall
        clock and converting would apply the analyst's."""
        result = parse_timestamp("2026-09-13T12:16:11.890")
        assert result == datetime(2026, 9, 13, 12, 16, 11, 890000, tzinfo=UTC)

    def test_unparseable_yields_none(self):
        for raw in ("", "not a time", "2026-13-45T99:99:99"):
            assert parse_timestamp(raw) is None


class TestDefenderCanHandle:
    def test_accepts_all_four_text_logs(self):
        parser = DefenderMpLogParser()
        base = "C/ProgramData/Microsoft/Windows Defender/Support"
        for name in (
            "MPLog-20260909-040355.log",
            "MPDetection-20260909-040355.log",
            "MPScanSkip-20260910-141445.log",
            "MPDeviceControl-20260910-141445.log",
        ):
            assert parser.can_handle(f"{base}/{name}")

    def test_rejects_the_binary_etw_traces(self):
        """MpWpp*.bin are ETW traces, not text. Decoding them needs a TMF
        schema this pipeline does not have."""
        parser = DefenderMpLogParser()
        base = "C/ProgramData/Microsoft/Windows Defender/Support"
        for name in (
            "MpWppTracing-20260913-120825-00000003.bin",
            "MpWppCoreTracing-20260913-150824.bin",
            "MpWppUpdateLogging-20260913-150824.bin",
        ):
            assert not parser.can_handle(f"{base}/{name}")

    def test_rejects_files_elsewhere(self):
        parser = DefenderMpLogParser()
        assert not parser.can_handle("C/Windows/System32/config/SAM")
        assert not parser.can_handle("C/Users/x/Documents/MPLog-fake.log")


@needs_s1v3
class TestDefenderAgainstRealLogs:
    @pytest.fixture(scope="class")
    def events(self):
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        rows = [e for e in events if e.source_artifact == "defender_mplog"]
        assert rows, "parser produced no events"
        return rows

    def test_the_payload_is_reported_but_never_convicted(self, events):
        """`ReportLowfi` is Defender's own word for LOW FIDELITY. Measured:
        zero 1116/1117 verdicts across all five collections, and a ReportLowfi
        for the payload on s1_v3. The engine looked and did not conclude."""
        from conftest import cached_collect_events as collect_events

        hits = [e for e in events if "invoice_scan" in str(e.path).lower()]
        assert hits
        assert all(e.event_type == "file_reported" for e in hits)

        all_events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        verdicts = [
            e
            for e in all_events
            if e.event_type in ("malware_detected", "malware_remediated")
        ]
        assert verdicts == []

    def test_every_row_names_its_log_family(self, events):
        families = {e.details["log_family"] for e in events}
        assert families
        assert families <= {"mplog", "mpdetection", "mpscanskip", "mpdevicecontrol"}

    def test_locators_are_unique_within_a_file(self, events):
        by_file: dict[str, list[str]] = {}
        for event in events:
            by_file.setdefault(event.source_file, []).append(event.source_locator)
        for locators in by_file.values():
            assert len(locators) == len(set(locators))


class TestLsaAndDefaultHives:
    def test_hive_kind(self):
        base = "C/Windows/System32/config"
        assert hive_kind(f"{base}/SECURITY") == "security"
        assert hive_kind(f"{base}/DEFAULT") == "default"
        assert hive_kind(f"{base}/SAM") is None
        assert hive_kind(f"{base}/SYSTEM") is None

    def test_transaction_logs_are_rejected(self):
        base = "C/Windows/System32/config"
        for suffix in (".LOG", ".LOG1", ".LOG2"):
            assert hive_kind(f"{base}/SECURITY{suffix}") is None

    def test_a_file_named_security_elsewhere_is_not_the_hive(self):
        assert hive_kind("C/Users/x/Documents/security") is None

    @needs_s1v3
    def test_privilege_holders_are_recorded(self):
        rel = "C/Windows/System32/config/SECURITY"
        path = EVIDENCE / "collection_s1_v3" / rel
        if not path.is_file():
            pytest.skip("SECURITY hive absent")
        events = list(SecurityHiveParser().parse(path, rel))
        assert events
        assert all(e.user.startswith("S-1-") for e in events)
        assert all(e.event_type == "privilege_granted" for e in events)
        # Built-ins are named, not suppressed.
        named = {e.details.get("well_known") for e in events}
        assert "Administrators" in named

    @needs_s1v3
    def test_no_credential_material_is_emitted(self):
        """Policy\\Secrets and PolEKList are not read, for the same reason
        sam_hive.py does not read the V value."""
        rel = "C/Windows/System32/config/SECURITY"
        path = EVIDENCE / "collection_s1_v3" / rel
        if not path.is_file():
            pytest.skip("SECURITY hive absent")
        for event in SecurityHiveParser().parse(path, rel):
            blob = str(event.details).lower()
            assert "secret" not in blob
            assert "polek" not in blob


class TestRegistryTxLog:
    def test_a_log_header_parses(self):
        header = parse_log_header(_log_blob())
        assert header["primary_sequence"] == 428
        assert header["entry_size"] == 32256

    def test_a_primary_hive_is_rejected(self):
        """file_type 0 is a hive, 6 is a log. A hive handed to this parser
        must yield nothing rather than being reported as pending writes."""
        assert parse_log_header(_log_blob(file_type=0)) is None

    def test_a_non_regf_file_is_rejected(self):
        assert parse_log_header(b"notaregf" + b"\x00" * 600) is None
        assert parse_log_header(b"") is None

    def test_a_log_with_no_dirty_pages_yields_no_event(self, tmp_path):
        """A fully flushed log asserts nothing."""
        path = tmp_path / "NTUSER.DAT.LOG1"
        path.write_bytes(_log_blob(entry_size=0))
        assert list(RegistryTxLogParser().parse(path, "x/NTUSER.DAT.LOG1")) == []

    def test_can_handle(self):
        parser = RegistryTxLogParser()
        assert parser.can_handle("C/Users/x/ntuser.dat.LOG1")
        assert parser.can_handle("C/Windows/System32/config/SYSTEM.LOG2")
        assert not parser.can_handle("C/Users/x/ntuser.dat")
        assert not parser.can_handle("C/Users/x/ntuser.dat.LOG")

    def test_hive_sequence_reads_the_base_block(self, tmp_path):
        hive = tmp_path / "NTUSER.DAT"
        hive.write_bytes(_log_blob(sequence=413, file_type=0))
        assert hive_sequence(hive) == 413

    def test_hive_sequence_on_a_missing_file(self, tmp_path):
        assert hive_sequence(tmp_path / "nope") is None

    @needs_cleanb
    def test_logs_are_ahead_of_their_hives(self):
        """THE measurement that overturned the earlier dismissal. These files
        were called "no committed values"; 21 of 27 on clean_b hold changes
        the hive has never seen."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_clean_b")
        rows = [e for e in events if e.source_artifact == "registry_txlog"]
        assert rows
        ahead = [e for e in rows if e.details.get("log_ahead_of_hive") == "true"]
        assert ahead, "no log is ahead of its hive; the dismissal may be right"
        assert max(int(e.details["pending_bytes"]) for e in ahead) > 100_000

    @needs_cleanb
    def test_every_row_names_its_hive(self):
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_clean_b")
        rows = [e for e in events if e.source_artifact == "registry_txlog"]
        assert all(e.details["hive_name"] for e in rows)


class TestBrowserProfile:
    def test_profile_database_matching(self):
        base = "C/Users/x/AppData/Local/Microsoft/Edge/User Data/Default"
        assert profile_database(f"{base}/Shortcuts") == "shortcuts"
        assert profile_database(f"{base}/Favicons") == "favicons"
        assert profile_database(f"{base}/Web Data") == "web data"
        assert profile_database(f"{base}/Top Sites") == "top sites"

    def test_login_data_is_not_read(self):
        """Its logins table holds DPAPI-encrypted credentials. The parser does
        not look, for the same reason sam_hive.py does not read the V value."""
        base = "C/Users/x/AppData/Local/Microsoft/Edge/User Data/Default"
        assert profile_database(f"{base}/Login Data") is None

    def test_journals_are_rejected(self):
        base = "C/Users/x/AppData/Local/Microsoft/Edge/User Data/Default"
        for suffix in ("-wal", "-shm", "-journal"):
            assert profile_database(f"{base}/Shortcuts{suffix}") is None

    def test_a_matching_name_outside_a_profile_is_rejected(self):
        assert profile_database("C/Users/x/Documents/Shortcuts") is None

    def test_webkit_time(self):
        assert webkit_to_utc(0) is None
        assert webkit_to_utc(-1) is None
        assert webkit_to_utc(True) is None
        result = webkit_to_utc(13431997206710763)
        assert result is not None and result.year == 2026

    @needs_s1v3
    def test_typed_queries_are_recovered(self):
        """`omni_box_shortcuts` records what a person typed into the address
        bar, which no other family holds."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        typed = [
            e
            for e in events
            if e.source_artifact == "browser_profile"
            and e.details["profile_table"] == "shortcuts"
        ]
        assert typed
        assert any(e.details.get("typed_text") for e in typed)

    @needs_s1v3
    def test_favicons_outlive_history(self):
        """`History` is the file a person clears; `Favicons` is not, and its
        icon_mapping names every page an icon was fetched for."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        icons = [
            e
            for e in events
            if e.source_artifact == "browser_profile"
            and e.details["profile_table"] == "favicons"
        ]
        assert len(icons) > 50
        assert all(e.path for e in icons)

    @needs_s1v3
    def test_rows_without_a_time_are_presence(self):
        """Top Sites and icon_mapping record no timestamp at all. Claiming one
        would invent it."""
        from conftest import cached_collect_events as collect_events

        events, _ = collect_events(EVIDENCE / "collection_s1_v3")
        rows = [e for e in events if e.source_artifact == "browser_profile"]
        for event in rows:
            if event.details["profile_table"] in ("top_sites", "favicons"):
                assert event.timestamp_type == "presence"
