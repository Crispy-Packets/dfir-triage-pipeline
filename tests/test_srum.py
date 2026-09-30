"""SRUM: per-application network bytes and resource usage.

Three properties here would each have produced well-formed, plausible, wrong
output, and none of them would have raised:

* the timestamp is an OLE date arriving as the raw float64 BITS in an int;
* `IdType=3` is the SID and 0/1/2 are all applications, which is the opposite
  of most format write-ups;
* `AppId=1` resolves under no IdType and is SRUM's unattributed sentinel.

That is the D-023 / D-041 failure shape, and it is what this suite is aimed at.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dfir_triage_pipeline.parsers.srum import (
    SrumParser,
    decode_app,
    decode_sid,
    ole_timestamp,
)

EVIDENCE = Path.home() / "dfir-evidence"
SRUM_REL = "C/Windows/System32/sru/SRUDB.dat"

needs_collection = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3" / SRUM_REL).is_file(),
    reason="collection_s1_v3 SRUDB.dat is required",
)


def _ole_int(when: datetime) -> int:
    """A datetime as SRUM stores it: float64 days, delivered as raw bits."""
    days = (when - datetime(1899, 12, 30, tzinfo=UTC)).total_seconds() / 86400
    return struct.unpack("<Q", struct.pack("<d", days))[0]


class TestOleTimestamp:
    def test_the_measured_value_decodes_to_the_measured_time(self):
        """The exact int read out of s1_v3, and the time it must produce.
        Scaling it as ticks instead places the event ~148 million years out."""
        assert ole_timestamp(4676592689485971456) == datetime(
            2026, 9, 9, 4, 30, tzinfo=UTC
        )

    def test_round_trip(self):
        when = datetime(2026, 9, 13, 11, 48, tzinfo=UTC)
        assert ole_timestamp(_ole_int(when)) == when

    def test_a_real_datetime_passes_through(self):
        """A future dissect release may convert the column itself. Then the
        value must not be reinterpreted as bits."""
        when = datetime(2026, 9, 13, 11, 48, tzinfo=UTC)
        assert ole_timestamp(when) == when

    def test_naive_datetime_gets_utc(self):
        assert ole_timestamp(datetime(2026, 9, 13, 11, 48)).tzinfo is UTC

    def test_out_of_band_values_are_rejected(self):
        """Not clamped -- rejected. A timestamp this parser cannot vouch for is
        an absence, and emitting a clamped one would invent a time."""
        for raw in (0, 1, -1, 2**63 - 1, 2**64 - 1):
            result = ole_timestamp(raw)
            assert result is None or datetime(1995, 1, 1, tzinfo=UTC) <= result

    def test_nan_and_infinity_do_not_raise(self):
        for bits in (
            struct.unpack("<Q", struct.pack("<d", float("nan")))[0],
            struct.unpack("<Q", struct.pack("<d", float("inf")))[0],
        ):
            assert ole_timestamp(bits) is None

    def test_non_numeric_is_rejected(self):
        for raw in (None, "46274.1875", b"\x00" * 8, 3.5):
            assert ole_timestamp(raw) is None

    def test_bool_is_not_a_timestamp(self):
        """bool subclasses int; True would otherwise be reinterpreted."""
        assert ole_timestamp(True) is None


class TestDecodeSid:
    def test_the_measured_blob(self):
        """Read out of s1_v3's IdType=3: this is what proves 3 is the SID."""
        blob = b"\x01\x01\x00\x00\x00\x00\x00\x05\x14\x00\x00\x00"
        assert decode_sid(blob) == "S-1-5-20"

    def test_a_user_sid(self):
        blob = struct.pack("<BB", 1, 5) + (5).to_bytes(6, "big")
        blob += struct.pack("<5I", 21, 1591430865, 807086247, 2139423957, 1000)
        assert decode_sid(blob) == "S-1-5-21-1591430865-807086247-2139423957-1000"

    def test_short_or_malformed_blobs_yield_none(self):
        for blob in (b"", b"\x01", b"\x01\x01\x00", b"\x01\x05\x00" * 2, None, "S-1-5-20"):
            assert decode_sid(blob) is None

    def test_wrong_revision_is_rejected(self):
        """Revision is 1 for every SID Windows has ever issued. A blob that
        says otherwise is an application identity misrouted into this decoder."""
        blob = b"\x09\x01\x00\x00\x00\x00\x00\x05\x14\x00\x00\x00"
        assert decode_sid(blob) is None

    def test_truncated_subauthorities_yield_none(self):
        """The count says 5, the bytes provide 2. Decoding what is there would
        emit a real-looking SID with the last components invented."""
        blob = struct.pack("<BB", 1, 5) + (5).to_bytes(6, "big") + struct.pack("<2I", 21, 7)
        assert decode_sid(blob) is None


class TestDecodeApp:
    def test_utf16_identity(self):
        blob = "!!WmiPrvSE.exe!2019/10/16:23:45:21!860a3!".encode("utf-16-le")
        assert decode_app(blob) == "!!WmiPrvSE.exe!2019/10/16:23:45:21!860a3!"

    def test_trailing_nulls_are_stripped(self):
        blob = "Dnscache".encode("utf-16-le") + b"\x00\x00"
        assert decode_app(blob) == "Dnscache"

    def test_empty_yields_none(self):
        assert decode_app(b"") is None
        assert decode_app(b"\x00\x00") is None
        assert decode_app(None) is None


class TestCanHandle:
    def test_accepts_srudb(self):
        parser = SrumParser()
        assert parser.can_handle("C/Windows/System32/sru/SRUDB.dat")
        assert parser.can_handle("c/windows/system32/sru/srudb.dat")

    def test_accepts_backslash_paths(self):
        assert SrumParser().can_handle("C\\Windows\\System32\\sru\\SRUDB.dat")

    def test_rejects_the_transaction_logs_and_siblings(self):
        """SRU.log, SRUtmp.log, SRUDB.jfm and SRU.chk sit beside the database
        and hold no committed rows."""
        parser = SrumParser()
        for name in ("SRU.log", "SRU00044.log", "SRUtmp.log", "SRUDB.jfm", "SRU.chk"):
            assert not parser.can_handle(f"C/Windows/System32/sru/{name}")

    def test_rejects_other_ese_databases(self):
        """Amcache.hve and the Windows Search index are also ESE."""
        parser = SrumParser()
        assert not parser.can_handle("C/Windows/appcompat/Programs/Amcache.hve")
        assert not parser.can_handle("C/ProgramData/Microsoft/Search/Data/Windows.edb")


@needs_collection
class TestAgainstRealDatabase:
    @pytest.fixture(scope="class")
    def events(self):
        path = EVIDENCE / "collection_s1_v3" / SRUM_REL
        result = list(SrumParser().parse(path, SRUM_REL))
        assert result, "parser produced no events; the tests would pass vacuously"
        return result

    def test_both_providers_are_emitted(self, events):
        assert {e.event_type for e in events} == {"network_usage", "resource_usage"}
        assert {e.source_artifact for e in events} == {"srum"}

    def test_timestamps_land_in_the_collection_window(self, events):
        """The regression guard for the OLE decode. A scaling error puts these
        millions of years out and every other assertion still passes."""
        for event in events:
            assert datetime(2026, 1, 1, tzinfo=UTC) <= event.timestamp
            assert event.timestamp <= datetime(2027, 1, 1, tzinfo=UTC)

    def test_most_rows_carry_a_resolved_sid(self, events):
        """Measured 1701/1732. Not all: the unattributed rows have no user."""
        with_sid = [e for e in events if e.user]
        assert len(with_sid) / len(events) > 0.95
        assert all(e.user.startswith("S-1-") for e in with_sid)

    def test_no_row_carries_a_fabricated_application_id(self, events):
        """An unresolvable id yields no event, or the explicit sentinel -- never
        a synthesised `<id 37>` name in a field a rule may join on."""
        for event in events:
            assert event.path
            assert not str(event.path).startswith("<id ")

    def test_the_unattributed_sentinel_is_present_and_bounded(self, events):
        """AppId=1 resolves under no IdType. Measured 31 rows on s1_v3; the
        bytes were still moved, so they are kept rather than dropped."""
        sentinel = [e for e in events if e.path == "<unattributed>"]
        assert sentinel
        assert len(sentinel) / len(events) < 0.05

    def test_network_rows_carry_byte_counters(self, events):
        rows = [e for e in events if e.event_type == "network_usage"]
        assert rows
        for event in rows:
            sent = int(event.details["bytes_sent"])
            received = int(event.details["bytes_received"])
            assert sent >= 0 and received >= 0
            assert sent or received  # a row with neither asserts nothing
            assert event.details["srum_provider"] == "network_data_usage"

    def test_resource_rows_carry_cpu_and_io(self, events):
        rows = [e for e in events if e.event_type == "resource_usage"]
        assert rows
        for event in rows:
            assert int(event.details["bytes_read"]) >= 0
            assert int(event.details["cpu_cycles"]) >= 0
            assert event.details["srum_provider"] == "application_resource_usage"

    def test_every_event_carries_provenance(self, events):
        """CD-003/CD-004."""
        for event in events:
            assert event.source_file == SRUM_REL
            assert event.source_locator

    def test_locators_are_unique_within_the_file(self, events):
        """CD-004. Both providers share a family, so the locator is prefixed by
        provider -- AutoIncId alone collides between the two tables."""
        locators = [e.source_locator for e in events]
        assert len(locators) == len(set(locators))

    def test_timestamp_type_is_recorded(self, events):
        assert all(e.timestamp_type == "recorded" for e in events)


@needs_collection
class TestTheMeasuredAbsence:
    """SRUM does not record the scenario binary on EITHER host, for two
    different reasons, and both are evidence rather than parser faults."""

    def test_srum_horizon_stops_before_the_s1v3_execution(self):
        """s1_v3: the last flush is 11:48 and the payload ran at 11:50:09, so
        zero rows exist at or after the execution for ANY program. Absence
        there is a collection-timing fact with a measurable boundary."""
        path = EVIDENCE / "collection_s1_v3" / SRUM_REL
        events = list(SrumParser().parse(path, SRUM_REL))
        executed_at = datetime(2026, 9, 13, 11, 50, 9, tzinfo=UTC)
        assert max(e.timestamp for e in events) < executed_at

    def test_s1v2_flushed_after_the_execution_and_still_never_names_it(self):
        """s1_v2 is the control for that explanation, and it refutes it as a
        general claim: SRUM flushed well past the 22:57 execution there and
        `invoice_scan.exe` is still absent. On that host the limit is duration
        -- every program SRUM names ran long enough to cross a sampling
        interval, and the payload exits immediately."""
        path = EVIDENCE / "collection_s1_v2" / SRUM_REL
        if not path.is_file():
            pytest.skip("collection_s1_v2 not present")
        events = list(SrumParser().parse(path, SRUM_REL))
        executed_at = datetime(2026, 8, 23, 22, 57, 15, tzinfo=UTC)
        assert [e for e in events if e.timestamp >= executed_at]
        assert not [e for e in events if "invoice" in str(e.path).lower()]


@needs_collection
class TestAcrossCollections:
    @pytest.mark.parametrize(
        "collection,network,resource",
        [
            ("collection_clean_a", 800, 5379),
            ("collection_clean_b", 800, 5379),
            ("collection_s1_v2", 1065, 7288),
            ("collection_clean_c", 279, 785),
            ("collection_s1_v3", 334, 1398),
        ],
    )
    def test_measured_row_counts(self, collection, network, resource):
        """Measured 2026-09-17 through ingest.collect_events, not assumed."""
        path = EVIDENCE / collection / SRUM_REL
        if not path.is_file():
            pytest.skip(f"{collection} not present")
        events = list(SrumParser().parse(path, SRUM_REL))
        counts = {"network_usage": 0, "resource_usage": 0}
        for event in events:
            counts[event.event_type] += 1
        assert counts["network_usage"] == network
        assert counts["resource_usage"] == resource
