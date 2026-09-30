r"""`WebCacheV01.dat`: the WinINet history, cache and transfer index.

The property that would silently produce wrong output is the container
mapping: rows live in `Container_<n>` tables whose number means nothing on its
own. Reading `Container_5` without consulting `Containers` would report cache
entries as browsing history.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from conftest import cached_collect_events as collect_events

from dfir_triage_pipeline.parsers.webcache import (
    WebCacheParser,
    filetime_to_utc,
    split_visited,
)

EVIDENCE = Path.home() / "dfir-evidence"

needs_s1v3 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3").is_dir(), reason="s1_v3 required"
)
needs_s1v2 = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v2").is_dir(), reason="s1_v2 required"
)


class TestFiletime:
    def test_the_measured_value(self):
        """`AccessedTime` on s1_v3 reads 134336824935732258. This is FILETIME,
        not the WebKit microseconds browser.py handles nor the OLE dates
        srum.py handles -- three time formats in one pipeline."""
        result = filetime_to_utc(134336824935732258)
        assert result is not None
        assert (result.year, result.month) == (2026, 9)

    def test_zero_and_absurd(self):
        assert filetime_to_utc(0) is None
        assert filetime_to_utc(-1) is None
        assert filetime_to_utc(True) is None
        assert filetime_to_utc(2**63 - 1) is None


class TestSplitVisited:
    def test_the_user_is_inside_the_record(self):
        """What lets this family attribute a visit without inferring the
        account from the file's location."""
        user, url = split_visited("Visited: vboxuser@https://example.com/x")
        assert user == "vboxuser"
        assert url == "https://example.com/x"

    def test_the_daily_container_prefix_is_stripped(self):
        user, url = split_visited(
            ":2026091020260911: vboxuser@https://login.live.com/oauth20"
        )
        assert user == "vboxuser"
        assert url.startswith("https://login.live.com")

    def test_a_record_with_no_marker_keeps_its_url(self):
        """No user is guessed from surrounding text."""
        user, url = split_visited("DOMStore:https://www.bing.com/")
        assert user is None
        assert url == "https://www.bing.com/"

    def test_an_email_in_a_url_is_not_mistaken_for_an_account(self):
        """`@` appears in ordinary URLs. A candidate containing a slash or a
        colon is part of the address, not a user name."""
        user, url = split_visited("Visited: https://site/a@b/c")
        assert user is None

    def test_background_transfer_marker(self):
        user, url = split_visited(":BackgroundTransferApi:87E89635-3E6A")
        assert user is None
        assert "87E89635" in url


class TestCanHandle:
    def test_accepts_the_database(self):
        parser = WebCacheParser()
        base = "C/Users/x/AppData/Local/Microsoft/Windows/WebCache"
        assert parser.can_handle(f"{base}/WebCacheV01.dat")
        assert parser.can_handle(f"{base}/webcachev01.dat".upper().replace("\\", "/"))

    def test_rejects_the_ese_journal_and_checkpoint(self):
        """V01.log, V01.chk and WebCacheV01.jfm hold no committed rows."""
        parser = WebCacheParser()
        base = "C/Users/x/AppData/Local/Microsoft/Windows/WebCache"
        for name in ("V01.log", "V01.chk", "WebCacheV01.jfm", "V010000A.log"):
            assert not parser.can_handle(f"{base}/{name}")

    def test_rejects_other_ese_databases(self):
        parser = WebCacheParser()
        assert not parser.can_handle("C/Windows/System32/SRU/SRUDB.dat")
        assert not parser.can_handle("C/Windows/appcompat/Programs/Amcache.hve")


@needs_s1v3
class TestAgainstTheRealDatabase:
    @pytest.fixture(scope="class")
    def events(self):
        root = EVIDENCE / "collection_s1_v3"
        parser = WebCacheParser()
        result = []
        for path in root.rglob("WebCacheV01.dat"):
            result.extend(parser.parse(path, path.relative_to(root).as_posix()))
        assert result, "parser produced no events"
        return result

    def test_only_activity_containers_are_emitted(self, events):
        """`Content` containers index cache files describing what a page
        loaded, not what a person did. Emitting them would bury the history
        under tens of thousands of cache entries."""
        containers = {e.details["container"] for e in events}
        assert not any(c == "Content" for c in containers)
        assert {e.event_type for e in events} <= {
            "page_visited",
            "dom_storage",
            "background_transfer",
        }

    def test_visits_are_attributed_to_the_hive_owner(self, events):
        visits = [e for e in events if e.event_type == "page_visited"]
        assert visits
        attributed = [e for e in visits if e.user]
        assert attributed
        assert all(e.user == "vboxuser" for e in attributed)

    def test_the_container_name_is_recorded(self, events):
        """So a consumer never has to infer meaning from a bare number."""
        assert all(e.details["container"] for e in events)
        assert all(e.details["container_id"].isdigit() for e in events)

    def test_daily_history_containers_are_treated_as_history(self, events):
        """`MSHist012026091020260911` bounds a visit to a date range."""
        daily = [
            e for e in events if e.details["container"].startswith("MSHist01")
        ]
        assert daily
        assert all(e.event_type == "page_visited" for e in daily)

    def test_timestamps_land_in_the_collection_window(self, events):
        dated = [e for e in events if e.timestamp_type == "recorded"]
        assert dated
        for event in dated:
            assert datetime(2019, 1, 1, tzinfo=UTC) <= event.timestamp
            assert event.timestamp <= datetime(2030, 1, 1, tzinfo=UTC)

    def test_locators_are_unique_within_a_file(self, events):
        by_file: dict[str, list[str]] = {}
        for event in events:
            by_file.setdefault(event.source_file, []).append(event.source_locator)
        for locators in by_file.values():
            assert len(locators) == len(set(locators))

    def test_no_cached_response_body_is_emitted(self, events):
        """The parser records that an entry exists with its URL and size, and
        does not read the cached content."""
        for event in events:
            assert len(str(event.path)) < 2048
            assert "body" not in event.details
            assert "content" not in event.details


@needs_s1v2
class TestMultiUserAttribution:
    def test_three_accounts_are_separated(self):
        """Host 1 has three profiles, each with its own WebCache. The account
        comes from INSIDE the record, so the separation is recorded rather
        than inferred."""
        root = EVIDENCE / "collection_s1_v2"
        parser = WebCacheParser()
        events = []
        for path in root.rglob("WebCacheV01.dat"):
            events.extend(parser.parse(path, path.relative_to(root).as_posix()))
        users = {e.user for e in events if e.user}
        assert {"Youssef", "janed", "admin_local"} <= users

    def test_the_transfer_volume_is_recorded(self):
        """`file:///Z:/` accesses -- the removable volume the LNK family also
        names. A second, independent record of the same device."""
        root = EVIDENCE / "collection_s1_v2"
        parser = WebCacheParser()
        events = []
        for path in root.rglob("WebCacheV01.dat"):
            events.extend(parser.parse(path, path.relative_to(root).as_posix()))
        assert any("file:///Z:/" in str(e.path) for e in events)


class TestThroughIngest:
    @needs_s1v3
    def test_no_parse_failures(self):
        _, stats = collect_events(EVIDENCE / "collection_s1_v3")
        assert [f for f in stats.failures if f[0] == "webcache"] == []
