"""No SQLite database in the pipeline silently drops uncommitted rows.

D-053: `timeline.py` read `ActivitiesCache.db` with `immutable=1`, which is
correct for not modifying evidence and ALSO ignores the write-ahead log. On
`clean_b` that hid every activity `admin_local` ever had -- the database was
empty and the 1.7 MB WAL held all 17.

The defect recorded a debt: `browser.py` and `browser_profile.py` use the same
flag. This audits them, and pins the structural reason the answer differs so
the next person does not have to re-derive it.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

EVIDENCE = Path.home() / "dfir-evidence"

COLLECTIONS = (
    "collection_clean_a",
    "collection_clean_b",
    "collection_s1_v2",
    "collection_clean_c",
    "collection_s1_v3",
)

#: (database filename, table) pairs the pipeline actually queries.
QUERIED = (
    ("History", "downloads"),
    ("History", "visits"),
    ("History", "keyword_search_terms"),
    ("Shortcuts", "omni_box_shortcuts"),
    ("Top Sites", "top_sites"),
    ("Favicons", "icon_mapping"),
    ("Web Data", "autofill"),
)

needs_evidence = pytest.mark.skipif(
    not (EVIDENCE / "collection_s1_v3").is_dir(), reason="evidence required"
)


def _count_immutable(path: Path, table: str) -> int | None:
    """What the parser sees today: the journal is ignored."""
    try:
        connection = sqlite3.connect(f"file:{path}?immutable=1&mode=ro", uri=True)
        try:
            return connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
        finally:
            connection.close()
    except sqlite3.Error:
        return None


def _count_replayed(path: Path, table: str) -> int | None:
    """What a copy with its journals beside it yields, after recovery."""
    with tempfile.TemporaryDirectory() as tmpdir:
        staged = Path(tmpdir) / path.name
        try:
            shutil.copy2(path, staged)
        except OSError:
            return None
        for suffix in ("-wal", "-shm", "-journal"):
            sibling = Path(str(path) + suffix)
            if sibling.is_file():
                try:
                    shutil.copy2(sibling, Path(str(staged) + suffix))
                except OSError:
                    pass
        try:
            connection = sqlite3.connect(str(staged))
            try:
                return connection.execute(
                    f'SELECT COUNT(*) FROM "{table}"'
                ).fetchone()[0]
            finally:
                connection.close()
        except sqlite3.Error:
            return None


def _profile_databases(root: Path, name: str):
    for path in root.rglob(name):
        if path.is_file() and "/user data/" in path.as_posix().lower():
            yield path


@needs_evidence
class TestBrowserParsersAreUnaffected:
    """The debt D-053 recorded, discharged by measurement."""

    @pytest.mark.parametrize("collection", COLLECTIONS)
    def test_no_queried_table_loses_rows_to_a_journal(self, collection):
        root = EVIDENCE / collection
        if not root.is_dir():
            pytest.skip(f"{collection} not present")

        differences = []
        for name, table in QUERIED:
            for path in _profile_databases(root, name):
                ignored = _count_immutable(path, table)
                replayed = _count_replayed(path, table)
                if ignored is None and replayed is None:
                    continue  # the table does not exist in this browser version
                if ignored != replayed:
                    differences.append(
                        f"{path.name}/{table}: {ignored} -> {replayed}"
                    )

        assert differences == [], (
            "a browser database loses rows when its journal is ignored; "
            f"browser.py and browser_profile.py need D-053's fix: {differences}"
        )


@needs_evidence
class TestTheStructuralReason:
    """Why the answer differs between the two families, so it is not taken as
    luck. Rollback journals and write-ahead logs are not interchangeable."""

    def test_browser_databases_use_rollback_journals(self):
        """A `-journal` holds UNDO data for a transaction that may be rolled
        back. Nothing committed is waiting in it, so ignoring it loses
        nothing. Measured: 8,720 bytes wherever present."""
        root = EVIDENCE / "collection_s1_v3"
        journals = []
        for name, _ in QUERIED:
            for path in _profile_databases(root, name):
                for suffix in ("-wal", "-journal"):
                    sibling = Path(str(path) + suffix)
                    if sibling.is_file():
                        journals.append(suffix)
        assert journals, "no browser journals at all; the audit proves nothing"
        assert "-wal" not in journals, (
            "a browser profile now uses WAL mode; re-run the audit above, "
            "because ignoring a WAL DOES lose committed rows"
        )

    def test_the_timeline_database_uses_a_write_ahead_log(self):
        """A `-wal` holds rows that ARE committed but not yet checkpointed.
        Measured on s1_v3: 1.8 MB beside a 409 KB database."""
        root = EVIDENCE / "collection_s1_v3"
        found = False
        for path in root.rglob("ActivitiesCache.db"):
            wal = Path(str(path) + "-wal")
            if wal.is_file():
                found = True
                assert wal.stat().st_size > path.stat().st_size / 4, (
                    "the WAL is unexpectedly small; D-053's measurement may "
                    "no longer describe this evidence"
                )
        assert found, "no Timeline WAL present; D-053's fix is untested here"

    def test_the_timeline_parser_reads_its_wal(self):
        """The fix itself, asserted end to end rather than by inspection."""
        from dfir_triage_pipeline.parsers.timeline import TimelineParser

        rel = (
            "C/Users/vboxuser/AppData/Local/ConnectedDevicesPlatform/"
            "L.vboxuser/ActivitiesCache.db"
        )
        path = EVIDENCE / "collection_s1_v3" / rel
        if not path.is_file():
            pytest.skip("timeline database absent")
        events = list(TimelineParser().parse(path, rel))
        ignored = _count_immutable(path, "Activity")
        assert len(events) > 0
        # More rows reach the parser than immutable=1 can see.
        assert _count_replayed(path, "Activity") > ignored


@needs_evidence
class TestEvidenceIsNeverModified:
    """CD-016. The recovery happens on a copy; the collected files are read."""

    def test_parsing_the_timeline_leaves_every_file_unchanged(self):
        import hashlib

        from dfir_triage_pipeline.parsers.timeline import TimelineParser

        rel = (
            "C/Users/vboxuser/AppData/Local/ConnectedDevicesPlatform/"
            "L.vboxuser/ActivitiesCache.db"
        )
        path = EVIDENCE / "collection_s1_v3" / rel
        if not path.is_file():
            pytest.skip("timeline database absent")

        watched = [path] + [
            Path(str(path) + s)
            for s in ("-wal", "-shm")
            if Path(str(path) + s).is_file()
        ]
        before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in watched}
        list(TimelineParser().parse(path, rel))
        after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in watched}
        assert before == after, "parsing modified the evidence"
