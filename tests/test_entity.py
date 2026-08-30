"""Entity resolution (Person A, Week 3, A-5).

CD-021 assigns executable extraction from a service ImagePath to core/entity.py.
These tests pin the extraction against the five forms that clause measured, plus
the sixth that D-032 separated out of the fourth.
"""

from __future__ import annotations

import pytest
from conftest import download, execution, log_cleared, make_event, runkey, service_install

from dfir_triage_pipeline.core import entity


class TestExeName:
    def test_prefers_the_parser_derived_key(self):
        assert entity.exe_name(execution()) == "invoice_scan.exe"

    def test_prefetch_bare_name_still_joins_to_a_full_path(self):
        """The whole point of B-9's path_basename_canonical: Prefetch carries no
        path, so without it the one artifact witnessing the scenario execution
        could never join to the download that carries a full path."""
        assert entity.exe_name(execution()) == entity.exe_name(download())

    def test_log_cleared_has_no_executable(self):
        assert entity.exe_name(log_cleared()) is None


class TestServiceImagePathForms:
    """The five forms CD-021 measured, and D-032's sixth."""

    @pytest.mark.parametrize(
        ("image", "expected"),
        [
            # 1. quoted executable, 27 rows
            ('"C:\\Program Files\\Microsoft SQL Server\\90\\Shared\\sqlwriter.exe"',
             "sqlwriter.exe"),
            # 2. quoted with arguments, part of the same 27
            ('"C:\\...\\MSSQL\\Binn\\sqlservr.exe" -sMSSQLSERVER', "sqlservr.exe"),
            # 3. unquoted drive path with arguments, 6 rows
            ("C:\\Windows\\system32\\svchost.exe -k netsvcs", "svchost.exe"),
            # 4. \SystemRoot NT form, 7 rows
            ("\\SystemRoot\\System32\\drivers\\VBoxWddm.sys", "vboxwddm.sys"),
            # 5. explicit environment variable with arguments, 4 rows (D-032)
            ("%SystemRoot%\\system32\\svchost.exe -k print", "svchost.exe"),
            # 6. root-relative driver image, 10 rows -- D-032's separated form.
            #    No drive, no separator prefix, no variable.
            ("system32\\DRIVERS\\RsFx0800.sys", "rsfx0800.sys"),
            # 7. bare drive path, 1 row
            ("C:\\Windows\\System32\\alg.exe", "alg.exe"),
        ],
    )
    def test_extracts_the_image_from_every_measured_form(self, image, expected):
        event = service_install(image=image)
        assert entity.exe_name(event) == expected

    def test_shortest_leading_prefix_not_longest(self):
        """An argument that is itself a path must not be mistaken for the image.

        An earlier draft of schema 4.2 said 'longest leading prefix'. It was
        wrong: the longest here runs to thing.exe, which is an argument.
        """
        event = service_install(
            image="C:\\Program Files\\App\\run.exe -config C:\\other\\thing.exe"
        )
        assert entity.exe_name(event) == "run.exe"

    def test_unresolvable_command_line_yields_no_key(self):
        """CD-021: emitting no key is a NOT-PARSED outcome Day 5 can count.
        Emitting a wrong one is a fabricated join Day 5 cannot see."""
        event = service_install(image="run this thing please")
        assert entity.exe_name(event) is None


class TestUserKey:
    @pytest.mark.parametrize("raw", ["", "-", "   "])
    def test_absent_forms_are_not_principals(self, raw):
        """CD-022 keeps both, and they are not the same thing -- but neither is
        a principal, so neither joins."""
        assert entity.user_key(make_event(
            __import__("datetime").datetime.now(__import__("datetime").UTC),
            "evtx.security", "logon", "recorded", user=raw,
        )) is None

    @pytest.mark.parametrize(
        "raw",
        ["SYSTEM", "LocalSystem", "LOCAL SERVICE", "NT AUTHORITY\\LOCALSERVICE",
         "NETWORK SERVICE", "DWM-1", "UMFD-0", "WIN-BQVKLIBL3LA$"],
    )
    def test_system_contexts_are_not_joinable(self, raw):
        """A correlation joined on `system` correlates the machine to itself."""
        event = log_cleared(user=raw)
        assert entity.user_key(event) is None

    def test_a_real_account_folds_case_only(self):
        assert entity.user_key(log_cleared(user="Admin_Local")) == "admin_local"

    def test_domain_qualified_and_bare_fold_together(self):
        a = entity.user_key(log_cleared(user="NT AUTHORITY\\LOCALSERVICE"))
        b = entity.user_key(log_cleared(user="LOCAL SERVICE"))
        assert a == b is None


class TestKeysFor:
    def test_absent_keys_are_omitted_never_empty(self):
        keys = entity.keys_for(execution())
        assert "entity.exe_name" in keys
        assert "entity.user" not in keys  # Prefetch carries no user
        assert all(v for v in keys.values())

    def test_host_is_derivable_but_not_joinable(self):
        assert "entity.host" in entity.keys_for(runkey())
        assert "entity.host" not in entity.JOINABLE

    def test_unknown_key_raises_rather_than_returning_none(self):
        with pytest.raises(KeyError):
            entity.resolve(execution(), "entity.department")
