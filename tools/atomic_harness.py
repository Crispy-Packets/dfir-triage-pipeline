"""Multi-channel rule coverage against the atomic-evtx corpus.

`rule_harness.py` runs over sbousseaden's samples, where each file is ONE
channel from one machine -- so a correlation rule joining two artifact families
has nothing to join and cannot be exercised at all.

This corpus is different: every technique directory holds Security, System and
PowerShell captured from the SAME run, so a multi-channel collection can be
staged per technique and the correlation rules finally get evidence to work on.

    python tools/atomic_harness.py <path to atomic-evtx checkout>

**Files are read from git, not from the working tree.** The repository contains
directory names with colons (`Brute Force:Credential Stuffing...`), which are
illegal on Windows, so `git checkout` fails partway and leaves an empty tree.
`git show HEAD:<path>` reads the blob regardless, which is why this harness
takes a repository rather than a directory of files.

**What it can and cannot establish**, stated because a coverage table invites
being read as more than it is:

* It proves a rule FIRES on evidence of a technique, captured by someone else.
  It is not a detection rate and says nothing about false positives -- that
  needs a labelled corpus with negatives.
* **EID 4688 is absent from this corpus entirely.** Process-creation rules
  cannot fire here however well they work, and their absence below is a
  property of the capture rather than of the rule.
* The PowerShell files are the LEGACY `Windows PowerShell` channel (EID
  400/600/800), not `Microsoft-Windows-PowerShell/Operational` (4104). The
  parser reads only the latter, by design -- the legacy channel carries no
  script blocks. So PowerShell evidence here is visible to this survey but not
  to the pipeline.

**The anomaly layer is not involved.** 4,244 techniques from a lab reset between
runs is 4,244 different baselines; fitting a model across them is the cross-host
failure `anomaly.baseline_warning` exists to catch.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from dfir_triage_pipeline.core.engine import run as run_rules  # noqa: E402
from dfir_triage_pipeline.core.ruleset import load_rules  # noqa: E402
from dfir_triage_pipeline.ingest import collect_events  # noqa: E402
from dfir_triage_pipeline.timeline import sort_events  # noqa: E402

#: Suffix in the corpus -> filename the parser's `can_handle` expects.
_CHANNELS = {
    "_Security.evtx": "Security.evtx",
    "_System.evtx": "System.evtx",
}

_LOG_SUBDIR = Path("C/Windows/System32/winevt/logs")
_TACTIC = re.compile(r"attacks_by_category[^/]*/([^/]+)/")


def git_files(repo: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "HEAD", "--name-only"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.splitlines()


def git_blob(repo: Path, path: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), "show", f"HEAD:{path}"], capture_output=True
    ).stdout


def group_by_technique(names: list[str]) -> dict[str, dict[str, str]]:
    """One entry per technique directory, holding each parsed channel."""
    groups: dict[str, dict[str, str]] = defaultdict(dict)
    for name in names:
        if not name.endswith(".evtx") or "/json/" in name:
            continue
        directory, _, filename = name.rpartition("/")
        for suffix, target in _CHANNELS.items():
            if filename.endswith(suffix):
                groups[directory][target] = name
    return groups


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", type=Path, help="atomic-evtx git checkout")
    parser.add_argument("--rules", type=Path, default=REPO / "rules")
    parser.add_argument(
        "--limit",
        type=int,
        default=400,
        help="techniques to run (default 400; the corpus holds 4,244)",
    )
    args = parser.parse_args(argv)

    if not (args.repo / ".git").is_dir():
        print(f"error: not a git repository: {args.repo}", file=sys.stderr)
        return 2

    rules = load_rules(args.rules)
    groups = group_by_technique(git_files(args.repo))
    multi = {d: g for d, g in groups.items() if len(g) >= 2}

    print(f"{len(rules)} rules")
    print(f"{len(groups)} technique directories, {len(multi)} with 2+ parsed channels")

    # Spread the sample across tactics rather than taking the first N, which
    # would all come from one tactic and would exercise one kind of technique.
    selected = sorted(multi)
    step = max(1, len(selected) // args.limit)
    selected = selected[::step][: args.limit]
    print(f"running {len(selected)} techniques, spread across the corpus\n")

    fired: dict[str, set[str]] = defaultdict(set)
    findings_by_rule: Counter[str] = Counter()
    tactics: Counter[str] = Counter()
    parsed = 0
    empty = 0

    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / "collection"
        for directory in selected:
            logs = staging / _LOG_SUBDIR
            if staging.exists():
                for old in logs.glob("*.evtx"):
                    old.unlink()
            logs.mkdir(parents=True, exist_ok=True)

            for target, source in groups[directory].items():
                blob = git_blob(args.repo, source)
                if blob:
                    (logs / target).write_bytes(blob)

            try:
                events, _ = collect_events(staging)
            except Exception:
                continue
            if not events:
                empty += 1
                continue
            parsed += 1

            found, _ = run_rules(rules, sort_events(events))
            label = directory.rsplit("/", 1)[-1]
            tactic_match = _TACTIC.search(directory)
            tactic = tactic_match.group(1) if tactic_match else "?"
            for finding in found:
                fired[finding.rule_id].add(f"{tactic}/{label}")
                findings_by_rule[finding.rule_id] += 1
                tactics[tactic] += 1

    print(f"{parsed} techniques produced events, {empty} produced none\n")

    print("=== RULE COVERAGE ===")
    print("A count is how many techniques contained the artifact, not how many")
    print("are about it: this corpus clears the Security log before most")
    print("captures, so R-ATOMIC-0002 matches real evidence throughout.")
    print()
    for rule in sorted(rules, key=lambda r: r.rule_id):
        hits = sorted(fired.get(rule.rule_id, ()))
        if hits:
            print(
                f"  {rule.rule_id}  FIRED on {len(hits)} technique(s), "
                f"{findings_by_rule[rule.rule_id]} finding(s)"
            )
            for name in hits[:3]:
                print(f"      {name}")
            if len(hits) > 3:
                print(f"      ... {len(hits) - 3} more")
        else:
            print(f"  {rule.rule_id}  no findings")

    if tactics:
        print("\n=== FINDINGS BY ATT&CK TACTIC ===")
        for tactic, count in tactics.most_common():
            print(f"  {count:>5}  {tactic}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
