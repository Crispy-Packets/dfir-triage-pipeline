"""Exercise the rule set against an independent public EVTX corpus.

Four of the ten rules fire on nothing in this project's own collections --
R-ATOMIC-0004 (services), R-ATOMIC-0005 (RDP), R-CORR-0004 (service then log
clear), and on host 2 also R-ATOMIC-0003 (encoded PowerShell). They are not
broken; the corpus simply contains no RDP, no service installation and no
encoded PowerShell. Untested code paths reported as passing checks is the thing
this project has refused throughout, so they are exercised here instead.

    python tools/rule_harness.py <path to evtx-attack-samples>

**This is a RULE test, not a model input.** The samples come from dozens of
different machines with no clean baseline between them, so training an anomaly
model on them would produce the cross-host failure `baseline_warning` exists to
catch. Nothing here touches the anomaly layer.

**Two things it cannot do**, both stated rather than worked around:

* It proves a rule FIRES on evidence of a technique. It does not prove the rule
  would fire on every instance of that technique, nor that it would not fire on
  a benign one -- those need a labelled corpus with negatives, which this is not.
* Each file is one channel from one machine. A correlation rule joining two
  channels has nothing to join, so R-CORR-* results here are expected to be
  empty and are reported as such rather than as failures.

The parser matches on FILENAME (`security.evtx`, `system.evtx`,
`microsoft-windows-powershell%4operational.evtx`) and these files are named by
scenario, so each is copied to a temporary tree under the name its channel
requires. That copy is the only accommodation made; no sample is edited.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

import evtx as evtx_lib

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from dfir_triage_pipeline.core.engine import run as run_rules  # noqa: E402
from dfir_triage_pipeline.core.ruleset import load_rules  # noqa: E402
from dfir_triage_pipeline.ingest import collect_events  # noqa: E402
from dfir_triage_pipeline.timeline import sort_events  # noqa: E402

_CHANNEL = re.compile(r"<Channel>([^<]+)</Channel>")

#: Channel name -> the filename the parser's can_handle expects, and the
#: collection-relative directory it must sit in.
_CHANNEL_FILENAME = {
    "Security": "Security.evtx",
    "System": "System.evtx",
    "Microsoft-Windows-PowerShell/Operational": (
        "Microsoft-Windows-PowerShell%4Operational.evtx"
    ),
}

_LOG_SUBDIR = Path("C/Windows/System32/winevt/logs")


def channel_of(path: Path) -> str | None:
    """The Channel of the file's first record.

    EVTX stores records as BINARY XML, so the channel name does not appear as
    readable bytes on disk -- it exists only after `PyEvtxParser` renders a
    record. Reading the raw file and searching for `<Channel>` finds nothing,
    which is the first thing this harness got wrong.

    One record is enough: a single .evtx file is one channel by construction.
    """
    try:
        parser = evtx_lib.PyEvtxParser(str(path))
        for record in parser.records():
            match = _CHANNEL.search(record["data"])
            return match.group(1) if match else None
    except Exception:
        return None
    return None


def stage(sample: Path, channel: str, root: Path) -> Path:
    """Copy one sample into a collection-shaped tree under its channel name."""
    target_dir = root / _LOG_SUBDIR
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / _CHANNEL_FILENAME[channel]
    shutil.copy2(sample, target)
    return target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("samples", type=Path, help="evtx-attack-samples checkout")
    parser.add_argument("--rules", type=Path, default=REPO / "rules")
    args = parser.parse_args(argv)

    if not args.samples.is_dir():
        print(f"error: not a directory: {args.samples}", file=sys.stderr)
        return 2

    rules = load_rules(args.rules)
    print(f"{len(rules)} rules loaded\n")

    files = sorted(args.samples.rglob("*.evtx"))
    usable: list[tuple[Path, str]] = []
    channels: Counter[str] = Counter()
    for sample in files:
        channel = channel_of(sample)
        if channel:
            channels[channel] += 1
        if channel in _CHANNEL_FILENAME:
            usable.append((sample, channel))

    print(f"{len(files)} samples, {len(usable)} in a channel this pipeline parses")
    print("channels present:")
    for channel, count in channels.most_common(8):
        mark = "  <- parsed" if channel in _CHANNEL_FILENAME else ""
        print(f"  {count:>4}  {channel}{mark}")
    print()

    fired: dict[str, list[str]] = {}
    events_by_rule: Counter[str] = Counter()
    parsed = 0
    failed: list[str] = []

    for sample, channel in usable:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage(sample, channel, root)
            try:
                events, _ = collect_events(root)
            except Exception as exc:  # pragma: no cover - sample-dependent
                failed.append(f"{sample.name}: {exc}")
                continue
            if not events:
                continue
            parsed += 1
            findings, _ = run_rules(rules, sort_events(events))
            for finding in findings:
                fired.setdefault(finding.rule_id, []).append(
                    f"{sample.parent.name}/{sample.name}"
                )
                events_by_rule[finding.rule_id] += 1

    print(f"{parsed} samples produced events\n")
    if failed:
        print(f"{len(failed)} samples failed to parse (reported, not hidden):")
        for line in failed[:5]:
            print(f"  {line}")
        print()

    print("=== RULE COVERAGE ===")
    print("A rule firing on many samples is not broad detection. Several of")
    print("these captures begin with a genuine EID 1102 because the collector")
    print("cleared the log before recording the technique it was isolating, so")
    print("R-ATOMIC-0002 matches real evidence in files named for something")
    print("else. The count says how many samples contain the artifact, not how")
    print("many are about the technique.")
    print()
    for rule in sorted(rules, key=lambda r: r.rule_id):
        hits = fired.get(rule.rule_id, [])
        if hits:
            unique = sorted(set(hits))
            print(f"  {rule.rule_id}  FIRED on {len(unique)} sample(s), "
                  f"{events_by_rule[rule.rule_id]} finding(s)")
            for name in unique[:4]:
                print(f"      {name}")
            if len(unique) > 4:
                print(f"      ... {len(unique) - 4} more")
        else:
            reason = (
                "correlation rule: one channel per sample, nothing to join"
                if rule.kind == "correlation"
                else "no sample in a parsed channel carries this technique"
            )
            print(f"  {rule.rule_id}  no findings  ({reason})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
