"""Measure every rule against every collection and compare with `expected:`.

    python tools/measure_rules.py                 # all five collections
    python tools/measure_rules.py clean_c s1_v3   # a subset

For each collection this runs the real ingest (every parser, as the pipeline
does) and the real engine over the full rule set, then prints each rule's
finding count beside the figure its `expected:` block declares. A declared
number that no longer matches is reported as DRIFT: either the rule, a parser,
or the evidence changed, and the declaration is now a claim nobody measured.

This is the instrument behind every measured `expected:` figure added from
2026-09-24 on. `expected:` blocks written before then were measured by hand
runs recorded in docs/evidence; this makes the measurement repeatable.

Read-only: it writes nothing but its report to stdout.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dfir_triage_pipeline.core import engine  # noqa: E402
from dfir_triage_pipeline.core.ruleset import load_rules  # noqa: E402
from dfir_triage_pipeline.ingest import collect_events  # noqa: E402

EVIDENCE = Path.home() / "dfir-evidence"
COLLECTIONS = ["clean_a", "clean_b", "s1_v2", "clean_c", "s1_v3"]


def main(argv: list[str]) -> int:
    wanted = argv or COLLECTIONS
    rules = load_rules(ROOT / "rules")
    measured: dict[str, dict[str, int]] = {}
    for name in wanted:
        root = EVIDENCE / f"collection_{name}"
        if not root.is_dir():
            print(f"!! {root} not found", file=sys.stderr)
            return 2
        t0 = time.time()
        events, _ = collect_events(root)
        _, stats = engine.run(rules, events)
        measured[name] = dict(stats.findings_by_rule)
        print(f"# {name}: {len(events)} events, {time.time() - t0:.0f}s", file=sys.stderr)

    drift = 0
    print(f"{'rule':<14}" + "".join(f"{n:>16}" for n in wanted))
    for rule in sorted(rules, key=lambda r: r.rule_id):
        declared = dict(rule.expected)
        cells = []
        for n in wanted:
            got = measured[n].get(rule.rule_id, 0)
            want = declared.get(n)
            if want is None or str(want) == "unmeasured":
                cells.append(f"{got} (unmeas.)")
            elif str(got) == str(want):
                cells.append(f"{got}")
            else:
                cells.append(f"{got} DRIFT/{want}")
                drift += 1
        print(f"{rule.rule_id:<14}" + "".join(f"{c:>16}" for c in cells))
    print(f"\n{drift} drift(s) against declared expected figures")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
