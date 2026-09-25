from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import anomaly as anomaly_layer
from . import features as feature_layer
from .core import manifest as manifest_mod
from .core import narration as narration_mod
from .core import report_html as report_html_mod
from .core import run_json as run_json_mod
from .core.engine import run as run_rules
from .core.entity_score import aggregate as aggregate_entities
from .core.entity_score import aggregate_by_kind as aggregate_entities_by_kind
from .core.entity_score import summary_lines_by_kind as entity_summary_lines
from .core.report import summary_lines, write_findings_csv
from .core.ruleset import RuleError, load_rules
from .ingest import collect_events
from .timeline import sort_events, write_csv

#: Rules live beside the package, not inside it, so a checkout without them
#: still produces a timeline. Resolved relative to the repository root.
DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dfir_triage_pipeline")
    p.add_argument("collection", type=Path, help="KAPE collection root directory")
    p.add_argument("--output", type=Path, required=True, help="timeline CSV path")
    p.add_argument("--findings", type=Path, help="findings CSV path (optional)")
    p.add_argument("--rules", type=Path, default=DEFAULT_RULES, help="rule directory")
    p.add_argument("--no-rules", action="store_true", help="produce the timeline only")
    p.add_argument(
        "--run-json",
        type=Path,
        help=(
            "write the canonical run.json here, plus findings.csv, anomalies.csv "
            "and a SHA-256 manifest beside it. The CSVs are DERIVED from run.json "
            "so they cannot disagree with it."
        ),
    )
    p.add_argument(
        "--report",
        action="store_true",
        help=(
            "also render report.html beside run.json. Reference renderer: "
            "Person A owns the report template, and this proves run.json carries "
            "everything a report needs."
        ),
    )
    p.add_argument(
        "--baseline",
        type=Path,
        help=(
            "a clean collection from the SAME HOST to fit the anomaly model on. "
            "Without it no percentiles are produced. Fitting on one machine and "
            "scoring another flags most rows and the ranking is uninterpretable "
            "-- the run reports that rather than hiding it."
        ),
    )
    p.add_argument(
        "--view",
        action="store_true",
        help=(
            "when the run is written, open it in the viewer (viewer/, its own "
            "Streamlit venv) in a separate window. Requires --run-json. A missing "
            "viewer environment is reported, never an error: the run is already "
            "written and hashed."
        ),
    )
    p.add_argument("--log-level", default="WARNING")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.view and not args.run_json:
        parser.error("--view needs --run-json: the viewer opens the run.json this run writes")
    logging.basicConfig(level=args.log_level.upper(), format="%(levelname)s %(message)s")

    if not args.collection.is_dir():
        print(f"error: not a directory: {args.collection}", file=sys.stderr)
        return 2

    events, stats = collect_events(args.collection)
    ordered = sort_events(events)
    write_csv(ordered, args.output)

    print(f"Collection : {args.collection}")
    print(f"Files      : {stats.files_seen} seen, {stats.files_handled} handled, "
          f"{stats.files_skipped} skipped, {stats.files_failed} failed")
    print(f"Events     : {stats.events_total}")
    for artifact in sorted(stats.events_by_artifact):
        print(f"  {artifact}: {stats.events_by_artifact[artifact]}")
    if ordered:
        print(f"Time range : {ordered[0].timestamp_iso} .. {ordered[-1].timestamp_iso}")
    for name, rel, err in stats.failures:
        print(f"  FAILED {name} :: {rel} :: {err}")
    print(f"Output     : {args.output}")

    if args.no_rules:
        return 0
    if not args.rules.is_dir():
        print(f"Rules      : {args.rules} not found; timeline only")
        return 0

    try:
        rules = load_rules(args.rules)
    except RuleError as exc:
        # A malformed rule aborts the run rather than silently matching nothing
        # (schema section 3.4). The timeline above is already written.
        print(f"error: {exc}", file=sys.stderr)
        return 3

    findings, engine_stats = run_rules(rules, ordered)
    print()
    for line in summary_lines(findings, engine_stats):
        print(line)

    # Entity view. An analyst triages entities rather than rule matches, and one
    # binary can be named by several rules -- see core/entity_score.py.
    #
    # Ranked per KIND (D-058): a user's score and a binary's score do not
    # measure the same thing, and printing them as neighbouring rows of one
    # table invited the comparison. entity.host is not scored at all.
    print()
    for line in entity_summary_lines(aggregate_entities_by_kind(findings)):
        print(line)

    if args.findings:
        write_findings_csv(findings, args.findings)
        print()
        print(f"Findings   : {args.findings}")

    if args.run_json:
        _write_run_artifacts(args, ordered, findings, stats, engine_stats)
        if args.view:
            from . import viewer_launch

            print()
            print(f"Viewer     : {viewer_launch.launch(args.run_json)}")
    return 0


def _score_anomalies(baseline: Path, events):
    """Fit on the baseline collection and score `events`.

    Returns (scores, unscored_families, warning, scorer_name). The warning is
    non-empty when the outlier rate says the baseline does not apply to this
    collection -- most often because the two came from different machines. The
    scorer_name comes from the model that actually scored, so run.json records
    the algorithm used rather than re-reading the flag.
    """
    baseline_events, _ = collect_events(baseline)
    if not baseline_events:
        return [], None, "baseline collection produced no events", anomaly_layer._selected_scorer()

    rarity = feature_layer.build_rarity_index(baseline_events)
    model = anomaly_layer.PerFamilyModel().fit(baseline_events, rarity)
    scores = model.score(events, rarity)
    summary = anomaly_layer.summarise(scores)
    warning = anomaly_layer.baseline_warning(summary.get("outlier_rate", 0.0))
    return scores, model.unscored_families, warning, model.scorer_name


def _write_run_artifacts(args, ordered, findings, stats, engine_stats) -> None:
    """Build run.json, derive the exports, and hash all four."""
    scores: list = []
    unscored = None
    # The selected scorer, so run.json records it even on a run with no baseline
    # (no scoring happened, but the config that would have been used is honest).
    scorer_name = anomaly_layer._selected_scorer()
    if args.baseline:
        scores, unscored, warning, scorer_name = _score_anomalies(args.baseline, ordered)
        print()
        print(f"Anomalies  : {len(scores)} rows scored against {args.baseline.name}")
        if warning:
            # Printed rather than logged: a mismatched baseline makes every
            # number below it uninterpretable, and a WARNING-level log line is
            # exactly what a hurried reader skips.
            print(f"  !! {warning}")

    doc = run_json_mod.build(
        collection=args.collection,
        events=ordered,
        findings=findings,
        entities=aggregate_entities(findings),
        scores=scores,
        ingest_stats=stats,
        engine_stats=engine_stats,
        unscored_families=unscored,
        scorer=scorer_name,
    )

    # LLM narration is optional and off by default (DFIR_NARRATION unset). When
    # enabled it is written into `doc` HERE -- before run.json is serialised and
    # hashed -- so the manifest covers it exactly like the derived CSVs and the
    # report. It is non-authoritative (is_verdict false) and can never alter a
    # finding; a backend failure is recorded as status='error', not raised, so a
    # run never aborts for want of narration.
    if narration_mod.narration_enabled():
        doc["narration"] = narration_mod.narrate(doc)
        status = doc["narration"].get("status")
        print()
        print(f"Narration  : {doc['narration']['backend']}:{doc['narration']['model']} -> {status}")
        if status == "rejected":
            unresolved = doc["narration"]["validation"]["unresolvable"]
            print(f"  !! rejected -- unresolved citations: {unresolved}")
        elif status == "error":
            print(f"  !! error -- {doc['narration']['error']}")

    out = args.run_json
    hashes = {out.name: run_json_mod.write(doc, out)}
    findings_csv = out.with_name("findings.csv")
    anomalies_csv = out.with_name("anomalies.csv")
    hashes[findings_csv.name] = manifest_mod.write_findings_csv(doc, findings_csv)
    hashes[anomalies_csv.name] = manifest_mod.write_anomalies_csv(doc, anomalies_csv)

    if args.report:
        # Rendered BEFORE the manifest is written, so the report is inside its
        # hash coverage. A generated artifact outside the manifest is a
        # generated artifact with no recorded provenance -- the thing the
        # manifest exists to prevent, and the same reason the LLM narration is
        # written back into run.json before hashing.
        report_path = out.with_name("report.html")
        hashes[report_path.name] = report_html_mod.write(out, report_path)

    manifest_path = out.with_name("manifest.sha256")
    manifest_mod.write_manifest(hashes, manifest_path)

    print()
    print(f"Run JSON   : {out}")
    derived = [findings_csv.name, anomalies_csv.name]
    if args.report:
        derived.append("report.html")
    print(f"  derived  : {', '.join(derived)}")
    print(f"  manifest : {manifest_path.name}")
    for name in sorted(hashes):
        print(f"    {hashes[name][:16]}...  {name}")


if __name__ == "__main__":
    raise SystemExit(main())
