"""A self-contained HTML report rendered from `run.json`.

**Person A owns the report template.** This is a reference renderer: it proves
`run.json` carries everything a report needs, and gives them a working starting
point to take, restyle or replace. It reads the canonical document and nothing
else -- no evidence, no model, no rule engine -- so a change to the report can
never change a result.

Four properties the output has to hold.

**Two panels, never one list.** Rule findings and anomaly percentiles are
different claims: a finding names the artifact and record that produced it, a
percentile is a rank within a population. The acceptance gate requires the ML be
labelled as prioritisation rather than a malicious verdict, and merging them
into one sorted table with one severity column would break that whether or not
a label appeared above it. `shared/DECIDED.md` records why the tier system was
rejected for the same reason.

**Every finding shows its provenance.** `source_file :: source_locator` for
each matched event, on the page rather than in a file the reader has to open.
That clause is what makes "traceable" checkable.

**No JavaScript, no external requests, no fonts.** The output is a forensic
artifact: it must render identically in five years, offline, from a case
archive. A CDN reference would make the report depend on a server outstanding it.

**Deterministic.** Same `run.json` in, byte-identical HTML out. The manifest
covers this file too, so a report that renders differently on each run could not
be hashed.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

# Imported rather than repeated: the panel split and the score filter must name
# the same class, or the report and the ranking disagree about what a verdict is.
from dfir_triage_pipeline.core.entity_score import SCORING_RULE_CLASS

#: Severity ordering for display, worst first. Matches entity_score's, so the
#: two cannot disagree about which of two findings is worse.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")

_CSS = """
:root{--bg:#f6f6f4;--panel:#fff;--ink:#1a1a1a;--dim:#5a5a5a;--line:#d8d6d0;
--crit:#8b1a1a;--high:#a5521a;--med:#7a6a1a;--low:#3a5a3a;--ml:#2a4a6a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:17px;margin:0 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:14px;margin:0 0 6px}
.sub{color:var(--dim);margin:0 0 20px;font-size:13px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:4px;
padding:18px;margin-bottom:22px}
.panel.ml{border-left:4px solid var(--ml)}
.panel.verdict{border-left:4px solid var(--crit)}
.panel.narration{border-left:4px dashed var(--dim)}
.narration-body{font-style:italic;line-height:1.55;margin:8px 0}
.panel.context{border-left:4px solid var(--dim)}
.finding.ctx-only{opacity:.92}
.cls{display:inline-block;font-size:11px;text-transform:uppercase;
letter-spacing:.04em;padding:1px 6px;border-radius:3px;border:1px solid var(--dim);
color:var(--dim);margin-left:6px;vertical-align:1px}
.note{background:#f0efe9;border-left:3px solid var(--dim);padding:10px 12px;
margin:0 0 16px;color:var(--dim);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:6px 8px;border-bottom:2px solid var(--line);
color:var(--dim);font-weight:600;font-size:12px;text-transform:uppercase;
letter-spacing:.04em}
td{padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:none}
.sev{font-weight:700;text-transform:uppercase;font-size:11px;letter-spacing:.04em}
.sev.critical{color:var(--crit)}.sev.high{color:var(--high)}
.sev.medium{color:var(--med)}.sev.low{color:var(--low)}
.finding{border:1px solid var(--line);border-radius:3px;padding:14px;
margin-bottom:12px;background:var(--panel)}
.finding-head{display:flex;justify-content:space-between;gap:12px;
align-items:baseline;margin-bottom:8px}
.rid{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:var(--dim)}
.prov{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;
background:#f0efe9;padding:8px 10px;border-radius:3px;margin-top:8px;
overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.ctx{display:inline-block;background:#e8eef4;color:var(--ml);padding:2px 7px;
border-radius:3px;font-size:12px;margin-top:8px}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
.num{text-align:right;font-variant-numeric:tabular-nums}
.slice{margin-top:10px}
.slice summary{cursor:pointer;color:var(--dim);font-size:12.5px}
.slice table{margin-top:8px;font-size:12px}
.hit{background:#fdf4d8}
footer{color:var(--dim);font-size:12px;margin-top:8px}
"""


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(_SEVERITY_ORDER)


def _run_header(doc: dict[str, Any]) -> str:
    collection = doc["collection"]
    events = doc["events"]
    ingest = doc.get("ingest", {})
    rules = doc.get("rules", {})

    rows = [
        ("Collection", collection["name"]),
        ("Path", collection["path"]),
        ("Events", f"{events['total']:,}"),
        ("Time range", f"{events['first_timestamp_utc']} .. {events['last_timestamp_utc']}"),
    ]
    if ingest:
        rows.append(
            (
                "Files",
                f"{ingest['files_seen']} seen, {ingest['files_handled']} handled, "
                f"{ingest['files_skipped']} skipped, {ingest['files_failed']} failed",
            )
        )
    if rules:
        rows.append(("Rules", f"{rules['evaluated']} evaluated"))

    body = "".join(
        f"<tr><td class=mono>{_esc(k)}</td><td>{_esc(v)}</td></tr>" for k, v in rows
    )
    out = [f"<div class=panel><h2>Run</h2><table>{body}</table>"]

    # A truncated search may have skipped a valid chain. On the page rather than
    # in the console, because a reader with only this file would otherwise
    # believe the run was complete.
    if rules.get("search_truncated"):
        out.append(
            "<div class=note><strong>Search truncated.</strong> A valid chain may "
            "have been missed for: " + _esc(", ".join(rules["search_truncated"])) + "</div>"
        )
    out.append("</div>")
    return "".join(out)


def _slice_table(slice_: dict[str, Any], matched_ids: set[str]) -> str:
    if not slice_.get("events"):
        return ""
    rows = []
    for event in slice_["events"]:
        cls = " class=hit" if event["event_id"] in matched_ids else ""
        rows.append(
            f"<tr{cls}><td class=mono>{_esc(event['timestamp_utc'])}</td>"
            f"<td>{_esc(event['source_artifact'])}</td>"
            f"<td>{_esc(event['event_type'])}</td>"
            f"<td>{_esc(event['user'])}</td>"
            f"<td class=mono>{_esc(event['path'][:70])}</td></tr>"
        )
    label = (
        f"Timeline: {slice_['events_in_window']} events within "
        f"±{slice_['window_seconds'] // 60} minutes"
    )
    if slice_.get("truncated"):
        label += f" (showing the {len(slice_['events'])} nearest)"
    return (
        f"<details class=slice><summary>{_esc(label)}</summary><table>"
        "<tr><th>Time (UTC)</th><th>Artifact</th><th>Event</th><th>User</th>"
        f"<th>Path</th></tr>{''.join(rows)}</table></details>"
    )


def _finding_block(finding: dict[str, Any]) -> str:
    matched_ids = {m["event_id"] for m in finding["matched"]}
    provenance = "\n".join(
        f"{m['step'] or m['event_type']}: {m['source_file']} :: {m['source_locator']}"
        f" @ {m['timestamp_utc']} ({m['timestamp_type']})"
        for m in finding["matched"]
    )

    known_behavior = finding.get("rule_class", SCORING_RULE_CLASS) != SCORING_RULE_CLASS
    badge = (
        "<span class=cls title='Known-behavior rule: expresses a real behaviour "
        "this corpus never exercised. Does not contribute to the entity "
        "score.'>context only</span>"
        if known_behavior
        else ""
    )

    parts = [
        f"<div class='finding{' ctx-only' if known_behavior else ''}'>"
        "<div class=finding-head>",
        f"<div><span class='sev {_esc(finding['severity'])}'>{_esc(finding['severity'])}</span> ",
        f"<strong>{_esc(finding['title'])}</strong>{badge}</div>",
        f"<div class=rid>{_esc(finding['rule_id'])} &middot; "
        f"{_esc(finding['attack_technique'])} &middot; weight {finding['weight']}</div>",
        "</div>",
        f"<div>{_esc(finding['reason'])}</div>",
    ]

    if finding["entity_keys"]:
        keys = ", ".join(f"{e['key']}={e['value']}" for e in finding["entity_keys"])
        parts.append(f"<div class=mono style='color:#5a5a5a'>{_esc(keys)}</div>")

    parts.append(f"<div class=prov>{_esc(provenance)}</div>")

    for note in finding.get("notes", []):
        parts.append(f"<div class=note style='margin-top:8px'>{_esc(note)}</div>")

    # The ML contribution, shown as CONTEXT beside the finding and never as part
    # of its severity. `is_verdict: false` travels in the data; this renders it.
    context = finding.get("anomaly_context")
    if context:
        for entity in context["entities"]:
            parts.append(
                "<div class=ctx>Anomaly context (not a verdict): "
                f"{_esc(entity['entity'])} ranks "
                f"{entity['percentile_in_family']:.2f} percentile among "
                f"{_esc(entity['family'])} rows</div> "
            )

    parts.append(_slice_table(finding["timeline_slice"], matched_ids))
    parts.append("</div>")
    return "".join(parts)


def _is_verdict_finding(finding: dict[str, Any]) -> bool:
    """A finding belongs in the verdict only if its rule is corpus-validated.

    Mirrors `entity_score.aggregate`, which is where the same split decides the
    score. Before D-072 the score was filtered and this was not, so a Class 2
    finding could not move the ranking but still rendered under a heading that
    said "verdict" -- the split held in the arithmetic and not in the document.
    """
    return finding.get("rule_class", SCORING_RULE_CLASS) == SCORING_RULE_CLASS


def _verdict_panel(doc: dict[str, Any]) -> str:
    findings = sorted(
        (f for f in doc["findings"] if _is_verdict_finding(f)),
        key=lambda f: (_severity_rank(f["severity"]), f["first_timestamp_utc"]),
    )
    if not findings:
        return (
            "<div class='panel verdict'><h2>Verdict — rule findings</h2>"
            "<p class=sub>No rule matched. That is a result, not an absence of "
            "output.</p></div>"
        )

    entities = doc["entities"]
    entity_rows = "".join(
        f"<tr><td class=num><strong>{e['score']}</strong></td>"
        f"<td><span class='sev {_esc(e['severity'])}'>{_esc(e['severity'])}</span></td>"
        f"<td class=mono>{_esc(e['key'])}={_esc(e['value'])}</td>"
        f"<td>{_esc(', '.join(e['rule_ids']))}</td>"
        f"<td class=num>{e.get('phase_span', 0)}</td>"
        f"<td class=num>{e['finding_count']}</td></tr>"
        for e in entities
    )

    return (
        "<div class='panel verdict'><h2>Verdict — rule findings</h2>"
        "<p class=sub>Deterministic matches. Every finding names the artifact "
        "and record that produced it.</p>"
        + (
            "<h3>Entities, worst first</h3><table>"
            "<tr><th class=num>Score</th><th>Severity</th><th>Entity</th>"
            "<th>Rules</th><th class=num>Phases</th>"
            f"<th class=num>Findings</th></tr>{entity_rows}</table>"
            "<h3 style='margin-top:18px'>Findings</h3>"
            if entities
            else ""
        )
        + "".join(_finding_block(f) for f in findings)
        + "</div>"
    )


def _context_panel(doc: dict[str, Any]) -> str:
    """Class 2 findings, outside the verdict and labelled as context."""
    findings = sorted(
        (f for f in doc["findings"] if not _is_verdict_finding(f)),
        key=lambda f: (_severity_rank(f["severity"]), f["first_timestamp_utc"]),
    )
    if not findings:
        return ""

    return (
        "<div class='panel context'><h2>Context — known-behavior rules</h2>"
        "<p class=sub>These rules express real intrusion behaviour that this "
        "corpus never exercised, so each ships a false-positive profile rather "
        "than a detection rate. <strong>They do not contribute to the entity "
        "score and are not a verdict.</strong> Their severity is the severity "
        "the behaviour would carry if confirmed, not a claim about these "
        "rows.</p>"
        + "".join(_finding_block(f) for f in findings)
        + "</div>"
    )


def _prioritisation_panel(doc: dict[str, Any], limit: int = 25) -> str:
    anomalies = doc["anomalies"]
    scored = anomalies.get("scored_entities", [])
    if not scored:
        return (
            "<div class='panel ml'><h2>Prioritisation — anomaly ranking</h2>"
            "<p class=sub>No anomaly scoring was performed for this run. A "
            "baseline collection from the same host is required.</p></div>"
        )

    rows = "".join(
        f"<tr><td class=num>{a['percentile_in_family']:.2f}</td>"
        f"<td class=mono>{_esc(a['entity'])}</td>"
        f"<td>{_esc(a['family'])}</td></tr>"
        for a in scored[:limit]
    )

    unscored = anomalies.get("unscored_families") or []
    unscored_html = ""
    if unscored:
        items = "".join(
            f"<li class=mono>{_esc(u['family'])} — {_esc(u['reason'])}</li>"
            for u in unscored
        )
        unscored_html = (
            "<h3 style='margin-top:18px'>Families not scored</h3>"
            "<p class=sub>Reported rather than silently omitted: a score of "
            "&ldquo;not anomalous&rdquo; for a row that was never modelled is a "
            f"claim the model did not make.</p><ul>{items}</ul>"
        )

    return (
        "<div class='panel ml'><h2>Prioritisation — anomaly ranking</h2>"
        f"<div class=note>{_esc(anomalies['meaning'])}</div>"
        f"<table><tr><th class=num>Percentile</th><th>Entity</th><th>Family</th></tr>"
        f"{rows}</table>"
        + (
            f"<p class=sub style='margin-top:10px'>Showing {limit} of "
            f"{len(scored)} scored entities.</p>"
            if len(scored) > limit
            else ""
        )
        + unscored_html
        + "</div>"
    )


def _narration_panel(doc: dict[str, Any]) -> str:
    """The optional LLM narration, rendered ONLY when it was accepted by the
    citation validator. Labelled AI-generated and non-authoritative, and set
    apart from the verdict so no reader mistakes generated prose for a finding.
    A rejected or errored narration renders nothing -- it stays in run.json for
    audit, out of the report."""
    narration = doc.get("narration")
    if not narration or narration.get("status") != "accepted":
        return ""
    model = _esc(f"{narration.get('backend', '')}:{narration.get('model', '')}")
    body = _esc(narration.get("text", "")).replace("\n", "<br>")
    return (
        "<div class='panel narration'><h2>Narration — AI-generated summary</h2>"
        "<p class=note><strong>This narration is AI-generated and "
        "non-authoritative.</strong> It summarises the findings above; it does "
        "not add to them. Detection comes from the rules, not from this text.</p>"
        f"<div class=narration-body>{body}</div>"
        f"<p class=sub>Generated by {model} · temperature 0 · "
        "validated against run.json</p></div>"
    )


def render(doc: dict[str, Any]) -> str:
    """The complete report. Same document in, byte-identical HTML out."""
    name = _esc(doc["collection"]["name"])
    return (
        "<!DOCTYPE html>\n<html lang=en><head><meta charset=utf-8>"
        f"<title>DFIR triage report — {name}</title>"
        f"<style>{_CSS}</style></head><body><div class=wrap>"
        f"<h1>DFIR triage report</h1>"
        f"<p class=sub>{name} &middot; run.json v{_esc(doc['run_json_version'])}</p>"
        + _run_header(doc)
        + _verdict_panel(doc)
        + _context_panel(doc)
        + _prioritisation_panel(doc)
        + _narration_panel(doc)
        + "<footer>Rendered from run.json. Detection claims come from the "
        "deterministic rules; the prioritisation panel ranks and does not "
        "decide.</footer>"
        "</div></body></html>\n"
    )


def write(run_json_path: Path, out_path: Path) -> str:
    """Render `run.json` to HTML and return the report's SHA-256."""
    import hashlib

    doc = json.loads(run_json_path.read_text(encoding="utf-8"))
    text = render(doc)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8", newline="\n")
    return hashlib.sha256(text.encode("utf-8")).hexdigest()
