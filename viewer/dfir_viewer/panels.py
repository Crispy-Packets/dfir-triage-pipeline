"""The screens. Each panel is a projection of the loaded run: it reads, it
never writes, re-scores, or re-orders across panels. Verdict stays verdict,
context stays context, ML stays ML, narration stays narration."""
from __future__ import annotations

import re
from pathlib import Path

import pandas as pd
import streamlit as st

from .components import (SEV_COLOR, SEV_LABEL, activity_timeline, anomaly_context_card,
                         attack_strip, case_file, esc, event_card, facts_card,
                         fam_pos, finding_card, fmt_pct, hbar, ingest_card, killchain_bar, num,
                         priority_list, render_legend, rules_card)
from .contract import CITE_RE, RULE_RE, SEV_ORDER, anomaly_of
from .model import _class_scoped, activity_rows, entity_matches, finding_matches, findings_csv


def md(html_str: str) -> None:
    st.markdown(html_str, unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Drill-down: entity -> findings -> events                                    #
# --------------------------------------------------------------------------- #

def render_events(f) -> None:
    events = f.get("events", [])
    if not events:
        md("<span class='note'>No source events recorded.</span>")
        return
    for ev in events:
        if isinstance(ev, dict):
            md(event_card(ev))


def render_timeline_slice(f) -> None:
    ts = f.get("timeline_slice")
    if not isinstance(ts, dict) or not isinstance(ts.get("events"), list) or not ts["events"]:
        return
    shown, total = len(ts["events"]), ts.get("events_in_window", len(ts["events"]))
    trunc = " — truncated by the pipeline" if ts.get("truncated") else ""
    md(f"<div class='cf-h' style='margin-top:12px'>Surrounding timeline "
       f"<span class='h-note'>±{num((ts.get('window_seconds') or 0) // 2)} s · "
       f"{shown} of {num(total)} events{trunc}</span></div>")
    rows = [{"time (UTC)": str(e.get("timestamp_utc", "")),
             "type": str(e.get("timestamp_type", "")),
             "artifact": str(e.get("source_artifact", "")),
             "event": str(e.get("action") or e.get("event_type", "")),
             "path": str(e.get("path", "")),
             "source": f"{e.get('source_file', '')} :: {e.get('source_locator', '')}"}
            for e in ts["events"] if isinstance(e, dict)]
    st.dataframe(rows, width='stretch', hide_index=True, height=260)


def render_finding(f, key_prefix: str) -> None:
    """One finding as a timeline node; the source events sit one click away."""
    md(finding_card(f))
    n_ev = len(f.get("event_ids", []))
    with st.container(key=f"fx_{key_prefix}"):
        with st.expander(f"Source events ({n_ev}) and reason", expanded=False):
            md(f"<div class='prov'>{esc(f.get('reason', ''))}</div>")
            render_events(f)
            ac = anomaly_context_card(f)
            if ac:
                md(ac)
            render_timeline_slice(f)


def _ids(e) -> list:
    return e.get("all_ids") or e.get("finding_ids", [])


def selectable_entity_table(entities, key: str, scoped=None, panel_key="") -> int:
    """The entity table as a click-to-select widget. Every column describes
    the findings on THIS page, so an entity on the Context page is described by
    its Class 2 findings, never by the Class 1 ones behind its triage score.
    The triage score column appears on the Verdict page only. The selection is
    mirrored to the URL (?entity=<value>)."""
    rows = []
    for e in entities:
        fs = [scoped[i] for i in _ids(e) if i in scoped] if scoped is not None else []
        sevs = [f.get("severity") for f in fs]
        band = (e.get("severity") if panel_key == "verdict" and e.get("listed")
                else max(sevs, key=lambda x: SEV_ORDER.get(x, 0)) if sevs
                else e.get("severity", ""))
        phases = [p for p in ("delivery", "execute", "persist", "destroy", "exfiltrate")
                  if any(f.get("phase") == p for f in fs)]
        row = {"entity": str(e.get("value", "")), "kind": e.get("kind", ""),
               "band": band}
        if panel_key == "verdict":
            sc = e.get("score")
            row["triage score"] = (f"{int(sc):\u2007>3}" if isinstance(sc, (int, float))
                                   and not isinstance(sc, bool) else "—")
        row.update({
            "rules": len({f.get("rule_id") for f in fs}),
            "findings here": len(fs),
            "phases": " · ".join(phases),
            "techniques": ", ".join(sorted({str(f.get("attack_technique")) for f in fs
                                            if f.get("attack_technique")})),
        })
        rows.append(row)
    rows = pd.DataFrame(rows)
    want = st.query_params.get("entity")
    dkey = f"_seldef_{key}"
    if dkey not in st.session_state:
        st.session_state[dkey] = next(
            (i for i, e in enumerate(entities) if str(e.get("value")) == want), None)
    d = st.session_state[dkey]
    default = ({"selection": {"rows": [d], "columns": []}}
               if d is not None and d < len(rows) else None)
    if panel_key == "verdict":
        st.caption("Select a row to open its case file. Triage score: the pipeline's "
                   "score from the Class 1 rules that matched — where to look first, not "
                   "a verdict. “—” means the rules layer gave this entity no score.")
    else:
        st.caption("Select a row to open its case file. Every column here describes "
                   "the entity's Class 2 (context) findings only.")
    ev = st.dataframe(
        rows, width='stretch', hide_index=True, key=key,
        on_select="rerun", selection_mode="single-row", selection_default=default,
        column_config={"triage score": st.column_config.TextColumn(alignment="right"),
                       "band": st.column_config.TextColumn(
                           help="Severity band: the weight of the rules that matched, "
                                "not an assessment of the entity")})
    try:
        sel = ev.selection["rows"]
    except Exception:
        sel = getattr(getattr(ev, "selection", None), "rows", []) or []
    idx = sel[0] if sel and sel[0] < len(entities) else 0
    if not sel and want and d is None:
        md(f"<div class='note' style='margin:4px 0'>{esc(want)} has no findings on this "
           f"page. Showing the first row instead.</div>")
    if sel and entities[idx].get("value") is not None:
        val = str(entities[idx]["value"])
        if st.query_params.get("entity") != val:
            st.query_params["entity"] = val
    return idx


def drilldown(entities, scoped, flt, panel_key: str, view) -> None:
    if not entities:
        st.info("No entities match the current filters.")
        return
    idx = selectable_entity_table(entities, f"tbl_{panel_key}", scoped, panel_key)
    e = entities[idx]
    md(case_file(e, view))
    everything = [view["by_id"][i] for i in _ids(e) if i in view["by_id"]]
    fs = [scoped[i] for i in _ids(e) if i in scoped]
    fs = [f for f in fs if finding_matches(f, flt)]
    if not fs:
        md("<span class='note'>No findings for this entity on this page under the "
           "current filters.</span>")
        return
    here = "Class 1" if panel_key == "verdict" else "Class 2 (context)"
    other = len(everything) - len([i for i in _ids(e) if i in scoped])
    scope = (f" · {other} more in the other panel" if other else "")
    # Timed findings in time order; presence-only ones after them, because a
    # key's last-write time is not an event time and must not imply order.
    timed = sorted((f for f in fs if str(f.get("time_claim", "")) != "none"),
                   key=lambda f: (str(f.get("first_timestamp_utc") or ""),
                                  str(f.get("rule_id", ""))))
    untimed = sorted((f for f in fs if str(f.get("time_claim", "")) == "none"),
                     key=lambda f: str(f.get("rule_id", "")))
    md(f"<h4>Findings timeline <span class='h-note'>{len(fs)} {here}{scope}</span></h4>")
    if timed:
        md("<div class='fd-group'>With an event time — earliest first</div>")
    for i, f in enumerate(timed):
        render_finding(f, f"{panel_key}_{idx}_t{i}")
    if untimed:
        md("<div class='fd-group'>Presence only — no event time, so no order</div>")
    for i, f in enumerate(untimed):
        render_finding(f, f"{panel_key}_{idx}_p{i}")


# --------------------------------------------------------------------------- #
# Panels                                                                      #
# --------------------------------------------------------------------------- #

def activity_block(findings, title: str, note: str, selected=None) -> None:
    untimed = sum(1 for f in findings if str(f.get("time_claim", "")) == "none")
    extra = (f" · {untimed} presence-only finding(s) not plotted" if untimed else "")
    md(f"<h4>{title} <span class='h-note'>{note}{extra}</span></h4>")
    md(f"<div class='card'>{activity_timeline(findings, selected)}</div>")
    rows = activity_rows(findings)
    if rows:
        with st.container(key="acttable"):
            with st.expander("Activity as a table", expanded=False):
                st.dataframe(rows, width='stretch', hide_index=True)


def panel_overview(view) -> None:
    c = view["counts"]
    by_class, by_sev = c["findings_by_class"], c["findings_by_severity"]

    hero_l, hero_r = st.columns([2, 1])
    with hero_l:
        md("<h4>Priority <span class='h-note'>rule-scored entities, by triage score"
           "</span></h4>")
        md(f"<div class='card'>{priority_list(view['entities'])}</div>")
    with hero_r:
        md("<h4>This run</h4>")
        md(facts_card(view))

    activity_block(view["findings"], "Activity", "findings per day · both classes")

    col1, col2 = st.columns(2)
    with col1:
        sev_segs = [(SEV_LABEL[s], by_sev.get(s, 0), SEV_COLOR[s])
                    for s in ("critical", "high", "medium", "low")]
        md("<h4>Findings by weight band <span class='h-note'>both classes</span></h4>")
        md(f"<div class='card'>{hbar(sev_segs)}</div>")
    with col2:
        class_segs = [("Class 1 · Verdict page", by_class.get("corpus-validated", 0),
                       "var(--accent)"),
                      ("Class 2 · Context page", by_class.get("known-behavior", 0),
                       "var(--line2)")]
        md("<h4>Findings by rule class</h4>")
        md(f"<div class='card'>{hbar(class_segs)}</div>")

    md("<h4>Phases <span class='h-note'>class 1 filled · class 2 as context</span></h4>")
    md(f"<div class='card'>{killchain_bar(view['findings'])}</div>")
    md("<h4>ATT&amp;CK techniques <span class='h-note'>what the rules map to</span></h4>")
    md(f"<div class='card'>{attack_strip(view['findings'])}</div>")
    if view.get("rules") or view.get("ingest"):
        a, b = st.columns(2)
        with a:
            md("<h4>Rule coverage</h4>")
            md(f"<div class='card'>{rules_card(view)}</div>")
        with b:
            md("<h4>Evidence ingested</h4>")
            md(f"<div class='card'>{ingest_card(view)}</div>")


def _panel_entities(entities, scoped, flt):
    ents = [e for e in entities if any(i in scoped for i in _ids(e))]
    return [e for e in ents if entity_matches(e, flt)]


def panel_verdict(entities, view, flt) -> None:
    md("<h3>Verdict</h3>")
    md("<div class='note'>Findings from Class 1 (corpus-validated) rules — the "
       "detection layer, independent of the anomaly scorer. Each is a rule match to "
       "verify in its source events, not a conclusion about the entity.</div>")
    scoped = _class_scoped(view["by_id"], "corpus-validated")
    ents = _panel_entities(entities, scoped, flt)
    if not ents:
        st.info("No corpus-validated (Class 1) findings in this run under the "
                "current filters.")
        return
    drilldown(ents, scoped, flt, "verdict", view)


def panel_context(entities, view, flt) -> None:
    md("<h3>Context</h3>")
    md("<div class='note'>Context only — not a verdict. Class 2 known-behavior rules "
       "fire on clean hosts too.</div>")
    scoped = _class_scoped(view["by_id"], "known-behavior")
    ents = _panel_entities(entities, scoped, flt)

    def _ctx_key(e):
        fs = [scoped[i] for i in _ids(e) if i in scoped]
        top = max((SEV_ORDER.get(f.get("severity"), 0) for f in fs), default=0)
        return (-top, -len(fs), str(e.get("value", "")))
    ents.sort(key=_ctx_key)  # by its context findings, not by its triage score
    if not ents:
        st.success("This run has no Class 2 (known-behavior) findings. "
                   "Nothing to show as context — that is the expected state for "
                   "a clean run.")
        return
    drilldown(ents, scoped, flt, "context", view)


def panel_prioritisation(view) -> None:
    an = view["anomalies"]
    md("<h3>Prioritisation</h3>")
    scorer = an.get("scorer") or "—"
    md(f"<div class='pz-head'><div><div class='pz-k'>Anomaly scorer</div>"
       f"<div class='pz-scorer'>{esc(scorer)}</div></div>"
       f"<div class='pz-meta'>is_verdict: <span class='mono'>{esc(an.get('is_verdict'))}"
       f"</span><br>{len(an['scored'])} entities ranked · {len(an['unscored'])} "
       f"families not scored</div></div>")
    if an.get("meaning"):
        md(f"<div class='note' style='margin:8px 0 4px'>{esc(an['meaning'])}</div>")
    md("<div class='note'>Prioritisation, not a verdict. Unusual is not malicious — "
       "expect common OS binaries near the top. Detection is the rules layer's job "
       "(Verdict page).</div>")
    if an.get("fixture"):
        md("<span class='chip fixture'>FIXTURE</span> "
           "<span class='note'>illustrative percentiles</span>")
    if not an["scored"]:
        st.info("No entities were ranked in this run.")
    else:
        fams = sorted({s["family"] for s in an["scored"]})
        c1, c2 = st.columns([1, 2])
        with c1:
            fam = st.selectbox("Family", ["all"] + fams, key="pz_fam")
        with c2:
            q = st.text_input("Find an entity in the ranking", key="pz_q")
        rows = [{"position": s["rank"], "entity": s["entity"], "family": s["family"],
                 "in family": fam_pos(s),
                 "percentile_in_family": s["percentile"]}
                for s in an["scored"]
                if (fam == "all" or s["family"] == fam)
                and (not q.strip() or q.strip().lower() in s["entity"].lower())]
        direction = (" · 0 = most unusual of its kind" if an["low_is_unusual"] else "")
        md(f"<div class='note' style='margin:6px 0'>Position is the order run.json gives "
           f"across families; percentiles (0–100) compare a row only with its own family"
           f"{direction}. Showing {len(rows)} of {len(an['scored'])}.</div>")
        st.dataframe(rows, width='stretch', hide_index=True, height=420,
                     column_config={"percentile_in_family": st.column_config.NumberColumn(
                         format="%.2f")})
    if an["unscored"]:
        with st.expander(f"Families not scored ({len(an['unscored'])}) and why"):
            st.dataframe([{"family": u["family"], "rows": u["rows"], "reason": u["reason"]}
                          for u in an["unscored"]], width='stretch', hide_index=True)


def _narr_html(text: str, rules, exes) -> str:
    """Escape first; then mark cited rule ids, `code` spans and legacy [[ids]]."""
    t = esc(text)
    t = CITE_RE.sub(lambda m: f"<span class='hash'>[{m.group(1).strip()}]</span>", t)
    t = re.sub(r"`([^`]{1,200})`", lambda m: f"<code>{m.group(1)}</code>", t)
    t = RULE_RE.sub(lambda m: f"<span class='mono cite'>{m.group(0)}</span>", t)
    return t


def _class_mix(view, e) -> str:
    fs = [view["by_id"][i] for i in _ids(e) if i in view["by_id"]]
    n1 = sum(1 for f in fs if f.get("rule_class") == "corpus-validated")
    return f"{len(fs)} finding(s): {n1} class 1, {len(fs) - n1} class 2"


def claims_table(view, gate) -> list:
    """What run.json records for everything the narration cites — so the
    analyst can read the prose against the record, not instead of it."""
    rows = []
    total = len(view["anomalies"]["scored"])
    ents = {str(e.get("value")): e for e in view["all_entities"]}
    for x in gate["cites_exes"]:
        e = ents.get(x)
        a = anomaly_of(view, x)
        rows.append({
            "cited": x, "kind": "name",
            "rules layer": (f"triage score {e['score']} · {e['severity']}"
                            if e and isinstance(e.get("score"), (int, float))
                            else (_class_mix(view, e) + ", not scored"
                                  if e else "no rule findings")),
            "anomaly ranking": (f"rank {a['rank']} of {total} · {fam_pos(a)} in "
                                f"{a['family']} · percentile "
                                f"{fmt_pct(a['percentile'])}" if a else "not ranked"),
        })
    for r in gate["cites_rules"]:
        fs = [f for f in view["findings"] if f.get("rule_id") == r]
        cls = {f.get("rule_class") for f in fs}
        rows.append({"cited": r, "kind": "rule",
                     "rules layer": f"{len(fs)} finding(s) · {', '.join(sorted(map(str, cls)))}",
                     "anomaly ranking": "—"})
    return rows


def panel_narrative(run, view, gate) -> None:
    md("<h3>Narrative</h3>")
    if not gate["present"]:
        st.info(gate["reason"])
        return
    if not gate["show"]:
        md("<div class='banner banner-warn'>NARRATION REJECTED — not shown. "
           f"{esc(gate['reason'])} Rejected narration is withheld, not shown with a "
           "disclaimer.</div>")
        return
    nar = run["narration"]
    prov = [("model", nar.get("model")), ("backend", nar.get("backend")),
            ("endpoint", nar.get("endpoint")), ("prompt", nar.get("prompt_version")),
            ("temperature", nar.get("temperature")), ("seed", nar.get("seed")),
            ("generated", nar.get("generated_at"))]
    prov_html = " · ".join(f"{k} <span class='mono'>{esc(v)}</span>"
                           for k, v in prov if v not in (None, ""))
    label = ("MODEL-GENERATED · PROVISIONAL" if gate["legacy"]
             else "AI-GENERATED · NOT A VERDICT")
    md(f"<div class='nar'><div class='nar-top'><span class='chip ai'>{label}</span>"
       f"<span class='note'>{prov_html}</span></div>"
       f"<div class='nar-text'>{_narr_html(nar.get('text', ''), gate['cites_rules'], gate['cites_exes'])}</div>"
       "<div class='nar-warn'>Shown because the pipeline accepted it and the viewer's "
       "re-check passed: cited rules and names exist, numbers match what they cite, no "
       "rank claim contradicts the record, no entity is compared as more or less "
       "suspicious. That is not proof the prose is right — read it against the record "
       "below.</div></div>")
    if gate["legacy"]:
        md("<h4>Cited findings</h4>")
        for c in gate["cites_findings"]:
            render_finding(view["by_id"][c], f"nar_{c}")
        return
    rows = claims_table(view, gate)
    if rows:
        md("<h4>The record for everything it cites <span class='h-note'>from run.json, "
           "not from the prose</span></h4>")
        st.dataframe(rows, width='stretch', hide_index=True)
    val = nar.get("validation") if isinstance(nar.get("validation"), dict) else {}
    with st.container(key="narcheck"), st.expander("How it was checked"):
        checks = [
            ("pipeline validator: validated", val.get("validated") is True),
            ("nothing unresolvable", not val.get("unresolvable")),
            ("names the anomaly scorer", bool(val.get("mentions_scorer"))),
            ("does not call the ranking detection",
             val.get("describes_ranking_as_detection") is False),
            ("viewer re-check: every cited rule and name is in this run", True),
            ("viewer re-check: numbers match what they cite", True),
            ("viewer re-check: no rank claim contradicts the record", True),
            ("viewer re-check: no suspicion comparison between entities", True),
        ]
        md("".join(f"<div class='chk'><span class='{'ok' if ok else 'no'}'>"
                   f"{'✓' if ok else '✗'}</span> {esc(k)}</div>" for k, ok in checks))
        if nar.get("model_digest"):
            md(f"<div class='note' style='margin-top:6px'>model digest "
               f"<span class='hash'>{esc(nar['model_digest'])}</span><br>prompt sha256 "
               f"<span class='hash'>{esc(nar.get('prompt_sha256', ''))}</span></div>")


def panel_downloads(run_path, run_bytes: bytes | None = None,
                    view_findings: list | None = None, filtered: bool = False,
                    manifest: dict | None = None, uploads: dict | None = None) -> None:
    md("<h3>Downloads</h3>")
    if view_findings is not None:
        label = ("Findings in the current filter" if filtered
                 else "All findings in this run")
        md(f"<div class='dl-view'><div><div class='dl-h'>{label}</div>"
           f"<div class='note'>{len(view_findings)} finding(s), CSV, built in "
           f"memory. Cells that start with = + - @ are prefixed with ' so a "
           f"spreadsheet shows them as text, not formulas.</div></div></div>")
        st.download_button("Export current view (CSV)",
                           data=findings_csv(view_findings),
                           file_name="findings_view.csv", mime="text/csv",
                           key="dl_view")
        md("<div class='cf-h' style='margin-top:18px'>Frozen artifacts</div>")
    wanted = ["run.json", "findings.csv", "anomalies.csv", "manifest.sha256", "report.html"]
    status = (manifest or {}).get("results", {})
    cols = st.columns(len(wanted))
    for col, name in zip(cols, wanted):
        data = None
        if run_path is not None:
            p = Path(run_path).parent / name
            data = p.read_bytes() if p.is_file() else None
        elif uploads:
            data = uploads.get(name)
            if name == "run.json" and data is None:
                data = run_bytes
        with col:
            st_txt = status.get(name)
            tag = (f"<span class='mf {st_txt}'>{st_txt}</span>" if st_txt else "")
            if data is not None:
                mime = ("application/json" if name.endswith(".json")
                        else "text/csv" if name.endswith(".csv")
                        else "text/html" if name.endswith(".html") else "text/plain")
                col.download_button(name, data=data, file_name=name, mime=mime,
                                    width='stretch', key=f"dl_{name}")
                if tag:
                    md(f"<div style='text-align:center'>{tag}</div>")
            else:
                col.markdown(f"<span class='note'>{name}<br>not present</span> {tag}",
                             unsafe_allow_html=True)


def panel_guide() -> None:
    md("<h3>Guide — how to read this viewer</h3>")
    md("<span class='note'>What the symbols mean, and the keys that drive it.</span>")
    md(render_legend())
