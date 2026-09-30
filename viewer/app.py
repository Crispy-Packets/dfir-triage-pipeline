"""DFIR Triage Viewer — an interactive projection of one frozen run.

The interactive UI reads the canonical run.json; it does not produce or modify
evidence.

The one rule: this app is a VIEWER over a frozen artifact. It reads run.json,
it does not modify it, does not re-run detection, does not change scoring.
Every screen is a projection of a single file whose SHA-256 is recorded in
manifest.sha256. There is no code path in this app that writes to, re-scores,
re-orders across panels, or otherwise alters the run. Interactivity is allowed;
claims are not. Verdict stays verdict, context stays context, ML stays ML.

Layout:  app.py (this file: page wiring and state)
         dfir_viewer/model.py       reading, validation, filters — pure Python
         dfir_viewer/components.py  HTML blocks; every run value is escaped
         dfir_viewer/panels.py      the screens
         dfir_viewer/theme.py + styles.css

Run:  streamlit run app.py
      streamlit run app.py -- --run samples/s1_v3/run.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlencode

import streamlit as st

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:  # so `dfir_viewer` imports from any cwd
    sys.path.insert(0, str(APP_DIR))

# Re-exported so tests and tools can reach the pure functions via `app.<name>`.
from dfir_viewer.components import (SEV_COLOR, SEV_LABEL, activity_timeline,  # noqa: E402,F401
                                    esc, render_legend)
from dfir_viewer.contract import (narration_gate, normalize_run,  # noqa: E402,F401
                                  parse_manifest, read_manifest_dir, verify_manifest)
from dfir_viewer.model import (FILTER_KEYS, PHASE_ORDER, SEV_ORDER,  # noqa: E402,F401
                               SUPPORTED_SCHEMA, _class_scoped, active_filter_count,
                               apply_filters, discover_runs, empty_filter,
                               entity_matches, finding_matches, findings_csv,
                               activity_rows, narration_citations, read_manifest,
                               run_days, timed,
                               validate_run)
from dfir_viewer.panels import (activity_block, md, panel_context,  # noqa: E402
                                panel_downloads, panel_guide, panel_narrative,
                                panel_overview, panel_prioritisation, panel_verdict)
from dfir_viewer.theme import stylesheet  # noqa: E402

VIEWS = ["All", "Verdict", "Context", "Prioritisation", "Narrative",
         "Downloads", "Guide"]
# Widget keys double as URL parameter names (bind="query-params").
MULTI_KEYS = {"severity": "sev", "phase": "phase", "family": "fam",
              "technique": "tech", "kinds": "kind"}


@st.cache_data(show_spinner=False)
def load_run(path_str: str, mtime: float):
    """Read run.json and return (data, raw_sha256). Cached on path+mtime.
    `mtime` participates in the cache key only; the file is never written."""
    raw = Path(path_str).read_bytes()
    data = json.loads(raw.decode("utf-8"))
    return data, hashlib.sha256(raw).hexdigest()


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default=None)
    known, _ = ap.parse_known_args(sys.argv[1:])
    return known


# --------------------------------------------------------------------------- #
# Keyboard and filter state                                                   #
# --------------------------------------------------------------------------- #

def _go(view: str) -> None:
    st.session_state["view"] = view


def _toggle_theme() -> None:
    st.session_state["light"] = not st.session_state.get("light", False)


def _clear_filters() -> None:
    for k in MULTI_KEYS.values():
        st.session_state[k] = []
    st.session_state["q"] = ""
    if st.session_state.get("_days_full"):  # back to the full range, which
        st.session_state["days"] = st.session_state["_days_full"]  # drops ?days


def keyboard() -> None:
    """Shortcuts: 1–7 pages, L theme, X clear filters. The buttons stay
    mounted (their keys work) but are visually hidden by `.st-key-kbd`."""
    with st.container(key="kbd"):
        for i, v in enumerate(VIEWS, 1):
            st.button(f"Go to {v}", key=f"k_{v}", shortcut=str(i),
                      on_click=_go, args=(v,))
        st.button("Toggle theme", key="k_theme", shortcut="L", on_click=_toggle_theme)
        st.button("Clear filters", key="k_clear", shortcut="X", on_click=_clear_filters)


def _sanitize(key: str, options: list) -> None:
    """A link or a previous run may carry values this run does not have;
    drop them before the widget is drawn rather than error."""
    cur = st.session_state.get(key)
    if isinstance(cur, list):
        keep = [v for v in cur if v in options]
        if keep != cur:
            st.session_state[key] = keep


def share_url(state: dict) -> str:
    base = (st.context.url or "http://localhost:8501").split("?")[0].rstrip("/")
    pairs = []
    for k, v in state.items():
        if isinstance(v, (list, tuple)):
            pairs += [(k, x) for x in v]
        elif v not in (None, "", False):
            pairs.append((k, "true" if v is True else v))
    return base + "/" + (("?" + urlencode(pairs)) if pairs else "")


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #

def main() -> None:
    st.set_page_config(page_title="DFIR Triage Viewer", layout="wide",
                       page_icon="◆", initial_sidebar_state="expanded")
    keyboard()
    _sp, _tc = st.columns([6, 1])
    with _tc:
        light = st.toggle("Light", key="light", bind="query-params",
                          help="Dark forensic theme ⇄ light presentation theme. "
                               "Shortcut: L")
    md(stylesheet("light" if light else "dark"))
    md("<div class='fx'><div class='fx-glow'></div></div>")
    args = parse_args()
    runs = discover_runs(APP_DIR)

    # ---- sidebar: case rail ----
    with st.sidebar:
        md("<div class='sb-brand'><div class='sb-logo'></div>"
           "<div><div class='sb-name'>DFIR&nbsp;Triage</div>"
           "<div class='sb-tag'>evidence viewer · read-only</div></div></div>")
        case_slot = st.empty()
        md("<div class='sb-sec'>View</div>")
        view = st.radio("Navigation", VIEWS, key="view", bind="query-params",
                        label_visibility="collapsed")
        md("<div class='sb-sec'>Run</div>")
        run_path = None
        labels = list(runs.keys())
        direct = None  # --run pointing at a file outside samples/
        if args.run:
            match = [n for n in labels if str(runs[n]) == str(Path(args.run).resolve())
                     or str(runs[n]).endswith(args.run.replace("\\", "/"))]
            if match and "run" not in st.session_state and "run" not in st.query_params:
                st.session_state["run"] = match[0]
            elif not match and Path(args.run).is_file():
                direct = Path(args.run)
        if direct is not None:
            run_path = direct
            md(f"<div class='note'>Opened with --run: <span class='mono'>{esc(direct)}"
               "</span></div>")
        elif len(labels) > 1:
            chosen = st.radio("Pipeline runs", labels, key="run", bind="query-params")
            run_path = runs[chosen]
        elif labels:
            run_path = runs[labels[0]]
        # Drawn after the uploader is read, so it can say whether it is the
        # run on screen: an uploaded run replaces it for as long as it is open.
        run_box = st.empty()
        md("<div class='sb-up'>Open your own run</div>")
        uploaded = st.file_uploader(
            "Upload a run folder's files", type=["json", "sha256", "csv", "html"],
            accept_multiple_files=True,
            help="Pick run.json — and, to verify it, the manifest.sha256 and the "
                 "CSV/HTML files shipped beside it. Everything is read in memory "
                 "and never written back.")

    uploads = {}
    for u in uploaded or []:
        name = "run.json" if u.name.lower().endswith(".json") else \
            ("manifest.sha256" if u.name.lower().endswith(".sha256") else u.name)
        uploads[name] = u.getvalue()
    upload_name = next((u.name for u in uploaded or [] if u.name.lower().endswith(".json")),
                       None)
    showing_upload = "run.json" in uploads
    sample_name = (st.session_state.get("run") if len(labels) > 1
                   else (labels[0] if labels else None))
    if direct is None and sample_name:
        if showing_upload:
            run_box.markdown(
                f"<div class='run-one off'><span class='mono'>{esc(sample_name)}</span>"
                "<span class='note'>hidden while your upload is open</span></div>"
                f"<div class='run-hint'>Showing your uploaded <span class='mono'>"
                f"{esc(upload_name)}</span>. Remove it with × below to return. "
                "Nothing is deleted.</div>",
                unsafe_allow_html=True)
        elif len(labels) == 1:
            run_box.markdown(
                f"<div class='run-one'><span class='mono'>{esc(sample_name)}</span>"
                "<span class='note'>samples/ · pipeline output</span></div>",
                unsafe_allow_html=True)

    # UI-less load path for automation / tests (no on-screen widget)
    if "run.json" not in uploads and os.environ.get("DFIR_RUN"):
        run_path = Path(os.environ["DFIR_RUN"])

    run_bytes = uploads.get("run.json")
    if uploads and run_bytes is None:
        st.warning("Uploaded files include no run.json — showing the selected run.")
    if run_bytes is not None:
        run_path = None  # in-memory; read-only, no disk write
        try:
            with st.spinner("Reading run.json…"):
                run = json.loads(run_bytes.decode("utf-8"))
                raw_sha = hashlib.sha256(run_bytes).hexdigest()
        except Exception as exc:
            st.error(f"Could not read the uploaded run.json: {exc}")
            st.stop()
    else:
        if not run_path or not Path(run_path).is_file():
            st.error("No run.json found. Pick a run, or upload one in the sidebar.")
            st.stop()
        run_path = Path(run_path).resolve()
        try:
            run, raw_sha = load_run(str(run_path), run_path.stat().st_mtime)
        except Exception as exc:  # pragma: no cover - defensive
            st.error(f"Could not read run.json: {exc}")
            st.stop()

    problems = validate_run(run)
    if problems:
        md("<div class='banner banner-warn'><span class='seal' "
           "style='background:#cf5a45'></span>RUN REJECTED — this file does not "
           "satisfy the run.json contract, so it is not rendered.</div>")
        md("<div class='card'><b>Problems</b><ul>"
           + "".join(f"<li class='mono'>{esc(p)}</li>" for p in problems)
           + "</ul></div>")
        st.stop()

    view_model = normalize_run(run)
    gate = narration_gate(run, view_model)
    findings = view_model["findings"]
    findings_by_id = view_model["by_id"]
    entities = view_model["all_entities"]

    # ---- masthead + provenance ----
    ver = view_model["version"]
    coll = view_model["collection"]
    md(f"<div class='masthead'><div class='mh-logo'><span>⬡</span></div>"
       f"<div><div class='mh-title'>DFIR Triage Viewer</div>"
       f"<div class='mh-sub'>Read-only evidence viewer</div></div>"
       f"<div class='mh-right'><div class='mh-k'>COLLECTION</div>"
       f"<div class='mh-v'>{esc(coll)}</div>"
       f"<div class='mh-k' style='margin-top:6px'>SCHEMA · ANOMALY SCORER</div>"
       f"<div class='mh-v'>v{esc(ver)} · <span class='scorer'>"
       f"{esc(view_model['anomalies'].get('scorer') or '—')}</span></div></div></div>")

    if view_model["fixture"]:
        md("<span class='chip fixture'>FIXTURE</span> "
           "<span class='note'>sample data, not a live pipeline run</span>")
    if view_model["legacy"]:
        md("<div class='note' style='margin:4px 0 8px'>Legacy v1.4.0 run — the current "
           f"contract is v{SUPPORTED_SCHEMA}.</div>")
    elif ver != SUPPORTED_SCHEMA:
        st.warning(f"run_json_version is {ver}; this viewer targets "
                   f"{SUPPORTED_SCHEMA}. Rendering best-effort.")

    # Every file the manifest attests is checked, not only run.json.
    if run_path is not None:
        attested, results = read_manifest_dir(run_path)
    elif "manifest.sha256" in uploads:
        try:
            attested = parse_manifest(uploads["manifest.sha256"].decode("utf-8"))
        except Exception:
            attested = {}
        results = verify_manifest(attested, {n: uploads.get(n) for n in attested})
    else:
        attested, results = {}, {}
    manifest_sha = attested.get("run.json")
    run_state = results.get("run.json")
    if run_state:
        ok = run_state == "verified" and "mismatch" not in results.values()
        others = " · ".join(f"{n} {s}" for n, s in results.items() if n != "run.json")
        detail = ("run.json hash matches manifest.sha256" if ok else
                  "a hash does not match manifest.sha256 — do not trust this view")
        md(f"<div class='banner {'banner-ok' if ok else 'banner-warn'}'>"
           f"<span class='seal'></span><div>Manifest {'verified' if ok else 'mismatch'}"
           f" — {detail}<div class='banner-sub'>{esc(others)}</div></div></div>")
    elif run_bytes is not None:
        md("<div class='banner' style='border:1px solid var(--line);"
           "background:var(--panel2);color:var(--muted)'>"
           "<span class='seal' style='background:var(--muted)'></span>"
           "Uploaded run — no manifest.sha256 uploaded with it; its hash is in the "
           "footer. Upload the manifest too to verify it.</div>")
    ok_all = bool(run_state) and run_state == "verified" and "mismatch" not in results.values()

    # ---- sidebar case-status card, now that provenance is known ----
    seal_txt = ("VERIFIED" if ok_all else "MISMATCH" if run_state
                else ("UPLOADED" if run_bytes is not None else "NO MANIFEST"))
    seal_col = ("var(--accent)" if ok_all else "#cf5a45" if run_state else "var(--muted)")
    cnt = view_model["counts"]
    case_slot.markdown(
        "<div class='case'>"
        f"<div class='case-row'><span class='case-k'>collection</span>"
        f"<span class='case-v'>{esc(coll)}</span></div>"
        f"<div class='case-row'><span class='case-k'>findings</span>"
        f"<span class='case-v'>{cnt['findings_total']}</span></div>"
        f"<div class='case-row'><span class='case-k'>rule-scored entities</span>"
        f"<span class='case-v'>{cnt['entities_total']}</span></div>"
        f"<div class='case-row'><span class='case-k'>scorer</span>"
        f"<span class='case-v'>{esc(view_model['anomalies'].get('scorer') or '—')}</span></div>"
        f"<div class='case-row'><span class='case-k'>source</span>"
        f"<span class='case-v'>{'FIXTURE' if view_model['fixture'] else 'PIPELINE'}"
        f"</span></div>"
        f"<div class='case-seal'><span class='seal' style='background:{seal_col}'>"
        f"</span>manifest {seal_txt}</div>"
        f"<div class='hash' style='font-size:10px;margin-top:6px'>"
        f"{esc((manifest_sha or raw_sha)[:34])}…</div>"
        "</div>", unsafe_allow_html=True)

    # ---- filters (sidebar; every value lives in the URL) ----
    with st.sidebar:
        md("<div class='sb-sec'>Filters</div>")
        opts = {
            "severity": sorted({f.get("severity") for f in findings} |
                               {e.get("severity") for e in entities} - {None},
                               key=lambda s: -SEV_ORDER.get(s, 0)),
            "phase": [p for p in PHASE_ORDER if any(f.get("phase") == p for f in findings)],
            "family": sorted({str(f.get("technique_family")) for f in findings
                              if f.get("technique_family")}),
            "technique": sorted({str(f.get("attack_technique")) for f in findings
                                 if f.get("attack_technique")}),
            "kinds": sorted({str(e.get("kind")) for e in entities if e.get("kind")}),
        }
        labels = {"severity": "Priority", "phase": "Phase",
                  "family": "Technique family", "technique": "Technique ID",
                  "kinds": "Entity kind"}
        flt = empty_filter()
        for name, key in MULTI_KEYS.items():
            _sanitize(key, opts[name])
            flt[name] = st.multiselect(labels[name], opts[name], key=key,
                                       bind="query-params")
        flt["query"] = st.text_input("Search (entity / rule_id / technique)",
                                     key="q", bind="query-params")
        days = run_days(findings)
        if len(days) > 1:
            full = (days[0], days[-1])
            st.session_state["_days_full"] = full
            cur = st.session_state.get("days")
            if cur is not None and not (isinstance(cur, (list, tuple)) and len(cur) == 2
                                        and all(d in days for d in cur)):
                st.session_state.pop("days")  # a range from another run
            rng = st.select_slider("Date range", options=days, value=full,
                                   key="days", bind="query-params",
                                   help="Only findings with a time claim can sit in a "
                                        "date range; presence-only findings are "
                                        "excluded while a range is set.")
            if tuple(rng) != (days[0], days[-1]):
                flt["days"] = tuple(rng)
        st.caption("Filters project the view. They never change the run.")

    fent, ffind = apply_filters(entities, findings, flt)
    active = active_filter_count(flt)

    with st.sidebar:
        md("<div class='sb-sec'>Share this view</div>")
        with st.container(key="share"):
            st.code(share_url({
                "view": None if view == "All" else view,
                "run": None if run_bytes is not None or not runs
                or st.session_state.get("run") == next(iter(runs))
                else st.session_state.get("run"),
                "light": light, **{k: flt[n] for n, k in MULTI_KEYS.items()},
                "q": flt["query"].strip(),
                "days": list(flt["days"]) if flt["days"] else None,
                "entity": st.query_params.get("entity"),
            }), language=None, wrap_lines=True)
            md("<div class='share-note'>Copy it to reopen this exact view. "
               "A <span class='mono'>localhost</span> link opens on this "
               "computer only; for another device use the Network URL.</div>")
        md("<div class='sb-foot kbd-hint'><kbd>1</kbd>–<kbd>7</kbd> pages · "
           "<kbd>L</kbd> theme · <kbd>X</kbd> clear filters<br>read-only viewer</div>")

    if active:
        md(f"<div class='filter-pill'><span class='seal'></span>{active} filter(s) "
           f"active — {len(fent)} of {len(entities)} entities, {len(ffind)} of "
           f"{len(findings)} findings · press <kbd>X</kbd> to clear</div>")

    manifest_info = {"attested": attested, "results": results}
    if view == "All":
        if active:
            # filtered mode: clear the run-level overview and show only what
            # matches — verdict and context stay separate (never merged).
            md("<h3>Filtered results</h3>")
            tl = (apply_filters(entities, findings, {**flt, "days": None})[1]
                  if flt["days"] else ffind)
            activity_block(tl, "Activity", "matching findings per day"
                           + (" · outlined: date range" if flt["days"] else ""),
                           flt["days"])
            panel_verdict(fent, view_model, flt)
            st.divider(); panel_context(fent, view_model, flt)
        else:
            panel_overview(view_model)
            st.divider(); panel_verdict(fent, view_model, flt)
            st.divider(); panel_context(fent, view_model, flt)
            st.divider(); panel_prioritisation(view_model)
            st.divider(); panel_narrative(run, view_model, gate)
            st.divider(); panel_downloads(run_path, run_bytes, ffind, bool(active),
                                          manifest_info, uploads)
    elif view == "Verdict":
        panel_verdict(fent, view_model, flt)
    elif view == "Context":
        panel_context(fent, view_model, flt)
    elif view == "Prioritisation":
        panel_prioritisation(view_model)
    elif view == "Narrative":
        panel_narrative(run, view_model, gate)
    elif view == "Downloads":
        panel_downloads(run_path, run_bytes, ffind, bool(active), manifest_info, uploads)
    elif view == "Guide":
        panel_guide()

    # ---- footer: the manifest is displayed, not embedded ----
    src = run_path if run_path else f"uploaded: {upload_name}"
    cpath = view_model.get("collection_path")
    md(f"<div class='foot'>manifest.sha256 (run.json): "
       f"<span class='hash'>{esc(manifest_sha or 'not present')}</span><br>"
       f"computed SHA-256 of loaded file: <span class='hash'>{raw_sha}</span><br>"
       f"source: {esc(src)} · schema v{esc(ver)}"
       + (f" · collected from <span class='mono'>{esc(cpath)}</span>" if cpath else "")
       + " · build: r4 · read-only viewer — no file writes, no recomputation, "
       "no reordering across panels.</div>")


if __name__ == "__main__":
    main()
