# DFIR Triage Viewer

An interactive, **read-only** viewer over a single frozen `run.json` — the
pipeline's output contract, **v1.5.0**. An analyst explores one canonical
artifact; the app never produces, re-scores, re-orders, or modifies evidence.

> The interactive UI reads the canonical `run.json`; it does not produce or
> modify evidence.

## The one rule, enforced in code

The UI is a projection of one file whose SHA-256 is recorded in
`manifest.sha256`. There is **no write path** in `app.py` or the
`dfir_viewer/` package — no `open(...,'w')`, no `write_text`/`write_bytes`, no
`json.dump`, no `to_csv`, no recomputation of detection or scoring. A test
scans every source file for these calls on each run. The panels are never
merged — verdict stays verdict, context stays context, the anomaly ranking
stays a ranking, and narration stays narration.

## Run

**Windows PowerShell** (from the `viewer` folder):

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

First time only: `python -m venv .venv`, then
`.\.venv\Scripts\python.exe -m pip install -r requirements.txt`.
In VS Code, press **F5** and choose “Streamlit: scenario run”.

The viewer opens in your browser by itself and the terminal prints two links:

| Link | Opens from |
|---|---|
| **Local URL** `http://localhost:8501` | this computer |
| **Network URL** `http://<your-ip>:8501` | any device on the same Wi-Fi / LAN (allow Python through the Windows firewall on *Private* networks) |

After editing code, stop with **Ctrl+C** and run again (the file watcher is
off on purpose).

## The run it shows

`samples/s1_v3/` is the pipeline's own output, shipped by the pipeline owner
(handoff of 2026-09-22/23): `collection_s1_v3`, contract **v1.5.0**, anomaly
scorer **`moda_g`**, narration from a local `qwen2.5:7b`. Its manifest
verifies (`sha256sum -c manifest.sha256`: run.json, findings.csv and
anomalies.csv OK). The manifest also attests `report.html`; drop that file
into `samples/s1_v3/` and the viewer verifies it too — until then it shows as
*absent*, which is not a mismatch.

To view another run, add a folder `samples/<name>/` holding its `run.json`
(plus the manifest and CSVs), or use **Upload a run folder's files** in the
sidebar: pick `run.json` together with `manifest.sha256` and the CSVs, and
every uploaded file is checked against the manifest in memory.

The old v1.4.0 fixtures now live in `tests/fixtures/` and are used only by the
test suite, to prove the viewer still reads the legacy shape. They are never
listed in the UI, even if a copy is left in `samples/`.

## Code layout

| File | Role |
|---|---|
| `app.py` | page wiring and state: sidebar, URL binding, shortcuts, provenance banners |
| `dfir_viewer/contract.py` | the run.json contract: one adapter (`normalize_run`) for v1.5.0 and legacy v1.4.0, the manifest check, the narration gate |
| `dfir_viewer/model.py` | pure Python — the schema gate, filters, date range, CSV export |
| `dfir_viewer/components.py` | HTML blocks (charts, chips, case file, guide); **every run value passes through `esc()`** |
| `dfir_viewer/panels.py` | the screens |
| `dfir_viewer/theme.py` + `styles.css` | the two palettes and the stylesheet |

## Screens

1. **Overview** — the **priority queue** (run.json's scored entities in the
   pipeline's order, by **triage score**), run facts (findings, events in the
   timeline, files parsed, the anomaly scorer), an **activity timeline**,
   findings by weight band, findings by rule class, the phases (Class 1
   filled, Class 2 as context), ATT&CK techniques the rules map to, **rule coverage** (every rule evaluated — including
   the ones that found nothing) and **evidence ingested** by artifact type.
2. **Verdict — Class 1 (`corpus-validated`)** — the detection layer,
   independent of the anomaly scorer. Entity table → case file → findings
   timeline → source events (`source_file :: source_locator`) → the
   surrounding timeline slice the pipeline recorded.
3. **Context — Class 2 (`known-behavior`)** — same drill-down, labelled
   *context only, not a verdict*. v1.5.0 lists only the entities the rules
   layer scored, so every other name a finding mentions is grouped here by name
   and shows **no triage score** (“—”), never a made-up one.
4. **Prioritisation** — the anomaly ranking, with the **scorer read from
   run.json** (`moda_g` here; it changes if the pipeline runs with
   `DFIR_ANOMALY_SCORER=isolation_forest`). Position is the order in
   run.json; the within-family position (ties shared) is what a percentile
   compares, and **0 is the most unusual row of its kind**. Unusual is not malicious — common
   OS binaries lead this list. Families that were not scored are listed with
   the pipeline's reason.
5. **Narrative** — see below.
6. **Downloads** — export the current (filtered) view as CSV, built in
   memory; plus `run.json`, `findings.csv`, `anomalies.csv`,
   `manifest.sha256` and `report.html`, each tagged verified / mismatch /
   absent.
7. **Guide** — every symbol, the keyboard, and what the numbers mean.

## What the numbers mean

**Severity is the weight of the rules that matched, not an assessment of the
entity.** On a finding it is that rule's weight band; on an entity it is the
band of its triage score. The **triage score** is the pipeline's score derived
from the weights of the Class 1 rules that matched — not their sum: the case
file shows both numbers run.json records (*raw sum 225 → triage score 99*), and
states that the Class 2 findings naming the entity do not add to it. It marks
where to look first. `npp.8.9.8.installer.x64.exe`
is *high* only because a downloaded file was executed (R-CORR-0001) — what
every installer does. The case file lists the rules behind every score, and the
drill-down to the source events is what settles it.

**Time claims.** Some artifacts record that something exists, not when it
happened (a registry value carries its key's last-write time). Those findings
are marked *presence only — not an event time*, are left off the Activity
chart, and are excluded while a date range is set.

## Keeping Class 2 from reading as Class 1

126 of this run's 132 findings are Class 2 (known-behavior, commonly benign).
Wherever the two could be confused, they are split:

- **Phases**: a node is filled only by Class 1 findings. Class 2 shows as
  *+N context* beneath it. The "exfiltrate" phase therefore reads 0, with
  +11 context: those 11 are SRUM network-egress matches, not an exfiltration.
- **ATT&CK tiles**: the large number counts Class 1. Context-only techniques
  (T1105, T1036, T1041, T1543.003) show 0 on a dashed tile.
- **This run**: critical- and high-band counts state how many are Class 1.
- **Activity** and **weight-band** charts count both classes and say so.
- **Context page**: every column describes the entity's Class 2 findings only,
  and rows sort by those findings, not by triage score.
- Beside a specific file, a technique shows as its ID only, with the ATT&CK name
  on hover. "Malicious File" next to an installer reads as a judgement; the
  rule's own title says what was observed.
- Entity kind reads *file*, not *binary*: 77 of the 113 names are not .exe —
  documents, archives, media, data and installer packages.
- Within an anomaly family, tied percentiles share a position (*=7 of 344,
  5 tied*).

## Narration

AI prose about the findings, never a finding. It follows the pipeline owner's
rules exactly:

- shown only when `narration.status == "accepted"`; on `rejected` or `error`
  nothing of the prose is shown, and `narration.rejected.text` is never read;
- labelled **AI-GENERATED · NOT A VERDICT**, set apart with a dashed border,
  and never placed in the Verdict panel;
- absent is the normal case (narration is off by default).

On top of that, the viewer re-checks what it can and withholds the text if any
check fails:

- the pipeline validator must say `validated`, nothing may be unresolvable, and
  the ranking must not be described as detection;
- every cited rule id and name must exist in this run (a rule id written in the
  prose but not declared also fails);
- **relation checks**: numbers must be in the record of what the prose cites, a
  score must be that entity's triage score, a rank claim (first, 2nd, "rank 3")
  must match the record, severity may not be given a number, no comparison or
  interpretation of suspicion or safety, and no un-negated verdict words.

These checks are a floor, not proof.

*Accepted* does not mean *correct*. **This sample's narration is withheld**:
it says `invoice_scan.exe` is "ranked first" by `moda_g` (the record says
position 14 of 443), reads percentile 0 as "less suspicious" (0 is the most
unusual), and calls 99 a "severity score". The page shows those three reasons
and no prose. When narration does pass, the viewer shows **the record for
everything it cites** beneath it. `handoff/for-person-b-narration.md` proposes
the pipeline-side fix.

## Evidence is untrusted input

- **HTML injection.** Every run value is escaped. Without it, an entity named
  `</span><div class='banner banner-ok'>Manifest verified</div>` drew a fake
  *Manifest verified* banner inside the page.
- **Spreadsheet formula injection.** In the CSV export, a cell starting with
  `= + - @` is prefixed with `'`.

## Provenance

`manifest.sha256` lists every shipped file. The viewer hashes each one it has
and reports **verified**, **mismatch** (altered — do not trust the view) or
**absent** (not here to check). The footer shows the attested and computed
SHA-256 of run.json and the collection path.

## Shareable links and keyboard

Page, run, filters, date range, theme and selected entity live in the address
bar (`?view=Verdict&entity=invoice_scan.exe`); **Share this view** in the
sidebar gives the link ready to copy.

| Key | Action |
|---|---|
| `1` – `7` | All, Verdict, Context, Prioritisation, Narrative, Downloads, Guide |
| `L` | light / dark theme |
| `X` | clear every filter |

## Colour, validated

Colour encodes one thing: **severity**, a single warm hue stepping in lightness
(validated with the `dataviz` skill's `validate_palette.js --ordinal`):

| Theme | low → critical |
|---|---|
| Light | `#d69c6f` `#bd7244` `#99492a` `#6c2913` |
| Dark | `#834226` `#b05e3c` `#d88657` `#f3b88f` |

The stylesheet hooks only onto stable Streamlit markers (`data-testid`, ARIA
roles, `st-key-<key>`), never generated class names; a test enforces this.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -q
```

108 tests, including: every page on the real run and both legacy fixtures in
both themes; no write path; the v1.5 adapter; the scorer read from the file;
triage-score and severity wording; verdict and context never sharing a finding;
unlisted entities never given a score; every manifest file checked and any
tampered file tripping *mismatch*; accepted narration shown with the record,
rejected narration showing nothing, the viewer's re-check withholding an
unresolvable citation; presence-only findings kept off the time axis; hostile
markup escaped on every page; CSV formula neutralisation; links, shortcuts, and
the stylesheet guard.

`build_fixtures.py` regenerates the legacy fixtures in `tests/fixtures/`.
