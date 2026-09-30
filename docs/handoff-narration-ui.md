# Handoff — attaching the narration to the viewer

From Person B (pipeline), to Person A (viewer). 2026-09-24.
Branch `week2/parsers-registry-browser`. Pull before building against this.

## The one thing to know

**The viewer never calls a model.** The narration is produced by the pipeline,
checked by the pipeline, and written into `run.json` *before* the manifest is
hashed. By the time the viewer loads a run, the narration is plain data in the
file it already reads, sealed by the same `manifest.sha256`. Uploading a
`run.json` brings its narration with it.

Where the model runs (this machine or the Mint laptop) makes no difference to
you: the `narration` block has the same shape either way.

## Where it lives

`run.json` → top-level key **`narration`**. It is **optional**: narration is off
by default, so most runs have no such key. Absence is the normal case, not an
error.

```json
"narration": {
  "is_verdict": false,
  "status": "accepted",                 // "accepted" | "rejected" | "error"
  "text": "invoice_scan.exe has triage score 99 (critical) ...",   // ONLY when accepted
  "ranking_sentences": [                // written by CODE from the record, not the model
    "In the moda_g anomaly ranking, invoice_scan.exe is rank 14 of 443 (amcache, percentile 0.9579; 0 = most unusual of its kind). This ranks unusualness; it is not a detection."
  ],
  "validation": {
    "validated": true,
    "unresolvable": [],                 // every failed check, one string each
    "citations": {"rule_ids": ["R-CORR-0003", "..."], "exes": ["invoice_scan.exe"]},
    "relation_errors": [],
    "missing_mentions": [],
    "describes_ranking_as_detection": false,
    "mentions_scorer": false            // informational only -- ignore
  },
  "backend": "ollama", "model": "qwen2.5:7b", "model_digest": "sha256...",
  "endpoint": "localhost:11434",
  "temperature": 0.0, "seed": 20260830,
  "prompt_version": "8", "prompt_sha256": "...", "facts_sha256": "...",
  "generated_at": "2026-09-24T...Z",
  "rejected": {"text": "..."},          // ONLY when rejected -- audit, never render
  "error": "URLError: ..."              // ONLY when error
}
```

`ranking_sentences` and `facts_sha256` are new in this handoff; every other key
is as before. `run_json_version` stays `1.5.0` — the block was already optional,
and both keys are additive.

## What to render, per state

| State | Show | Never show |
|---|---|---|
| no `narration` key | nothing, or "No AI summary for this run." | — |
| `status: "accepted"` | `text`, then `ranking_sentences`, then the provenance line | — |
| `status: "rejected"` | a neutral notice: "AI summary withheld — it failed N checks." (N = `validation.unresolvable.length`) | **`rejected.text`** — not in the page, not in a tooltip, not in the DOM |
| `status: "error"` | "AI summary unavailable (model not reachable)." | the raw `error` string, unless in a debug view |

Your current rule (render only on `accepted`, never read `rejected.text`, a test
planting text there to prove it) is exactly right — keep it. The only addition
is the optional one-line notice on `rejected` / `error`, so an analyst can tell
"no summary was requested" from "a summary was requested and blocked".

## How to present it

- **Narrative tab only.** Never inside the Verdict panel, the priority list or
  the entity case file. `is_verdict` is `false`: this is prose *about* the
  findings, never a finding.
- **Label:** `AI-GENERATED · NOT A VERDICT`, dashed border — what you have.
- **Two visually different parts.** `text` is the model's; `ranking_sentences`
  are code, taken verbatim from the record. Render the ranking sentences under
  the summary with their own small label, e.g. "From the anomaly ranking (not
  AI)". Do not merge them into the AI paragraph.
- **Keep "the record for everything it cites".** For each id in
  `validation.citations.rule_ids`, link to that rule's findings; for each name in
  `citations.exes`, link to its case file. That table is what lets an analyst
  check the summary in one click, and it is the best feature of your panel.
- **Provenance line** (small, under the panel): model, `model_digest` (first 12
  chars), `prompt_version`, `seed`, `temperature`, `generated_at`.

## What "accepted" does and does not mean

`accepted` means every check passed: every rule id, name, number, time, date,
event-log name and host resolves to this run; the critical entity and every
corpus-validated finding on it are cited; no rank, score-ordering or
"then/after" claim contradicts the record; at least 3 sentences.

It does **not** mean the prose is right in every way. Claims about intent or
cause have no field to check against. That is why it stays labelled, separate
and non-authoritative — say so in your Guide.

## The honest current state

With `qwen2.5:7b` and prompt v8, the s1_v3 narration is **rejected**: it skips
the Recycle Bin deletion (R-CORR-0006) and puts R-CORR-0003's 11:50 execution
time next to R-ATOMIC-0006. The checks are doing their job — but it means a
real narrated run today exercises your **withheld** path, not the accepted one.

For building and testing the **accepted** path, make a fixture: copy a
`run.json`, set `status` to `"accepted"`, and put in `text` the corrected
summary from your own review (section 7) — the pipeline's validator accepts that
text. Mark the file as a fixture, as your viewer already does for samples.

## Producing a narrated run yourself

Needs Ollama reachable (locally or on the Mint laptop) — see
`docs/narration-setup.md`. Then, from the repo:

```powershell
.\tools\run_with_narration.ps1 -Check        # is Ollama up, is the model pulled?
.\tools\run_with_narration.ps1 `
    -Collection $HOME\dfir-evidence\collection_s1_v3 `
    -Baseline   $HOME\dfir-evidence\collection_clean_c
```

Add `-Endpoint http://<mint-ip>:11434` to use the Mint laptop. Output is in
`outputs\narrated\` — load that `run.json` in the viewer as usual.

**For the demo: load a pre-generated run. Do not call the model live.**
