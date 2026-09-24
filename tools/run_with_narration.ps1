<#
.SYNOPSIS
  Run the pipeline with LLM narration, against Ollama on THIS machine or on
  another one (the Mint laptop).

.DESCRIPTION
  Narration is off by default. This helper turns it on for one run, checks the
  Ollama endpoint and the model BEFORE the ~6-minute pipeline starts, and
  clears any endpoint left over in the shell from an earlier remote run.

  Local  (default): Ollama on this machine, http://localhost:11434
  Remote          : -Endpoint http://192.168.10.217:11434

.EXAMPLE
  # check only -- is Ollama up, is the model pulled?
  .\tools\run_with_narration.ps1 -Check

.EXAMPLE
  # full run, Ollama on this machine
  .\tools\run_with_narration.ps1 `
      -Collection %USERPROFILE%\dfir-evidence\collection_s1_v3 `
      -Baseline   %USERPROFILE%\dfir-evidence\collection_clean_c

.EXAMPLE
  # full run, Ollama on the Mint laptop
  .\tools\run_with_narration.ps1 -Collection ... -Baseline ... `
      -Endpoint http://192.168.10.217:11434
#>
param(
    [string]$Collection,
    [string]$Baseline,
    [string]$Model = "qwen2.5:7b",
    [string]$Endpoint = "http://localhost:11434",
    [string]$OutDir = ".\outputs\narrated",
    [switch]$Check
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$python = Join-Path $repo ".venv\Scripts\python.exe"

# ---- 1. is Ollama reachable, and is the model pulled? ----------------------
Write-Host "Ollama     : $Endpoint"
try {
    $tags = Invoke-RestMethod -Uri "$Endpoint/api/tags" -TimeoutSec 10
} catch {
    Write-Host "  !! not reachable. Local: is the Ollama app running (tray icon)?" -ForegroundColor Red
    Write-Host "     Remote: is OLLAMA_HOST=0.0.0.0 set on that machine, and is the IP right?" -ForegroundColor Red
    exit 1
}
$names = @($tags.models | ForEach-Object { $_.name })
if ($names -notcontains $Model) {
    Write-Host "  !! model '$Model' is not pulled there. Have: $($names -join ', ')" -ForegroundColor Red
    Write-Host "     Fix:  ollama pull $Model" -ForegroundColor Red
    exit 1
}
Write-Host "  ok -- '$Model' is available"
if ($Check) { exit 0 }

if (-not $Collection -or -not $Baseline) {
    Write-Host "  !! -Collection and -Baseline are required for a run (or use -Check)" -ForegroundColor Red
    exit 1
}

# ---- 2. run the pipeline with narration on, for this process only ---------
$env:DFIR_NARRATION = "ollama:$Model"
$env:DFIR_NARRATION_ENDPOINT = $Endpoint   # set explicitly: never inherit a stale one

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
& $python -m dfir_triage_pipeline $Collection `
    --output (Join-Path $OutDir "timeline.csv") `
    --run-json (Join-Path $OutDir "run.json") `
    --report --baseline $Baseline
$code = $LASTEXITCODE

Remove-Item Env:DFIR_NARRATION -ErrorAction SilentlyContinue
Remove-Item Env:DFIR_NARRATION_ENDPOINT -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Output     : $OutDir  (run.json, report.html, manifest.sha256, ...)"
exit $code
