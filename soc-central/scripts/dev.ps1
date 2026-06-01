<#
.SYNOPSIS
  SOC Central developer task runner for Windows (mirrors the Makefile).
.EXAMPLE
  pwsh scripts/dev.ps1 up
  pwsh scripts/dev.ps1 health
#>
param(
  [Parameter(Position = 0)]
  [ValidateSet('help','env','up','down','clean','restart','ps','logs','health','clone-refs','seed','test','agent-run')]
  [string]$Target = 'help'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
$Compose = 'docker compose'

function Ensure-Env {
  if (-not (Test-Path "$Root\.env")) {
    Copy-Item "$Root\.env.example" "$Root\.env"
    Write-Host "Created .env from .env.example"
  }
}

switch ($Target) {
  'help' {
    Write-Host "SOC Central targets:"
    'env, up, down, clean, restart, ps, logs, health, clone-refs, seed, test, agent-run' -split ', ' |
      ForEach-Object { Write-Host "  $_" }
  }
  'env'      { Ensure-Env }
  'up'       { Ensure-Env; Invoke-Expression "$Compose up -d --build" }
  'down'     { Invoke-Expression "$Compose down" }
  'clean'    { Invoke-Expression "$Compose down -v" }
  'restart'  { Invoke-Expression "$Compose restart" }
  'ps'       { Invoke-Expression "$Compose ps" }
  'logs'     { Invoke-Expression "$Compose logs -f --tail=100" }
  'health'   {
    Write-Host "--- /health ---";        Invoke-RestMethod http://localhost:8000/health | ConvertTo-Json -Compress
    Write-Host "--- /version ---";       Invoke-RestMethod http://localhost:8000/version | ConvertTo-Json -Compress
    Write-Host "--- /health/ready ---";  Invoke-RestMethod http://localhost:8000/health/ready | ConvertTo-Json -Depth 5
  }
  'clone-refs' { bash scripts/clone-references.sh }
  'seed'       { Write-Host "seed: not implemented until Phase 1" }
  'test'       { Write-Host "test: not implemented until Phase 1" }
  'agent-run'  { Write-Host "agent-run: not implemented until Phase 2" }
}
