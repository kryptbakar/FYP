<#
.SYNOPSIS
  SOC Central developer task runner for Windows (mirrors the Makefile).
.EXAMPLE
  pwsh scripts/dev.ps1 up
  pwsh scripts/dev.ps1 health
#>
param(
  [Parameter(Position = 0)]
  [ValidateSet('help','env','certs','up','down','clean','restart','ps','logs','health','clone-refs','clone-tools','produce','feeds-seed','feeds-sync','assess','risk-train','risk-score','sensors-test','wazuh-pull','scan-ingest','intel-enrich','mirror-sync','airgap-up','airgap-verify','seed','test','agent-run')]
  [string]$Target = 'help',
  [int]$N = 500
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
    'env, certs, up, down, clean, restart, ps, logs, health, clone-refs, clone-tools, produce, feeds-seed, feeds-sync, assess, risk-train, risk-score, sensors-test, seed, test, agent-run' -split ', ' |
      ForEach-Object { Write-Host "  $_" }
  }
  'env'      { Ensure-Env }
  'certs'    { bash scripts/gen-certs.sh }
  'up'       { Ensure-Env; bash scripts/gen-certs.sh; Invoke-Expression "$Compose up -d --build" }
  'produce'  { Invoke-Expression "$Compose run --rm fake-producer --count $N" }
  'feeds-seed' { Invoke-Expression "$Compose --profile feeds run --rm feed-sync --seed" }
  'feeds-sync' { Invoke-Expression "$Compose --profile feeds run --rm feed-sync --feeds kev,epss,nvd" }
  'assess'     { Invoke-Expression "$Compose run --rm enrichment --once" }
  'risk-train' { Invoke-Expression "$Compose --profile ml run --rm risk-engine train" }
  'risk-score' { Invoke-Expression "$Compose --profile ml run --rm risk-engine score" }
  'clone-tools'  { bash scripts/clone-references-tools.sh }
  'wazuh-pull'   {
    $ct = "$Compose -f docker-compose.yml -f docker-compose.tools.yml"
    Invoke-Expression "$ct build wazuh-bridge"
    Invoke-Expression "$ct run --rm wazuh-bridge --from-fixtures"
  }
  'sensors-test' {
    $ct = "$Compose -f docker-compose.yml -f docker-compose.tools.yml"
    docker run --rm -v "$Root\tools\sensors:/w" -w /w python:3.12-slim python make_test_pcap.py data/test.pcap
    Invoke-Expression "$ct build sensor-bridge"
    Invoke-Expression "$ct run --rm --entrypoint suricata suricata -r /pcaps/test.pcap -l /var/log/suricata -S /var/lib/suricata/rules/local.rules -k none"
    Invoke-Expression "$ct run --rm sensor-bridge --once"
  }
  'scan-ingest'  {
    Invoke-Expression "$Compose build enrichment"
    Invoke-Expression "$Compose run --rm enrichment --scan"
  }
  'intel-enrich' {
    $ct = "$Compose -f docker-compose.yml -f docker-compose.tools.yml"
    Invoke-Expression "$ct build intel-enricher"
    Invoke-Expression "$ct run --rm intel-enricher"
  }
  'mirror-sync'   {
    $seed = if ($N -eq 1) { '--seed' } else { '' }   # pass -N 1 for offline seed mode
    bash tools/airgap/mirror-sync.sh $seed
  }
  'airgap-up'     {
    Ensure-Env; bash scripts/gen-certs.sh
    Invoke-Expression "$Compose -f docker-compose.yml -f docker-compose.airgap.yml up -d --build"
  }
  'airgap-verify' { bash tools/airgap/verify-egress.sh }
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
  'agent-run'  {
    Invoke-Expression "$Compose --profile agent up -d --build agent"
    Write-Host "agent up. Follow logs:  $Compose logs -f agent"
  }
}
