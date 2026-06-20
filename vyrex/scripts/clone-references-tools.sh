#!/usr/bin/env bash
# Phase A (tool-integration expansion): shallow-clone the new tool reference repos
# into reference/ (gitignored, study-only). wazuh/wazuh is already present from Phase 0.
set -u
REF_DIR="$(cd "$(dirname "$0")/.." && pwd)/reference"
mkdir -p "$REF_DIR"; cd "$REF_DIR" || exit 1
LOG="$REF_DIR/_clone_tools.log"; : > "$LOG"

repos=(
  "https://github.com/OISF/suricata"
  "https://github.com/zeek/zeek"
  "https://github.com/projectdiscovery/nuclei"
  "https://github.com/aquasecurity/trivy"
  "https://github.com/MISP/PyMISP"
  "https://github.com/OpenCTI-Platform/client-python"
  "https://github.com/SigmaHQ/pySigma"
  "https://github.com/SigmaHQ/pySigma-backend-opensearch"
  "https://github.com/SigmaHQ/sigma"
  "https://github.com/falcosecurity/falco"
  "https://github.com/falcosecurity/client-go"
  "https://github.com/Fortra/nvdlib"
  "https://github.com/corelight/zeek2es"
  "https://github.com/pfyon/suricatarest"
  "https://github.com/zeek/broker"
  "https://github.com/mrtc0/wazuh"
)

ok=0; fail=0
for url in "${repos[@]}"; do
  name="$(basename "$url")"
  if [ -d "$name/.git" ]; then echo "SKIP  $name" | tee -a "$LOG"; ok=$((ok+1)); continue; fi
  echo "CLONE $url" | tee -a "$LOG"
  if git clone --depth 1 --single-branch --no-tags "$url" "$name" >>"$LOG" 2>&1; then
    echo "  OK   $name" | tee -a "$LOG"; ok=$((ok+1))
  else
    echo "  FAIL $name" | tee -a "$LOG"; fail=$((fail+1))
  fi
done
echo "DONE tools cloned_ok=$ok failed=$fail" | tee -a "$LOG"
