#!/usr/bin/env bash
# Phase 0: shallow-clone all reference repositories into reference/.
# These are for STUDY ONLY. reference/ is gitignored and never committed.
# Shallow (--depth 1) keeps disk/bandwidth down while still giving us the
# LICENSE file we need for ATTRIBUTIONS.md.
set -u

REF_DIR="$(cd "$(dirname "$0")/.." && pwd)/reference"
mkdir -p "$REF_DIR"
cd "$REF_DIR" || exit 1

LOG="$REF_DIR/_clone.log"
: > "$LOG"

repos=(
  "https://github.com/DefectDojo/django-DefectDojo"
  "https://github.com/infobyte/faraday"
  "https://github.com/IKER-36/Cve-Extractor-Public"
  "https://github.com/dinesh-murugan-h/CVEraptor"
  "https://github.com/tcoatswo/cve-watch"
  "https://github.com/cyb3ri0t/Faraday_CVE_Parser"
  "https://github.com/shreyas23dev/Attack-Phase-Aware-Dynamic-Vulnerability-Prioritization-Framework"
  "https://github.com/francesco-denu/cve-enriched-dataset"
  "https://github.com/themalkaanjalarathnasiri/cvss_score_prediction_model"
  "https://github.com/dmlc/xgboost"
  "https://github.com/shap/shap"
  "https://github.com/osquery/osquery"
  "https://github.com/cilium/ebpf"
  "https://github.com/VirusTotal/yara"
  "https://github.com/wazuh/wazuh"
  "https://github.com/Velocidex/velociraptor"
  "https://github.com/TheHive-Project/TheHive"
  "https://github.com/TheHive-Project/Cortex"
  "https://github.com/ArfanAbid/Open-Source-SIEM_SOC-Stack"
  "https://github.com/dominguezbernaldo943-svg/SOC-IN-A-BOX"
  "https://github.com/FunnyWolf/agentic-soc-platform"
)

ok=0; fail=0
for url in "${repos[@]}"; do
  name="$(basename "$url")"
  if [ -d "$name/.git" ]; then
    echo "SKIP  $name (already present)" | tee -a "$LOG"
    ok=$((ok+1)); continue
  fi
  echo "CLONE $url" | tee -a "$LOG"
  if git clone --depth 1 --single-branch --no-tags "$url" "$name" >>"$LOG" 2>&1; then
    echo "  OK   $name" | tee -a "$LOG"
    ok=$((ok+1))
  else
    echo "  FAIL $name" | tee -a "$LOG"
    fail=$((fail+1))
  fi
done

echo "DONE cloned_ok=$ok failed=$fail" | tee -a "$LOG"
