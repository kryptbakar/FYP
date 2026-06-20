#!/usr/bin/env bash
# Generate a dated posture report (CSV + HTML) from the API. Pairs the console's on-demand
# PDF/CSV export with a *scheduled* report for stakeholders who want it pushed, not pulled.
# Run by the scheduled-report CronJob; writes to a shared volume (or pipe to email/object store).
set -euo pipefail

API="${API:-http://api:8000}"
OUT="${OUT:-/reports}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${OUT}"

echo "[report] pulling posture from ${API}"
STATS="$(curl -fsS "${API}/stats/summary")"
COMP="$(curl -fsS "${API}/compliance/summary")"
RANK="$(curl -fsS "${API}/risk/ranking?limit=25")"

# --- CSV: top risks ---
CSV="${OUT}/soc-report-${STAMP}.csv"
echo "rank,score,severity,asset,cve,title" >"${CSV}"
echo "${RANK}" | jq -r '.[] | [.risk_rank, .risk_score, .severity, .asset_id, (.cve_id // ""), .title] | @csv' >>"${CSV}"

# --- HTML: one-page executive summary ---
HTML="${OUT}/soc-report-${STAMP}.html"
KEV="$(echo "${STATS}" | jq -r '.kev_findings')"
ASSETS="$(echo "${STATS}" | jq -r '.assets')"
{
  echo "<!doctype html><meta charset=utf-8><title>SOC Central posture ${STAMP}</title>"
  echo "<body style='font-family:system-ui;margin:32px;color:#111'>"
  echo "<h1>SOC Central — posture report</h1><p>Generated ${STAMP} (UTC)</p>"
  echo "<p><b>${ASSETS}</b> assets monitored · <b>${KEV}</b> KEV-listed findings</p>"
  echo "<h2>Top risks</h2><table border=1 cellpadding=6 cellspacing=0><tr><th>#</th><th>Score</th><th>Severity</th><th>Asset</th><th>CVE</th><th>Title</th></tr>"
  echo "${RANK}" | jq -r '.[] | "<tr><td>\(.risk_rank)</td><td>\(.risk_score)</td><td>\(.severity)</td><td>\(.asset_id)</td><td>\(.cve_id // "")</td><td>\(.title)</td></tr>"'
  echo "</table></body>"
} >"${HTML}"

echo "[report] wrote ${CSV} and ${HTML}"
