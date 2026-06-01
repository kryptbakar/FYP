"""Online feed fetchers — the ONLY code in the platform that calls the internet.

Each returns rows already normalized to the mirror's shape (see db.py). Raw
responses are cached to disk so an air-gapped site can ship the cache and replay
it with `--from-cache` instead of reaching out.

Verify endpoints/format before relying on them (NVD/EPSS/CISA change paths):
- NVD 2.0:  https://services.nvd.nist.gov/rest/json/cves/2.0
- EPSS CSV: https://epss.cyentia.com/epss_scores-current.csv.gz
- CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import csv
import gzip
import io
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

log = logging.getLogger("feed-sync.fetch")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


# ---------------------------------------------------------------- KEV --------
def fetch_kev(client: httpx.Client) -> list[dict[str, Any]]:
    r = client.get(KEV_URL, timeout=60)
    r.raise_for_status()
    data = r.json()
    rows = []
    for v in data.get("vulnerabilities", []):
        rows.append(
            {
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "date_added": v.get("dateAdded"),
                "due_date": v.get("dueDate"),
                "known_ransomware": v.get("knownRansomwareCampaignUse"),
                "notes": v.get("notes"),
            }
        )
    log.info("KEV: %d entries", len(rows))
    return rows


# --------------------------------------------------------------- EPSS --------
def fetch_epss(client: httpx.Client, limit: int = 0) -> list[dict[str, Any]]:
    r = client.get(EPSS_URL, timeout=120)
    r.raise_for_status()
    raw = gzip.decompress(r.content).decode("utf-8", errors="replace")
    score_date = None
    rows: list[dict[str, Any]] = []
    reader = csv.reader(io.StringIO(raw))
    header_seen = False
    for line in reader:
        if not line:
            continue
        if line[0].startswith("#"):  # e.g. "#model_version:...,score_date:2026-06-01T00:00:00+0000"
            for tok in ",".join(line).split(","):
                if "score_date" in tok:
                    score_date = tok.split(":", 1)[1].strip()[:10]
            continue
        if not header_seen:  # the "cve,epss,percentile" header row
            header_seen = True
            continue
        if len(line) < 3:
            continue
        rows.append(
            {"cve_id": line[0], "epss": float(line[1]), "percentile": float(line[2]), "score_date": score_date}
        )
        if limit and len(rows) >= limit:
            break
    log.info("EPSS: %d scores (score_date=%s)", len(rows), score_date)
    return rows


# ---------------------------------------------------------------- NVD --------
def fetch_nvd(client: httpx.Client, days: int, api_key: str | None) -> list[dict[str, Any]]:
    """Incremental NVD pull over the last `days` (lastModStartDate/EndDate window)."""
    headers = {"apiKey": api_key} if api_key else {}
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    page_size = 2000
    sleep = 0.7 if api_key else 6.5  # respect NVD rate limits
    out: list[dict[str, Any]] = []
    start_index = 0
    while True:
        params = {
            "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        r = client.get(NVD_URL, params=params, headers=headers, timeout=120)
        r.raise_for_status()
        data = r.json()
        for item in data.get("vulnerabilities", []):
            out.append(_parse_nvd_cve(item.get("cve", {})))
        total = data.get("totalResults", 0)
        start_index += page_size
        log.info("NVD: %d/%d", min(start_index, total), total)
        if start_index >= total:
            break
        time.sleep(sleep)
    return out


def _parse_nvd_cve(cve: dict[str, Any]) -> dict[str, Any]:
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    score, severity, vector = _best_cvss(cve.get("metrics", {}))
    return {
        "cve_id": cve.get("id"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "description": desc,
        "affected": _parse_configs(cve.get("configurations", [])),
    }


def _best_cvss(metrics: dict[str, Any]):
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity"), d.get("vectorString")
    arr = metrics.get("cvssMetricV2")
    if arr:
        d = arr[0].get("cvssData", {})
        return d.get("baseScore"), arr[0].get("baseSeverity"), d.get("vectorString")
    return None, None, None


def _parse_configs(configs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    affected: list[dict[str, Any]] = []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", False):
                    continue
                parts = (m.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                vendor, product, exact = parts[3], parts[4], parts[5]
                row = {"vendor": vendor, "product": product,
                       "version_start": None, "version_start_incl": True,
                       "version_end": None, "version_end_excl": True}
                if m.get("versionStartIncluding"):
                    row["version_start"], row["version_start_incl"] = m["versionStartIncluding"], True
                elif m.get("versionStartExcluding"):
                    row["version_start"], row["version_start_incl"] = m["versionStartExcluding"], False
                if m.get("versionEndIncluding"):
                    row["version_end"], row["version_end_excl"] = m["versionEndIncluding"], False
                elif m.get("versionEndExcluding"):
                    row["version_end"], row["version_end_excl"] = m["versionEndExcluding"], True
                if exact not in ("*", "-") and not row["version_start"] and not row["version_end"]:
                    row["version_start"] = row["version_end"] = exact
                    row["version_start_incl"] = row["version_end_excl"] = True
                affected.append(row)
    return affected
