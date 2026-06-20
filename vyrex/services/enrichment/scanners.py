"""Parse active-scanner output (Trivy, Nuclei) into enriched findings.

The scanners already map a target to CVEs/templates; we route each CVE through the
LOCAL feed mirror (EPSS + KEV from the matcher) and write a finding tagged by
`source_tool`, so scanner results become first-class findings — ranked by the
risk-engine and fused with agent findings in Phase F (consensus by `dedup_key`).
"""
from __future__ import annotations

from domains import _finding
from matcher import Matcher

_SEV = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _epss_kev(matcher: Matcher, cve: str | None):
    if not cve:
        return {}, None
    return matcher.epss.get(cve, {}), matcher.kev.get(cve)


def _trivy_cvss(v: dict) -> float | None:
    cvss = v.get("CVSS") or {}
    for src in ("nvd", "redhat", "ghsa"):
        if cvss.get(src) and cvss[src].get("V3Score") is not None:
            return cvss[src]["V3Score"]
    return None


def parse_trivy(report: dict, asset_id: str, matcher: Matcher) -> list[dict]:
    out = []
    for res in report.get("Results", []) or []:
        target = res.get("Target")
        for v in res.get("Vulnerabilities") or []:
            cve = v.get("VulnerabilityID")
            sev = (v.get("Severity") or "UNKNOWN").upper()
            e, k = _epss_kev(matcher, cve)
            out.append(_finding(
                asset_id, "application", cve or v.get("PkgName"),
                title=f"{cve} in {v.get('PkgName')} {v.get('InstalledVersion')}",
                severity=sev if sev in _SEV else "UNKNOWN",
                description=v.get("Title") or v.get("Description"),
                cve_id=cve, package_name=v.get("PkgName"), package_version=v.get("InstalledVersion"),
                cvss_score=_trivy_cvss(v), cvss_severity=sev if sev in _SEV else None,
                epss=e.get("epss"), epss_percentile=e.get("percentile"),
                kev=k is not None, kev_due_date=(k["due_date"] if k else None),
                source_tool="trivy", raw_ref=v.get("PrimaryURL") or target,
                evidence={"target": target, "fixed_version": v.get("FixedVersion"), "pkg": v.get("PkgName")},
            ))
    return out


def parse_nuclei(records: list[dict], asset_id: str, matcher: Matcher) -> list[dict]:
    out = []
    for rec in records:
        info = rec.get("info", {})
        tid = rec.get("template-id")
        sev = (info.get("severity") or "info").upper()
        cves = (info.get("classification") or {}).get("cve-id") or []
        cve = cves[0] if cves else None
        port = _port_of(rec.get("matched-at") or rec.get("host"))
        domain = "application" if cve else "network"
        e, k = _epss_kev(matcher, cve)
        out.append(_finding(
            asset_id, domain, cve or tid,
            title=info.get("name") or tid,
            severity=sev if sev in _SEV else "INFO",
            description=f"Nuclei template '{tid}' matched at {rec.get('matched-at')}",
            cve_id=cve, port=port, proto="tcp",
            epss=e.get("epss"), epss_percentile=e.get("percentile"),
            kev=k is not None, kev_due_date=(k["due_date"] if k else None),
            source_tool="nuclei", raw_ref=rec.get("matched-at"),
            evidence={"template": tid, "matched_at": rec.get("matched-at"), "type": rec.get("type")},
        ))
    return out


def _port_of(url: str | None) -> int | None:
    if not url:
        return None
    try:
        rest = url.split("://", 1)[-1]
        hostport = rest.split("/", 1)[0]
        if ":" in hostport:
            return int(hostport.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None
    return None
