"""The three assessment domains, each turning host state into findings.

  application  package (name, version) -> matched CVEs (CVSS/EPSS/KEV enriched)
  system       rule-based host-hardening gaps (CIS-flavoured; full engine = Phase 4)
  network      exposed sensitive services + suspicious egress, from flow telemetry

Each finding carries a stable fingerprint so re-runs upsert rather than duplicate,
and an `evidence` blob so the finding is explainable (the composite risk score and
SHAP explanations come in Phase 5).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from matcher import Matcher

# Ports we consider sensitive if exposed, and ports that suggest C2 / suspicious egress.
SENSITIVE_PORTS = {21, 23, 25, 110, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
SUSPICIOUS_EGRESS = {4444, 1337, 31337, 6667, 9001, 12345}

INSECURE_PKGS = {"telnetd", "telnet", "inetutils-telnetd", "ftpd", "vsftpd", "proftpd",
                 "rsh-server", "rsh-client", "nis", "tftpd", "xinetd"}
FIREWALL_PKGS = {"nftables", "ufw", "iptables", "iptables-persistent", "firewalld"}


def _fp(*parts: Any) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()


def _finding(asset_id: str, domain: str, rule_id: str, title: str, severity: str, **kw) -> dict:
    source_tool = kw.get("source_tool", "agent")
    # dedup_key groups the SAME underlying issue across tools (Phase-F fusion); fingerprint is
    # per-tool (so e.g. agent + trivy both record a CVE -> consensus). Agent fingerprints keep
    # their original form (no source_tool prefix) so re-assess stays idempotent.
    dedup_key = kw.get("dedup_key") or _fp(asset_id, domain, kw.get("cve_id") or rule_id, kw.get("port"))
    fp_parts = [asset_id, domain, rule_id, kw.get("package_name"), kw.get("port")]
    if source_tool != "agent":
        fp_parts = [source_tool] + fp_parts
    f = {
        "asset_id": asset_id, "domain": domain, "rule_id": rule_id, "title": title,
        "severity": severity, "description": kw.get("description"),
        "cve_id": kw.get("cve_id"), "package_name": kw.get("package_name"),
        "package_version": kw.get("package_version"), "port": kw.get("port"),
        "proto": kw.get("proto"), "cvss_score": kw.get("cvss_score"),
        "cvss_severity": kw.get("cvss_severity"), "epss": kw.get("epss"),
        "epss_percentile": kw.get("epss_percentile"), "kev": kw.get("kev", False),
        "kev_due_date": kw.get("kev_due_date"), "evidence": kw.get("evidence", {}),
        "source_tool": source_tool, "raw_ref": kw.get("raw_ref"), "dedup_key": dedup_key,
        "exploit_refs": kw.get("exploit_refs", []),
        "exploit_available": bool(kw.get("exploit_refs")) or kw.get("kev", False),
    }
    f["fingerprint"] = _fp(*fp_parts)
    return f


# ----------------------------------------------------------- application -----
def assess_application(asset_id: str, packages: list[dict], matcher: Matcher) -> list[dict]:
    findings = []
    for pkg in packages:
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        for m in matcher.match_package(name, version):
            findings.append(_finding(
                asset_id, "application", m.cve_id,
                title=f"{m.cve_id} in {name} {version}",
                severity=m.cvss_severity or "UNKNOWN",
                description=m.description,
                cve_id=m.cve_id, package_name=name, package_version=version,
                cvss_score=m.cvss_score, cvss_severity=m.cvss_severity,
                epss=m.epss, epss_percentile=m.epss_percentile,
                kev=m.kev, kev_due_date=m.kev_due_date,
                exploit_refs=m.exploit_refs,
                evidence={"matched": m.matched_range, "cvss_vector": m.cvss_vector,
                          "product": m.product,
                          "exploits": [r["ref"] for r in (m.exploit_refs or [])][:5]},
            ))
    return findings


# ---------------------------------------------------------------- system -----
def assess_system(asset_id: str, installed: set[str], os_info: dict | None) -> list[dict]:
    findings = []
    installed = {p.lower() for p in installed}

    if "auditd" not in installed:
        findings.append(_finding(
            asset_id, "system", "sys.auditd_missing",
            title="Audit daemon (auditd) not installed",
            severity="MEDIUM",
            description="No host auditing — process/file/network audit trail unavailable (CIS 4.x).",
            evidence={"check": "auditd in installed packages", "result": "missing"},
        ))

    if not (installed & FIREWALL_PKGS):
        findings.append(_finding(
            asset_id, "system", "sys.no_firewall",
            title="No host firewall package installed",
            severity="MEDIUM",
            description="None of nftables/ufw/iptables present — host-based filtering not enforced (CIS 3.x).",
            evidence={"checked": sorted(FIREWALL_PKGS), "result": "none present"},
        ))

    if "unattended-upgrades" not in installed:
        findings.append(_finding(
            asset_id, "system", "sys.no_auto_updates",
            title="Automatic security updates (unattended-upgrades) not installed",
            severity="LOW",
            description="Security patches are not applied automatically.",
            evidence={"check": "unattended-upgrades installed", "result": "missing"},
        ))

    for pkg in sorted(installed & INSECURE_PKGS):
        findings.append(_finding(
            asset_id, "system", f"sys.insecure_service.{pkg}",
            title=f"Insecure/cleartext service package installed: {pkg}",
            severity="HIGH",
            description=f"{pkg} transmits credentials/data in cleartext and should be removed.",
            package_name=pkg,
            evidence={"package": pkg},
        ))
    return findings


# --------------------------------------------------------------- network -----
def assess_network(asset_id: str, flows: list[dict]) -> list[dict]:
    findings = []
    exposed: dict[int, set[str]] = defaultdict(set)
    egress: dict[int, set[str]] = defaultdict(set)

    for fl in flows:
        direction = fl.get("direction")
        if direction == "inbound":
            lp = fl.get("local_port")
            if lp in SENSITIVE_PORTS:
                exposed[lp].add(fl.get("local_ip") or "0.0.0.0")
        elif direction == "outbound":
            rp = fl.get("remote_port")
            if rp in SUSPICIOUS_EGRESS:
                egress[rp].add(fl.get("remote_ip") or "?")

    for port, ips in exposed.items():
        findings.append(_finding(
            asset_id, "network", f"net.exposed.{port}",
            title=f"Sensitive service exposed on port {port}",
            severity="MEDIUM", port=port, proto="tcp",
            description=f"A sensitive service is listening on port {port}.",
            evidence={"bind_addresses": sorted(ips)[:10]},
        ))
    for port, ips in egress.items():
        findings.append(_finding(
            asset_id, "network", f"net.suspicious_egress.{port}",
            title=f"Suspicious outbound traffic to port {port}",
            severity="HIGH", port=port, proto="tcp",
            description=f"Outbound connections to port {port} (commonly C2 / reverse shells).",
            evidence={"sample_remote_ips": sorted(ips)[:10], "distinct_peers": len(ips)},
        ))
    return findings
