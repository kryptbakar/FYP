"""Rule-based compliance engine: CIS-Benchmark-style + org-policy checks evaluated
against an asset's osquery state, producing pass / fail / partial / not_applicable.

Honest about data: rules that need state we don't yet collect (e.g. sshd_config)
return `not_applicable` rather than a false pass. Each result is written with a
hash-chained evidence record (see evidence.py) for audit traceability.

This is a representative starter benchmark, not the full CIS Debian 12 set — the
rule shape is what matters; more rules are pure data.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

PASS, FAIL, PARTIAL, NA = "pass", "fail", "partial", "not_applicable"

APPROVED_OS = {
    ("debian gnu/linux", "12"), ("ubuntu", "22.04"), ("ubuntu", "24.04"),
    ("debian gnu/linux", "11"), ("rocky linux", "9"),
}
FIREWALL = {"nftables", "ufw", "iptables", "iptables-persistent", "firewalld"}
TIME_SYNC = {"chrony", "ntp", "ntpsec", "systemd-timesyncd"}
INSECURE = {"telnetd", "telnet", "inetutils-telnetd", "rsh-server", "rsh-client",
            "talk", "talkd", "tftpd", "tftpd-hpa", "xinetd", "nis"}


@dataclass
class State:
    os: dict
    pkg_names: set[str]
    kernel: dict | None
    listening: list[dict]
    users: list[dict]


@dataclass
class Rule:
    id: str
    benchmark: str
    title: str
    severity: str
    remediation: str
    check: Callable[[State], tuple[str, str, dict]]


def _has(state: State, *names: str) -> bool:
    return bool(state.pkg_names & set(names))


# --------------------------------------------------------------- rules -------
def _auditd(s: State):
    ok = "auditd" in s.pkg_names
    return (PASS if ok else FAIL,
            "auditd installed" if ok else "auditd not installed — no host audit trail",
            {"auditd_installed": ok})


def _firewall(s: State):
    present = sorted(s.pkg_names & FIREWALL)
    return (PASS if present else FAIL,
            f"firewall present: {present}" if present else "no host firewall package installed",
            {"firewall_packages": present})


def _apparmor(s: State):
    ok = _has(s, "apparmor", "selinux-basics", "libselinux1")
    return (PASS if ok else FAIL,
            "MAC framework present" if ok else "no AppArmor/SELinux package present",
            {"mac_present": ok})


def _timesync(s: State):
    present = sorted(s.pkg_names & TIME_SYNC)
    return (PASS if present else FAIL,
            f"time sync present: {present}" if present else "no time-synchronization service installed",
            {"time_sync_packages": present})


def _logging(s: State):
    if "rsyslog" in s.pkg_names:
        return PASS, "rsyslog installed", {"logging": "rsyslog"}
    if "systemd" in s.pkg_names:
        return PARTIAL, "systemd present (journald likely active) — verify persistent logging", {"logging": "journald?"}
    return FAIL, "no system logging package detected", {"logging": "none"}


def _insecure_services(s: State):
    offenders = sorted(s.pkg_names & INSECURE)
    return (PASS if not offenders else FAIL,
            "no legacy/cleartext service packages installed" if not offenders else f"insecure packages present: {offenders}",
            {"insecure_packages": offenders})


def _plaintext_ports(s: State):
    bad = sorted({int(p["port"]) for p in s.listening if str(p.get("port")) in ("21", "23", "512", "513", "514")}
                 ) if s.listening else []
    return (PASS if not bad else FAIL,
            "no telnet/ftp/r-services listening" if not bad else f"cleartext service ports listening: {bad}",
            {"plaintext_ports": bad, "ports_observed": len(s.listening or [])})


def _auto_updates(s: State):
    ok = "unattended-upgrades" in s.pkg_names
    return (PASS if ok else FAIL,
            "unattended-upgrades installed" if ok else "automatic security updates not configured",
            {"unattended_upgrades": ok})


def _approved_os(s: State):
    name = (s.os.get("name") or "").lower()
    ver = (s.os.get("version") or "").split(" ")[0].lower()
    ok = any(name == n and ver.startswith(v) for (n, v) in APPROVED_OS)
    return (PASS if ok else FAIL,
            f"{s.os.get('name')} {s.os.get('version')} is an approved platform" if ok
            else f"{s.os.get('name')} {s.os.get('version')} is not on the approved-OS list",
            {"os": s.os})


def _remote_root(s: State):
    remote_root = [u for u in (s.users or []) if u.get("user") == "root" and u.get("host") not in ("", "-", None)]
    if not s.users:
        return PASS, "no interactive logins observed", {"logins": 0}
    return (PASS if not remote_root else FAIL,
            "no remote root logins" if not remote_root else f"{len(remote_root)} remote root login(s) observed",
            {"remote_root_logins": len(remote_root)})


def _ssh_root_login(_s: State):
    # Needs sshd_config, which the MVP agent does not collect yet.
    return NA, "sshd_config not collected by the agent (osquery sshd_config pack pending)", {"data": "unavailable"}


RULES: list[Rule] = [
    Rule("CIS-4.1.1", "CIS Debian 12 §4.1", "Ensure auditd is installed", "MEDIUM",
         "apt-get install auditd audispd-plugins", _auditd),
    Rule("CIS-3.5.1", "CIS Debian 12 §3.5", "Ensure a host firewall is installed", "MEDIUM",
         "apt-get install nftables && configure default-deny", _firewall),
    Rule("CIS-1.3.1", "CIS Debian 12 §1.3", "Ensure a MAC framework (AppArmor) is installed", "MEDIUM",
         "apt-get install apparmor apparmor-utils && enable profiles", _apparmor),
    Rule("CIS-2.3.1", "CIS Debian 12 §2.3", "Ensure time synchronization is in use", "LOW",
         "apt-get install chrony && enable the service", _timesync),
    Rule("CIS-4.2.1", "CIS Debian 12 §4.2", "Ensure system logging is configured", "MEDIUM",
         "apt-get install rsyslog OR ensure journald persistent storage", _logging),
    Rule("CIS-2.1.1", "CIS Debian 12 §2.1", "Ensure legacy/cleartext services are not installed", "HIGH",
         "apt-get purge telnetd rsh-server tftpd xinetd nis", _insecure_services),
    Rule("CIS-3.1.1", "CIS Debian 12 §3.1", "Ensure cleartext service ports are not listening", "HIGH",
         "disable/remove telnet/ftp/r-services", _plaintext_ports),
    Rule("CIS-1.9", "CIS Debian 12 §1.9", "Ensure automatic security updates are enabled", "LOW",
         "apt-get install unattended-upgrades && dpkg-reconfigure", _auto_updates),
    Rule("ORG-POL-001", "Org Policy", "Host runs an approved/supported OS", "MEDIUM",
         "migrate to an approved, vendor-supported distribution/version", _approved_os),
    Rule("ORG-POL-002", "Org Policy", "No remote root logins", "HIGH",
         "disable remote root login; use sudo with named accounts", _remote_root),
    Rule("CIS-5.2.7", "CIS Debian 12 §5.2", "Ensure SSH PermitRootLogin is disabled", "HIGH",
         "set 'PermitRootLogin no' in sshd_config", _ssh_root_login),
]


def evaluate_asset(state: State) -> list[dict]:
    results = []
    for r in RULES:
        status, rationale, evidence = r.check(state)
        results.append({
            "rule_id": r.id, "benchmark": r.benchmark, "title": r.title,
            "severity": r.severity, "status": status, "rationale": rationale,
            "remediation": r.remediation, "evidence": evidence,
        })
    return results
