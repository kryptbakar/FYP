"""Analyst Toolkit — capabilities ported from the A.R.I.S. dashboard, adapted to VYREX's
air-gapped, dependency-light identity.

Only two capabilities genuinely need server-side system access and live here:

  * GET  /node/vitals       — appliance-node telemetry read straight from /proc (stdlib only,
                              no psutil); container-aware. Nothing leaves the box.
  * POST /toolkit/port-scan — a real multithreaded TCP scanner, but *hard-restricted* to
                              loopback and RFC-1918 private ranges (same guard A.R.I.S. uses)
                              so it can never be pointed at the public internet.

The remaining A.R.I.S. tools (phishing/log/IR/CVE/assistant/news) are deterministic text
analysis and are implemented client-side in the console (assets/toolkit.js) — instant,
offline, and explainable, which fits the air-gap thesis better than a cloud LLM.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["toolkit"])


# ───────────────────────────── node vitals (stdlib /proc) ────────────────────
def _read(path: str) -> str:
    try:
        with open(path, "r") as f:
            return f.read()
    except Exception:
        return ""


def _cpu_lines() -> dict:
    """Map of cpu-id -> (idle, total) jiffies from /proc/stat."""
    out = {}
    for line in _read("/proc/stat").splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        label = parts[0]
        try:
            nums = [float(x) for x in parts[1:]]
        except ValueError:
            continue
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0.0)
        out[label] = (idle, sum(nums))
    return out


def _bytes_h(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _uptime_h(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


@router.get("/node/vitals")
def node_vitals() -> dict:
    # CPU% via two /proc/stat samples (overall + per-core)
    s1 = _cpu_lines()
    time.sleep(0.15)
    s2 = _cpu_lines()

    def pct(label: str):
        if label not in s1 or label not in s2:
            return None
        i1, t1 = s1[label]
        i2, t2 = s2[label]
        dt = t2 - t1
        if dt <= 0:
            return None
        return round((1.0 - (i2 - i1) / dt) * 100.0, 1)

    total_pct = pct("cpu")
    per_core = [pct(k) for k in sorted(s1) if k != "cpu" and k.startswith("cpu")]

    # memory
    mem = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        mem[k.strip()] = v.strip()

    def kb(key: str) -> int:
        try:
            return int(mem.get(key, "0").split()[0])
        except Exception:
            return 0

    mt, ma = kb("MemTotal"), kb("MemAvailable")
    mem_total, mem_used = mt * 1024, (mt - ma) * 1024
    mem_pct = round((mt - ma) / mt * 100.0, 1) if mt else None
    swt, swf = kb("SwapTotal"), kb("SwapFree")
    swap_pct = round((swt - swf) / swt * 100.0, 1) if swt else 0.0

    # uptime + load
    up = _read("/proc/uptime").split()
    uptime_s = float(up[0]) if up else 0.0
    la = _read("/proc/loadavg").split()
    load = [float(x) for x in la[:3]] if len(la) >= 3 else [0.0, 0.0, 0.0]

    # disk (root fs of the container)
    du = shutil.disk_usage("/")

    return {
        "os": {
            "system": platform.system(),
            "node": socket.gethostname(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "boot_time": datetime.fromtimestamp(time.time() - uptime_s, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "uptime": _uptime_h(uptime_s),
            "note": "VYREX appliance node (API container) — read from /proc, nothing egresses",
        },
        "cpu": {
            "logical": os.cpu_count() or len(per_core) or 1,
            "total_pct": total_pct,
            "per_core": per_core,
            "load1": load[0], "load5": load[1], "load15": load[2],
        },
        "ram": {
            "total": mem_total, "used": mem_used, "percent": mem_pct,
            "total_h": _bytes_h(mem_total), "used_h": _bytes_h(mem_used),
            "swap_percent": swap_pct, "swap_total_h": _bytes_h(swt * 1024),
        },
        "disk": {
            "total": du.total, "used": du.used, "free": du.free,
            "percent": round(du.used / du.total * 100.0, 1) if du.total else None,
            "total_h": _bytes_h(du.total), "used_h": _bytes_h(du.used), "free_h": _bytes_h(du.free),
        },
        "captured": datetime.now(timezone.utc).isoformat(),
    }


# ───────────────────────────── port scanner (range-guarded) ──────────────────
_SERVICE = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3", 111: "RPC",
    123: "NTP", 135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP-sub", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1194: "OpenVPN", 1433: "MSSQL", 1521: "OracleDB", 1723: "PPTP", 2049: "NFS",
    2181: "ZooKeeper", 2375: "Docker", 3000: "Dev-HTTP", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit", 5000: "Dev-HTTP", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis", 6443: "K8s-API", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 8888: "Jupyter", 9200: "Elasticsearch", 9418: "Git",
    27017: "MongoDB", 27018: "MongoDB",
}
_QUICK = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 9200]
_ATTACK = [21, 23, 25, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017, 4444, 2375]
_TOP100 = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144,
           179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990,
           993, 995, 1080, 1099, 1194, 1433, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2181, 2375,
           3000, 3128, 3306, 3389, 3986, 4444, 4899, 5000, 5009, 5051, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
           5900, 5985, 5986, 6000, 6001, 6379, 6443, 7070, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9418,
           9999, 10000, 32768, 49152, 27017]
_CRIT = {23, 4444, 5900, 5985, 5986}
_HIGH = {21, 69, 135, 137, 139, 389, 445, 636, 1433, 1521, 2375, 3306, 3389, 5432, 6379, 6443, 9200, 27017, 27018}
_MED = {22, 25, 53, 80, 110, 143, 587, 993, 995, 1080, 3000, 5000, 8080, 8888}


def _risk(port: int) -> str:
    if port in _CRIT:
        return "CRITICAL"
    if port in _HIGH:
        return "HIGH"
    if port in _MED:
        return "MEDIUM"
    return "LOW"


def _banner(host: str, port: int, timeout: float = 0.7) -> str:
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        if port in (80, 8080, 3000, 5000, 8000, 8081):
            s.send(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        raw = s.recv(256).decode("utf-8", errors="replace")
        s.close()
        for line in raw.splitlines():
            line = line.strip()
            if line:
                return line[:80]
    except Exception:
        pass
    return ""


def _allowed(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_loopback or a.is_private
    except ValueError:
        return False


class ScanReq(BaseModel):
    target: str = "127.0.0.1"
    mode: str = "quick"


@router.post("/toolkit/port-scan")
def port_scan(req: ScanReq) -> dict:
    target = (req.target or "127.0.0.1").strip()
    try:
        resolved = socket.gethostbyname(target)
    except Exception:
        return {"error": f"Could not resolve '{target}'.", "target": target}

    if not _allowed(resolved):
        return {
            "error": "Scanning is restricted to localhost and private ranges "
                     "(10/8, 172.16/12, 192.168/16). Only scan systems you own or are "
                     "authorised to test.",
            "target": target, "resolved_ip": resolved,
        }

    ports = {"quick": _QUICK, "attack": _ATTACK, "top100": _TOP100,
             "full": list(range(1, 1025))}.get(req.mode, _QUICK)

    open_ports: list[dict] = []

    def scan_one(p: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            rc = s.connect_ex((resolved, p))
            s.close()
            if rc != 0:
                return
            try:
                svc = socket.getservbyport(p, "tcp")
            except OSError:
                svc = _SERVICE.get(p, "unknown")
            open_ports.append({"port": p, "service": svc, "risk": _risk(p), "banner": _banner(resolved, p)})
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(120, len(ports))) as ex:
        list(ex.map(scan_one, ports))
    open_ports.sort(key=lambda x: x["port"])

    return {
        "target": target, "resolved_ip": resolved, "mode": req.mode,
        "scanned": len(ports), "open": open_ports,
        "assessment": _assess(target, open_ports),
    }


def _assess(target: str, open_ports: list[dict]) -> dict:
    if not open_ports:
        return {"posture": "MINIMAL", "summary": f"No open ports found on {target} in the scanned range — minimal external attack surface.", "notes": []}
    crit = [p for p in open_ports if p["risk"] == "CRITICAL"]
    high = [p for p in open_ports if p["risk"] == "HIGH"]
    notes = []
    for p in crit:
        notes.append(f"Port {p['port']} ({p['service']}) is CRITICAL — cleartext/remote-admin exposure; close or restrict to a management VLAN.")
    for p in high:
        notes.append(f"Port {p['port']} ({p['service']}) is HIGH — ensure auth, patching and firewalling; should not be internet-facing.")
    posture = "CRITICAL" if crit else "HIGH" if high else "MODERATE" if len(open_ports) > 3 else "LOW"
    summary = (f"{len(open_ports)} open port(s) on {target}: "
               f"{len(crit)} critical, {len(high)} high. Posture {posture}. "
               "Reduce surface to only required services; everything else should be filtered.")
    return {"posture": posture, "summary": summary, "notes": notes[:8]}
