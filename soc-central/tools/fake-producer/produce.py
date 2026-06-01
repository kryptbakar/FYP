"""Fake telemetry producer — stands in for the Phase 2 Go agent.

Generates realistic telemetry envelopes across all five kinds and POSTs them to
ingest-edge over **mutual TLS** with a bearer token, exactly as a real agent will.
Used to exercise the whole ingestion backbone and to load-test back-pressure.

Usage (inside the compose network):
    python produce.py --count 500 --batch 50 --rate 0     # as fast as possible
    python produce.py --count 1000 --rate 50              # 50 envelopes/sec
"""
from __future__ import annotations

import argparse
import os
import random
import ssl
import time
import uuid
from datetime import datetime, timezone

import httpx

KINDS = ["system_info", "process_event", "network_flow", "fim_event", "osquery_result"]


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_payload(kind: str) -> dict:
    if kind == "process_event":
        return {
            "pid": random.randint(100, 60000),
            "ppid": random.randint(1, 100),
            "name": random.choice(["sshd", "nginx", "bash", "python3", "curl", "nc"]),
            "cmdline": "/usr/bin/example --flag",
            "user": random.choice(["root", "www-data", "analyst"]),
            "action": random.choice(["exec", "fork", "exit"]),
        }
    if kind == "network_flow":
        return {
            "proto": random.choice(["tcp", "udp"]),
            "direction": random.choice(["inbound", "outbound"]),
            "local_ip": "10.0.0.5",
            "local_port": random.randint(1024, 65535),
            "remote_ip": f"185.220.{random.randint(0,255)}.{random.randint(1,254)}",
            "remote_port": random.choice([22, 53, 80, 443, 4444, 8080]),
            "bytes": random.randint(64, 1_000_000),
        }
    if kind == "fim_event":
        return {
            "path": random.choice(["/etc/passwd", "/etc/shadow", "/usr/bin/ssh", "/var/www/index.html"]),
            "change": random.choice(["created", "modified", "deleted", "attr"]),
            "sha256": uuid.uuid4().hex + uuid.uuid4().hex,
            "size": random.randint(0, 1_000_000),
        }
    if kind == "osquery_result":
        return {
            "query_name": random.choice(["listening_ports", "deb_packages", "logged_in_users"]),
            "columns": {"name": "openssl", "version": "3.0.2-0ubuntu1.15"},
        }
    # system_info
    return {
        "metric": random.choice(["cpu_pct", "mem_pct", "disk_pct", "load1"]),
        "value": round(random.uniform(0, 100), 2),
        "unit": random.choice(["percent", "ratio"]),
    }


def make_envelope(agent_id: str, host_id: str, hostname: str) -> dict:
    kind = random.choice(KINDS)
    return {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "host": {"host_id": host_id, "hostname": hostname, "os": "ubuntu-22.04", "ip": "10.0.0.5"},
        "collected_at": now_rfc3339(),
        "kind": kind,
        "labels": {"env": "lab", "site": "giki"},
        "payload": make_payload(kind),
    }


def build_client(args) -> httpx.Client:
    # Build the mTLS context explicitly (robust across httpx SSL-handling changes):
    # verify the server against our CA, and present the agent client cert.
    if args.ca:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca)
    else:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if args.client_cert and args.client_key:
        ctx.load_cert_chain(certfile=args.client_cert, keyfile=args.client_key)
    return httpx.Client(verify=ctx, timeout=30.0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.getenv("INGEST_URL", "https://ingest-edge:8443/v1/telemetry"))
    ap.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent-001"))
    ap.add_argument("--host-id", default=os.getenv("HOST_ID", "host-lab-01"))
    ap.add_argument("--hostname", default=os.getenv("HOSTNAME_LABEL", "lab-ubuntu-01"))
    ap.add_argument("--token", default=os.getenv("INGEST_AGENT_TOKEN", ""))
    ap.add_argument("--ca", default=os.getenv("CA_CERT", "/certs/ca.crt"))
    ap.add_argument("--client-cert", default=os.getenv("CLIENT_CERT", "/certs/agent-001.crt"))
    ap.add_argument("--client-key", default=os.getenv("CLIENT_KEY", "/certs/agent-001.key"))
    ap.add_argument("--count", type=int, default=int(os.getenv("COUNT", "500")))
    ap.add_argument("--batch", type=int, default=int(os.getenv("BATCH", "50")))
    ap.add_argument("--rate", type=float, default=float(os.getenv("RATE", "0")), help="envelopes/sec; 0 = unlimited")
    args = ap.parse_args()

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    client = build_client(args)
    sent = accepted = rejected = 0
    start = time.time()
    batch: list[dict] = []

    def flush() -> None:
        nonlocal accepted, rejected
        if not batch:
            return
        resp = client.post(args.url, json=batch, headers=headers)
        resp.raise_for_status()
        body = resp.json()
        accepted += body.get("accepted", 0)
        rejected += body.get("rejected", 0)
        if body.get("errors"):
            print("  sample error:", body["errors"][0])
        batch.clear()

    for _ in range(args.count):
        batch.append(make_envelope(args.agent_id, args.host_id, args.hostname))
        sent += 1
        if len(batch) >= args.batch:
            flush()
        if args.rate > 0:
            time.sleep(1.0 / args.rate)
    flush()

    elapsed = time.time() - start
    print(
        f"done: sent={sent} accepted={accepted} rejected={rejected} "
        f"in {elapsed:.1f}s ({sent/elapsed:.0f}/s)"
    )
    client.close()


if __name__ == "__main__":
    main()
