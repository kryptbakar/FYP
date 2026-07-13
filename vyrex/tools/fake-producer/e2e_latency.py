"""End-to-end ingestion latency probe.

Measures the full pipeline an envelope traverses — ingest-edge (mTLS + schema
validation) -> NATS JetStream -> worker -> TimescaleDB — by posting uniquely
marked envelopes and polling `telemetry_raw` until each event_id lands. Reports
p50 / p95 / p99 / max wall-clock latency, the numbers quoted in
docs/BENCHMARKS.md.

Runs inside the compose network in the fake-producer container (the image bundles
this script and its deps):

    make bench-e2e            # or:
    docker compose run --rm --entrypoint python fake-producer e2e_latency.py --probes 100
"""
from __future__ import annotations

import argparse
import os
import statistics
import time
import uuid

import psycopg

from produce import build_client, make_envelope, now_rfc3339  # reuse mTLS client + envelope shape


def pct(values: list[float], p: float) -> float:
    values = sorted(values)
    idx = min(len(values) - 1, max(0, round(p / 100 * (len(values) - 1))))
    return values[idx]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.getenv("INGEST_URL", "https://ingest-edge:8443/v1/telemetry"))
    ap.add_argument("--dsn", default=os.getenv("TIMESCALE_DSN",
                    "postgresql://vyrex:vyrex@timescaledb:5432/telemetry"))
    ap.add_argument("--token", default=os.getenv("INGEST_AGENT_TOKEN", ""))
    ap.add_argument("--ca", default=os.getenv("CA_CERT", "/certs/ca.crt"))
    ap.add_argument("--client-cert", default=os.getenv("CLIENT_CERT", "/certs/agent-001.crt"))
    ap.add_argument("--client-key", default=os.getenv("CLIENT_KEY", "/certs/agent-001.key"))
    ap.add_argument("--probes", type=int, default=int(os.getenv("PROBES", "100")))
    ap.add_argument("--interval", type=float, default=0.2, help="seconds between probes")
    ap.add_argument("--timeout", type=float, default=30.0, help="max wait per probe")
    args = ap.parse_args()

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    client = build_client(args)
    conn = psycopg.connect(args.dsn, autocommit=True)

    latencies: list[float] = []
    lost = 0
    for i in range(args.probes):
        env = make_envelope("agent-bench", "host-bench-01", "bench-probe")
        env["event_id"] = str(uuid.uuid4())
        env["collected_at"] = now_rfc3339()
        t0 = time.perf_counter()
        client.post(args.url, json=[env], headers=headers).raise_for_status()
        # Poll until the worker has landed the row.
        deadline = t0 + args.timeout
        found = False
        while time.perf_counter() < deadline:
            with conn.cursor() as cur:
                cur.execute("SELECT 1 FROM telemetry_raw WHERE event_id = %s", (env["event_id"],))
                if cur.fetchone():
                    found = True
                    break
            time.sleep(0.01)
        if found:
            latencies.append(time.perf_counter() - t0)
        else:
            lost += 1
        time.sleep(args.interval)

    if not latencies:
        raise SystemExit("no probe ever landed — is the worker running?")
    ms = [v * 1000 for v in latencies]
    print(f"probes={args.probes} landed={len(ms)} lost={lost}")
    print(f"e2e latency ms: p50={pct(ms, 50):.0f} p95={pct(ms, 95):.0f} "
          f"p99={pct(ms, 99):.0f} max={max(ms):.0f} mean={statistics.mean(ms):.0f}")
    print("(poll resolution ~10 ms; subtract for the true pipeline figure)")


if __name__ == "__main__":
    main()
