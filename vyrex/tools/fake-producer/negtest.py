"""Negative/positive auth + validation tests against ingest-edge.

Run inside the compose network:
    docker compose run --rm --entrypoint python fake-producer negtest.py
"""
from __future__ import annotations

import os
import ssl

import httpx

URL = os.getenv("INGEST_URL", "https://ingest-edge:8443/v1/telemetry")
TOKEN = os.getenv("INGEST_AGENT_TOKEN", "")
CA = os.getenv("CA_CERT", "/certs/ca.crt")
CC = os.getenv("CLIENT_CERT", "/certs/agent-001.crt")
CK = os.getenv("CLIENT_KEY", "/certs/agent-001.key")

VALID = {
    "schema_version": "1.0",
    "event_id": "11111111-1111-4111-8111-111111111111",
    "agent_id": "agent-001",
    "host": {"host_id": "h1", "hostname": "lab"},
    "collected_at": "2026-06-01T00:00:00Z",
    "kind": "system_info",
    "payload": {"metric": "cpu_pct", "value": 42.0},
}
BAD_SCHEMA = {**VALID, "event_id": "22222222-2222-4222-8222-222222222222", "payload": {"metric": "cpu_pct"}}
MISMATCH = {**VALID, "event_id": "33333333-3333-4333-8333-333333333333", "agent_id": "agent-999"}


def ctx(with_cert: bool) -> ssl.SSLContext:
    c = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA)
    if with_cert:
        c.load_cert_chain(CC, CK)
    return c


def post(client: httpx.Client, body: dict, token: str, label: str) -> None:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = client.post(URL, json=body, headers=headers)
        print(f"{label:24s} -> http={r.status_code} {r.text.strip()[:160]}")
    except Exception as e:  # handshake failures land here
        print(f"{label:24s} -> BLOCKED at TLS: {type(e).__name__}")


def main() -> None:
    # 1) No client cert -> server must reject the handshake (mTLS enforced).
    with httpx.Client(verify=ctx(False), timeout=10) as c:
        post(c, VALID, TOKEN, "1 no-client-cert")

    # 2-5) With a valid client cert.
    with httpx.Client(verify=ctx(True), timeout=10) as c:
        post(c, VALID, "WRONG-TOKEN", "2 wrong-token")
        post(c, BAD_SCHEMA, TOKEN, "3 invalid-schema")
        post(c, MISMATCH, TOKEN, "4 agentid!=certCN")
        post(c, VALID, TOKEN, "5 fully-valid")


if __name__ == "__main__":
    main()
