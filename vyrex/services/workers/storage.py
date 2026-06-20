"""Storage fan-out: write raw telemetry to TimescaleDB and OpenSearch.

- TimescaleDB holds the structured, queryable record (a hypertable on
  ingested_at) for trends/dashboards.
- OpenSearch holds the full envelope for free-text/log search, keyed by
  event_id so re-delivery is idempotent.

Kept deliberately simple for Phase 1; batching/pooling tuning comes later.
"""
from __future__ import annotations

import json
import logging
from typing import Any

import httpx
import psycopg
from psycopg.types.json import Jsonb

log = logging.getLogger("workers.storage")

# --- TimescaleDB DDL (idempotent; runs on worker startup) -------------------
_DDL = """
CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
CREATE TABLE IF NOT EXISTS telemetry_raw (
    ingested_at   timestamptz NOT NULL,
    collected_at  timestamptz NOT NULL,
    event_id      uuid        NOT NULL,
    agent_id      text        NOT NULL,
    host_id       text        NOT NULL,
    hostname      text,
    kind          text        NOT NULL,
    stream_seq    bigint,
    payload       jsonb       NOT NULL
);
SELECT create_hypertable('telemetry_raw', 'ingested_at', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS telemetry_raw_kind_time  ON telemetry_raw (kind, ingested_at DESC);
CREATE INDEX IF NOT EXISTS telemetry_raw_agent_time ON telemetry_raw (agent_id, ingested_at DESC);
"""

_INSERT = """
INSERT INTO telemetry_raw
    (ingested_at, collected_at, event_id, agent_id, host_id, hostname, kind, stream_seq, payload)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
"""

# --- OpenSearch index mapping ----------------------------------------------
_OS_INDEX_BODY = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "event_id": {"type": "keyword"},
            "agent_id": {"type": "keyword"},
            "kind": {"type": "keyword"},
            "collected_at": {"type": "date"},
            "ingested_at": {"type": "date"},
            "host": {
                "properties": {
                    "host_id": {"type": "keyword"},
                    "hostname": {"type": "keyword"},
                    "os": {"type": "keyword"},
                    "ip": {"type": "ip"},
                }
            },
            "labels": {"type": "object"},
            "payload": {"type": "object", "enabled": True},
        }
    },
}


class Storage:
    def __init__(self, pg_dsn: str, os_url: str, os_index: str):
        self._pg_dsn = pg_dsn
        self._os_url = os_url.rstrip("/")
        self._os_index = os_index
        self._conn: psycopg.AsyncConnection | None = None
        self._http: httpx.AsyncClient | None = None

    async def init(self) -> None:
        # TimescaleDB: connect (autocommit) and ensure the hypertable.
        self._conn = await psycopg.AsyncConnection.connect(self._pg_dsn, autocommit=True)
        async with self._conn.cursor() as cur:
            await cur.execute(_DDL)
        log.info("timescaledb ready (telemetry_raw hypertable)")

        # OpenSearch: ensure the index exists.
        self._http = httpx.AsyncClient(timeout=10.0)
        resp = await self._http.put(f"{self._os_url}/{self._os_index}", json=_OS_INDEX_BODY)
        if resp.status_code in (200, 201):
            log.info("opensearch index %s created", self._os_index)
        elif resp.status_code == 400 and "resource_already_exists" in resp.text:
            log.info("opensearch index %s already exists", self._os_index)
        else:
            resp.raise_for_status()

    async def write_timescale(self, rows: list[tuple]) -> None:
        if not rows or self._conn is None:
            return
        async with self._conn.cursor() as cur:
            await cur.executemany(_INSERT, rows)

    async def write_opensearch(self, docs: list[dict[str, Any]]) -> None:
        if not docs or self._http is None:
            return
        # Build a _bulk NDJSON body; _id = event_id for idempotent indexing.
        lines: list[str] = []
        for d in docs:
            lines.append(json.dumps({"index": {"_index": self._os_index, "_id": d.get("event_id")}}))
            lines.append(json.dumps(d))
        body = "\n".join(lines) + "\n"
        resp = await self._http.post(
            f"{self._os_url}/_bulk",
            content=body,
            headers={"Content-Type": "application/x-ndjson"},
        )
        resp.raise_for_status()
        result = resp.json()
        if result.get("errors"):
            # Surface the first item error for visibility.
            for item in result.get("items", []):
                idx = item.get("index", {})
                if idx.get("error"):
                    raise RuntimeError(f"opensearch bulk error: {idx['error']}")

    @staticmethod
    def to_row(env: dict[str, Any], stream_seq: int | None) -> tuple:
        host = env.get("host", {})
        return (
            env.get("ingested_at"),
            env.get("collected_at"),
            env.get("event_id"),
            env.get("agent_id"),
            host.get("host_id"),
            host.get("hostname"),
            env.get("kind"),
            stream_seq,
            Jsonb(env.get("payload", {})),
        )

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
        if self._http is not None:
            await self._http.aclose()
