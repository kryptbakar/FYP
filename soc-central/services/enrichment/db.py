"""Data access for enrichment.

Two stores, both read-only-or-write as appropriate:
  - TimescaleDB (soc_telemetry): READ raw telemetry the agent shipped.
  - PostgreSQL (soc_central):     READ the feed mirror; WRITE assets + findings.

No internet — enrichment consumes only the local mirror (air-gapped).
"""
from __future__ import annotations

import logging
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

log = logging.getLogger("enrichment.db")

FINDINGS_DDL = """
CREATE TABLE IF NOT EXISTS assets (
    host_id     text PRIMARY KEY,
    hostname    text,
    os          text,
    ip          text,
    first_seen  timestamptz DEFAULT now(),
    last_seen   timestamptz
);

CREATE TABLE IF NOT EXISTS findings (
    id              bigserial PRIMARY KEY,
    asset_id        text REFERENCES assets(host_id),
    domain          text NOT NULL,             -- application | system | network
    rule_id         text,                      -- CVE id or rule key
    title           text NOT NULL,
    description     text,
    severity        text,                      -- preliminary; composite risk = Phase 5
    cve_id          text,
    package_name    text,
    package_version text,
    port            integer,
    proto           text,
    cvss_score      numeric,
    cvss_severity   text,
    epss            numeric,
    epss_percentile numeric,
    kev             boolean DEFAULT false,
    kev_due_date    date,
    risk_score      numeric,                   -- filled by the Phase 5 risk engine
    status          text DEFAULT 'open',       -- analyst-owned; never overwritten by re-runs
    evidence        jsonb,
    first_seen      timestamptz DEFAULT now(),
    last_seen       timestamptz DEFAULT now(),
    fingerprint     text UNIQUE
);
CREATE INDEX IF NOT EXISTS findings_asset  ON findings (asset_id);
CREATE INDEX IF NOT EXISTS findings_domain ON findings (domain);
CREATE INDEX IF NOT EXISTS findings_kev    ON findings (kev) WHERE kev;
"""


def connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, autocommit=True)


def ensure_schema(pg: psycopg.Connection) -> None:
    with pg.cursor() as cur:
        cur.execute(FINDINGS_DDL)
    log.info("findings schema ready")


# ----------------------------------------------------- telemetry (read) ------
def list_assets(ts: psycopg.Connection) -> list[dict]:
    with ts.cursor() as cur:
        cur.execute(
            """
            SELECT host_id, max(hostname) AS hostname, max(ingested_at) AS last_seen
            FROM telemetry_raw GROUP BY host_id
            """
        )
        return [{"host_id": h, "hostname": hn, "last_seen": ls} for (h, hn, ls) in cur.fetchall()]


def os_for(ts: psycopg.Connection, host_id: str) -> dict | None:
    with ts.cursor() as cur:
        cur.execute(
            """
            SELECT payload->'columns' FROM telemetry_raw
            WHERE host_id=%s AND kind='osquery_result' AND payload->>'query_name'='os_version'
            ORDER BY ingested_at DESC LIMIT 1
            """,
            (host_id,),
        )
        row = cur.fetchone()
        return row[0] if row else None


def packages_for(ts: psycopg.Connection, host_id: str, window: str = "2 days") -> list[dict]:
    with ts.cursor() as cur:
        cur.execute(
            f"""
            SELECT DISTINCT payload->'columns'->>'name' AS name,
                            payload->'columns'->>'version' AS version
            FROM telemetry_raw
            WHERE host_id=%s AND kind='osquery_result'
              AND payload->>'query_name'='deb_packages'
              AND ingested_at > now() - interval '{window}'
            """,
            (host_id,),
        )
        return [{"name": n, "version": v} for (n, v) in cur.fetchall() if n]


def flows_for(ts: psycopg.Connection, host_id: str, window: str = "2 days", limit: int = 5000) -> list[dict]:
    with ts.cursor() as cur:
        cur.execute(
            f"""
            SELECT payload FROM telemetry_raw
            WHERE host_id=%s AND kind='network_flow' AND ingested_at > now() - interval '{window}'
            LIMIT %s
            """,
            (host_id, limit),
        )
        return [row[0] for row in cur.fetchall()]


# ------------------------------------------------------- findings (write) ----
def upsert_asset(pg: psycopg.Connection, host_id: str, hostname: str | None,
                 os_name: str | None, ip: str | None, last_seen) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """
            INSERT INTO assets (host_id, hostname, os, ip, last_seen)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (host_id) DO UPDATE SET
                hostname = EXCLUDED.hostname, os = EXCLUDED.os,
                ip = COALESCE(EXCLUDED.ip, assets.ip), last_seen = EXCLUDED.last_seen
            """,
            (host_id, hostname, os_name, ip, last_seen),
        )


def upsert_findings(pg: psycopg.Connection, findings: list[dict]) -> int:
    if not findings:
        return 0
    with pg.cursor() as cur:
        for f in findings:
            cur.execute(
                """
                INSERT INTO findings (asset_id, domain, rule_id, title, description, severity,
                    cve_id, package_name, package_version, port, proto,
                    cvss_score, cvss_severity, epss, epss_percentile, kev, kev_due_date,
                    evidence, fingerprint, last_seen)
                VALUES (%(asset_id)s, %(domain)s, %(rule_id)s, %(title)s, %(description)s, %(severity)s,
                    %(cve_id)s, %(package_name)s, %(package_version)s, %(port)s, %(proto)s,
                    %(cvss_score)s, %(cvss_severity)s, %(epss)s, %(epss_percentile)s, %(kev)s, %(kev_due_date)s,
                    %(evidence)s, %(fingerprint)s, now())
                ON CONFLICT (fingerprint) DO UPDATE SET
                    severity = EXCLUDED.severity, description = EXCLUDED.description,
                    cvss_score = EXCLUDED.cvss_score, cvss_severity = EXCLUDED.cvss_severity,
                    epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile,
                    kev = EXCLUDED.kev, kev_due_date = EXCLUDED.kev_due_date,
                    evidence = EXCLUDED.evidence, last_seen = now()
                """,
                {**f, "evidence": Jsonb(f.get("evidence", {}))},
            )
    return len(findings)


def summary(pg: psycopg.Connection) -> list[tuple]:
    with pg.cursor() as cur:
        cur.execute("SELECT domain, severity, count(*) FROM findings GROUP BY domain, severity ORDER BY 1,2")
        return cur.fetchall()
