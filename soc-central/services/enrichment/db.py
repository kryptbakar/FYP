"""Data access for enrichment.

Two stores, both read-only-or-write as appropriate:
  - TimescaleDB (soc_telemetry): READ raw telemetry the agent shipped.
  - PostgreSQL (soc_central):     READ the feed mirror; WRITE assets + findings.

No internet — enrichment consumes only the local mirror (air-gapped).
"""
from __future__ import annotations

import logging
from typing import Any

import hashlib

import psycopg
from psycopg.types.json import Jsonb

import evidence

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

-- Tool-integration expansion (Phase A): provenance + fusion dedup fields.
-- Every finding carries which tool produced it, a pointer to the raw record, and a
-- deterministic dedup_key so the AI Fusion Engine (Phase F) can merge findings that
-- describe the same issue on the same asset and weight by tool consensus.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS source_tool text NOT NULL DEFAULT 'agent';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS raw_ref     text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedup_key   text;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS consensus   jsonb;   -- [{tool, ...}] populated in Phase F
-- Exploit availability (Exploit-DB / Metasploit / PoC), from the feed-sync mirror.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exploit_available boolean DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exploit_refs jsonb;
CREATE INDEX IF NOT EXISTS findings_dedup  ON findings (dedup_key);
CREATE INDEX IF NOT EXISTS findings_source ON findings (source_tool);
CREATE INDEX IF NOT EXISTS findings_exploit ON findings (exploit_available) WHERE exploit_available;
"""

COMPLIANCE_DDL = """
CREATE TABLE IF NOT EXISTS compliance_results (
    id            bigserial PRIMARY KEY,
    asset_id      text REFERENCES assets(host_id),
    rule_id       text NOT NULL,
    benchmark     text,
    title         text NOT NULL,
    severity      text,
    status        text NOT NULL,           -- pass | fail | partial | not_applicable
    rationale     text,
    remediation   text,
    evidence      jsonb,
    evidence_hash text,                     -- hash of the appended evidence record
    run_id        text,
    evaluated_at  timestamptz DEFAULT now(),
    fingerprint   text UNIQUE               -- asset+rule -> latest result upserts
);
CREATE INDEX IF NOT EXISTS compliance_asset  ON compliance_results (asset_id);
CREATE INDEX IF NOT EXISTS compliance_status ON compliance_results (status);

-- Append-only, hash-chained audit log (see evidence.py). Never updated/deleted.
CREATE TABLE IF NOT EXISTS compliance_evidence (
    seq        bigserial PRIMARY KEY,
    run_id     text,
    asset_id   text,
    rule_id    text,
    record     jsonb NOT NULL,
    prev_hash  text NOT NULL,
    hash       text NOT NULL,
    created_at timestamptz DEFAULT now()
);
"""


def connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, autocommit=True)


def ensure_schema(pg: psycopg.Connection) -> None:
    with pg.cursor() as cur:
        cur.execute(FINDINGS_DDL)
        cur.execute(COMPLIANCE_DDL)
    log.info("findings + compliance schema ready")


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


def osquery_latest(ts: psycopg.Connection, host_id: str, query_name: str, window: str = "2 days") -> list[dict]:
    """All column-dicts for the latest run of a named osquery query on this host."""
    with ts.cursor() as cur:
        cur.execute(
            f"""
            SELECT payload->'columns' FROM telemetry_raw
            WHERE host_id=%s AND kind='osquery_result' AND payload->>'query_name'=%s
              AND ingested_at > now() - interval '{window}'
            """,
            (host_id, query_name),
        )
        return [row[0] for row in cur.fetchall() if row[0]]


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
                    source_tool, raw_ref, dedup_key, exploit_available, exploit_refs,
                    evidence, fingerprint, last_seen)
                VALUES (%(asset_id)s, %(domain)s, %(rule_id)s, %(title)s, %(description)s, %(severity)s,
                    %(cve_id)s, %(package_name)s, %(package_version)s, %(port)s, %(proto)s,
                    %(cvss_score)s, %(cvss_severity)s, %(epss)s, %(epss_percentile)s, %(kev)s, %(kev_due_date)s,
                    %(source_tool)s, %(raw_ref)s, %(dedup_key)s, %(exploit_available)s, %(exploit_refs)s,
                    %(evidence)s, %(fingerprint)s, now())
                ON CONFLICT (fingerprint) DO UPDATE SET
                    severity = EXCLUDED.severity, description = EXCLUDED.description,
                    cvss_score = EXCLUDED.cvss_score, cvss_severity = EXCLUDED.cvss_severity,
                    epss = EXCLUDED.epss, epss_percentile = EXCLUDED.epss_percentile,
                    kev = EXCLUDED.kev, kev_due_date = EXCLUDED.kev_due_date,
                    source_tool = EXCLUDED.source_tool, raw_ref = EXCLUDED.raw_ref,
                    dedup_key = EXCLUDED.dedup_key,
                    exploit_available = EXCLUDED.exploit_available, exploit_refs = EXCLUDED.exploit_refs,
                    evidence = EXCLUDED.evidence, last_seen = now()
                """,
                {**f, "evidence": Jsonb(f.get("evidence", {})),
                 "source_tool": f.get("source_tool", "agent"),
                 "raw_ref": f.get("raw_ref"), "dedup_key": f.get("dedup_key"),
                 "exploit_available": f.get("exploit_available", False),
                 "exploit_refs": Jsonb(f.get("exploit_refs") or [])},
            )
    return len(findings)


def summary(pg: psycopg.Connection) -> list[tuple]:
    with pg.cursor() as cur:
        cur.execute("SELECT domain, severity, count(*) FROM findings GROUP BY domain, severity ORDER BY 1,2")
        return cur.fetchall()


# ----------------------------------------------------- compliance (write) ----
def append_evidence(pg: psycopg.Connection, run_id: str, asset_id: str, rule_id: str, record: dict) -> str:
    """Append one immutable, hash-chained evidence record; return its hash.

    Sequential within the single-threaded run, so the chain stays consistent.
    """
    with pg.cursor() as cur:
        cur.execute("SELECT hash FROM compliance_evidence ORDER BY seq DESC LIMIT 1")
        row = cur.fetchone()
        prev = row[0] if row else evidence.GENESIS
        h = evidence.record_hash(prev, record)
        cur.execute(
            """
            INSERT INTO compliance_evidence (run_id, asset_id, rule_id, record, prev_hash, hash)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (run_id, asset_id, rule_id, Jsonb(record), prev, h),
        )
    return h


def upsert_compliance_result(pg: psycopg.Connection, asset_id: str, run_id: str,
                             result: dict, evidence_hash: str) -> None:
    fp = hashlib.sha1(f"{asset_id}|{result['rule_id']}".encode()).hexdigest()
    with pg.cursor() as cur:
        cur.execute(
            """
            INSERT INTO compliance_results (asset_id, rule_id, benchmark, title, severity, status,
                rationale, remediation, evidence, evidence_hash, run_id, fingerprint, evaluated_at)
            VALUES (%(asset_id)s, %(rule_id)s, %(benchmark)s, %(title)s, %(severity)s, %(status)s,
                %(rationale)s, %(remediation)s, %(evidence)s, %(evidence_hash)s, %(run_id)s, %(fp)s, now())
            ON CONFLICT (fingerprint) DO UPDATE SET
                status = EXCLUDED.status, rationale = EXCLUDED.rationale,
                evidence = EXCLUDED.evidence, evidence_hash = EXCLUDED.evidence_hash,
                run_id = EXCLUDED.run_id, evaluated_at = now()
            """,
            {"asset_id": asset_id, "run_id": run_id, "fp": fp,
             "evidence": Jsonb(result.get("evidence", {})), "evidence_hash": evidence_hash,
             **{k: result.get(k) for k in ("rule_id", "benchmark", "title", "severity",
                                           "status", "rationale", "remediation")}},
        )


def evidence_rows(pg: psycopg.Connection) -> list[dict]:
    with pg.cursor() as cur:
        cur.execute("SELECT seq, record, prev_hash, hash FROM compliance_evidence ORDER BY seq")
        return [{"seq": s, "record": rec, "prev_hash": p, "hash": h} for (s, rec, p, h) in cur.fetchall()]


def compliance_summary(pg: psycopg.Connection) -> list[tuple]:
    with pg.cursor() as cur:
        cur.execute("SELECT status, count(*) FROM compliance_results GROUP BY status ORDER BY 1")
        return cur.fetchall()
