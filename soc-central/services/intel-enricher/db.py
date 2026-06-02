"""DB access for the threat-intel enricher (Postgres soc_central + Timescale read).

Adds two columns to findings: `attack` (MITRE ATT&CK technique, from OpenCTI) and
`threat_intel` (IOC-match context, from MISP). IOC and Sigma matches also create new
findings tagged by source_tool.
"""
from __future__ import annotations

import hashlib
import logging

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

log = logging.getLogger("intel.db")

MIGRATION = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS attack       text;   -- MITRE ATT&CK technique (OpenCTI)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS threat_intel jsonb;  -- IOC match context (MISP)
CREATE INDEX IF NOT EXISTS findings_attack ON findings (attack);
"""


def connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)


def ensure(pg: psycopg.Connection) -> None:
    with pg.cursor() as cur:
        cur.execute(MIGRATION)
    log.info("intel schema ready (findings.attack, findings.threat_intel)")


def fp(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()


def network_rows(ts: psycopg.Connection, window: str = "30 days", limit: int = 20000) -> list[dict]:
    """Telemetry rows that may carry network indicators (IPs/domains)."""
    with ts.cursor() as cur:
        cur.execute(
            f"""
            SELECT host_id, kind, payload FROM telemetry_raw
            WHERE kind IN ('network_flow','ids_alert','traffic_metadata','runtime_alert','scan_finding')
              AND ingested_at > now() - interval '{window}'
            LIMIT {limit}
            """
        )
        return cur.fetchall()


def upsert_finding(pg: psycopg.Connection, f: dict) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """
            INSERT INTO findings (asset_id, domain, rule_id, title, description, severity,
                cve_id, port, proto, source_tool, raw_ref, dedup_key, attack, threat_intel,
                evidence, fingerprint, last_seen)
            VALUES (%(asset_id)s, %(domain)s, %(rule_id)s, %(title)s, %(description)s, %(severity)s,
                %(cve_id)s, %(port)s, %(proto)s, %(source_tool)s, %(raw_ref)s, %(dedup_key)s,
                %(attack)s, %(threat_intel)s, %(evidence)s, %(fingerprint)s, now())
            ON CONFLICT (fingerprint) DO UPDATE SET
                severity = EXCLUDED.severity, description = EXCLUDED.description,
                attack = COALESCE(EXCLUDED.attack, findings.attack),
                threat_intel = EXCLUDED.threat_intel, evidence = EXCLUDED.evidence, last_seen = now()
            """,
            {**{k: f.get(k) for k in ("asset_id", "domain", "rule_id", "title", "description",
                                      "severity", "cve_id", "port", "proto", "source_tool",
                                      "raw_ref", "dedup_key", "attack", "fingerprint")},
             "threat_intel": Jsonb(f["threat_intel"]) if f.get("threat_intel") else None,
             "evidence": Jsonb(f.get("evidence", {}))},
        )


def ensure_asset(pg: psycopg.Connection, host_id: str) -> None:
    with pg.cursor() as cur:
        cur.execute(
            "INSERT INTO assets (host_id, hostname, last_seen) VALUES (%s, %s, now()) "
            "ON CONFLICT (host_id) DO NOTHING",
            (host_id, host_id),
        )


def tag_attack(pg: psycopg.Connection, where_sql: str, params: dict, technique: str) -> int:
    # Escape LIKE wildcards: psycopg parses '%' as a placeholder marker, so '%' in
    # `LIKE 'net.%'` must be doubled. Predicates carry no params; technique is positional.
    safe = where_sql.replace("%", "%%")
    with pg.cursor() as cur:
        cur.execute(
            f"UPDATE findings SET attack = %s WHERE attack IS NULL AND ({safe})",
            (technique,),
        )
        return cur.rowcount
