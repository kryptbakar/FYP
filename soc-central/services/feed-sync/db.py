"""Local mirror store (PostgreSQL). feed-sync writes here; enrichment reads here.

The whole point of the air-gapped design: feed-sync is the ONLY component that
touches the internet, and it lands everything in these tables. Every other
service reads the mirror and never makes an outbound call.
"""
from __future__ import annotations

import logging
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

log = logging.getLogger("feed-sync.db")

DDL = """
CREATE TABLE IF NOT EXISTS nvd_cve (
    cve_id        text PRIMARY KEY,
    published     timestamptz,
    last_modified timestamptz,
    cvss_score    numeric,
    cvss_severity text,
    cvss_vector   text,
    description   text,
    source        text DEFAULT 'nvd',
    synced_at     timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nvd_affected (
    id                 bigserial PRIMARY KEY,
    cve_id             text REFERENCES nvd_cve(cve_id) ON DELETE CASCADE,
    vendor             text,
    product            text NOT NULL,
    version_start      text,
    version_start_incl boolean DEFAULT true,
    version_end        text,
    version_end_excl   boolean DEFAULT true
);
CREATE INDEX IF NOT EXISTS nvd_affected_product ON nvd_affected (product);

CREATE TABLE IF NOT EXISTS epss (
    cve_id     text PRIMARY KEY,
    epss       numeric,
    percentile numeric,
    score_date date
);

CREATE TABLE IF NOT EXISTS kev (
    cve_id             text PRIMARY KEY,
    vendor             text,
    product            text,
    name               text,
    date_added         date,
    due_date           date,
    known_ransomware   text,
    notes              text
);

-- Exploit availability mirror (Exploit-DB / Metasploit / public PoC). Turns a CVE id into
-- "is there a working exploit?" — a stronger prioritisation signal than CVSS alone, and the
-- piece the Cve-Extractor reference contributes. One CVE can have several refs.
CREATE TABLE IF NOT EXISTS exploit_refs (
    cve_id  text NOT NULL,
    source  text NOT NULL,            -- exploit-db | metasploit | github-poc | nuclei
    ref     text NOT NULL,            -- EDB-id / msf module path / PoC URL
    type    text,                     -- exploit | metasploit | poc
    title   text,
    PRIMARY KEY (cve_id, source, ref)
);
CREATE INDEX IF NOT EXISTS exploit_refs_cve ON exploit_refs (cve_id);

-- Maps a distro package name (what osquery reports) to the upstream product
-- name used in NVD CPEs (what CVEs are keyed on). The hard part of CVE matching.
CREATE TABLE IF NOT EXISTS pkg_product_alias (
    deb_name text PRIMARY KEY,
    product  text NOT NULL
);

-- Bookkeeping: when each feed last synced and how many rows.
CREATE TABLE IF NOT EXISTS feed_sync_log (
    feed       text PRIMARY KEY,
    rows       integer,
    mode       text,
    synced_at  timestamptz DEFAULT now()
);
"""


def connect(dsn: str) -> psycopg.Connection:
    conn = psycopg.connect(dsn, autocommit=True)
    return conn


def ensure_schema(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(DDL)
    log.info("mirror schema ready")


def upsert_cves(conn: psycopg.Connection, cves: list[dict[str, Any]]) -> int:
    if not cves:
        return 0
    with conn.cursor() as cur:
        for c in cves:
            cur.execute(
                """
                INSERT INTO nvd_cve (cve_id, published, last_modified, cvss_score,
                                     cvss_severity, cvss_vector, description, source)
                VALUES (%(cve_id)s, %(published)s, %(last_modified)s, %(cvss_score)s,
                        %(cvss_severity)s, %(cvss_vector)s, %(description)s, %(source)s)
                ON CONFLICT (cve_id) DO UPDATE SET
                    last_modified = EXCLUDED.last_modified,
                    cvss_score    = EXCLUDED.cvss_score,
                    cvss_severity = EXCLUDED.cvss_severity,
                    cvss_vector   = EXCLUDED.cvss_vector,
                    description   = EXCLUDED.description,
                    synced_at     = now()
                """,
                {"source": "nvd", **c},
            )
            # Replace affected ranges for this CVE.
            cur.execute("DELETE FROM nvd_affected WHERE cve_id = %s", (c["cve_id"],))
            for a in c.get("affected", []):
                cur.execute(
                    """
                    INSERT INTO nvd_affected (cve_id, vendor, product, version_start,
                                              version_start_incl, version_end, version_end_excl)
                    VALUES (%(cve_id)s, %(vendor)s, %(product)s, %(version_start)s,
                            %(version_start_incl)s, %(version_end)s, %(version_end_excl)s)
                    """,
                    {
                        "cve_id": c["cve_id"],
                        "vendor": a.get("vendor"),
                        "product": a["product"],
                        "version_start": a.get("version_start"),
                        "version_start_incl": a.get("version_start_incl", True),
                        "version_end": a.get("version_end"),
                        "version_end_excl": a.get("version_end_excl", True),
                    },
                )
    return len(cves)


def upsert_epss(conn: psycopg.Connection, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO epss (cve_id, epss, percentile, score_date)
            VALUES (%(cve_id)s, %(epss)s, %(percentile)s, %(score_date)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                epss = EXCLUDED.epss, percentile = EXCLUDED.percentile, score_date = EXCLUDED.score_date
            """,
            rows,
        )
    return len(rows)


def upsert_kev(conn: psycopg.Connection, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO kev (cve_id, vendor, product, name, date_added, due_date, known_ransomware, notes)
            VALUES (%(cve_id)s, %(vendor)s, %(product)s, %(name)s, %(date_added)s, %(due_date)s,
                    %(known_ransomware)s, %(notes)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                name = EXCLUDED.name, due_date = EXCLUDED.due_date,
                known_ransomware = EXCLUDED.known_ransomware, notes = EXCLUDED.notes
            """,
            rows,
        )
    return len(rows)


def upsert_exploit_refs(conn: psycopg.Connection, rows: list[dict[str, Any]]) -> int:
    if not rows:
        return 0
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO exploit_refs (cve_id, source, ref, type, title)
            VALUES (%(cve_id)s, %(source)s, %(ref)s, %(type)s, %(title)s)
            ON CONFLICT (cve_id, source, ref) DO UPDATE SET
                type = EXCLUDED.type, title = EXCLUDED.title
            """,
            rows,
        )
    return len(rows)


def upsert_aliases(conn: psycopg.Connection, aliases: dict[str, str]) -> int:
    if not aliases:
        return 0
    with conn.cursor() as cur:
        cur.executemany(
            """
            INSERT INTO pkg_product_alias (deb_name, product) VALUES (%s, %s)
            ON CONFLICT (deb_name) DO UPDATE SET product = EXCLUDED.product
            """,
            list(aliases.items()),
        )
    return len(aliases)


def record_sync(conn: psycopg.Connection, feed: str, rows: int, mode: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO feed_sync_log (feed, rows, mode, synced_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (feed) DO UPDATE SET rows = EXCLUDED.rows, mode = EXCLUDED.mode, synced_at = now()
            """,
            (feed, rows, mode),
        )


# Silence "unused import" while keeping Jsonb handy for future evidence columns.
_ = Jsonb
