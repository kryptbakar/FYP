"""DB access for the risk engine (Postgres soc_central). Reads findings + context,
writes back risk scores, rankings and explanations. No internet.
"""
from __future__ import annotations

import logging

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

import features

log = logging.getLogger("ml.db")

# Idempotent migration: risk columns on findings + explanation/feedback tables +
# an asset criticality knob. Mirrors enrichment's schema ownership; safe to re-run.
MIGRATION = """
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_rank       integer;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_components jsonb;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ml_risk_score   numeric;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS model_version   text;
ALTER TABLE assets   ADD COLUMN IF NOT EXISTS criticality     numeric DEFAULT 0.5;

CREATE TABLE IF NOT EXISTS finding_explanations (
    finding_id     bigint PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    ml_risk_score  numeric,
    base_value     numeric,
    shap           jsonb,
    top_factors    jsonb,
    counterfactuals jsonb,
    model_version  text,
    created_at     timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS analyst_feedback (
    id            bigserial PRIMARY KEY,
    finding_id    bigint REFERENCES findings(id) ON DELETE CASCADE,
    analyst       text,
    action        text,           -- accept | dismiss | escalate | deprioritize | relabel
    label_priority numeric,       -- optional analyst-assigned 0..100 (training signal)
    comment       text,
    created_at    timestamptz DEFAULT now()
);
"""


def connect(dsn: str) -> psycopg.Connection:
    return psycopg.connect(dsn, autocommit=True, row_factory=dict_row)


def ensure_schema(pg: psycopg.Connection) -> None:
    with pg.cursor() as cur:
        cur.execute(MIGRATION)
    log.info("risk schema ready")


def load_findings(pg: psycopg.Connection) -> list[dict]:
    with pg.cursor() as cur:
        cur.execute(
            "SELECT id, asset_id, domain, rule_id, severity, cve_id, cvss_score, epss, kev, first_seen FROM findings"
        )
        return cur.fetchall()


def load_context(pg: psycopg.Connection) -> features.Context:
    with pg.cursor() as cur:
        # Asset exposure from network findings.
        cur.execute("SELECT asset_id, count(*) AS n FROM findings WHERE domain='network' GROUP BY asset_id")
        exposure = {r["asset_id"]: min(1.0, 0.34 * r["n"]) for r in cur.fetchall()}
        # Compliance impact = fraction of graded controls that FAIL.
        cur.execute(
            """SELECT asset_id,
                      count(*) FILTER (WHERE status='fail')::float
                      / NULLIF(count(*) FILTER (WHERE status IN ('pass','fail','partial')),0) AS impact
               FROM compliance_results GROUP BY asset_id"""
        )
        compliance_impact = {r["asset_id"]: float(r["impact"]) for r in cur.fetchall() if r["impact"] is not None}
        # Asset business criticality.
        cur.execute("SELECT host_id, COALESCE(criticality,0.5) AS c FROM assets")
        criticality = {r["host_id"]: float(r["c"]) for r in cur.fetchall()}
        # CVE publish dates (for age).
        cur.execute("SELECT cve_id, published FROM nvd_cve")
        cve_published = {r["cve_id"]: r["published"] for r in cur.fetchall()}
    return features.Context(exposure, compliance_impact, criticality, cve_published)


def write_risk(pg: psycopg.Connection, finding_id: int, composite: float,
               components: dict, ml_score: float | None, model_version: str | None) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """UPDATE findings SET risk_score=%s, risk_components=%s, ml_risk_score=%s, model_version=%s
               WHERE id=%s""",
            (composite, Jsonb(components), ml_score, model_version, finding_id),
        )


def upsert_explanation(pg: psycopg.Connection, finding_id: int, exp: dict, model_version: str | None) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """INSERT INTO finding_explanations
                 (finding_id, ml_risk_score, base_value, shap, top_factors, counterfactuals, model_version, created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s, now())
               ON CONFLICT (finding_id) DO UPDATE SET
                 ml_risk_score=EXCLUDED.ml_risk_score, base_value=EXCLUDED.base_value,
                 shap=EXCLUDED.shap, top_factors=EXCLUDED.top_factors,
                 counterfactuals=EXCLUDED.counterfactuals, model_version=EXCLUDED.model_version, created_at=now()""",
            (finding_id, exp["ml_risk_score"], exp["base_value"], Jsonb(exp["shap"]),
             Jsonb(exp["top_factors"]), Jsonb(exp["counterfactuals"]), model_version),
        )


def recompute_ranks(pg: psycopg.Connection) -> None:
    with pg.cursor() as cur:
        cur.execute(
            """UPDATE findings f SET risk_rank = s.rnk FROM (
                   SELECT id, dense_rank() OVER (ORDER BY risk_score DESC NULLS LAST) AS rnk FROM findings
               ) s WHERE f.id = s.id"""
        )


def load_feedback(pg: psycopg.Connection) -> list[dict]:
    """Analyst-labelled findings to fold into training."""
    with pg.cursor() as cur:
        cur.execute(
            """SELECT f.id, f.asset_id, f.domain, f.rule_id, f.severity, f.cve_id,
                      f.cvss_score, f.epss, f.kev, f.first_seen, af.label_priority
               FROM analyst_feedback af JOIN findings f ON f.id = af.finding_id
               WHERE af.label_priority IS NOT NULL"""
        )
        return cur.fetchall()
