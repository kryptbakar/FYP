"""intel-enricher — threat-intel layer: MISP IOC matching, OpenCTI ATT&CK mapping,
and Sigma detection. Reads telemetry + findings, writes findings + tags. No internet
at runtime (MISP/OpenCTI consumed from internal instances / mirror)."""
from __future__ import annotations

import logging
import os

import attack
import db
import ioc
import sigma_eval

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("intel-enricher")


def e(k: str, d: str) -> str:
    return os.getenv(k) or d


def pg_dsn() -> str:
    return (f"host={e('POSTGRES_HOST', 'postgres')} port={e('POSTGRES_PORT_INTERNAL', '5432')} "
            f"dbname={e('POSTGRES_DB', 'soc_central')} user={e('POSTGRES_USER', 'soc')} "
            f"password={e('POSTGRES_PASSWORD', 'soc')}")


def ts_dsn() -> str:
    return (f"host={e('TIMESCALE_HOST', 'timescaledb')} port={e('TIMESCALE_PORT_INTERNAL', '5432')} "
            f"dbname={e('TIMESCALE_DB', 'soc_telemetry')} user={e('TIMESCALE_USER', 'soc')} "
            f"password={e('TIMESCALE_PASSWORD', 'soc')}")


def os_url() -> str:
    return f"http://{e('OPENSEARCH_HOST', 'opensearch')}:{e('OPENSEARCH_PORT_INTERNAL', '9200')}"


def main() -> None:
    ts = db.connect(ts_dsn())
    pg = db.connect(pg_dsn())
    try:
        db.ensure(pg)
        n_ioc = ioc.run(pg, ts)            # MISP
        n_sigma = sigma_eval.run(pg, os_url())  # Sigma (before attack so sigma findings get tagged)
        n_attack = attack.run(pg)          # OpenCTI ATT&CK
        log.info("intel-enrich done: ioc=%d sigma=%d attack_tags=%d", n_ioc, n_sigma, n_attack)
        with pg.cursor() as cur:
            cur.execute("SELECT source_tool, count(*) FROM findings GROUP BY source_tool ORDER BY 1")
            for r in cur.fetchall():
                log.info("  source_tool %-10s %s", r["source_tool"], r["count"])
            cur.execute("SELECT attack, count(*) FROM findings WHERE attack IS NOT NULL GROUP BY attack ORDER BY 2 DESC")
            for r in cur.fetchall():
                log.info("  attack %-12s %s", r["attack"], r["count"])
    finally:
        ts.close()
        pg.close()


if __name__ == "__main__":
    main()
