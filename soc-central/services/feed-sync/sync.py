"""feed-sync — mirror NVD / EPSS / CISA-KEV into the local Postgres store.

THE ONLY INTERNET-FACING JOB. Everything else reads the mirror it produces.

Modes:
  (default, online)  fetch live, write the mirror, and cache normalized rows to disk
  --from-cache       replay the on-disk cache (air-gapped sites ship the cache)
  --seed             load the bundled fixtures (offline, deterministic; good for dev/CI)

Examples:
  python sync.py --seed
  python sync.py --feeds kev,epss
  python sync.py --feeds kev,epss,nvd --from-cache
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
from pathlib import Path

import httpx

import db
import fetchers

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("feed-sync")

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
CACHE_DIR = Path(os.getenv("FEED_CACHE_DIR", "/feeds-cache"))


def dsn() -> str:
    return (
        f"host={os.getenv('POSTGRES_HOST', 'postgres')} port={os.getenv('POSTGRES_PORT_INTERNAL', '5432')} "
        f"dbname={os.getenv('POSTGRES_DB', 'soc_central')} user={os.getenv('POSTGRES_USER', 'soc')} "
        f"password={os.getenv('POSTGRES_PASSWORD', 'soc')}"
    )


# --------------------------------------------------------------- loaders -----
def load_fixture_nvd() -> list[dict]:
    return json.loads((FIXTURES / "nvd_seed.json").read_text())


def load_fixture_epss() -> list[dict]:
    rows = []
    with (FIXTURES / "epss_seed.csv").open() as f:
        for row in csv.DictReader(f):
            rows.append(
                {"cve_id": row["cve"], "epss": float(row["epss"]),
                 "percentile": float(row["percentile"]), "score_date": row.get("score_date")}
            )
    return rows


def load_fixture_kev() -> list[dict]:
    data = json.loads((FIXTURES / "kev_seed.json").read_text())
    out = []
    for v in data.get("vulnerabilities", []):
        out.append(
            {"cve_id": v["cveID"], "vendor": v.get("vendorProject"), "product": v.get("product"),
             "name": v.get("vulnerabilityName"), "date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
             "known_ransomware": v.get("knownRansomwareCampaignUse"), "notes": v.get("notes")}
        )
    return out


def load_fixture_exploit() -> list[dict]:
    data = json.loads((FIXTURES / "exploit_seed.json").read_text())
    return data.get("exploits", [])


def load_aliases() -> dict[str, str]:
    return json.loads((FIXTURES / "pkg_alias_seed.json").read_text())


def cache_write(name: str, rows: list[dict]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{name}.json").write_text(json.dumps(rows, default=str))


def cache_read(name: str) -> list[dict]:
    return json.loads((CACHE_DIR / f"{name}.json").read_text())


# ----------------------------------------------------------------- main ------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--feeds", default="kev,epss,nvd,exploit", help="comma list: kev,epss,nvd,exploit")
    ap.add_argument("--seed", action="store_true", help="load bundled fixtures (offline)")
    ap.add_argument("--from-cache", action="store_true", help="replay the on-disk cache (offline)")
    ap.add_argument("--nvd-days", type=int, default=int(os.getenv("NVD_SYNC_DAYS", "7")))
    ap.add_argument("--epss-limit", type=int, default=int(os.getenv("EPSS_LIMIT", "0")))
    args = ap.parse_args()
    feeds = {f.strip() for f in args.feeds.split(",") if f.strip()}
    mode = "seed" if args.seed else ("cache" if args.from_cache else "online")

    conn = db.connect(dsn())
    db.ensure_schema(conn)

    # Package->product aliases are our curated config, refreshed every run.
    n = db.upsert_aliases(conn, load_aliases())
    log.info("aliases: %d", n)

    client = None if mode != "online" else httpx.Client(headers={"User-Agent": "soc-central-feed-sync/0.3"})
    try:
        if "kev" in feeds:
            rows = load_fixture_kev() if mode == "seed" else (cache_read("kev") if mode == "cache" else fetchers.fetch_kev(client))
            if mode == "online":
                cache_write("kev", rows)
            db.record_sync(conn, "kev", db.upsert_kev(conn, rows), mode)

        if "epss" in feeds:
            if mode == "seed":
                rows = load_fixture_epss()
            elif mode == "cache":
                rows = cache_read("epss")
            else:
                rows = fetchers.fetch_epss(client, limit=args.epss_limit)
                cache_write("epss", rows)
            db.record_sync(conn, "epss", db.upsert_epss(conn, rows), mode)

        if "nvd" in feeds:
            if mode == "seed":
                rows = load_fixture_nvd()
            elif mode == "cache":
                rows = cache_read("nvd")
            else:
                rows = fetchers.fetch_nvd(client, days=args.nvd_days, api_key=os.getenv("NVD_API_KEY") or None)
                cache_write("nvd", rows)
            db.record_sync(conn, "nvd", db.upsert_cves(conn, rows), mode)

        if "exploit" in feeds:
            rows = load_fixture_exploit() if mode == "seed" else (
                cache_read("exploit") if mode == "cache" else fetchers.fetch_exploit_refs(client))
            if mode == "online":
                cache_write("exploit", rows)
            db.record_sync(conn, "exploit", db.upsert_exploit_refs(conn, rows), mode)
    finally:
        if client:
            client.close()

    with conn.cursor() as cur:
        cur.execute("SELECT feed, rows, mode, synced_at FROM feed_sync_log ORDER BY feed")
        for feed, rows_n, m, ts in cur.fetchall():
            log.info("mirror: %-5s rows=%-8s mode=%s at=%s", feed, rows_n, m, ts)
    conn.close()
    log.info("feed-sync done (mode=%s feeds=%s)", mode, ",".join(sorted(feeds)))


if __name__ == "__main__":
    main()
