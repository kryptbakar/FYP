# feed-sync

**Built in:** Phase 3 · **Language:** Python · **Role:** the *only* internet-facing job

Mirrors the free vulnerability feeds into the local Postgres store. Every other
service reads that mirror and **never** makes an outbound call — that's the
air-gapped design (D-018).

| Feed | Source | Mirror table |
|------|--------|--------------|
| CISA KEV | `known_exploited_vulnerabilities.json` | `kev` |
| FIRST EPSS | daily `epss_scores-current.csv.gz` | `epss` |
| NVD CVE 2.0 | incremental `lastModStartDate/EndDate` window | `nvd_cve` + `nvd_affected` |

`pkg_product_alias` (curated) maps distro package names → upstream CPE product names.

## Modes

```bash
make feeds-seed                 # offline: load bundled fixtures (deterministic, dev/CI)
make feeds-sync                 # online: fetch live (KEV + EPSS + NVD window)
# replay a shipped cache on an air-gapped site:
docker compose --profile feeds run --rm feed-sync --feeds kev,epss,nvd --from-cache
```

Online runs also **cache** the normalized rows to a volume (`/feeds-cache`), so an
air-gapped site can carry the cache in and replay it with `--from-cache`.

## Config (env)
`POSTGRES_*`, `NVD_API_KEY` (recommended — raises NVD rate limit), `NVD_SYNC_DAYS`
(default 7), `EPSS_LIMIT`, `FEED_CACHE_DIR`.

## Fixtures
`fixtures/` holds a small, real CVE set (glibc Looney-Tunables, bash, openssl, zlib)
targeting actual Debian-bookworm packages plus EPSS scores and a KEV subset — enough to
exercise all three assessment domains offline. One KEV entry is **labelled a lab demo**
(`CVE-2023-4911`) so the KEV-enrichment join can be shown end-to-end.

## Not yet
MISP and abuse.ch (URLhaus/MalwareBazaar/ThreatFox) are approved sources but stubbed for
the MVP; they slot in as additional fetchers writing IOC tables.
