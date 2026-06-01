"""Package -> CVE matching, enriched from the local mirror only (air-gapped).

Loads the whole mirror into memory (small for a bounded/seed mirror) and answers
"which CVEs affect this (package, version)?", attaching CVSS + EPSS + KEV. This is
the adaptation of the reference Cve-Extractor / cve-watch enrichment idea: every
match carries the *why* (matched product, version range, scores) so findings are
explainable.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import psycopg

import version as ver

log = logging.getLogger("enrichment.matcher")


@dataclass
class Match:
    cve_id: str
    product: str
    matched_range: str
    cvss_score: float | None
    cvss_severity: str | None
    cvss_vector: str | None
    description: str | None
    epss: float | None
    epss_percentile: float | None
    kev: bool
    kev_due_date: Any | None
    extra: dict = field(default_factory=dict)


class Matcher:
    def __init__(self) -> None:
        self.by_product: dict[str, list[dict]] = {}
        self.epss: dict[str, dict] = {}
        self.kev: dict[str, dict] = {}
        self.alias: dict[str, str] = {}

    @classmethod
    def load(cls, conn: psycopg.Connection) -> "Matcher":
        m = cls()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.product, a.cve_id, a.version_start, a.version_start_incl,
                       a.version_end, a.version_end_excl,
                       c.cvss_score, c.cvss_severity, c.cvss_vector, c.description
                FROM nvd_affected a JOIN nvd_cve c USING (cve_id)
                """
            )
            for row in cur.fetchall():
                (product, cve_id, vs, vsi, ve, vee, score, sev, vec, desc) = row
                m.by_product.setdefault(product.lower(), []).append(
                    {"cve_id": cve_id, "vs": vs, "vsi": vsi, "ve": ve, "vee": vee,
                     "score": score, "sev": sev, "vec": vec, "desc": desc}
                )
            cur.execute("SELECT cve_id, epss, percentile FROM epss")
            for cve_id, epss, pct in cur.fetchall():
                m.epss[cve_id] = {"epss": float(epss) if epss is not None else None,
                                  "percentile": float(pct) if pct is not None else None}
            cur.execute("SELECT cve_id, due_date FROM kev")
            for cve_id, due in cur.fetchall():
                m.kev[cve_id] = {"due_date": due}
            cur.execute("SELECT deb_name, product FROM pkg_product_alias")
            for deb, product in cur.fetchall():
                m.alias[deb.lower()] = product.lower()
        log.info("mirror loaded: products=%d epss=%d kev=%d aliases=%d",
                 len(m.by_product), len(m.epss), len(m.kev), len(m.alias))
        return m

    def products_for(self, deb_name: str) -> set[str]:
        name = deb_name.lower()
        out = {name}
        if name in self.alias:
            out.add(self.alias[name])
        return out

    def match_package(self, deb_name: str, version: str) -> list[Match]:
        matches: list[Match] = []
        for product in self.products_for(deb_name):
            for c in self.by_product.get(product, []):
                if ver.in_range(version, c["vs"], c["vsi"], c["ve"], c["vee"]):
                    matches.append(self._enrich(product, version, c))
        return matches

    def _enrich(self, product: str, version: str, c: dict) -> Match:
        rng = _range_str(c["vs"], c["vsi"], c["ve"], c["vee"])
        e = self.epss.get(c["cve_id"], {})
        k = self.kev.get(c["cve_id"])
        return Match(
            cve_id=c["cve_id"],
            product=product,
            matched_range=f"{product} {version} ∈ {rng}",
            cvss_score=float(c["score"]) if c["score"] is not None else None,
            cvss_severity=c["sev"],
            cvss_vector=c["vec"],
            description=c["desc"],
            epss=e.get("epss"),
            epss_percentile=e.get("percentile"),
            kev=k is not None,
            kev_due_date=k["due_date"] if k else None,
        )


def _range_str(vs, vsi, ve, vee) -> str:
    if not vs and not ve:
        return "any version"
    lo = "" if not vs else (f"[{vs}" if vsi else f"({vs}")
    hi = "" if not ve else (f"{ve})" if vee else f"{ve}]")
    return f"{lo or '(-inf'}, {hi or '+inf)'}"
