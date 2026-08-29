"""Which composite factors are DEFINED for a given finding.

`scoring.composite` renormalises over whatever this returns, so a mistake here
moves every score in the system. It is worth pinning precisely, in both
directions: marking a factor inapplicable when it IS evidenceable inflates the
score for free, which would turn a correctness fix into a demo cheat.
"""
from features import applicability


def _f(**kw):
    base = {"cve_id": None, "domain": "system", "observable_key": None}
    base.update(kw)
    return base


# --------------------------------------------------------------- CVE-scoped ---
def test_kev_and_epss_need_a_cve():
    """The CISA KEV catalogue lists CVEs and EPSS is a per-CVE percentile. An IP
    indicator can never appear in either, so neither may consume weight."""
    a = applicability(_f(cve_id=None, domain="network"))
    assert a["kev"] is False
    assert a["epss"] is False


def test_kev_and_epss_apply_when_there_is_a_cve():
    """And a CVE that simply is not in the EPSS feed is MISSING DATA, not an
    inapplicable factor — it keeps its weight and scores 0, which is the
    conservative reading and the one we can defend."""
    a = applicability(_f(cve_id="CVE-2024-3094", domain="application"))
    assert a["kev"] is True
    assert a["epss"] is True


# ------------------------------------------------------------- threat intel ---
def test_threat_intel_inapplicable_to_a_package_finding():
    """MISP ships IPs, domains, URLs and hashes. No IOC can match "liblzma5 is
    version 5.6.0", so corroboration is undefined rather than absent."""
    a = applicability(_f(cve_id="CVE-2024-3094", domain="application"))
    assert a["threat_intel"] is False


def test_threat_intel_applies_to_a_network_finding():
    a = applicability(_f(domain="network"))
    assert a["threat_intel"] is True


def test_threat_intel_applies_when_an_observable_was_recorded():
    """observable_key means a concrete thing was observed — the exact shape an IOC
    feed can match — even if the domain says otherwise."""
    a = applicability(_f(domain="system", observable_key="a" * 40))
    assert a["threat_intel"] is True


# ------------------------------------------------- the guard against inflation ---
def test_evidence_bearing_factors_are_never_marked_inapplicable():
    """consensus, exposure, criticality, age, compliance_impact and attack_ctx can
    be evidenced for ANY finding. If one of them ever appears here, every score in
    the system rises for no reason, so assert the omission explicitly."""
    for f in ("consensus", "exposure", "criticality", "age",
              "compliance_impact", "attack_ctx", "cvss"):
        for finding in (_f(), _f(cve_id="CVE-2021-44228", domain="application"),
                        _f(domain="network", observable_key="b" * 40)):
            assert applicability(finding).get(f, True) is True, f


def test_only_the_three_documented_factors_can_be_false():
    for finding in (_f(), _f(cve_id="CVE-1", domain="network", observable_key="c")):
        falsey = {k for k, v in applicability(finding).items() if v is False}
        assert falsey <= {"epss", "kev", "threat_intel"}
