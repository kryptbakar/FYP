"""Unit tests for the fusion engine — the clustering behaviour we defend.

Pins: cluster grouping by dedup_key, key-less findings stay solo, consensus
weight saturation, cross-cluster inheritance of threat-intel/ATT&CK, and the
severity-first primary selection the console leads with.
"""
from fusion import build_clusters, cluster_key, consensus_weight


def _f(id, tool="agent", key=None, severity="medium", **kw):
    return {"id": id, "source_tool": tool, "dedup_key": key, "severity": severity, **kw}


def test_consensus_weight_saturates():
    assert consensus_weight(1) == 0.0
    assert consensus_weight(2) == 0.5
    assert consensus_weight(3) == 1.0
    assert consensus_weight(7) == 1.0  # saturating, never above 1


def test_keyless_finding_is_its_own_cluster():
    f = _f(1)
    assert cluster_key(f) == "solo:1"
    rec = build_clusters([f])[1]
    assert rec["n_tools"] == 1 and rec["weight"] == 0.0 and rec["dedup_key"] is None


def test_same_key_same_cluster():
    fs = [_f(1, "trivy", "cve:X:h1"), _f(2, "wazuh", "cve:X:h1"), _f(3, "nuclei", "cve:X:h1")]
    by_id = build_clusters(fs)
    assert by_id[1] is by_id[2] is by_id[3]
    assert by_id[1]["n_tools"] == 3 and by_id[1]["weight"] == 1.0
    assert by_id[1]["tools"] == ["nuclei", "trivy", "wazuh"]
    assert by_id[1]["members"] == [1, 2, 3]


def test_same_tool_twice_counts_once():
    fs = [_f(1, "trivy", "cve:X:h1"), _f(2, "trivy", "cve:X:h1")]
    rec = build_clusters(fs)[1]
    assert rec["n_tools"] == 1 and rec["weight"] == 0.0  # duplicates of one tool ≠ consensus


def test_different_assets_stay_separate():
    fs = [_f(1, "trivy", "cve:X:h1"), _f(2, "trivy", "cve:X:h2")]
    by_id = build_clusters(fs)
    assert by_id[1]["members"] == [1] and by_id[2]["members"] == [2]


def test_intel_and_attack_inherited_across_cluster():
    fs = [
        _f(1, "suricata", "net:c2:h1", threat_intel=True),
        _f(2, "zeek", "net:c2:h1", attack="T1071"),
    ]
    rec = build_clusters(fs)[1]
    assert rec["threat_intel"] is True and rec["attack"] == "T1071"


def test_primary_is_highest_severity_member():
    fs = [
        _f(1, "zeek", "net:c2:h1", severity="low"),
        _f(2, "suricata", "net:c2:h1", severity="critical"),
        _f(3, "falco", "net:c2:h1", severity="high"),
    ]
    assert build_clusters(fs)[1]["primary"] == 2


def test_missing_tool_defaults_to_agent():
    fs = [{"id": 1, "dedup_key": "k", "severity": "low"},
          _f(2, "trivy", "k")]
    rec = build_clusters(fs)[1]
    assert rec["tools"] == ["agent", "trivy"] and rec["n_tools"] == 2


# --- observable-key clustering (the cross-tool fusion fix, 2026-08-28) ---------------
#
# Regression guard for the defect in ml/FUSION.md section 1: dedup_key identified the
# RULE THAT FIRED, so a MISP IOC hit, a Sigma detection and an agent rule about ONE
# connection produced three unrelated keys, n_tools=1 for all three, and the engine
# reported "0 corroborated by >1 tool" on the exact scenario the docs used as their
# worked example. observable_key identifies the THING OBSERVED and takes priority.

OBS = "sha1-of-lab-vm-01|flow|185.220.101.45|4444"


def test_observable_key_takes_priority_over_dedup_key():
    f = _f(1, key="rule-scoped", observable_key=OBS)
    assert cluster_key(f) == OBS


def test_dedup_key_still_used_when_there_is_no_observable():
    """Vulnerability findings have no network observable and must keep clustering:
    the same CVE on the same asset is one issue whichever scanner reported it."""
    assert cluster_key(_f(1, key="cve-scoped")) == "cve-scoped"
    assert cluster_key(_f(2, key="cve-scoped", observable_key=None)) == "cve-scoped"


def test_three_tools_on_one_connection_reach_full_consensus():
    """THE regression. Different rule identities, one observable -> n_tools=3."""
    findings = [
        _f(1, tool="agent", key="agent-rule-4444", observable_key=OBS, severity="high"),
        _f(2, tool="misp",  key="ioc-185.220.101.45", observable_key=OBS, severity="high",
           threat_intel={"indicator": "185.220.101.45"}),
        _f(3, tool="sigma", key="sigma-rule-id", observable_key=OBS, severity="high",
           attack="T1571"),
    ]
    clusters = build_clusters(findings)
    for fid in (1, 2, 3):
        rec = clusters[fid]
        assert rec["n_tools"] == 3, f"finding {fid} saw {rec['n_tools']} tool(s)"
        assert rec["weight"] == 1.0
        assert sorted(rec["tools"]) == ["agent", "misp", "sigma"]
        # Intel and ATT&CK inherit across the cluster, so the agent row now benefits
        # from what MISP and Sigma knew - the point of fusing in the first place.
        assert rec["threat_intel"] is True
        assert rec["attack"] == "T1571"


def test_different_ports_to_the_same_host_do_not_merge():
    """Two flows are two observables. Merging them would invent corroboration."""
    a = _f(1, tool="agent", observable_key=OBS)
    b = _f(2, tool="misp", observable_key=OBS.replace("4444", "8080"))
    clusters = build_clusters([a, b])
    assert clusters[1]["n_tools"] == 1
    assert clusters[2]["n_tools"] == 1


def test_same_tool_twice_is_not_corroboration():
    """Consensus counts DISTINCT tools; one tool reporting twice proves nothing."""
    findings = [_f(1, tool="sigma", observable_key=OBS),
                _f(2, tool="sigma", observable_key=OBS)]
    rec = build_clusters(findings)[1]
    assert rec["n_tools"] == 1 and rec["weight"] == 0.0
