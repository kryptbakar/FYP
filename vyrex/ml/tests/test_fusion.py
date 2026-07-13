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
