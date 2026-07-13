"""Test the attack-scenario validation — the intelligence layer on a scripted intrusion.

This is the CI gate for the fusion + ranking claims: all four property checks must
pass, so a regression that breaks consensus or exploit-aware ordering fails the build.
"""
import attack_scenario


def test_scenario_all_properties_hold():
    r = attack_scenario.run()
    assert r["passed"], r["checks"]
    # every individual property, named, so a failure says which one broke
    for name, ok in r["checks"].items():
        assert ok, f"property failed: {name}"


def test_c2_cluster_has_full_consensus():
    r = attack_scenario.run()
    c2 = next(s for s in r["ranked"] if s["id"] == 3)
    assert c2["n_tools"] == 3 and c2["consensus"] == 1.0


def test_fusion_lift_is_positive():
    r = attack_scenario.run()
    by_id = {s["id"]: s for s in r["ranked"]}
    assert by_id[3]["score"] > by_id[6]["score"]   # corroborated C2 > identical solo C2


def test_distractor_sinks_below_exploited():
    r = attack_scenario.run()
    by_id = {s["id"]: s for s in r["ranked"]}
    assert by_id[7]["rank"] > by_id[1]["rank"]     # high-CVSS-unexploited ranks below Log4Shell


def test_markdown_renders():
    md = attack_scenario.to_markdown(attack_scenario.run())
    assert "Attack-scenario validation" in md and "Result: PASS" in md
