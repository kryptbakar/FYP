"""Unit tests for the compliance engine.

Pins the pass/fail/partial/not_applicable logic per rule, and the honesty property
the docstring promises: rules whose evidence we don't collect return not_applicable
rather than a false pass.
"""
import compliance
from compliance import FAIL, NA, PARTIAL, PASS, State, evaluate_asset


def _state(pkgs=(), os=None, listening=None, users=None, kernel=None) -> State:
    return State(os=os or {"name": "Debian GNU/Linux", "version": "12"},
                 pkg_names=set(pkgs), kernel=kernel, listening=list(listening or []),
                 users=list(users or []))


def _run(rule_id, state) -> dict:
    return {r["rule_id"]: r for r in evaluate_asset(state)}[rule_id]


def test_all_rules_return_valid_status():
    results = evaluate_asset(_state(pkgs={"auditd"}))
    assert len(results) == len(compliance.RULES)
    assert all(r["status"] in (PASS, FAIL, PARTIAL, NA) for r in results)


def test_auditd_pass_and_fail():
    assert _run("CIS-4.1.1", _state(pkgs={"auditd"}))["status"] == PASS
    assert _run("CIS-4.1.1", _state(pkgs=set()))["status"] == FAIL


def test_firewall_detects_any_known_package():
    assert _run("CIS-3.5.1", _state(pkgs={"nftables"}))["status"] == PASS
    assert _run("CIS-3.5.1", _state(pkgs={"ufw"}))["status"] == PASS
    assert _run("CIS-3.5.1", _state(pkgs={"vim"}))["status"] == FAIL


def test_logging_partial_on_systemd_only():
    assert _run("CIS-4.2.1", _state(pkgs={"rsyslog"}))["status"] == PASS
    assert _run("CIS-4.2.1", _state(pkgs={"systemd"}))["status"] == PARTIAL
    assert _run("CIS-4.2.1", _state(pkgs=set()))["status"] == FAIL


def test_insecure_services_flagged():
    assert _run("CIS-2.1.1", _state(pkgs={"telnetd"}))["status"] == FAIL
    assert _run("CIS-2.1.1", _state(pkgs={"nginx"}))["status"] == PASS


def test_plaintext_ports():
    assert _run("CIS-3.1.1", _state(listening=[{"port": "23"}]))["status"] == FAIL   # telnet
    assert _run("CIS-3.1.1", _state(listening=[{"port": "443"}]))["status"] == PASS


def test_approved_os_matching():
    assert _run("ORG-POL-001", _state(os={"name": "Ubuntu", "version": "22.04"}))["status"] == PASS
    assert _run("ORG-POL-001", _state(os={"name": "Arch Linux", "version": "rolling"}))["status"] == FAIL


def test_remote_root_login():
    assert _run("ORG-POL-002", _state(users=[{"user": "root", "host": "10.0.0.9"}]))["status"] == FAIL
    assert _run("ORG-POL-002", _state(users=[{"user": "alice", "host": "10.0.0.9"}]))["status"] == PASS
    # no login data observed → pass (nothing bad seen), not a false fail
    assert _run("ORG-POL-002", _state(users=[]))["status"] == PASS


def test_uncollected_evidence_is_not_applicable_not_false_pass():
    # sshd_config isn't collected yet — the rule must be NA, never a bogus PASS.
    assert _run("CIS-5.2.7", _state(pkgs={"openssh-server"}))["status"] == NA


def test_evidence_and_remediation_present():
    r = _run("CIS-3.5.1", _state(pkgs=set()))
    assert r["remediation"] and isinstance(r["evidence"], dict)
    assert r["benchmark"].startswith("CIS")
