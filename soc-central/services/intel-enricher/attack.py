"""OpenCTI ATT&CK mapping — tag findings with the MITRE ATT&CK technique.

In production these mappings are resolved from OpenCTI (pycti / STIX-TAXII): a finding's
signature/CVE/behaviour is looked up to its attack-pattern. Here we use a curated mapping
table standing in for that lookup (the live OpenCTI client feeds the same `attack` column,
D-038). The `attack` feature also feeds the Phase-F Fusion model.
"""
from __future__ import annotations

import logging

import db

log = logging.getLogger("intel.attack")

# Applied in order; tag_attack only sets findings where attack IS NULL, so first match wins.
# (SQL predicate over the findings row, ATT&CK technique id, human name)
MAPPINGS = [
    ("source_tool='misp' OR rule_id LIKE 'net.suspicious_egress%'", "T1071.001", "Application Layer Protocol: Web (C2)"),
    ("cve_id IS NOT NULL AND domain='application'",                  "T1190",     "Exploit Public-Facing Application"),
    ("rule_id LIKE 'net.exposed%'",                                  "T1133",     "External Remote Services"),
    ("rule_id LIKE 'sys.insecure_service%'",                         "T1021",     "Remote Services"),
    ("source_tool='falco'",                                          "T1059",     "Command and Scripting Interpreter"),
    ("rule_id LIKE 'sigma.%'",                                       "T1071",     "Application Layer Protocol"),
    ("rule_id LIKE 'sys.%'",                                         "T1562",     "Impair Defenses (hardening gap)"),
]


def run(pg) -> int:
    tagged = 0
    for predicate, tech, _name in MAPPINGS:
        tagged += db.tag_attack(pg, predicate, {}, tech)
    log.info("opencti/attack: tagged %d finding(s) with ATT&CK techniques", tagged)
    return tagged
