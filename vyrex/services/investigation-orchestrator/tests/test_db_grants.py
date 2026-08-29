"""The least-privilege DB grant list must cover every table the orchestrator reads.

This exists because of a bug that hid well. `compliance_results` was left out of the
`vyrex_orchestrator` grants in services/api/app/schema.py, so `asset_context` died with
InsufficientPrivilege — and the investigation still **completed**, because branch isolation
caught it and recorded the branch as failed.

That is the designed behaviour and it is correct. It also means a missing grant degrades
the product silently instead of failing loudly: the run finishes, the report is produced,
and one evidence branch is quietly absent. Nobody notices until they compare evidence
counts across runs.

So the two lists are pinned against each other statically. A specialist that starts
reading a new table fails here, at the moment the query is added, rather than in
production as a missing evidence branch.

Static parse only — no database, no container, runs in CI with the rest of the suite.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

# tests/ -> investigation-orchestrator/ -> services/ -> vyrex/
VYREX = pathlib.Path(__file__).resolve().parents[3]
REPOSITORY = VYREX / "services/investigation-orchestrator/orchestrator/repository.py"
SCHEMA = VYREX / "services/api/app/schema.py"

# Tables the orchestrator owns and writes; granted DML rather than SELECT.
OWNED = {
    "investigations",
    "investigation_steps",
    "investigation_evidence",
    "investigation_outbox",
    "triage_reports",
    "checkpoints",
    "checkpoint_blobs",
    "checkpoint_writes",
    "checkpoint_migrations",
}

# FROM/JOIN also match subqueries and CTEs; these are the non-table words that survive.
NOT_TABLES = {"select", "lateral", "unnest", "generate_series", "only", "set", "skip"}

TABLE_RE = re.compile(r"\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)", re.IGNORECASE)


def _sql_strings(path: pathlib.Path) -> list[str]:
    """Every string literal in the module that looks like SQL.

    Parsed with `ast` rather than scanned line-by-line. Two earlier attempts got this
    wrong in opposite directions: scanning the whole file matched Python
    `from __future__ import ...` and English prose in comments, while restricting to
    triple-quoted blocks missed the single-line `cur.execute("SELECT * FROM findings ...")`
    queries — which is most of them. `ast` sees exactly the string literals and nothing
    else, and requiring SELECT filters out prose docstrings.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if re.search(r"\bSELECT\b", node.value, re.IGNORECASE):
                out.append(node.value)
    return out


def _tables_read() -> set[str]:
    found: set[str] = set()
    for sql in _sql_strings(REPOSITORY):
        found |= {m.group(1).lower() for m in TABLE_RE.finditer(sql)}
    return {t for t in found if t not in NOT_TABLES and t not in OWNED}


def _granted() -> set[str]:
    """Table names inside the ORCHESTRATOR_ROLE GRANT statements."""
    src = SCHEMA.read_text(encoding="utf-8")
    start = src.find("ORCHESTRATOR_ROLE")
    assert start != -1, "ORCHESTRATOR_ROLE block not found in schema.py"
    block = src[start:start + 4000]

    granted: set[str] = set()
    for m in re.finditer(r"GRANT\s+[A-Z, ]+?\s+ON\s+(.*?)\s+TO\s+vyrex_orchestrator",
                         block, re.DOTALL):
        for token in m.group(1).replace("\n", " ").split(","):
            name = token.strip().strip("'").strip()
            if re.fullmatch(r"[a-z_][a-z0-9_]*", name):
                granted.add(name)
    return granted


@pytest.mark.skipif(not REPOSITORY.exists() or not SCHEMA.exists(),
                    reason="run from a full checkout; both services must be present")
def test_every_table_the_orchestrator_reads_is_granted():
    read = _tables_read()
    granted = _granted()
    missing = read - granted
    assert not missing, (
        f"the orchestrator reads {sorted(missing)} but the vyrex_orchestrator role has no "
        f"grant on them. Add them to the SELECT grant in services/api/app/schema.py. "
        f"Without it the specialist fails with InsufficientPrivilege and the run still "
        f"completes, degraded - so the evidence just goes missing."
    )


@pytest.mark.skipif(not REPOSITORY.exists() or not SCHEMA.exists(),
                    reason="run from a full checkout; both services must be present")
def test_the_parser_actually_found_something():
    """A regex that silently matches nothing would make the test above vacuously pass."""
    assert len(_tables_read()) >= 3, "table extraction looks broken, not clean"
    assert "findings" in _tables_read()
    assert len(_granted()) >= 5, "grant extraction looks broken, not clean"


@pytest.mark.skipif(not SCHEMA.exists(), reason="api service not present")
def test_privileged_tables_are_never_granted():
    """The whole point of the role: no reach into response, identity or audit state."""
    granted = _granted()
    for forbidden in ("response_actions", "users", "sessions",
                      "action_audit", "access_audit", "defense_policy"):
        assert forbidden not in granted, (
            f"{forbidden} must never be granted to vyrex_orchestrator - it is the service "
            f"that reads attacker-influenced text into a language model "
            f"(docs/THREAT-MODEL.md §3.1)"
        )
