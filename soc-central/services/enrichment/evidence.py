"""Hash-chained, append-only evidence log — tamper-evident audit trail.

Each compliance evaluation appends one immutable evidence record. Record N stores
the hash of record N-1, and its own hash = SHA-256(prev_hash + canonical(record)).
Altering any past record breaks every hash after it, so the chain is verifiable
(like a lightweight blockchain / Merkle list). This gives the audit traceability
the brief requires for compliance evidence (D-021).

Pure functions here; the DB append/read lives in db.py.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS = "0" * 64


def canonical(record: dict[str, Any]) -> str:
    """Deterministic serialization so the same record always hashes the same,
    regardless of key order or whitespace (survives a jsonb round-trip)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(prev_hash: str, record: dict[str, Any]) -> str:
    return hashlib.sha256((prev_hash + canonical(record)).encode("utf-8")).hexdigest()


def verify_chain(rows: list[dict]) -> dict:
    """rows: ordered by seq, each {seq, record, prev_hash, hash}.
    Returns {ok, length, broken_at?, reason?}."""
    expected_prev = GENESIS
    for r in rows:
        if r["prev_hash"] != expected_prev:
            return {"ok": False, "length": len(rows), "broken_at": r["seq"],
                    "reason": "prev_hash does not match preceding record's hash"}
        recomputed = record_hash(expected_prev, r["record"])
        if recomputed != r["hash"]:
            return {"ok": False, "length": len(rows), "broken_at": r["seq"],
                    "reason": "record content does not match stored hash (tampered)"}
        expected_prev = r["hash"]
    return {"ok": True, "length": len(rows), "head_hash": expected_prev}
