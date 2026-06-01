"""Hash-chained, append-only audit of active-response actions (same construction
as the compliance evidence log, D-021): each record commits to the previous hash,
so any tampering with the action history is detectable. This is what makes
destructive-action accountability defensible."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import psycopg
from psycopg.types.json import Jsonb

from .config import settings

GENESIS = "0" * 64


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev_hash: str, record: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(record)).encode("utf-8")).hexdigest()


def append(action_id: int, event: str, actor: str | None, detail: dict | None = None) -> str:
    """Append one immutable audit record; returns its hash."""
    record = {
        "action_id": action_id, "event": event, "actor": actor,
        "detail": detail or {}, "ts": datetime.now(timezone.utc).isoformat(),
    }
    with psycopg.connect(settings.postgres_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT hash FROM action_audit ORDER BY seq DESC LIMIT 1")
            row = cur.fetchone()
            prev = row[0] if row else GENESIS
            h = _hash(prev, record)
            cur.execute(
                "INSERT INTO action_audit (action_id, event, actor, record, prev_hash, hash) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (action_id, event, actor, Jsonb(record), prev, h),
            )
    return h


def verify() -> dict:
    with psycopg.connect(settings.postgres_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT seq, record, prev_hash, hash FROM action_audit ORDER BY seq")
            rows = cur.fetchall()
    expected_prev = GENESIS
    for seq, record, prev_hash, h in rows:
        if prev_hash != expected_prev:
            return {"ok": False, "length": len(rows), "broken_at": seq, "reason": "prev_hash mismatch"}
        if _hash(expected_prev, record) != h:
            return {"ok": False, "length": len(rows), "broken_at": seq, "reason": "record tampered"}
        expected_prev = h
    return {"ok": True, "length": len(rows), "head_hash": expected_prev}
