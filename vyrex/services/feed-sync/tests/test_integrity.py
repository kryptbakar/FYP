"""Tests for feed-cache integrity — the fail-closed mirror-poisoning gate (TB4)."""
import pytest

import integrity
from integrity import IntegrityError


ROWS = [{"cve_id": "CVE-2021-44228", "epss": 0.97}, {"cve_id": "CVE-2020-0001", "epss": 0.01}]


def test_digest_is_deterministic_and_order_independent():
    d1 = integrity.digest(ROWS)
    # same rows, keys in different insertion order → same digest
    reordered = [{"epss": r["epss"], "cve_id": r["cve_id"]} for r in ROWS]
    assert d1 == integrity.digest(reordered)
    assert len(d1) == 64  # sha-256 hex


def test_digest_changes_when_data_changes():
    tampered = [{"cve_id": "CVE-2021-44228", "epss": 0.01}, ROWS[1]]  # EPSS lowered
    assert integrity.digest(ROWS) != integrity.digest(tampered)


def test_write_then_verify_roundtrip(tmp_path):
    integrity.write_manifest(tmp_path, "epss", ROWS)
    integrity.verify(tmp_path, "epss", ROWS)  # no raise


def test_verify_detects_tampering(tmp_path):
    integrity.write_manifest(tmp_path, "epss", ROWS)
    tampered = [{"cve_id": "CVE-2021-44228", "epss": 0.01}, ROWS[1]]
    with pytest.raises(IntegrityError, match="failed integrity check"):
        integrity.verify(tmp_path, "epss", tampered)


def test_verify_fails_closed_without_manifest(tmp_path):
    # no manifest written → must refuse, not silently pass
    with pytest.raises(IntegrityError, match="no integrity manifest"):
        integrity.verify(tmp_path, "kev", ROWS)
