"""Feed-cache integrity — fail-closed verification of the mirror carried across the gap.

feed-sync is the only internet-facing job; air-gapped sites run it once online to
build an on-disk cache (`--from-cache` replay), then carry that cache inside. That
carried cache is a mirror-poisoning vector (THREAT-MODEL TB4): tampered EPSS/KEV/NVD
rows would silently skew every downstream risk score.

This module stamps a SHA-256 over each cached feed when it is written and verifies it
before the cache is imported, refusing to load on mismatch or a missing manifest.
It is the same checksum discipline as the offline installer bundle
(tools/airgap/install.sh), applied to the feed cache specifically.

Bundled fixtures (`--seed`) are covered by the image supply chain (cosign, D-048),
not this — they never travel outside the signed image.

Pure functions, no I/O beyond the manifest file; unit-tested in tests/.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

log = logging.getLogger("feed-sync.integrity")


class IntegrityError(Exception):
    """Raised when a cached feed fails verification — always fail closed."""


def digest(rows: list[dict]) -> str:
    """Deterministic SHA-256 over a feed's rows.

    Canonicalised as sorted-key, compact JSON so the hash is stable regardless of
    dict ordering; `default=str` matches how cache_write serialises dates.
    """
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def manifest_path(cache_dir: Path, name: str) -> Path:
    return Path(cache_dir) / f"{name}.sha256"


def write_manifest(cache_dir: Path, name: str, rows: list[dict]) -> str:
    """Write `{name}.sha256` alongside the cached feed; returns the digest."""
    d = digest(rows)
    manifest_path(cache_dir, name).write_text(d + "\n")
    return d


def verify(cache_dir: Path, name: str, rows: list[dict]) -> None:
    """Raise IntegrityError unless `rows` match the stored manifest (fail closed)."""
    mp = manifest_path(cache_dir, name)
    if not mp.exists():
        raise IntegrityError(
            f"no integrity manifest for cached feed '{name}' ({mp}); refusing to import")
    expected = mp.read_text().strip()
    actual = digest(rows)
    if actual != expected:
        raise IntegrityError(
            f"cached feed '{name}' failed integrity check: "
            f"expected {expected[:12]}…, got {actual[:12]}… — possible tampering")
    log.info("cache integrity OK: %s (%s…)", name, actual[:12])
