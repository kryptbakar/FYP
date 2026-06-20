"""Ed25519 signing of active-response commands.

Every command the platform issues to an agent is signed with the server's private
key; the agent verifies it against the embedded public key before executing. This
makes the command channel tamper-proof and non-repudiable even if the transport is
compromised. The agent verifies the *exact bytes* it receives (we ship the canonical
payload string), so there's no cross-language canonicalization risk.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from functools import lru_cache

from cryptography.hazmat.primitives import serialization

log = logging.getLogger("api.signing")

KEY_PATH = os.getenv("COMMAND_SIGNING_KEY", "/keys/command_signing.key")


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@lru_cache(maxsize=1)
def _private_key():
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def signing_available() -> bool:
    try:
        _private_key()
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("command signing unavailable: %s", e)
        return False


def public_key_b64() -> str:
    raw = _private_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode()


def sign_command(payload: dict) -> tuple[str, str, str]:
    """Return (canonical_payload_string, signature_b64, pubkey_b64)."""
    msg = canonical(payload)
    sig = _private_key().sign(msg.encode("utf-8"))
    return msg, base64.b64encode(sig).decode(), public_key_b64()
