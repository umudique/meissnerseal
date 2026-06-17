#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-verify transfer_hybrid_v1.json.

This script is read-only. It verifies the ADR-035 UG hash-everything combiner
with real X25519 from the Python `cryptography` package and a manual
HKDF-SHA256 implementation from the Python standard library.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
except ImportError as exc:  # pragma: no cover - environment guard
    print(
        "missing dependency: cryptography is required for real X25519 verification",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


INFO = b"meissnerseal-transfer-v1"
VECTOR_PATH = Path(__file__).with_name("transfer_hybrid_v1.json")


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def raw_public_key(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def require_len(case_id: str, name: str, value: bytes, expected_len: int) -> None:
    if len(value) != expected_len:
        raise ValueError(f"{case_id}: {name} length {len(value)} != {expected_len}")


def verify_case(case: dict[str, str]) -> None:
    case_id = case["case_id"]
    sender_private_bytes = bytes.fromhex(case["sender_ephemeral_private_key"])
    sender_public_bytes = bytes.fromhex(case["sender_ephemeral_public_key"])
    recipient_private_bytes = bytes.fromhex(case["recipient_classical_private_key"])
    recipient_public_bytes = bytes.fromhex(case["recipient_classical_public_key"])
    pqc_shared_secret = bytes.fromhex(case["pqc_shared_secret"])
    pqc_ciphertext = bytes.fromhex(case["pqc_ciphertext"])
    transcript_hash = bytes.fromhex(case["transcript_hash"])
    expected_transfer_key = bytes.fromhex(case["expected_transfer_key"])

    require_len(case_id, "sender_ephemeral_private_key", sender_private_bytes, 32)
    require_len(case_id, "sender_ephemeral_public_key", sender_public_bytes, 32)
    require_len(case_id, "recipient_classical_private_key", recipient_private_bytes, 32)
    require_len(case_id, "recipient_classical_public_key", recipient_public_bytes, 32)
    require_len(case_id, "pqc_shared_secret", pqc_shared_secret, 32)
    require_len(case_id, "pqc_ciphertext", pqc_ciphertext, 1088)
    require_len(case_id, "transcript_hash", transcript_hash, 32)
    require_len(case_id, "expected_transfer_key", expected_transfer_key, 32)

    sender_private = X25519PrivateKey.from_private_bytes(sender_private_bytes)
    recipient_private = X25519PrivateKey.from_private_bytes(recipient_private_bytes)

    computed_sender_public = raw_public_key(sender_private)
    computed_recipient_public = raw_public_key(recipient_private)
    if computed_sender_public != sender_public_bytes:
        raise ValueError(f"{case_id}: sender public key mismatch")
    if computed_recipient_public != recipient_public_bytes:
        raise ValueError(f"{case_id}: recipient public key mismatch")

    ss_x25519 = sender_private.exchange(recipient_private.public_key())
    ikm = (
        pqc_shared_secret
        + ss_x25519
        + sender_public_bytes
        + recipient_public_bytes
        + pqc_ciphertext
    )
    computed_transfer_key = hkdf_sha256(transcript_hash, ikm, INFO, 32)

    if computed_transfer_key != expected_transfer_key:
        raise ValueError(f"{case_id}: expected_transfer_key mismatch")


def main() -> int:
    data = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    for case in data["cases"]:
        verify_case(case)
        print(f"✓ {case['case_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
