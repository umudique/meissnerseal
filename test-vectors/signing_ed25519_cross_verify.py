#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-verify signing_ed25519_v1.json with Python cryptography.

This script is read-only: it recomputes Ed25519 public keys and signatures from
the fixed seeds in signing_ed25519_v1.json and exits non-zero on drift.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


VECTOR_PATH = Path(__file__).with_name("signing_ed25519_v1.json")


def main() -> None:
    vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    if vectors["profile"] != "ED25519_V1":
        raise SystemExit("unexpected profile")
    if vectors["version"] != 1:
        raise SystemExit(f"unexpected version: {vectors['version']}")
    if not vectors["cases"]:
        raise SystemExit("KAT file contains no cases")

    for case in vectors["cases"]:
        if case.get("expected", {}).get("result") == "Err":
            verify_rejection(case)
        else:
            verify_positive(case)
        print(f"{case['case_id']}: ok")


def verify_positive(case: dict[str, str]) -> None:
    seed = bytes.fromhex(case["private_key_seed"])
    if len(seed) != 32:
        raise SystemExit(f"{case['case_id']}: seed must be 32 bytes, got {len(seed)}")
    if case["algorithm_id_u16_le"] != "0100":
        raise SystemExit(f"{case['case_id']}: unexpected algorithm_id_u16_le")
    message = bytes.fromhex(case["message"])
    signing_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = signing_key.sign(message)

    if public_key.hex() != case["public_key"]:
        raise SystemExit(f"{case['case_id']}: public key drift")
    if signature.hex() != case["expected_signature"]:
        raise SystemExit(f"{case['case_id']}: signature drift")


def verify_rejection(case: dict[str, str]) -> None:
    message = bytes.fromhex(case["message"])
    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(case["wrong_public_key"]))
    signature = bytes.fromhex(case["expected_signature"])
    try:
        public_key.verify(signature, message)
    except Exception:
        return
    raise SystemExit(f"{case['case_id']}: wrong-key rejection drift")


if __name__ == "__main__":
    main()
