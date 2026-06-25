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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


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
        seed = bytes.fromhex(case["private_key_seed"])
        if len(seed) != 32:
            raise SystemExit(f"{case['case_id']}: seed must be 32 bytes, got {len(seed)}")
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
        print(f"{case['case_id']}: ok")


if __name__ == "__main__":
    main()
