#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-verify signing_hybrid_v1.json with independent Python primitives.

This script is read-only: it recomputes the hybrid public key from the fixed
Ed25519 and ML-DSA-87 seeds, then verifies the stored hybrid signatures with
an explicit AND combiner. The positive case is verify-only for ML-DSA because
PyCA cryptography 49.0.0 uses hedged ML-DSA signing in this environment.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey, MLDSA87PublicKey


VECTOR_PATH = Path(__file__).with_name("signing_hybrid_v1.json")
ALGORITHM_ID_U16_LE = "0200"
ED25519_PUBLIC_KEY_LEN = 32
MLDSA87_PUBLIC_KEY_LEN = 2592
HYBRID_PUBLIC_KEY_LEN = ED25519_PUBLIC_KEY_LEN + MLDSA87_PUBLIC_KEY_LEN
ED25519_SIGNATURE_LEN = 64
MLDSA87_SIGNATURE_LEN = 4627
HYBRID_SIGNATURE_LEN = ED25519_SIGNATURE_LEN + MLDSA87_SIGNATURE_LEN


def main() -> None:
    vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    if vectors["profile"] != "ED25519_MLDSA87_HYBRID_V1":
        raise SystemExit(f"unexpected profile: {vectors['profile']}")
    if vectors["version"] != 1:
        raise SystemExit(f"unexpected version: {vectors['version']}")
    if vectors["algorithm_id_u16_le"] != ALGORITHM_ID_U16_LE:
        raise SystemExit("unexpected top-level algorithm_id_u16_le")
    if not vectors["cases"]:
        raise SystemExit("KAT file contains no cases")

    cases = {case["id"]: case for case in vectors["cases"]}

    verify_positive(cases["hybrid-sign-verify-00"])
    print("hybrid-sign-verify-00: ok")

    verify_tampered_ed25519(cases["hybrid-tampered-ed25519-component"])
    print("hybrid-tampered-ed25519-component: ok")

    verify_tampered_mldsa(cases["hybrid-tampered-mldsa87-component"])
    print("hybrid-tampered-mldsa87-component: ok")

    verify_wrong_public_key(cases["hybrid-wrong-public-key"])
    print("hybrid-wrong-public-key: ok")


def verify_positive(case: dict[str, object]) -> None:
    public_key = recompute_hybrid_public_key(case)
    stored_public_key = bytes.fromhex(expect_str(case, "hybrid_public_key"))
    if public_key != stored_public_key:
        raise SystemExit(f"{case['id']}: hybrid public key drift")

    message = bytes.fromhex(expect_str(case, "message"))
    signature = bytes.fromhex(expect_str(case, "expected_hybrid_signature"))
    assert_algorithm_id(case)
    assert_public_key_len(case["id"], stored_public_key)
    assert_signature_len(case["id"], signature)

    ed25519_ok = verify_ed25519_component(stored_public_key, signature, message)
    mldsa_ok = verify_mldsa_component(stored_public_key, signature, message)
    if not ed25519_ok:
        raise SystemExit(f"{case['id']}: Ed25519 component verification drift")
    if not mldsa_ok:
        raise SystemExit(f"{case['id']}: ML-DSA-87 component verification drift")


def verify_tampered_ed25519(case: dict[str, object]) -> None:
    public_key = recompute_hybrid_public_key(case)
    stored_public_key = bytes.fromhex(expect_str(case, "hybrid_public_key"))
    if public_key != stored_public_key:
        raise SystemExit(f"{case['id']}: hybrid public key drift")

    message = bytes.fromhex(expect_str(case, "message"))
    signature = bytes.fromhex(expect_str(case, "tampered_hybrid_signature"))
    assert_algorithm_id(case)
    assert_public_key_len(case["id"], stored_public_key)
    assert_signature_len(case["id"], signature)
    assert_expected_reason(case, "tampered_ed25519_component")

    ed25519_ok = verify_ed25519_component(stored_public_key, signature, message)
    mldsa_ok = verify_mldsa_component(stored_public_key, signature, message)
    if ed25519_ok:
        raise SystemExit(f"{case['id']}: Ed25519 tamper was not rejected")
    if not mldsa_ok:
        raise SystemExit(f"{case['id']}: ML-DSA component should still verify")


def verify_tampered_mldsa(case: dict[str, object]) -> None:
    public_key = recompute_hybrid_public_key(case)
    stored_public_key = bytes.fromhex(expect_str(case, "hybrid_public_key"))
    if public_key != stored_public_key:
        raise SystemExit(f"{case['id']}: hybrid public key drift")

    message = bytes.fromhex(expect_str(case, "message"))
    signature = bytes.fromhex(expect_str(case, "tampered_hybrid_signature"))
    assert_algorithm_id(case)
    assert_public_key_len(case["id"], stored_public_key)
    assert_signature_len(case["id"], signature)
    assert_expected_reason(case, "tampered_mldsa87_component")

    ed25519_ok = verify_ed25519_component(stored_public_key, signature, message)
    mldsa_ok = verify_mldsa_component(stored_public_key, signature, message)
    if not ed25519_ok:
        raise SystemExit(f"{case['id']}: Ed25519 component should still verify")
    if mldsa_ok:
        raise SystemExit(f"{case['id']}: ML-DSA tamper was not rejected")


def verify_wrong_public_key(case: dict[str, object]) -> None:
    correct_public_key = recompute_hybrid_public_key(case)
    stored_public_key = bytes.fromhex(expect_str(case, "hybrid_public_key"))
    if correct_public_key != stored_public_key:
        raise SystemExit(f"{case['id']}: hybrid public key drift")

    wrong_public_key = bytes.fromhex(expect_str(case, "wrong_hybrid_public_key"))
    message = bytes.fromhex(expect_str(case, "message"))
    signature = bytes.fromhex(expect_str(case, "expected_hybrid_signature"))
    assert_algorithm_id(case)
    assert_public_key_len(case["id"], wrong_public_key)
    assert_signature_len(case["id"], signature)
    assert_expected_reason(case, "wrong_public_key")

    if wrong_public_key == stored_public_key:
        raise SystemExit(f"{case['id']}: wrong_hybrid_public_key unexpectedly matches")

    ed25519_ok = verify_ed25519_component(wrong_public_key, signature, message)
    mldsa_ok = verify_mldsa_component(wrong_public_key, signature, message)
    if ed25519_ok or mldsa_ok:
        raise SystemExit(f"{case['id']}: wrong public key rejection drift")


def recompute_hybrid_public_key(case: dict[str, object]) -> bytes:
    ed25519_seed = bytes.fromhex(expect_str(case, "ed25519_seed"))
    mldsa87_seed = bytes.fromhex(expect_str(case, "mldsa87_seed"))
    if len(ed25519_seed) != 32:
        raise SystemExit(f"{case['id']}: Ed25519 seed must be 32 bytes")
    if len(mldsa87_seed) != 32:
        raise SystemExit(f"{case['id']}: ML-DSA-87 seed must be 32 bytes")

    ed25519_public = Ed25519PrivateKey.from_private_bytes(ed25519_seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    mldsa87_public = MLDSA87PrivateKey.from_seed_bytes(mldsa87_seed).public_key().public_bytes_raw()
    return ed25519_public + mldsa87_public


def verify_ed25519_component(public_key: bytes, signature: bytes, message: bytes) -> bool:
    verifying_key = Ed25519PublicKey.from_public_bytes(public_key[:ED25519_PUBLIC_KEY_LEN])
    try:
        verifying_key.verify(signature[:ED25519_SIGNATURE_LEN], message)
    except InvalidSignature:
        return False
    return True


def verify_mldsa_component(public_key: bytes, signature: bytes, message: bytes) -> bool:
    verifying_key = MLDSA87PublicKey.from_public_bytes(public_key[ED25519_PUBLIC_KEY_LEN:])
    try:
        verifying_key.verify(signature[ED25519_SIGNATURE_LEN:], message)
    except InvalidSignature:
        return False
    return True


def assert_algorithm_id(case: dict[str, object]) -> None:
    if expect_str(case, "algorithm_id_u16_le") != ALGORITHM_ID_U16_LE:
        raise SystemExit(f"{case['id']}: unexpected algorithm_id_u16_le")


def assert_expected_reason(case: dict[str, object], reason: str) -> None:
    expected = case.get("expected")
    if not isinstance(expected, dict):
        raise SystemExit(f"{case['id']}: missing expected block")
    if expected.get("result") != "Err" or expected.get("reason") != reason:
        raise SystemExit(f"{case['id']}: unexpected rejection expectation")


def assert_public_key_len(case_id: object, public_key: bytes) -> None:
    if len(public_key) != HYBRID_PUBLIC_KEY_LEN:
        raise SystemExit(f"{case_id}: hybrid public key must be {HYBRID_PUBLIC_KEY_LEN} bytes")


def assert_signature_len(case_id: object, signature: bytes) -> None:
    if len(signature) != HYBRID_SIGNATURE_LEN:
        raise SystemExit(f"{case_id}: hybrid signature must be {HYBRID_SIGNATURE_LEN} bytes")


def expect_str(case: dict[str, object], key: str) -> str:
    value = case.get(key)
    if not isinstance(value, str):
        raise SystemExit(f"{case.get('id', '<unknown>')}: missing string field {key}")
    return value


if __name__ == "__main__":
    main()
