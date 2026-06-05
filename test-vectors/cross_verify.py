#!/usr/bin/env python3
"""
Arcanum test vector cross-verification.

Independently computes expected cryptographic outputs using standard
Python libraries. The Rust implementation is correct when it reproduces
every value in this script.

Usage:
    python3 cross_verify.py           # run all verifications
    python3 cross_verify.py kdf       # run KDF vectors only
    python3 cross_verify.py hkdf      # run HKDF domain separation only
    python3 cross_verify.py aead      # run AEAD vectors only

Requirements:
    pip install argon2-cffi cryptography

This script produces JSON output compatible with the test-vectors/ format.
It does NOT read existing vector files — it computes from scratch for
maximum independence.
"""

import hashlib
import hmac
import json
import struct
import sys
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def hex_bytes(s: str) -> bytes:
    """Parse a hex string to bytes."""
    return bytes.fromhex(s)


def to_hex(b: bytes) -> str:
    """Format bytes as lowercase hex string."""
    return b.hex()


def u16le(n: int) -> bytes:
    return struct.pack("<H", n)


def u32le(n: int) -> bytes:
    return struct.pack("<I", n)


def u64le(n: int) -> bytes:
    return struct.pack("<Q", n)


# ─────────────────────────────────────────────────────────────────────────────
# KDF_ARGON2ID_V1
# ─────────────────────────────────────────────────────────────────────────────

def argon2id_v1_salt(vault_id: bytes) -> bytes:
    """
    Compute Argon2id salt for KDF_ARGON2ID_V1.
    salt = b"arcanum-argon2id-salt-v1" || vault_id
    """
    domain = b"arcanum-argon2id-salt-v1"
    assert len(domain) == 24, f"domain length must be 24, got {len(domain)}"
    assert len(vault_id) == 16, f"vault_id must be 16 bytes, got {len(vault_id)}"
    return domain + vault_id


def derive_master_unlock_key(
    password: str,
    vault_id: bytes,
    m_cost_kib: int = 65536,
    t_cost: int = 3,
    p_lanes: int = 4,
    output_len: int = 32,
) -> bytes:
    """
    Derive Master Unlock Key using KDF_ARGON2ID_V1.

    Profile parameters:
        m_cost_kib = 65536 (64 MiB)
        t_cost     = 3
        p_lanes    = 4
        output_len = 32 bytes
        argon2_version = 0x13
    """
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        raise ImportError(
            "argon2-cffi is required: pip install argon2-cffi"
        )

    salt = argon2id_v1_salt(vault_id)
    password_bytes = password.encode("utf-8")

    muk = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=t_cost,
        memory_cost=m_cost_kib,
        parallelism=p_lanes,
        hash_len=output_len,
        type=Type.ID,
        version=0x13,
    )
    return muk


# ─────────────────────────────────────────────────────────────────────────────
# HKDF-SHA256
# ─────────────────────────────────────────────────────────────────────────────

def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-SHA256 Extract."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256 Expand."""
    n = (length + 31) // 32
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return okm[:length]


def derive_vkek(master_unlock_key: bytes, vault_id: bytes) -> bytes:
    """
    Derive Vault Key Encryption Key from Master Unlock Key.

    vkek_salt = b"arcanum-vkek-salt-v1" || vault_id
    vkek_prk  = HKDF-SHA256-Extract(vkek_salt, master_unlock_key)
    vkek      = HKDF-SHA256-Expand(vkek_prk, b"arcanum:vault-kek:v1", 32)
    """
    domain = b"arcanum-vkek-salt-v1"
    assert len(domain) == 20
    assert len(vault_id) == 16

    vkek_salt = domain + vault_id
    vkek_prk = hkdf_extract_sha256(vkek_salt, master_unlock_key)
    vkek = hkdf_expand_sha256(vkek_prk, b"arcanum:vault-kek:v1", 32)
    return vkek


def vault_id_hex(vault_id: bytes) -> str:
    """Encode vault_id as lowercase hex (32 chars) for HKDF info strings."""
    assert len(vault_id) == 16
    return vault_id.hex()


def aead_id_decimal(aead_profile_id: int) -> str:
    """Encode aead_id as decimal string for HKDF info strings."""
    return str(aead_profile_id)


def hkdf_info_string(purpose: str, vault_id: bytes, aead_id: Optional[int] = None) -> bytes:
    """
    Construct canonical HKDF info string.

    Format: arcanum:{purpose}:v1:vault:{vault_id_hex}[:aead:{aead_id_decimal}]

    vault_id is lowercase hex (32 chars).
    aead_id is decimal string (e.g. "1" for XChaCha20-Poly1305).
    """
    vid_hex = vault_id_hex(vault_id)
    if aead_id is not None:
        info = f"arcanum:{purpose}:v1:vault:{vid_hex}:aead:{aead_id_decimal(aead_id)}"
    else:
        info = f"arcanum:{purpose}:v1:vault:{vid_hex}"
    return info.encode("ascii")


def derive_root_prk(vault_root_key: bytes, vault_id: bytes, header_nonce: bytes) -> bytes:
    """
    Derive root PRK from Vault Root Key.

    root_salt = SHA256(b"arcanum-root-salt-v1" || vault_id || header_nonce)
    root_prk  = HKDF-SHA256-Extract(root_salt, vault_root_key)
    """
    domain = b"arcanum-root-salt-v1"
    assert len(domain) == 20
    assert len(vault_id) == 16
    assert len(header_nonce) == 24

    salt_input = domain + vault_id + header_nonce
    root_salt = hashlib.sha256(salt_input).digest()
    return hkdf_extract_sha256(root_salt, vault_root_key)


# AEAD_XCHACHA20_POLY1305_V1 = 0x0001
AEAD_XCHACHA20_POLY1305_V1 = 1

SUBKEY_PURPOSES = {
    "item_key_wrapping_key":  ("item-wrap",      True),   # needs aead_id
    "metadata_encryption_key": ("metadata",       True),
    "local_audit_event_key":  ("audit",           False),  # no aead_id
    "sync_envelope_key":      ("sync-envelope",   False),
    "device_enrollment_key":  ("device-enroll",   False),
    "recovery_wrapping_key":  ("recovery-wrap",   False),
    "export_bundle_key":      ("export-bundle",   False),
}


def derive_subkey(
    root_prk: bytes,
    name: str,
    vault_id: bytes,
    aead_id: Optional[int] = None,
) -> bytes:
    """Derive a named subkey from root PRK using HKDF domain separation."""
    purpose, needs_aead = SUBKEY_PURPOSES[name]
    if needs_aead and aead_id is None:
        aead_id = AEAD_XCHACHA20_POLY1305_V1
    info = hkdf_info_string(purpose, vault_id, aead_id if needs_aead else None)
    return hkdf_expand_sha256(root_prk, info, 32)


# ─────────────────────────────────────────────────────────────────────────────
# AEAD_XCHACHA20_POLY1305_V1
# ─────────────────────────────────────────────────────────────────────────────

def xchacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> bytes:
    """Encrypt using XChaCha20-Poly1305."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError:
        raise ImportError("cryptography is required: pip install cryptography")

    assert len(key) == 32, f"key must be 32 bytes, got {len(key)}"
    assert len(nonce) == 24, f"nonce must be 24 bytes (XChaCha20), got {len(nonce)}"

    # Note: Python cryptography library uses ChaCha20Poly1305 with 12-byte nonce.
    # XChaCha20-Poly1305 with 24-byte nonce requires the xchacha20poly1305 variant.
    # Using PyNaCl or the xchacha20 extension for true XChaCha20 support.
    try:
        from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
        cipher = XChaCha20Poly1305(key)
        return cipher.encrypt(nonce, plaintext, aad)
    except ImportError:
        # Fallback: use PyNaCl
        try:
            import nacl.secret
            import nacl.bindings
            # XChaCha20-Poly1305 via libsodium bindings
            # TODO: implement via PyNaCl when available
            raise NotImplementedError(
                "XChaCha20-Poly1305 requires cryptography >= 41.0 or PyNaCl. "
                "Install: pip install 'cryptography>=41.0'"
            )
        except ImportError:
            raise ImportError(
                "XChaCha20-Poly1305 requires 'cryptography >= 41.0': "
                "pip install 'cryptography>=41.0'"
            )


def xchacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
) -> bytes:
    """Decrypt using XChaCha20-Poly1305. Raises on authentication failure."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import XChaCha20Poly1305
    except ImportError:
        raise ImportError("cryptography >= 41.0 required: pip install 'cryptography>=41.0'")

    assert len(key) == 32
    assert len(nonce) == 24

    cipher = XChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, aad)


# ─────────────────────────────────────────────────────────────────────────────
# AAD construction (vault_format_v1.md §7)
# ─────────────────────────────────────────────────────────────────────────────

def build_aad_v1(
    vault_id: bytes,
    format_version: int,
    schema_profile: int,
    aead_profile: int,
    kdf_profile: int,
    pqc_profile: int,
    record_id: bytes,
    revision_id: bytes,
    record_kind: int,
) -> bytes:
    """
    Canonical AAD construction for vault_format_v1.

    AAD = b"arcanum-aad-v1"   (14 bytes)
       || vault_id             (16 bytes)
       || format_version:u16le ( 2 bytes)
       || schema_profile:u16le ( 2 bytes)
       || aead_profile:u16le   ( 2 bytes)
       || kdf_profile:u16le    ( 2 bytes)
       || pqc_profile:u16le    ( 2 bytes)
       || record_id            (16 bytes)
       || revision_id          (16 bytes)
       || record_kind:u16le    ( 2 bytes)
                               = 74 bytes total
    """
    domain = b"arcanum-aad-v1"
    assert len(domain) == 14
    assert len(vault_id) == 16
    assert len(record_id) == 16
    assert len(revision_id) == 16

    aad = (
        domain
        + vault_id
        + u16le(format_version)
        + u16le(schema_profile)
        + u16le(aead_profile)
        + u16le(kdf_profile)
        + u16le(pqc_profile)
        + record_id
        + revision_id
        + u16le(record_kind)
    )
    assert len(aad) == 74, f"AAD v1 must be 74 bytes, got {len(aad)}"
    return aad


# ─────────────────────────────────────────────────────────────────────────────
# Test vector generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_kdf_vectors() -> dict:
    """
    Generate vault_kdf_v1.json test vectors.
    These vectors are used to validate KDF_ARGON2ID_V1 implementation.
    """
    # Fixed test inputs — never use real secrets here
    vault_id = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    password = "test-password-never-real"

    # Derive MUK
    muk = derive_master_unlock_key(password, vault_id)

    # Derive VKEK
    vkek = derive_vkek(muk, vault_id)

    # Derive root PRK (requires vault_root_key and header_nonce)
    vault_root_key = bytes.fromhex(
        "a0b1c2d3e4f5060718293a4b5c6d7e8f"
        "9001112131415161718191a1b1c1d1e1f"
    )[:32]
    header_nonce = bytes.fromhex(
        "010203040506070809101112131415161718192021222324"
    )
    root_prk = derive_root_prk(vault_root_key, vault_id, header_nonce)

    # Derive all subkeys
    subkeys = {}
    for name in SUBKEY_PURPOSES:
        subkeys[name] = to_hex(derive_subkey(root_prk, name, vault_id))

    return {
        "profile": "KDF_ARGON2ID_V1",
        "version": 1,
        "description": "Argon2id KDF and HKDF derivation chain test vectors",
        "generated_by": "cross_verify.py",
        "cases": [
            {
                "id": "muk-derivation",
                "description": "Master Unlock Key from password and vault_id",
                "inputs": {
                    "password": password,
                    "vault_id": to_hex(vault_id),
                    "m_cost_kib": 65536,
                    "t_cost": 3,
                    "p_lanes": 4,
                    "output_len": 32,
                    "argon2_version": "0x13",
                },
                "expected": {
                    "argon2_salt": to_hex(argon2id_v1_salt(vault_id)),
                    "master_unlock_key": to_hex(muk),
                },
            },
            {
                "id": "vkek-derivation",
                "description": "Vault Key Encryption Key from MUK",
                "inputs": {
                    "master_unlock_key": to_hex(muk),
                    "vault_id": to_hex(vault_id),
                },
                "expected": {
                    "vault_key_encryption_key": to_hex(vkek),
                },
            },
            {
                "id": "root-prk-derivation",
                "description": "Root PRK from Vault Root Key",
                "inputs": {
                    "vault_root_key": to_hex(vault_root_key),
                    "vault_id": to_hex(vault_id),
                    "header_nonce": to_hex(header_nonce),
                },
                "expected": {
                    "root_prk": to_hex(root_prk),
                },
            },
            {
                "id": "subkey-derivation",
                "description": "All domain-separated subkeys from root PRK",
                "inputs": {
                    "root_prk": to_hex(root_prk),
                    "vault_id": to_hex(vault_id),
                    "aead_id": AEAD_XCHACHA20_POLY1305_V1,
                },
                "expected": subkeys,
            },
        ],
    }


def generate_aad_vectors() -> dict:
    """Generate AAD v1 construction test vectors."""
    vault_id   = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    record_id  = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    revision_id = bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")

    aad = build_aad_v1(
        vault_id=vault_id,
        format_version=1,
        schema_profile=1,
        aead_profile=AEAD_XCHACHA20_POLY1305_V1,
        kdf_profile=1,
        pqc_profile=0,
        record_id=record_id,
        revision_id=revision_id,
        record_kind=1,  # Item
    )

    return {
        "profile": "SCHEMA_ARCANUM_RECORDS_V1_AAD",
        "version": 1,
        "description": "Canonical AAD v1 construction (74 bytes, all fixed-width)",
        "generated_by": "cross_verify.py",
        "cases": [
            {
                "id": "aad-basic-item",
                "description": "AAD for an Item record, no PQC",
                "inputs": {
                    "vault_id": to_hex(vault_id),
                    "format_version": 1,
                    "schema_profile": 1,
                    "aead_profile": AEAD_XCHACHA20_POLY1305_V1,
                    "kdf_profile": 1,
                    "pqc_profile": 0,
                    "record_id": to_hex(record_id),
                    "revision_id": to_hex(revision_id),
                    "record_kind": 1,
                },
                "expected": {
                    "aad_hex": to_hex(aad),
                    "aad_length": len(aad),
                },
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

GENERATORS = {
    "kdf":  ("vault_kdf_v1.json",    generate_kdf_vectors),
    "aad":  ("vault_format_v1.json", generate_aad_vectors),
    # "aead": ("aead_xchacha20_v1.json", generate_aead_vectors),   # TODO MVP-0
    # "transfer": ("transfer_hybrid_v1.json", generate_transfer_vectors),  # TODO MVP-2
    # "recovery": ("recovery_kit_v1.json", generate_recovery_vectors),     # TODO MVP-1
}


def run(target: Optional[str] = None) -> None:
    import os
    vectors_dir = os.path.dirname(os.path.abspath(__file__))

    targets = {target: GENERATORS[target]} if target else GENERATORS

    for name, (filename, generator) in targets.items():
        print(f"Generating {filename} ...")
        try:
            vectors = generator()
            path = os.path.join(vectors_dir, filename)
            with open(path, "w") as f:
                json.dump(vectors, f, indent=2)
                f.write("\n")
            case_count = len(vectors.get("cases", []))
            print(f"  ✓ {filename} — {case_count} case(s)")
        except NotImplementedError as e:
            print(f"  ! {filename} — skipped: {e}")
        except ImportError as e:
            print(f"  ! {filename} — missing dependency: {e}")
        except Exception as e:
            print(f"  ✗ {filename} — error: {e}")
            raise


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if target and target not in GENERATORS:
        print(f"Unknown target: {target}")
        print(f"Available: {', '.join(GENERATORS.keys())}")
        sys.exit(1)
    run(target)
