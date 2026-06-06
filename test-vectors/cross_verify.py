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
        "901112131415161718191a1b1c1d1e1f"
    )
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
            {
                "id": "aad-pqc-mlkem768-wrappedrootkey",
                "description": "D5: AAD edge with pqc_profile=PQC_MLKEM_768_V1 (0x0001) and record_kind=WrappedRootKey (0x0002) (§7)",
                "inputs": {
                    "vault_id": to_hex(vault_id),
                    "format_version": 1,
                    "schema_profile": 1,
                    "aead_profile": AEAD_XCHACHA20_POLY1305_V1,
                    "kdf_profile": 1,
                    "pqc_profile": 0x0001,
                    "record_id": to_hex(record_id),
                    "revision_id": to_hex(revision_id),
                    "record_kind": 0x0002,
                },
                "expected": {
                    "aad_hex": to_hex(build_aad_v1(
                        vault_id=vault_id, format_version=1, schema_profile=1,
                        aead_profile=AEAD_XCHACHA20_POLY1305_V1, kdf_profile=1,
                        pqc_profile=0x0001, record_id=record_id,
                        revision_id=revision_id, record_kind=0x0002)),
                    "aad_length": 74,
                },
            },
            {
                "id": "aad-auditevent-kind",
                "description": "D5: AAD edge with varying record_kind=AuditEvent (0x0005), no PQC (§7)",
                "inputs": {
                    "vault_id": to_hex(vault_id),
                    "format_version": 1,
                    "schema_profile": 1,
                    "aead_profile": AEAD_XCHACHA20_POLY1305_V1,
                    "kdf_profile": 1,
                    "pqc_profile": 0,
                    "record_id": to_hex(record_id),
                    "revision_id": to_hex(revision_id),
                    "record_kind": 0x0005,
                },
                "expected": {
                    "aad_hex": to_hex(build_aad_v1(
                        vault_id=vault_id, format_version=1, schema_profile=1,
                        aead_profile=AEAD_XCHACHA20_POLY1305_V1, kdf_profile=1,
                        pqc_profile=0, record_id=record_id,
                        revision_id=revision_id, record_kind=0x0005)),
                    "aad_length": 74,
                },
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# AEAD_XCHACHA20_POLY1305_V1
# ─────────────────────────────────────────────────────────────────────────────

def generate_aead_vectors() -> dict:
    """Generate aead_xchacha20_v1.json test vectors."""
    import nacl.bindings

    key   = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    nonce = bytes.fromhex("010203040506070809101112131415161718192021222324")
    aad   = bytes.fromhex(
        "617263616e756d2d6161642d7631"          # b"arcanum-aad-v1"  (14 bytes)
        "0102030405060708090a0b0c0d0e0f10"      # vault_id          (16 bytes)
        "01000100010001000100"                   # 5 × u16le(1)      (10 bytes)
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"      # record_id         (16 bytes)
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"      # revision_id       (16 bytes)
        "0100"                                   # record_kind u16le  (2 bytes)
    )
    assert len(aad) == 74, f"AAD must be 74 bytes, got {len(aad)}"
    plaintext = b"secret-payload-for-arcanum-test"

    # libsodium XChaCha20-Poly1305 IETF: returns ciphertext || 16-byte tag
    ciphertext_with_tag = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, aad, nonce, key
    )
    ciphertext = ciphertext_with_tag[:-16]
    tag        = ciphertext_with_tag[-16:]

    # Wrong AAD must fail decryption
    wrong_aad = bytes(aad[:-1]) + bytes([aad[-1] ^ 0xff])
    try:
        nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext_with_tag, wrong_aad, nonce, key
        )
        raise AssertionError("wrong AAD must not decrypt successfully")
    except nacl.exceptions.CryptoError:
        pass  # expected

    import nacl.exceptions

    # C1 — tampered ciphertext byte -> decrypt fails
    tampered_ct = bytearray(ciphertext_with_tag)
    tampered_ct[0] ^= 0xff  # flip a ciphertext byte (offset 0 is in the ciphertext region)
    tampered_ct = bytes(tampered_ct)
    try:
        nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(tampered_ct, aad, nonce, key)
        raise AssertionError("tampered ciphertext must not decrypt")
    except nacl.exceptions.CryptoError:
        pass

    # C2 — tampered tag byte -> decrypt fails (last 16 bytes are the tag)
    tampered_tag = bytearray(ciphertext_with_tag)
    tampered_tag[-1] ^= 0xff
    tampered_tag = bytes(tampered_tag)
    try:
        nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(tampered_tag, aad, nonce, key)
        raise AssertionError("tampered tag must not decrypt")
    except nacl.exceptions.CryptoError:
        pass

    # C3 — wrong key -> decrypt fails
    wrong_key = bytes([key[0] ^ 0xff]) + key[1:]
    try:
        nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext_with_tag, aad, nonce, wrong_key)
        raise AssertionError("wrong key must not decrypt")
    except nacl.exceptions.CryptoError:
        pass

    # C4 — empty-plaintext encrypt edge: ciphertext is empty, tag still authenticates AAD
    empty_ct_tag = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(b"", aad, nonce, key)
    empty_pt = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(empty_ct_tag, aad, nonce, key)
    assert empty_pt == b""
    assert len(empty_ct_tag) == 16  # tag only

    return {
        "profile": "AEAD_XCHACHA20_POLY1305_V1",
        "version": 1,
        "description": "XChaCha20-Poly1305 IETF encrypt/decrypt with canonical AAD (libsodium)",
        "generated_by": "cross_verify.py (pynacl/libsodium)",
        "cases": [
            {
                "id": "xchacha20-basic-encrypt",
                "description": "Encrypt with canonical 74-byte AAD, verify ciphertext and tag",
                "inputs": {
                    "key":       to_hex(key),
                    "nonce":     to_hex(nonce),
                    "plaintext": to_hex(plaintext),
                    "aad":       to_hex(aad),
                },
                "expected": {
                    "ciphertext": to_hex(ciphertext),
                    "tag":        to_hex(tag),
                },
            },
            {
                "id": "xchacha20-decrypt-round-trip",
                "description": "Decrypt ciphertext||tag back to plaintext",
                "inputs": {
                    "key":            to_hex(key),
                    "nonce":          to_hex(nonce),
                    "ciphertext_tag": to_hex(ciphertext_with_tag),
                    "aad":            to_hex(aad),
                },
                "expected": {
                    "plaintext": to_hex(plaintext),
                },
            },
            {
                "id": "xchacha20-wrong-aad-rejected",
                "description": "Authentication fails when AAD is modified (last byte flipped)",
                "inputs": {
                    "key":            to_hex(key),
                    "nonce":          to_hex(nonce),
                    "ciphertext_tag": to_hex(ciphertext_with_tag),
                    "aad":            to_hex(wrong_aad),
                },
                "expected": {
                    "result": "Err",
                },
            },
            {
                "id": "c1-tampered-ciphertext-rejected",
                "description": "vault_format_v1.md §10: flipped ciphertext byte -> AEAD auth fails, no plaintext",
                "inputs": {
                    "key": to_hex(key),
                    "nonce": to_hex(nonce),
                    "ciphertext_tag": to_hex(tampered_ct),
                    "aad": to_hex(aad),
                },
                "expected": {"result": "Err"},
            },
            {
                "id": "c2-tampered-tag-rejected",
                "description": "vault_format_v1.md §10: flipped tag byte -> AEAD auth fails, no plaintext",
                "inputs": {
                    "key": to_hex(key),
                    "nonce": to_hex(nonce),
                    "ciphertext_tag": to_hex(tampered_tag),
                    "aad": to_hex(aad),
                },
                "expected": {"result": "Err"},
            },
            {
                "id": "c3-wrong-key-rejected",
                "description": "vault_format_v1.md §10: decrypt with a different key -> AEAD auth fails",
                "inputs": {
                    "key": to_hex(wrong_key),
                    "nonce": to_hex(nonce),
                    "ciphertext_tag": to_hex(ciphertext_with_tag),
                    "aad": to_hex(aad),
                },
                "expected": {"result": "Err"},
            },
            {
                "id": "c4-empty-plaintext-encrypt",
                "description": "Empty-plaintext encrypt edge: empty ciphertext, 16-byte tag authenticates AAD (crypto_design.md §6)",
                "inputs": {
                    "key": to_hex(key),
                    "nonce": to_hex(nonce),
                    "plaintext": "",
                    "aad": to_hex(aad),
                },
                "expected": {
                    "ciphertext_tag": to_hex(empty_ct_tag),
                    "tag": to_hex(empty_ct_tag),
                    "result": "Ok",
                },
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Shared fixtures (reused across generators for cross-consistency)
# ─────────────────────────────────────────────────────────────────────────────

FIX_VAULT_ID    = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
FIX_RECORD_ID   = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
FIX_REVISION_ID = bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
FIX_HEADER_NONCE = bytes.fromhex("010203040506070809101112131415161718192021222324")
FIX_AEAD_KEY    = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
FIX_AEAD_NONCE  = bytes.fromhex("010203040506070809101112131415161718192021222324")
# Deterministic test material — NOT a real secret.
FIX_VAULT_ROOT_KEY = bytes.fromhex(
    "a0b1c2d3e4f5060718293a4b5c6d7e8f901112131415161718191a1b1c1d1e1f"
)

# Record kinds (vault_format_v1.md §5)
KIND_ITEM            = 0x0001
KIND_WRAPPED_ROOTKEY = 0x0002
KIND_AUDITEVENT      = 0x0005

# Profiles (vault_format_v1.md §3 enum assignments)
KDF_ARGON2ID_V1           = 0x0001
SCHEMA_ARCANUM_RECORDS_V1 = 0x0001
PQC_NONE                  = 0x0000
PQC_MLKEM_768_V1          = 0x0001


def xchacha_encrypt(key, nonce, pt, aad):
    import nacl.bindings
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, nonce, key)


def xchacha_decrypt(key, nonce, ct, aad):
    import nacl.bindings
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce, key)


# ─────────────────────────────────────────────────────────────────────────────
# B1 / B3 — Vault Root Key wrap/unwrap  (crypto_design.md §Step 4)
# ─────────────────────────────────────────────────────────────────────────────

def generate_wrap_vectors() -> dict:
    """
    WrappedRootKey: wrap the Vault Root Key with the VKEK and canonical AAD.

    crypto_design.md Step 4:
      vkek_nonce = 192-bit random
      wrap_aad   = canonical AAD (§7) with record_kind = WrappedRootKey (0x0002)
      ciphertext = XChaCha20-Poly1305(key=VKEK, nonce=vkek_nonce, aad=wrap_aad, pt=VRK)
    VKEK derived via derive_vkek (MUK -> VKEK).
    """
    password = "test-password-never-real"
    muk  = derive_master_unlock_key(password, FIX_VAULT_ID)
    vkek = derive_vkek(muk, FIX_VAULT_ID)

    vkek_nonce = FIX_AEAD_NONCE  # deterministic test nonce (test fixture only)
    wrap_aad = build_aad_v1(
        vault_id=FIX_VAULT_ID,
        format_version=1,
        schema_profile=SCHEMA_ARCANUM_RECORDS_V1,
        aead_profile=AEAD_XCHACHA20_POLY1305_V1,
        kdf_profile=KDF_ARGON2ID_V1,
        pqc_profile=PQC_NONE,
        record_id=FIX_RECORD_ID,
        revision_id=FIX_REVISION_ID,
        record_kind=KIND_WRAPPED_ROOTKEY,
    )
    wrapped = xchacha_encrypt(vkek, vkek_nonce, FIX_VAULT_ROOT_KEY, wrap_aad)
    unwrapped = xchacha_decrypt(vkek, vkek_nonce, wrapped, wrap_aad)
    assert unwrapped == FIX_VAULT_ROOT_KEY

    cases = [
        {
            "id": "wrap-vrk-roundtrip",
            "description": "crypto_design.md Step 4: wrap VRK with VKEK + WrappedRootKey AAD, then unwrap",
            "inputs": {
                "vault_kek": to_hex(vkek),
                "vkek_nonce": to_hex(vkek_nonce),
                "wrap_aad": to_hex(wrap_aad),
                "vault_root_key": to_hex(FIX_VAULT_ROOT_KEY),
            },
            "expected": {
                "wrapped_root_key": to_hex(wrapped),
                "unwrapped_root_key": to_hex(FIX_VAULT_ROOT_KEY),
                "result": "Ok",
            },
        },
    ]

    # B3 — cross-vault domain separation: second vault_id must yield a distinct
    # VKEK and distinct wrapped output, even with the same VRK and nonce.
    vault_id2 = bytes.fromhex("1112131415161718191a1b1c1d1e1f20")
    muk2  = derive_master_unlock_key(password, vault_id2)
    vkek2 = derive_vkek(muk2, vault_id2)
    wrap_aad2 = build_aad_v1(
        vault_id=vault_id2,
        format_version=1,
        schema_profile=SCHEMA_ARCANUM_RECORDS_V1,
        aead_profile=AEAD_XCHACHA20_POLY1305_V1,
        kdf_profile=KDF_ARGON2ID_V1,
        pqc_profile=PQC_NONE,
        record_id=FIX_RECORD_ID,
        revision_id=FIX_REVISION_ID,
        record_kind=KIND_WRAPPED_ROOTKEY,
    )
    wrapped2 = xchacha_encrypt(vkek2, vkek_nonce, FIX_VAULT_ROOT_KEY, wrap_aad2)
    assert vkek2 != vkek
    assert wrapped2 != wrapped
    cases.append({
        "id": "wrap-vrk-cross-vault-domain-separation",
        "description": "B3: distinct vault_id -> distinct VKEK and distinct WrappedRootKey (crypto_design.md §VKEK derivation, §Step 4)",
        "inputs": {
            "vault_id": to_hex(vault_id2),
            "vault_kek": to_hex(vkek2),
            "vkek_nonce": to_hex(vkek_nonce),
            "wrap_aad": to_hex(wrap_aad2),
            "vault_root_key": to_hex(FIX_VAULT_ROOT_KEY),
        },
        "expected": {
            "wrapped_root_key": to_hex(wrapped2),
            "differs_from_vault1": True,
            "result": "Ok",
        },
    })

    # B4 — wrong-password MUK distinctness: different password -> different MUK/VKEK.
    muk_wrong  = derive_master_unlock_key("different-password-never-real", FIX_VAULT_ID)
    vkek_wrong = derive_vkek(muk_wrong, FIX_VAULT_ID)
    assert muk_wrong != muk
    assert vkek_wrong != vkek
    cases.append({
        "id": "wrong-password-muk-distinct",
        "description": "B4: a different password yields a distinct MUK and VKEK (crypto_design.md §KDF/§VKEK)",
        "inputs": {
            "password": "different-password-never-real",
            "vault_id": to_hex(FIX_VAULT_ID),
        },
        "expected": {
            "master_unlock_key": to_hex(muk_wrong),
            "vault_key_encryption_key": to_hex(vkek_wrong),
            "differs_from_correct_password": True,
        },
    })

    return {
        "profile": "AEAD_XCHACHA20_POLY1305_V1",
        "version": 1,
        "description": "Vault Root Key wrap/unwrap (WrappedRootKey) and key-derivation domain separation",
        "generated_by": "cross_verify.py (pynacl/libsodium, argon2-cffi)",
        "cases": cases,
    }


# ─────────────────────────────────────────────────────────────────────────────
# B2 — KDF parameter TLV  (vault_format_v1.md §4)
# ─────────────────────────────────────────────────────────────────────────────

def kdf_param_tlv(tag: int, value: bytes) -> bytes:
    """KdfParamTlv := tag:u16le || len:u16le || value (§4)."""
    return u16le(tag) + u16le(len(value)) + value


def generate_kdf_tlv_vectors() -> dict:
    """
    KDF parameter block per vault_format_v1.md §4:
      kdf_profile_value := profile_id:u16le || params_len:u32le || kdf_param_tlv[params_len]
    Tags 0x0101–0x0105 for KDF_ARGON2ID_V1.
    """
    params = [
        (0x0101, "m_cost_kib",     u32le(65536)),
        (0x0102, "t_cost",         u32le(3)),
        (0x0103, "p_lanes",        u32le(4)),
        (0x0104, "output_len",     u16le(32)),
        (0x0105, "argon2_version", u32le(0x13)),
    ]
    param_tlvs = b"".join(kdf_param_tlv(tag, val) for tag, _, val in params)
    block = u16le(KDF_ARGON2ID_V1) + u32le(len(param_tlvs)) + param_tlvs

    parsed = []
    for tag, name, val in params:
        parsed.append({
            "tag": f"0x{tag:04x}",
            "name": name,
            "len": len(val),
            "value_hex": to_hex(val),
        })

    return {
        "profile": "KDF_ARGON2ID_V1",
        "version": 1,
        "description": "KDF parameter TLV block encoding (vault_format_v1.md §4)",
        "generated_by": "cross_verify.py",
        "cases": [
            {
                "id": "kdf-param-tlv-argon2id-v1",
                "description": "profile_id:u16le || params_len:u32le || param TLVs 0x0101-0x0105 (§4)",
                "inputs": {
                    "profile_id": KDF_ARGON2ID_V1,
                    "m_cost_kib": 65536,
                    "t_cost": 3,
                    "p_lanes": 4,
                    "output_len": 32,
                    "argon2_version": "0x13",
                },
                "expected": {
                    "kdf_profile_value_hex": to_hex(block),
                    "params_len": len(param_tlvs),
                    "param_tlvs_hex": to_hex(param_tlvs),
                    "parsed_tlvs": parsed,
                },
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# D1–D4 — Vault binary format structures  (vault_format_v1.md §2,§3,§5,§6)
# ─────────────────────────────────────────────────────────────────────────────

MAGIC = bytes([0x41, 0x52, 0x43, 0x41, 0x4e, 0x55, 0x4d, 0x01])  # "ARCANUM\x01"


def header_tlv(tag: int, value: bytes, critical: bool) -> bytes:
    """HeaderTlv := tag:u16le || flags:u8 || len:u32le || value (§3). flags bit0=critical."""
    flags = 0x01 if critical else 0x00
    return u16le(tag) + bytes([flags]) + u32le(len(value)) + value


def generate_format_struct_vectors() -> dict:
    created_at_ms = 1_700_000_000_000

    # ── D2: header TLV (all 7 required tags, §3) ──
    kdf_param_tlvs = (
        kdf_param_tlv(0x0101, u32le(65536))
        + kdf_param_tlv(0x0102, u32le(3))
        + kdf_param_tlv(0x0103, u32le(4))
        + kdf_param_tlv(0x0104, u16le(32))
        + kdf_param_tlv(0x0105, u32le(0x13))
    )
    kdf_value = u16le(KDF_ARGON2ID_V1) + u32le(len(kdf_param_tlvs)) + kdf_param_tlvs

    header_tags = [
        ("vault_id",       0x0001, FIX_VAULT_ID,                          True),
        ("created_at",     0x0002, u64le(created_at_ms),                  True),
        ("kdf_profile",    0x0003, kdf_value,                            True),
        ("aead_profile",   0x0004, u16le(AEAD_XCHACHA20_POLY1305_V1),    True),
        ("pqc_profile",    0x0005, u16le(PQC_NONE),                      False),
        ("schema_profile", 0x0006, u16le(SCHEMA_ARCANUM_RECORDS_V1),     True),
        ("header_nonce",   0x0007, FIX_HEADER_NONCE,                      True),
    ]
    header = b"".join(header_tlv(tag, val, crit) for _, tag, val, crit in header_tags)

    header_parsed = [
        {"tag": f"0x{tag:04x}", "name": name, "critical": crit,
         "len": len(val), "value_hex": to_hex(val)}
        for name, tag, val, crit in header_tags
    ]

    # ── D3: record table (§5) ──
    frame_offset = 26 + len(header)  # prefix + header (illustrative offset)
    record_table_records = [
        (FIX_RECORD_ID,   KIND_WRAPPED_ROOTKEY, FIX_REVISION_ID,   frame_offset, 0),
        (bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"),
         KIND_ITEM,
         bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"),
         frame_offset + 200, 0),
    ]
    record_table = u32le(len(record_table_records))
    rt_parsed = []
    for rid, kind, rev, off, flen in record_table_records:
        entry = rid + u16le(kind) + rev + u64le(off) + u32le(flen)
        record_table += entry
        rt_parsed.append({
            "record_id": to_hex(rid),
            "record_kind": f"0x{kind:04x}",
            "revision_id": to_hex(rev),
            "frame_offset": off,
            "frame_len": flen,
        })

    # ── D4: record frame (§6) — encrypt an Item record ──
    record_aad = build_aad_v1(
        vault_id=FIX_VAULT_ID,
        format_version=1,
        schema_profile=SCHEMA_ARCANUM_RECORDS_V1,
        aead_profile=AEAD_XCHACHA20_POLY1305_V1,
        kdf_profile=KDF_ARGON2ID_V1,
        pqc_profile=PQC_NONE,
        record_id=FIX_RECORD_ID,
        revision_id=FIX_REVISION_ID,
        record_kind=KIND_ITEM,
    )
    plaintext = b"secret-payload-for-arcanum-test"
    ct_tag = xchacha_encrypt(FIX_AEAD_KEY, FIX_AEAD_NONCE, plaintext, record_aad)
    nonce_len = len(FIX_AEAD_NONCE)
    frame = (
        u16le(1)                  # frame_version
        + FIX_RECORD_ID
        + FIX_REVISION_ID
        + u16le(AEAD_XCHACHA20_POLY1305_V1)
        + bytes([nonce_len])
        + FIX_AEAD_NONCE
        + u32le(len(record_aad))
        + record_aad
        + u32le(len(ct_tag))
        + ct_tag
    )

    # ── D1: 26-byte file prefix (§2) ──
    prefix = (
        MAGIC
        + u16le(1)                 # format_version
        + u32le(len(header))       # header_len
        + u32le(len(record_table)) # record_table_len
        + u64le(len(frame))        # body_len
    )
    assert len(prefix) == 26, f"prefix must be 26 bytes, got {len(prefix)}"

    return {
        "profile": "SCHEMA_ARCANUM_RECORDS_V1",
        "version": 1,
        "description": "Vault binary format structures: file prefix, header TLV, record table, record frame",
        "generated_by": "cross_verify.py (pynacl/libsodium)",
        "cases": [
            {
                "id": "d1-file-prefix",
                "description": "26-byte file prefix: magic || format_version || header_len || record_table_len || body_len (§2)",
                "inputs": {
                    "format_version": 1,
                    "header_len": len(header),
                    "record_table_len": len(record_table),
                    "body_len": len(frame),
                },
                "expected": {
                    "prefix_hex": to_hex(prefix),
                    "prefix_length": len(prefix),
                    "magic_hex": to_hex(MAGIC),
                },
            },
            {
                "id": "d2-header-tlv",
                "description": "Header TLV with all 7 required MVP-0 tags (§3)",
                "inputs": {
                    "vault_id": to_hex(FIX_VAULT_ID),
                    "created_at_ms": created_at_ms,
                    "kdf_profile": KDF_ARGON2ID_V1,
                    "aead_profile": AEAD_XCHACHA20_POLY1305_V1,
                    "pqc_profile": PQC_NONE,
                    "schema_profile": SCHEMA_ARCANUM_RECORDS_V1,
                    "header_nonce": to_hex(FIX_HEADER_NONCE),
                },
                "expected": {
                    "header_hex": to_hex(header),
                    "header_len": len(header),
                    "tlvs": header_parsed,
                },
            },
            {
                "id": "d3-record-table",
                "description": "Record table: record_count + entries (record_id, record_kind, revision_id, frame_offset, frame_len) (§5)",
                "inputs": {"record_count": len(record_table_records)},
                "expected": {
                    "record_table_hex": to_hex(record_table),
                    "record_table_len": len(record_table),
                    "records": rt_parsed,
                },
            },
            {
                "id": "d4-record-frame",
                "description": "Encrypted record frame for an Item record (§6)",
                "inputs": {
                    "frame_version": 1,
                    "record_id": to_hex(FIX_RECORD_ID),
                    "revision_id": to_hex(FIX_REVISION_ID),
                    "aead_profile": AEAD_XCHACHA20_POLY1305_V1,
                    "nonce": to_hex(FIX_AEAD_NONCE),
                    "aad": to_hex(record_aad),
                    "key": to_hex(FIX_AEAD_KEY),
                    "plaintext": to_hex(plaintext),
                },
                "expected": {
                    "frame_hex": to_hex(frame),
                    "frame_len": len(frame),
                    "nonce_len": nonce_len,
                    "ciphertext_with_tag_hex": to_hex(ct_tag),
                },
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# D6 — Vault format negative fixtures  (vault_format_v1.md §10 reject rules)
# ─────────────────────────────────────────────────────────────────────────────

def _build_valid_vault(extra_header: bytes = b"") -> tuple:
    """
    Build one structurally valid vault blob from the shared TV-1 fixtures:

        blob = prefix(26) || header || record_table || body(frame)

    The blob contains a single Item record frame whose ciphertext is a real
    XChaCha20-Poly1305 output over the canonical AAD, so the AEAD-failure case
    can tamper a byte of an otherwise-valid frame. `extra_header` lets a caller
    append one additional Header TLV (used by the unknown-critical-tag case)
    while keeping every declared length field internally consistent.

    Returns (blob, meta) where meta carries the byte offsets needed to mutate
    exactly one field per negative case.
    """
    created_at_ms = 1_700_000_000_000

    kdf_param_tlvs = (
        kdf_param_tlv(0x0101, u32le(65536))
        + kdf_param_tlv(0x0102, u32le(3))
        + kdf_param_tlv(0x0103, u32le(4))
        + kdf_param_tlv(0x0104, u16le(32))
        + kdf_param_tlv(0x0105, u32le(0x13))
    )
    kdf_value = u16le(KDF_ARGON2ID_V1) + u32le(len(kdf_param_tlvs)) + kdf_param_tlvs

    header_tags = [
        (0x0001, FIX_VAULT_ID, True),                       # vault_id
        (0x0002, u64le(created_at_ms), True),               # created_at
        (0x0003, kdf_value, True),                          # kdf_profile
        (0x0004, u16le(AEAD_XCHACHA20_POLY1305_V1), True),  # aead_profile
        (0x0005, u16le(PQC_NONE), False),                   # pqc_profile
        (0x0006, u16le(SCHEMA_ARCANUM_RECORDS_V1), True),   # schema_profile
        (0x0007, FIX_HEADER_NONCE, True),                   # header_nonce
    ]
    header = b"".join(header_tlv(tag, val, crit) for tag, val, crit in header_tags) + extra_header

    # One Item record frame (§6), AEAD over canonical AAD (§7).
    record_aad = build_aad_v1(
        vault_id=FIX_VAULT_ID,
        format_version=1,
        schema_profile=SCHEMA_ARCANUM_RECORDS_V1,
        aead_profile=AEAD_XCHACHA20_POLY1305_V1,
        kdf_profile=KDF_ARGON2ID_V1,
        pqc_profile=PQC_NONE,
        record_id=FIX_RECORD_ID,
        revision_id=FIX_REVISION_ID,
        record_kind=KIND_ITEM,
    )
    plaintext = b"secret-payload-for-arcanum-test"
    ct_tag = xchacha_encrypt(FIX_AEAD_KEY, FIX_AEAD_NONCE, plaintext, record_aad)
    nonce_len = len(FIX_AEAD_NONCE)  # 24 for XChaCha20
    frame = (
        u16le(1)                                  # frame_version
        + FIX_RECORD_ID
        + FIX_REVISION_ID
        + u16le(AEAD_XCHACHA20_POLY1305_V1)
        + bytes([nonce_len])
        + FIX_AEAD_NONCE
        + u32le(len(record_aad))
        + record_aad
        + u32le(len(ct_tag))
        + ct_tag
    )
    body = frame

    header_len = len(header)
    record_count = 1
    entry_size = 16 + 2 + 16 + 8 + 4  # record_id||kind||revision_id||frame_offset||frame_len = 46
    record_table_len = 4 + record_count * entry_size  # record_count:u32le + entries
    frame_offset = 26 + header_len + record_table_len
    entry = (
        FIX_RECORD_ID
        + u16le(KIND_ITEM)
        + FIX_REVISION_ID
        + u64le(frame_offset)
        + u32le(len(frame))
    )
    record_table = u32le(record_count) + entry
    assert len(record_table) == record_table_len

    prefix = (
        MAGIC
        + u16le(1)                  # format_version
        + u32le(header_len)
        + u32le(record_table_len)
        + u64le(len(body))
    )
    assert len(prefix) == 26, f"prefix must be 26 bytes, got {len(prefix)}"

    blob = prefix + header + record_table + body

    # Frame-relative offsets (for mutating fields inside the frame).
    nonce_len_off = 2 + 16 + 16 + 2                                   # = 36
    ciphertext_len_off = nonce_len_off + 1 + nonce_len + 4 + len(record_aad)  # = 139
    meta = {
        "header_len": header_len,
        "record_table_len": record_table_len,
        "body_offset": 26 + header_len + record_table_len,
        "frame_len": len(frame),
        "nonce_len_off": nonce_len_off,
        "ciphertext_len_off": ciphertext_len_off,
        "ct_tag_len": len(ct_tag),
    }
    return blob, meta


def _neg_case(cid: str, desc: str, reason: str, blob: bytes, mutation: str) -> dict:
    """One negative fixture: malformed input_hex + cited §10 rule + Err/reason."""
    return {
        "id": cid,
        "description": desc,
        "inputs": {
            "input_hex": to_hex(blob),
            "mutation": mutation,
        },
        "expected": {
            "result": "Err",
            "reason": reason,
        },
    }


def generate_format_negative_vectors() -> dict:
    """
    D6: 7 reject fixtures, one per vault_format_v1.md §10 rejection rule.

    Each fixture builds the valid vault blob first, then mutates exactly one
    field to violate one rule. No acceptance cases — negatives only.
    """
    blob, meta = _build_valid_vault()
    bo = meta["body_offset"]
    cases = []

    # 1. Wrong magic (§2/§10): corrupt the first magic byte.
    m = bytearray(blob)
    m[0] ^= 0xFF
    cases.append(_neg_case(
        "neg-wrong-magic",
        "§10 rule 'wrong magic bytes' (§2 file prefix): first magic byte flipped",
        "wrong_magic",
        bytes(m),
        "prefix[0] ^= 0xFF",
    ))

    # 2. Unsupported format_version (§2/§3): set format_version to 0x0063 (99).
    m = bytearray(blob)
    m[8:10] = u16le(0x0063)
    cases.append(_neg_case(
        "neg-unsupported-format-version",
        "§10 rule 'unsupported format_version' (§2/§3): format_version set to 99, MVP-0 only supports 1",
        "unsupported_format_version",
        bytes(m),
        "prefix.format_version = 0x0063",
    ))

    # 3. Length exceeds file (§2/§5): header_len points beyond blob end.
    m = bytearray(blob)
    m[10:14] = u32le(len(blob) + 1000)
    cases.append(_neg_case(
        "neg-header-len-exceeds-file",
        "§10 rule 'header_len/record_table_len/body_len exceeding file size' (§2/§5): header_len declared past EOF",
        "header_len_exceeds_file",
        bytes(m),
        "prefix.header_len = len(blob) + 1000",
    ))

    # 4. Unknown critical TLV tag (§3): inject a must-understand tag the parser
    #    does not know. Rebuilt with consistent lengths so the ONLY violation is
    #    the unknown critical tag.
    unknown_tlv = header_tlv(0x7F00, bytes.fromhex("deadbeef"), critical=True)
    blob4, _ = _build_valid_vault(extra_header=unknown_tlv)
    cases.append(_neg_case(
        "neg-unknown-critical-tlv-tag",
        "§10 rule 'unknown critical TLV tags' (§3): critical Header TLV tag 0x7F00 injected; parser must reject, not ignore",
        "unknown_critical_tlv_tag",
        blob4,
        "header += critical TLV tag=0x7F00",
    ))

    # 5. nonce_len / AEAD mismatch (§6): aead_profile stays XChaCha20 (needs 24)
    #    but nonce_len is set to 12 (the AES-GCM length).
    m = bytearray(blob)
    m[bo + meta["nonce_len_off"]] = 12
    cases.append(_neg_case(
        "neg-nonce-len-aead-mismatch",
        "§10 rule 'nonce_len mismatching AEAD profile' (§6): nonce_len=12 with aead_profile=XChaCha20 (requires 24)",
        "nonce_len_aead_mismatch",
        bytes(m),
        "frame.nonce_len = 12",
    ))

    # 6. ciphertext_len exceeds frame (§6): declared ciphertext_len larger than
    #    the actual frame body.
    m = bytearray(blob)
    off = bo + meta["ciphertext_len_off"]
    m[off:off + 4] = u32le(meta["ct_tag_len"] + 1000)
    cases.append(_neg_case(
        "neg-ciphertext-len-exceeds-frame",
        "§10 rule 'ciphertext_len exceeding frame boundary' (§6): ciphertext_len overstated by 1000 bytes",
        "ciphertext_len_exceeds_frame",
        bytes(m),
        "frame.ciphertext_len = actual + 1000",
    ))

    # 7. AEAD auth failure (§10): structurally valid frame, last ciphertext/tag
    #    byte flipped so Poly1305 verification fails — no partial plaintext.
    m = bytearray(blob)
    m[bo + meta["frame_len"] - 1] ^= 0xFF
    cases.append(_neg_case(
        "neg-aead-auth-failure",
        "§10 rule 'AEAD authentication failure — no partial plaintext output' (§10): final tag byte flipped on an otherwise-valid frame",
        "aead_auth_failure",
        bytes(m),
        "frame.ciphertext[-1] ^= 0xFF",
    ))

    return {
        "profile": "SCHEMA_ARCANUM_RECORDS_V1",
        "version": 1,
        "description": "D6: vault format negative fixtures — 7 reject cases, one per vault_format_v1.md §10 rule",
        "generated_by": "cross_verify.py (pynacl/libsodium)",
        "cases": cases,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

GENERATORS = {
    "kdf":  ("vault_kdf_v1.json",    generate_kdf_vectors),
    "aad":  ("vault_format_v1.json", generate_aad_vectors),
    "aead": ("aead_xchacha20_v1.json", generate_aead_vectors),
    "wrap": ("vault_wrap_v1.json", generate_wrap_vectors),
    "kdf_tlv": ("vault_kdf_param_tlv_v1.json", generate_kdf_tlv_vectors),
    "format_struct": ("vault_format_struct_v1.json", generate_format_struct_vectors),
    "format_negative": ("vault_format_negative_v1.json", generate_format_negative_vectors),
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
