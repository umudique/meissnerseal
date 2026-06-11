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
    salt = b"meissnerseal-argon2id-salt-v1" || vault_id
    """
    domain = b"meissnerseal-argon2id-salt-v1"
    assert len(domain) == 29, f"domain length must be 29, got {len(domain)}"
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

    vkek_salt = b"meissnerseal-vkek-salt-v1" || vault_id
    vkek_prk  = HKDF-SHA256-Extract(vkek_salt, master_unlock_key)
    vkek      = HKDF-SHA256-Expand(vkek_prk, b"meissnerseal:vault-kek:v1", 32)
    """
    domain = b"meissnerseal-vkek-salt-v1"
    assert len(domain) == 25
    assert len(vault_id) == 16

    vkek_salt = domain + vault_id
    vkek_prk = hkdf_extract_sha256(vkek_salt, master_unlock_key)
    vkek = hkdf_expand_sha256(vkek_prk, b"meissnerseal:vault-kek:v1", 32)
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

    Format: meissnerseal:{purpose}:v1:vault:{vault_id_hex}[:aead:{aead_id_decimal}]

    vault_id is lowercase hex (32 chars).
    aead_id is decimal string (e.g. "1" for XChaCha20-Poly1305).
    """
    vid_hex = vault_id_hex(vault_id)
    if aead_id is not None:
        info = f"meissnerseal:{purpose}:v1:vault:{vid_hex}:aead:{aead_id_decimal(aead_id)}"
    else:
        info = f"meissnerseal:{purpose}:v1:vault:{vid_hex}"
    return info.encode("ascii")


def derive_root_prk(vault_root_key: bytes, vault_id: bytes, header_nonce: bytes) -> bytes:
    """
    Derive root PRK from Vault Root Key.

    root_salt = SHA256(b"meissnerseal-root-salt-v1" || vault_id || header_nonce)
    root_prk  = HKDF-SHA256-Extract(root_salt, vault_root_key)
    """
    domain = b"meissnerseal-root-salt-v1"
    assert len(domain) == 25
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

    AAD = b"meissnerseal-aad-v1" (19 bytes)
       || vault_id               (16 bytes)
       || format_version:u16le   ( 2 bytes)
       || schema_profile:u16le   ( 2 bytes)
       || aead_profile:u16le     ( 2 bytes)
       || kdf_profile:u16le      ( 2 bytes)
       || pqc_profile:u16le      ( 2 bytes)
       || record_id              (16 bytes)
       || revision_id            (16 bytes)
       || record_kind:u16le      ( 2 bytes)
                                 = 79 bytes total
    """
    domain = b"meissnerseal-aad-v1"
    assert len(domain) == 19
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
    assert len(aad) == 79, f"AAD v1 must be 79 bytes, got {len(aad)}"
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
        schema_profile=SCHEMA_ARCANUM_RECORDS_V2,
        aead_profile=AEAD_XCHACHA20_POLY1305_V1,
        kdf_profile=1,
        pqc_profile=0,
        record_id=record_id,
        revision_id=revision_id,
        record_kind=1,  # Item
    )

    return {
        "profile": "SCHEMA_ARCANUM_RECORDS_V2_AAD",
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
                    "schema_profile": SCHEMA_ARCANUM_RECORDS_V2,
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
                    "schema_profile": SCHEMA_ARCANUM_RECORDS_V2,
                    "aead_profile": AEAD_XCHACHA20_POLY1305_V1,
                    "kdf_profile": 1,
                    "pqc_profile": 0x0001,
                    "record_id": to_hex(record_id),
                    "revision_id": to_hex(revision_id),
                    "record_kind": 0x0002,
                },
                "expected": {
                    "aad_hex": to_hex(build_aad_v1(
                        vault_id=vault_id, format_version=1, schema_profile=SCHEMA_ARCANUM_RECORDS_V2,
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
                    "schema_profile": SCHEMA_ARCANUM_RECORDS_V2,
                    "aead_profile": AEAD_XCHACHA20_POLY1305_V1,
                    "kdf_profile": 1,
                    "pqc_profile": 0,
                    "record_id": to_hex(record_id),
                    "revision_id": to_hex(revision_id),
                    "record_kind": 0x0005,
                },
                "expected": {
                    "aad_hex": to_hex(build_aad_v1(
                        vault_id=vault_id, format_version=1, schema_profile=SCHEMA_ARCANUM_RECORDS_V2,
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
        "01000200010001000100"                   # format=1, schema=2, aead=1, kdf=1, pqc=1
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"      # record_id         (16 bytes)
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"      # revision_id       (16 bytes)
        "0100"                                   # record_kind u16le  (2 bytes)
    )
    assert len(aad) == 74, f"AAD must be 74 bytes, got {len(aad)}"
    plaintext = b"secret-payload-for-meissnerseal-test"

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
SCHEMA_ARCANUM_RECORDS_V2 = 0x0002
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
        schema_profile=SCHEMA_ARCANUM_RECORDS_V2,
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
        schema_profile=SCHEMA_ARCANUM_RECORDS_V2,
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


def table_aad_v2(vault_id: bytes, schema_profile: int = SCHEMA_ARCANUM_RECORDS_V2) -> bytes:
    """V2 sealed-table AAD: vault_id[16] || schema_profile:u16le (§5)."""
    assert len(vault_id) == 16
    assert schema_profile == SCHEMA_ARCANUM_RECORDS_V2
    aad = vault_id + u16le(schema_profile)
    assert len(aad) == 18
    return aad


def sealed_table_bucket_capacity(entry_count: int) -> int:
    """Smallest power-of-two bucket capacity >= entry_count, with 0 -> 1 (§5)."""
    bucket = 1
    while bucket < entry_count:
        bucket *= 2
    return bucket


def record_table_entry_v2(record_id: bytes, kind: int, revision_id: bytes, offset: int, length: int) -> bytes:
    """V2 table entry: record_id[16] || record_kind:u16le || revision_id[16] || frame_offset:u64le || frame_len:u32le."""
    assert len(record_id) == 16
    assert len(revision_id) == 16
    return record_id + u16le(kind) + revision_id + u64le(offset) + u32le(length)


def sealed_table_plaintext_v2(entries: list, pad_byte: int = 0) -> bytes:
    """entry_count:u32le || entries || padding to power-of-two bucket (§5)."""
    bucket = sealed_table_bucket_capacity(len(entries))
    plaintext = u32le(len(entries)) + b"".join(entries)
    target_len = 4 + bucket * 46
    assert len(plaintext) <= target_len
    return plaintext + bytes([pad_byte]) * (target_len - len(plaintext))


def seal_record_table_v2(entries: list, mek: bytes, vault_id: bytes, nonce: bytes, pad_byte: int = 0) -> tuple:
    """Return (section, plaintext, ciphertext_and_tag) for the V2 sealed table."""
    plaintext = sealed_table_plaintext_v2(entries, pad_byte=pad_byte)
    aad = table_aad_v2(vault_id)
    ct_tag = xchacha_encrypt(mek, nonce, plaintext, aad)
    sealed_table_len = len(nonce) + len(ct_tag)
    section = u32le(sealed_table_len) + nonce + ct_tag
    return section, plaintext, ct_tag


def record_frame_v1(record_id: bytes, revision_id: bytes, kind: int, key: bytes, nonce: bytes, plaintext: bytes, schema_profile: int) -> tuple:
    """Serialize one §6 encrypted record frame and return (frame, aad, ciphertext_and_tag)."""
    aad = build_aad_v1(
        vault_id=FIX_VAULT_ID,
        format_version=1,
        schema_profile=schema_profile,
        aead_profile=AEAD_XCHACHA20_POLY1305_V1,
        kdf_profile=KDF_ARGON2ID_V1,
        pqc_profile=PQC_NONE,
        record_id=record_id,
        revision_id=revision_id,
        record_kind=kind,
    )
    ct_tag = xchacha_encrypt(key, nonce, plaintext, aad)
    frame = (
        u16le(1)
        + record_id
        + revision_id
        + u16le(AEAD_XCHACHA20_POLY1305_V1)
        + bytes([len(nonce)])
        + nonce
        + u32le(len(aad))
        + aad
        + u32le(len(ct_tag))
        + ct_tag
    )
    return frame, aad, ct_tag


def header_v2(created_at_ms: int, schema_profile: int = SCHEMA_ARCANUM_RECORDS_V2) -> tuple:
    """Build the V2 header TLV section and parsed TLV metadata (§3)."""
    kdf_param_tlvs = (
        kdf_param_tlv(0x0101, u32le(65536))
        + kdf_param_tlv(0x0102, u32le(3))
        + kdf_param_tlv(0x0103, u32le(4))
        + kdf_param_tlv(0x0104, u16le(32))
        + kdf_param_tlv(0x0105, u32le(0x13))
    )
    kdf_value = u16le(KDF_ARGON2ID_V1) + u32le(len(kdf_param_tlvs)) + kdf_param_tlvs
    header_tags = [
        ("vault_id",       0x0001, FIX_VAULT_ID,                         True),
        ("created_at",     0x0002, u64le(created_at_ms),                 True),
        ("kdf_profile",    0x0003, kdf_value,                            True),
        ("aead_profile",   0x0004, u16le(AEAD_XCHACHA20_POLY1305_V1),    True),
        ("pqc_profile",    0x0005, u16le(PQC_NONE),                     False),
        ("schema_profile", 0x0006, u16le(schema_profile),               True),
        ("header_nonce",   0x0007, FIX_HEADER_NONCE,                     True),
    ]
    header = b"".join(header_tlv(tag, val, crit) for _, tag, val, crit in header_tags)
    parsed = [
        {"tag": f"0x{tag:04x}", "name": name, "critical": crit, "len": len(val), "value_hex": to_hex(val)}
        for name, tag, val, crit in header_tags
    ]
    return header, parsed


def generate_format_struct_vectors() -> dict:
    created_at_ms = 1_700_000_000_000
    header, header_parsed = header_v2(created_at_ms)
    mek = bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
    table_nonce_empty = bytes.fromhex("303132333435363738393a3b3c3d3e3f4041424344454647")
    table_nonce_multi = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")

    wrk_plaintext = FIX_VAULT_ROOT_KEY
    wrk_frame, wrk_aad, wrk_ct_tag = record_frame_v1(
        FIX_RECORD_ID,
        FIX_REVISION_ID,
        KIND_WRAPPED_ROOTKEY,
        FIX_AEAD_KEY,
        FIX_AEAD_NONCE,
        wrk_plaintext,
        SCHEMA_ARCANUM_RECORDS_V2,
    )
    wrk_frame_offset = 26 + len(header)

    empty_table, empty_plaintext, empty_ct_tag = seal_record_table_v2(
        [], mek, FIX_VAULT_ID, table_nonce_empty
    )
    body_empty = wrk_frame + empty_table
    prefix_empty = MAGIC + u16le(1) + u32le(len(header)) + u32le(len(empty_table)) + u64le(len(body_empty))
    vault_empty = prefix_empty + header + body_empty

    item1_id = bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf")
    item1_rev = bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
    item2_id = bytes.fromhex("e0e1e2e3e4e5e6e7e8e9eaebecedeeef")
    item2_rev = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    item1_frame, item1_aad, item1_ct_tag = record_frame_v1(
        item1_id, item1_rev, KIND_ITEM, FIX_AEAD_KEY, bytes.fromhex("1112131415161718191a1b1c1d1e1f202122232425262728"), b"item-one-payload", SCHEMA_ARCANUM_RECORDS_V2
    )
    item2_frame, item2_aad, item2_ct_tag = record_frame_v1(
        item2_id, item2_rev, KIND_AUDITEVENT, FIX_AEAD_KEY, bytes.fromhex("2122232425262728292a2b2c2d2e2f303132333435363738"), b"item-two-payload-longer", SCHEMA_ARCANUM_RECORDS_V2
    )
    provisional_empty_table_len = len(empty_table)
    item1_offset = wrk_frame_offset + len(wrk_frame) + provisional_empty_table_len
    item2_offset = item1_offset + len(item1_frame)
    entries = [
        record_table_entry_v2(item1_id, KIND_ITEM, item1_rev, item1_offset, len(item1_frame)),
        record_table_entry_v2(item2_id, KIND_AUDITEVENT, item2_rev, item2_offset, len(item2_frame)),
    ]
    multi_table, multi_plaintext, multi_ct_tag = seal_record_table_v2(
        entries, mek, FIX_VAULT_ID, table_nonce_multi
    )
    item1_offset = wrk_frame_offset + len(wrk_frame) + len(multi_table)
    item2_offset = item1_offset + len(item1_frame)
    entries = [
        record_table_entry_v2(item1_id, KIND_ITEM, item1_rev, item1_offset, len(item1_frame)),
        record_table_entry_v2(item2_id, KIND_AUDITEVENT, item2_rev, item2_offset, len(item2_frame)),
    ]
    multi_table, multi_plaintext, multi_ct_tag = seal_record_table_v2(
        entries, mek, FIX_VAULT_ID, table_nonce_multi
    )
    body_multi = wrk_frame + multi_table + item1_frame + item2_frame
    prefix_multi = MAGIC + u16le(1) + u32le(len(header)) + u32le(len(multi_table)) + u64le(len(body_multi))
    vault_multi = prefix_multi + header + body_multi

    table_records = [
        {
            "record_id": to_hex(item1_id),
            "record_kind": f"0x{KIND_ITEM:04x}",
            "revision_id": to_hex(item1_rev),
            "frame_offset": item1_offset,
            "frame_len": len(item1_frame),
        },
        {
            "record_id": to_hex(item2_id),
            "record_kind": f"0x{KIND_AUDITEVENT:04x}",
            "revision_id": to_hex(item2_rev),
            "frame_offset": item2_offset,
            "frame_len": len(item2_frame),
        },
    ]

    return {
        "profile": "SCHEMA_ARCANUM_RECORDS_V2",
        "version": 2,
        "description": "V2 vault format: fixed-position WrappedRootKey and MEK-sealed record table",
        "generated_by": "cross_verify.py (pynacl/libsodium)",
        "cases": [
            {
                "id": "v2-empty-table-fixed-wrk",
                "description": "V2 layout with WRK at fixed offset and an empty MEK-sealed table (§5)",
                "inputs": {
                    "vault_id": to_hex(FIX_VAULT_ID),
                    "schema_profile": SCHEMA_ARCANUM_RECORDS_V2,
                    "metadata_encryption_key": to_hex(mek),
                    "table_nonce": to_hex(table_nonce_empty),
                    "wrapped_root_key_nonce": to_hex(FIX_AEAD_NONCE),
                    "wrapped_root_key_plaintext": to_hex(wrk_plaintext),
                },
                "expected": {
                    "prefix_hex": to_hex(prefix_empty),
                    "header_hex": to_hex(header),
                    "header_len": len(header),
                    "header_tlvs": header_parsed,
                    "wrk_frame_offset": wrk_frame_offset,
                    "wrk_frame_hex": to_hex(wrk_frame),
                    "wrk_frame_len": len(wrk_frame),
                    "wrk_aad_hex": to_hex(wrk_aad),
                    "wrapped_root_key_ciphertext_tag_hex": to_hex(wrk_ct_tag),
                    "table_aad_hex": to_hex(table_aad_v2(FIX_VAULT_ID)),
                    "sealed_table_plaintext_hex": to_hex(empty_plaintext),
                    "sealed_table_plaintext_len": len(empty_plaintext),
                    "sealed_table_len": len(table_nonce_empty) + len(empty_ct_tag),
                    "sealed_table_section_hex": to_hex(empty_table),
                    "sealed_table_ciphertext_tag_hex": to_hex(empty_ct_tag),
                    "vault_file_hex": to_hex(vault_empty),
                    "result": "Ok",
                },
            },
            {
                "id": "v2-multi-entry-sealed-table",
                "description": "V2 sealed table with two item-frame entries, power-of-two padding, and generalized frame offsets (§5/§6)",
                "inputs": {
                    "vault_id": to_hex(FIX_VAULT_ID),
                    "schema_profile": SCHEMA_ARCANUM_RECORDS_V2,
                    "metadata_encryption_key": to_hex(mek),
                    "table_nonce": to_hex(table_nonce_multi),
                    "entry_count": 2,
                    "bucket_capacity": 2,
                },
                "expected": {
                    "prefix_hex": to_hex(prefix_multi),
                    "header_hex": to_hex(header),
                    "wrk_frame_offset": wrk_frame_offset,
                    "sealed_table_plaintext_hex": to_hex(multi_plaintext),
                    "sealed_table_plaintext_len": len(multi_plaintext),
                    "sealed_table_len": len(table_nonce_multi) + len(multi_ct_tag),
                    "sealed_table_section_hex": to_hex(multi_table),
                    "sealed_table_ciphertext_tag_hex": to_hex(multi_ct_tag),
                    "records": table_records,
                    "item_frames_hex": [to_hex(item1_frame), to_hex(item2_frame)],
                    "item_aad_hex": [to_hex(item1_aad), to_hex(item2_aad)],
                    "item_ciphertext_tag_hex": [to_hex(item1_ct_tag), to_hex(item2_ct_tag)],
                    "vault_file_hex": to_hex(vault_multi),
                    "result": "Ok",
                },
            },
        ],
    }


# ─────────────────────────────────────────────────────────────────────────────
# D6 — Vault format negative fixtures  (vault_format_v1.md §10 reject rules)
# ─────────────────────────────────────────────────────────────────────────────

def _build_valid_v2_vault(table_section: bytes = None, schema_profile: int = SCHEMA_ARCANUM_RECORDS_V2) -> tuple:
    """Build a V2 vault blob with fixed WRK and a caller-provided sealed table."""
    created_at_ms = 1_700_000_000_000
    header, _ = header_v2(created_at_ms, schema_profile=schema_profile)
    wrk_frame, _, _ = record_frame_v1(
        FIX_RECORD_ID,
        FIX_REVISION_ID,
        KIND_WRAPPED_ROOTKEY,
        FIX_AEAD_KEY,
        FIX_AEAD_NONCE,
        FIX_VAULT_ROOT_KEY,
        schema_profile,
    )
    mek = bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
    table_nonce = bytes.fromhex("303132333435363738393a3b3c3d3e3f4041424344454647")
    if table_section is None:
        table_section, _, _ = seal_record_table_v2([], mek, FIX_VAULT_ID, table_nonce)
    body = wrk_frame + table_section
    prefix = MAGIC + u16le(1) + u32le(len(header)) + u32le(len(table_section)) + u64le(len(body))
    blob = prefix + header + body
    return blob, {
        "header_len": len(header),
        "wrk_frame_len": len(wrk_frame),
        "table_offset": 26 + len(header) + len(wrk_frame),
        "table_len": len(table_section),
        "metadata_encryption_key": mek,
        "table_nonce": table_nonce,
    }


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
    """V2 reject fixtures for vault_format_v1.md §10 fail-closed rules."""
    blob, meta = _build_valid_v2_vault()
    cases = []

    blob_v1, _ = _build_valid_v2_vault(schema_profile=SCHEMA_ARCANUM_RECORDS_V1)
    cases.append(_neg_case(
        "neg-schema-profile-v1-rejected",
        "§10: pre-release schema_profile V1 is rejected; V2 readers never best-effort parse V1",
        "schema_profile_v1",
        blob_v1,
        "header.schema_profile = 0x0001",
    ))

    wrk_entry = record_table_entry_v2(FIX_RECORD_ID, KIND_WRAPPED_ROOTKEY, FIX_REVISION_ID, 26 + meta["header_len"], meta["wrk_frame_len"])
    section, plaintext, ct_tag = seal_record_table_v2([wrk_entry], meta["metadata_encryption_key"], FIX_VAULT_ID, meta["table_nonce"])
    blob_wrk, _ = _build_valid_v2_vault(table_section=section)
    cases.append(_neg_case(
        "neg-wrk-entry-inside-sealed-table",
        "§10: V2 sealed table must not contain record_kind=0x0002 WrappedRootKey",
        "wrapped_root_key_entry_in_table",
        blob_wrk,
        "sealed_table_plaintext contains record_kind 0x0002",
    ))

    item_entry = record_table_entry_v2(bytes.fromhex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"), KIND_ITEM, bytes.fromhex("d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"), 512, 96)
    bad_pad_section, bad_pad_plaintext, bad_pad_ct = seal_record_table_v2([item_entry], meta["metadata_encryption_key"], FIX_VAULT_ID, meta["table_nonce"], pad_byte=0x7f)
    blob_bad_pad, _ = _build_valid_v2_vault(table_section=bad_pad_section)
    cases.append(_neg_case(
        "neg-non-zero-sealed-table-padding",
        "§10: authenticated sealed-table plaintext padding must be all zero bytes",
        "non_zero_padding",
        blob_bad_pad,
        "sealed_table_plaintext padding byte = 0x7f",
    ))

    non_bucket_plaintext = u32le(0) + (b"\x00" * 45)
    non_bucket_ct = xchacha_encrypt(meta["metadata_encryption_key"], meta["table_nonce"], non_bucket_plaintext, table_aad_v2(FIX_VAULT_ID))
    non_bucket_section = u32le(len(meta["table_nonce"]) + len(non_bucket_ct)) + meta["table_nonce"] + non_bucket_ct
    blob_non_bucket, _ = _build_valid_v2_vault(table_section=non_bucket_section)
    cases.append(_neg_case(
        "neg-non-bucket-sealed-table-plaintext-length",
        "§10: sealed-table plaintext length after entry_count must be a power-of-two bucket of 46-byte entries",
        "non_bucket_length",
        blob_non_bucket,
        "decrypted table payload length = 45, not bucket*46",
    ))

    too_short_section = u32le(39) + (b"\x00" * 39)
    blob_short, _ = _build_valid_v2_vault(table_section=too_short_section)
    cases.append(_neg_case(
        "neg-sealed-table-len-less-than-40",
        "§10: sealed_table_len less than nonce[24] + tag[16] is rejected",
        "sealed_table_len_too_short",
        blob_short,
        "sealed_table_len = 39",
    ))

    tampered = bytearray(blob)
    tampered[meta["table_offset"] + meta["table_len"] - 1] ^= 0x01
    cases.append(_neg_case(
        "neg-table-aead-auth-failure",
        "§10: MEK-sealed-table AEAD authentication failure rejects with no partial output",
        "table_aead_auth_failure",
        bytes(tampered),
        "sealed_table_ciphertext_and_tag[-1] ^= 0x01",
    ))

    return {
        "profile": "SCHEMA_ARCANUM_RECORDS_V2",
        "version": 2,
        "description": "V2 vault format negative fixtures for MEK-sealed table and schema fail-closed rules",
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
                json.dump(vectors, f, indent=2, ensure_ascii=False)
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
