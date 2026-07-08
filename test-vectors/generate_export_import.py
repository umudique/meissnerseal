#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate encrypted export/import vectors for MeissnerSeal.

This script is standalone and independent from the Rust implementation. It
reproduces the `.msexp` framing and payload rules from the documented MeissnerSeal
export/import surface and emits a JSON vector file consumed by later Rust KATs.

Usage:
    python3 generate_export_import.py
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt


SCRIPT_PATH = Path(__file__)
VECTOR_PATH = SCRIPT_PATH.with_name("export_import_v1.json")

MSEXP_MAGIC = b"MSEXP\x01\x00\x00"
MSEXP_VERSION_V1 = 1
AEAD_XCHACHA20_POLY1305_V1 = 1
KDF_ARGON2ID_V1 = 1

ITEM_KIND_PASSWORD = 0x0001
ITEM_KIND_SEED_PHRASE = 0x0002
ITEM_KIND_SSH_PRIVATE_KEY = 0x0003
ITEM_KIND_API_TOKEN = 0x0004
ITEM_KIND_SECURE_NOTE = 0x0005

ARGON2_M_COST_KIB = 65536
ARGON2_T_COST = 3
ARGON2_P_LANES = 4
ARGON2_OUTPUT_LEN = 32
ARGON2_VERSION = 0x13


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_bytes(label: str, length: int) -> bytes:
    """Deterministically derive non-real test bytes from a label."""
    output = b""
    counter = 0
    while len(output) < length:
        output += sha256(f"tv-2-a:{label}:{counter}".encode("utf-8"))
        counter += 1
    return output[:length]


def u16le(value: int) -> bytes:
    return struct.pack("<H", value)


def u32le(value: int) -> bytes:
    return struct.pack("<I", value)


def hexlify(value: bytes) -> str:
    return value.hex()


def argon2id_salt(vault_id: bytes) -> bytes:
    domain = b"meissnerseal-argon2id-salt-v1"
    assert len(domain) == 29
    assert len(vault_id) == 16
    return domain + vault_id


EXPORT_BUNDLE_INFO = b"meissnerseal:export-bundle:v1"


def hkdf_expand_32(prk: bytes, info: bytes) -> bytes:
    """HKDF-SHA256-Expand for exactly 32 bytes (one round, RFC 5869 §2.3).

    T(1) = HMAC-SHA256(PRK, T(0) || info || 0x01) where T(0) = b"".
    """
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def derive_export_key(passphrase: str, vault_id: bytes) -> bytes:
    """Derive the 32-byte export AEAD key.

    Chain: Argon2id(passphrase, salt=ARGON2ID_SALT_DOMAIN_V1||vault_id) → MUK
           HKDF-SHA256-Expand(PRK=MUK, info="meissnerseal:export-bundle:v1") → AeadKey

    The HKDF-Expand step provides export-specific domain separation (F-73):
    the resulting key is distinct from the vault MUK and from all HKDF session
    subkeys even when passphrase == vault_password and vault_id == source_vault_id.
    """
    muk = hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=argon2id_salt(vault_id),
        time_cost=ARGON2_T_COST,
        memory_cost=ARGON2_M_COST_KIB,
        parallelism=ARGON2_P_LANES,
        hash_len=ARGON2_OUTPUT_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )
    return hkdf_expand_32(muk, EXPORT_BUNDLE_INFO)


def derive_muk(passphrase: str, vault_id: bytes) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=argon2id_salt(vault_id),
        time_cost=ARGON2_T_COST,
        memory_cost=ARGON2_M_COST_KIB,
        parallelism=ARGON2_P_LANES,
        hash_len=ARGON2_OUTPUT_LEN,
        type=Type.ID,
        version=ARGON2_VERSION,
    )


def export_aad(source_vault_id: bytes, version: int) -> bytes:
    assert len(source_vault_id) == 16
    return source_vault_id + MSEXP_MAGIC + u16le(version)


def serialize_kdf_profile_params() -> bytes:
    params = [
        (0x0101, u32le(ARGON2_M_COST_KIB)),
        (0x0102, u32le(ARGON2_T_COST)),
        (0x0103, u32le(ARGON2_P_LANES)),
        (0x0104, u16le(ARGON2_OUTPUT_LEN)),
        (0x0105, u32le(ARGON2_VERSION)),
    ]
    param_tlvs = b"".join(u16le(tag) + u16le(len(value)) + value for tag, value in params)
    return u16le(KDF_ARGON2ID_V1) + u32le(len(param_tlvs)) + param_tlvs


def write_len_prefixed(out: bytearray, value: bytes) -> None:
    out.extend(u32le(len(value)))
    out.extend(value)


def serialize_item_set(items: list[dict[str, object]]) -> bytes:
    out = bytearray()
    out.extend(u32le(len(items)))
    for item in items:
        out.extend(u16le(int(item["kind_u16"])))
        write_len_prefixed(out, str(item["label"]).encode("utf-8"))
        tags = list(item["tags"])
        out.extend(u32le(len(tags)))
        for tag in tags:
            write_len_prefixed(out, str(tag).encode("utf-8"))
        write_len_prefixed(out, bytes.fromhex(str(item["secret_hex"])))
    return bytes(out)


def build_bundle(
    source_vault_id: bytes,
    passphrase: str,
    nonce: bytes,
    items: list[dict[str, object]],
) -> dict[str, str]:
    kdf_params = serialize_kdf_profile_params()
    plaintext = serialize_item_set(items)
    export_key = derive_export_key(passphrase, source_vault_id)
    aad = export_aad(source_vault_id, MSEXP_VERSION_V1)
    ciphertext_and_tag = crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        aad,
        nonce,
        export_key,
    )
    bundle = (
        MSEXP_MAGIC
        + u16le(MSEXP_VERSION_V1)
        + source_vault_id
        + u32le(len(kdf_params))
        + kdf_params
        + nonce
        + u32le(len(ciphertext_and_tag))
        + ciphertext_and_tag
    )
    return {
        "kdf_params_hex": hexlify(kdf_params),
        "aad_hex": hexlify(aad),
        "plaintext_hex": hexlify(plaintext),
        "export_key_hex": hexlify(export_key),
        "ciphertext_and_tag_hex": hexlify(ciphertext_and_tag),
        "bundle_hex": hexlify(bundle),
    }


def flip_ciphertext_bit(bundle_hex: str, ciphertext_and_tag_hex: str) -> tuple[str, int]:
    bundle = bytearray.fromhex(bundle_hex)
    ciphertext_and_tag = bytes.fromhex(ciphertext_and_tag_hex)
    ciphertext_len = len(ciphertext_and_tag)
    ciphertext_offset = len(bundle) - ciphertext_len
    flip_offset = ciphertext_offset + 7
    bundle[flip_offset] ^= 0x01
    return hexlify(bytes(bundle)), flip_offset


def flip_tag_bit(bundle_hex: str, ciphertext_and_tag_hex: str) -> tuple[str, int]:
    bundle = bytearray.fromhex(bundle_hex)
    ciphertext_and_tag = bytes.fromhex(ciphertext_and_tag_hex)
    ciphertext_offset = len(bundle) - len(ciphertext_and_tag)
    flip_offset = ciphertext_offset + len(ciphertext_and_tag) - 1
    bundle[flip_offset] ^= 0x01
    return hexlify(bytes(bundle)), flip_offset


def main() -> int:
    source_vault_id = derive_bytes("source-vault-id", 16)
    nonce = derive_bytes("bundle-nonce", 24)
    export_passphrase = "tv-2-a export passphrase never real"
    wrong_passphrase = "tv-2-a wrong decryption key never real"

    items = [
        {
            "kind": "SecureNote",
            "kind_u16": ITEM_KIND_SECURE_NOTE,
            "label": "boundary-empty-secret",
            "tags": [],
            "secret_hex": "",
        },
        {
            "kind": "SshPrivateKey",
            "kind_u16": ITEM_KIND_SSH_PRIVATE_KEY,
            "label": "roundtrip-key-material",
            "tags": ["prod", "ops"],
            "secret_hex": hexlify(derive_bytes("ssh-private-key-secret", 48)),
        },
    ]

    base = build_bundle(source_vault_id, export_passphrase, nonce, items)
    tampered_bundle_hex, flipped_offset = flip_ciphertext_bit(
        base["bundle_hex"], base["ciphertext_and_tag_hex"]
    )
    tag_flipped_bundle_hex, tag_flip_offset = flip_tag_bit(
        base["bundle_hex"], base["ciphertext_and_tag_hex"]
    )
    unsupported_version_bundle = bytearray.fromhex(base["bundle_hex"])
    unsupported_version_bundle[8:10] = u16le(2)
    muk = derive_muk(export_passphrase, source_vault_id)

    vector = {
        "profile": "MSEXP_EXPORT_IMPORT_V1",
        "version": 1,
        "description": (
            "Known-answer vectors for encrypted .msexp export/import framing and "
            "AEAD authentication. Covers round-trip semantics, ciphertext "
            "corruption rejection, wrong decryption key rejection, and boundary "
            "payload values via an empty-secret item."
        ),
        "generated_by": (
            "generate_export_import.py (argon2-cffi 23.1.0, PyNaCl 1.5.0, "
            "Python stdlib struct/hashlib/json)"
        ),
        "handoff_note": (
            "Core should use the round-trip case to build live items, call "
            "export(session, passphrase), then import into a second unlocked "
            "vault and assert the imported plaintext matches expected_items. "
            "Use bundle_hex directly for import KATs. The corruption and wrong-"
            "decryption-key cases should call import(...) and assert a specific "
            "authentication rejection. The export AEAD key is derived as: "
            "Argon2id(passphrase, salt=meissnerseal-argon2id-salt-v1||source_vault_id) "
            "→ MUK; HKDF-SHA256-Expand(PRK=MUK, "
            "info=meissnerseal:export-bundle:v1) → AeadKey. "
            "The HKDF-Expand step provides export-specific domain separation (F-73)."
        ),
        "cases": [
            {
                "id": "export-import-roundtrip-v1",
                "type": "round_trip",
                "inputs": {
                    "source_vault_id_hex": hexlify(source_vault_id),
                    "export_passphrase_utf8": export_passphrase,
                    "nonce_hex": hexlify(nonce),
                    "items": items,
                },
                "expected": {
                    "bundle_magic_hex": hexlify(MSEXP_MAGIC),
                    "bundle_version": MSEXP_VERSION_V1,
                    "aead_profile_id": AEAD_XCHACHA20_POLY1305_V1,
                    "kdf_profile_id": KDF_ARGON2ID_V1,
                    "kdf_params_hex": base["kdf_params_hex"],
                    "aad_hex": base["aad_hex"],
                    "payload_plaintext_hex": base["plaintext_hex"],
                    "ciphertext_and_tag_hex": base["ciphertext_and_tag_hex"],
                    "bundle_hex": base["bundle_hex"],
                    "expected_items": items,
                },
            },
            {
                "id": "export-import-ciphertext-corruption-v1",
                "type": "ciphertext_corruption",
                "inputs": {
                    "export_passphrase_utf8": export_passphrase,
                    "bundle_hex": tampered_bundle_hex,
                    "flipped_bundle_byte_offset": flipped_offset,
                },
                "expected": {
                    "rejection": "auth",
                },
            },
            {
                "id": "export-import-wrong-decryption-key-v1",
                "type": "wrong_decryption_key",
                "inputs": {
                    "wrong_passphrase_utf8": wrong_passphrase,
                    "bundle_hex": base["bundle_hex"],
                },
                "expected": {
                    "rejection": "auth",
                },
            },
            {
                "id": "export-import-kdf-chain-v1",
                "type": "kdf_chain",
                "inputs": {
                    "source_vault_id_hex": hexlify(source_vault_id),
                    "export_passphrase_utf8": export_passphrase,
                },
                "expected": {
                    "argon2id_salt_hex": hexlify(argon2id_salt(source_vault_id)),
                    "muk_hex": hexlify(muk),
                    "hkdf_info_utf8": EXPORT_BUNDLE_INFO.decode("utf-8"),
                    "aead_key_hex": base["export_key_hex"],
                    "aad_hex": base["aad_hex"],
                },
            },
            {
                "id": "export-import-tag-flip-rejection-v1",
                "type": "tag_flip",
                "inputs": {
                    "export_passphrase_utf8": export_passphrase,
                    "bundle_hex": tag_flipped_bundle_hex,
                    "flipped_bundle_byte_offset": tag_flip_offset,
                },
                "expected": {
                    "rejection": "auth",
                },
            },
            {
                "id": "export-import-unsupported-version-v1",
                "type": "unsupported_version",
                "inputs": {
                    "export_passphrase_utf8": export_passphrase,
                    "bundle_hex": hexlify(bytes(unsupported_version_bundle)),
                },
                "expected": {
                    "rejection": "format",
                },
            },
        ],
    }

    VECTOR_PATH.write_text(json.dumps(vector, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {VECTOR_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
