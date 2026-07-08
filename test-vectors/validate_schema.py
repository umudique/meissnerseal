#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Read-only structural validator for MeissnerSeal JSON test vectors."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


VECTOR_DIR = Path(__file__).resolve().parent
HEX_RE = re.compile(r"^[0-9A-Fa-f]*$")
HEX_FIELD_NAMES = {
    "aad",
    "aad_hex",
    "algorithm_id_u16_le",
    "bundle_hex",
    "bundle_magic_hex",
    "c",
    "ciphertext",
    "ciphertext_and_tag_hex",
    "ciphertext_tag",
    "dk",
    "ek",
    "expected_signature",
    "expected_k_prime",
    "expected_transfer_key",
    "export_key_hex",
    "header_hex",
    "input_hex",
    "k",
    "key",
    "kdf_params_hex",
    "kdf_profile_value_hex",
    "m",
    "message",
    "nonce",
    "nonce_hex",
    "param_tlvs_hex",
    "payload_plaintext_hex",
    "plaintext",
    "plaintext_hex",
    "private_key_seed",
    "public_key",
    "record_id",
    "revision_id",
    "sealed_table_ciphertext_tag_hex",
    "sealed_table_plaintext_hex",
    "sealed_table_section_hex",
    "sender_ephemeral_private_key",
    "sender_ephemeral_public_key",
    "source_vault_id_hex",
    "tag",
    "tampered_c_hex",
    "table_aad_hex",
    "table_nonce",
    "transcript_hash",
    "value_hex",
    "vault_file_hex",
    "vault_id",
    "vault_root_key",
    "vkek_nonce",
    "wrap_aad",
    "wrapped_root_key",
    "wrapped_root_key_ciphertext_tag_hex",
    "wrapped_root_key_nonce",
    "wrong_public_key",
    "wrong_vkek_hex",
}


def is_hex_field(name: str) -> bool:
    return (
        name in HEX_FIELD_NAMES
        or name.endswith("_hex")
        or name.endswith("_key")
        or name.endswith("_key_hex")
    )


def validate_hex(path: Path, current_path: str, key: str, value: str, errors: list[str]) -> None:
    if not is_hex_field(key):
        return
    if key == "tag" and value.startswith("0x"):
        value = value[2:]
    if len(value) % 2 != 0:
        errors.append(f"{path.name}:{current_path}: hex string has odd length")
    if not HEX_RE.fullmatch(value):
        errors.append(f"{path.name}:{current_path}: non-hex characters")


def walk(path: Path, value: Any, errors: list[str], current_path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            next_path = f"{current_path}.{key}"
            if isinstance(child, str):
                validate_hex(path, next_path, key, child, errors)
            walk(path, child, errors, next_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(path, child, errors, f"{current_path}[{index}]")


def validate_top_level(path: Path, data: dict[str, Any], errors: list[str]) -> None:
    if "cases" in data:
        required = {"description", "generated_by", "cases"}
        if "profile" in data:
            required |= {"profile", "version"}
        elif "schema" in data:
            required |= {"schema"}
        else:
            errors.append(f"{path.name}: case vector must declare profile/version or schema")
            return
    elif "vectors" in data:
        required = {"schema", "description", "source", "vectors"}
    else:
        errors.append(f"{path.name}: missing cases or vectors")
        return

    missing = sorted(required - data.keys())
    if missing:
        errors.append(f"{path.name}: missing top-level keys: {', '.join(missing)}")

    collection_name = "cases" if "cases" in data else "vectors"
    collection = data.get(collection_name)
    if not isinstance(collection, list) or not collection:
        errors.append(f"{path.name}: {collection_name} must be a non-empty array")


def main() -> int:
    errors: list[str] = []
    for path in sorted(VECTOR_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.name}: invalid JSON: {exc}")
            continue
        if not isinstance(data, dict):
            errors.append(f"{path.name}: top-level JSON value must be an object")
            continue
        validate_top_level(path, data, errors)
        walk(path, data, errors)

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("schema validation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
