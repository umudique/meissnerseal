#!/usr/bin/env python3
"""
ML-KEM-768 test vector cross-verification.

Fetches the authoritative NIST ACVP internalProjection.json and verifies
that mlkem_768_kat_v1.json in this directory matches the upstream source
byte-for-byte (upper-case hex).

Usage:
    python3 mlkem_cross_verify.py          # verify all 3 vectors
    python3 mlkem_cross_verify.py --offline  # skip network, check format only

Requirements: no external packages (uses stdlib urllib only).

Source: NIST ACVP-Server ML-KEM-encapDecap-FIPS203/internalProjection.json
        https://github.com/usnistgov/ACVP-Server
"""

import json
import re
import sys
import urllib.request
from pathlib import Path

NIST_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
    "65370b861b96efd30dfe0daae607bde26a78a5c8"
    "/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json"
)
LOCAL_JSON = Path(__file__).parent / "mlkem_768_kat_v1.json"
TC_IDS = {26, 27, 28}
PARAMETER_SET = "ML-KEM-768"
UPPER_HEX_RE = re.compile(r"^[0-9A-F]+$")
FIELD_LENGTHS = {
    "ek": 1184,
    "dk": 2400,
    "c": 1088,
    "k": 32,
    "m": 32,
}




VAL_TG_FIELD_LENGTHS = {"dk": 2400, "ek": 1184}
VAL_CASE_FIELD_LENGTHS = {"c": 1088, "k": 32}
VAL_REASONS = {"modify ciphertext", "no modification"}


def verify_val_format(val_group: dict) -> bool:
    ok = True
    for field, want_bytes in VAL_TG_FIELD_LENGTHS.items():
        value = val_group.get(field, "")
        if not UPPER_HEX_RE.fullmatch(value):
            print(f"  FAIL val_group {field}: expected uppercase hex, got {value[:32]!r}")
            ok = False
        elif len(bytes.fromhex(value)) != want_bytes:
            print(f"  FAIL val_group {field}: got {len(bytes.fromhex(value))} bytes, want {want_bytes}")
            ok = False
    for t in val_group.get("tests", []):
        tc_id = t.get("tcId", "?")
        if t.get("reason") not in VAL_REASONS:
            print(f"  FAIL tcId={tc_id}: unknown reason {t.get('reason')!r}")
            ok = False
        for field, want_bytes in VAL_CASE_FIELD_LENGTHS.items():
            value = t.get(field, "")
            if not UPPER_HEX_RE.fullmatch(value):
                print(f"  FAIL tcId={tc_id} {field}: expected uppercase hex")
                ok = False
            elif len(bytes.fromhex(value)) != want_bytes:
                print(f"  FAIL tcId={tc_id} {field}: got {len(bytes.fromhex(value))} bytes, want {want_bytes}")
                ok = False
    return ok


def verify_val_nist_match(val_group: dict, nist_data: dict) -> bool:
    nist_tg = next(
        (tg for tg in nist_data.get("testGroups", [])
         if tg.get("tgId") == val_group["tgId"]),
        None,
    )
    if nist_tg is None:
        print(f"  FAIL: tgId={val_group['tgId']} not found in NIST data")
        return False
    ok = True
    for field in ("dk", "ek"):
        lv = val_group.get(field, "").upper()
        nv = nist_tg.get(field, "").upper()
        if lv != nv:
            print(f"  FAIL val_group {field} mismatch")
            ok = False
    nist_by_id = {t["tcId"]: t for t in nist_tg["tests"]}
    for t in val_group["tests"]:
        tc_id = t["tcId"]
        nt = nist_by_id.get(tc_id)
        if nt is None:
            print(f"  FAIL tcId={tc_id} not in NIST VAL group")
            ok = False
            continue
        for field in ("c", "k"):
            lv = t.get(field, "").upper()
            nv = nt.get(field, "").upper()
            if lv != nv:
                print(f"  FAIL tcId={tc_id} {field} mismatch")
                ok = False
    return ok


def verify_format(vectors: dict) -> bool:
    ok = True
    for tc_id, v in vectors.items():
        for field, want_bytes in FIELD_LENGTHS.items():
            value = v.get(field, "")
            if not UPPER_HEX_RE.fullmatch(value):
                print(f"  FAIL tcId={tc_id} {field}: expected uppercase hex")
                ok = False
                continue
            got_bytes = len(bytes.fromhex(value))
            if got_bytes != want_bytes:
                print(f"  FAIL tcId={tc_id} {field}: got {got_bytes} bytes, want {want_bytes}")
                ok = False
    return ok


def load_local_full() -> tuple[dict, dict]:
    """Return (aft_by_tcid, val_group) from the local JSON."""
    with LOCAL_JSON.open() as f:
        data = json.load(f)
    assert data.get("schema") == "mlkem-768-kat-v1", "unexpected schema"
    aft = {v["tcId"]: v for v in data["vectors"]}
    val = data.get("val_group", {})
    return aft, val


def main() -> None:
    offline = "--offline" in sys.argv

    local, val_group = load_local_full()
    print(f"Loaded {len(local)} AFT vectors + {len(val_group.get('tests', []))} VAL vectors "
          f"from {LOCAL_JSON.name}")

    if not verify_format(local):
        print("FAIL: AFT vector format errors")
        sys.exit(1)
    print("AFT format check: PASS")

    if val_group:
        if not verify_val_format(val_group):
            print("FAIL: VAL vector format errors")
            sys.exit(1)
        modify_ct = sum(1 for t in val_group["tests"] if t.get("reason") == "modify ciphertext")
        no_mod    = sum(1 for t in val_group["tests"] if t.get("reason") == "no modification")
        print(f"VAL format check: PASS ({modify_ct} implicit-rejection, {no_mod} positive)")

    if offline:
        print("Offline mode — skipping NIST source comparison.")
        print("PASS (format only)")
        return

    print("Fetching NIST data for AFT + VAL comparison ...")
    with urllib.request.urlopen(NIST_URL, timeout=30) as r:
        nist_data = json.loads(r.read())

    # AFT comparison (tcIds 26-28)
    nist_aft = {}
    for tg in nist_data.get("testGroups", []):
        if tg.get("parameterSet") == PARAMETER_SET and tg.get("testType") == "AFT":
            for t in tg["tests"]:
                if t["tcId"] in TC_IDS:
                    nist_aft[t["tcId"]] = {
                        "ek": t["ek"].upper(), "dk": t["dk"].upper(),
                        "c":  t["c"].upper(),  "k":  t["k"].upper(),
                        "m":  t["m"].upper(),
                    }

    failures = []
    for tc_id in sorted(TC_IDS):
        if tc_id not in nist_aft:
            failures.append(f"AFT tcId {tc_id} missing from NIST response")
            continue
        if tc_id not in local:
            failures.append(f"AFT tcId {tc_id} missing from local file")
            continue
        for field in ("ek", "dk", "c", "k", "m"):
            lv = local[tc_id].get(field, "")
            nv = nist_aft[tc_id].get(field, "")
            if lv != nv:
                failures.append(
                    f"AFT tcId {tc_id} field '{field}' mismatch\n"
                    f"  local: {lv[:32]}...\n"
                    f"  nist:  {nv[:32]}..."
                )

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        sys.exit(1)
    print(f"NIST AFT source comparison: {len(TC_IDS)} vectors match — PASS")

    # VAL comparison (tgId=5)
    if val_group:
        if not verify_val_nist_match(val_group, nist_data):
            print("FAIL: VAL vectors do not match NIST source")
            sys.exit(1)
        print(f"NIST VAL source comparison: {len(val_group['tests'])} vectors match — PASS")


if __name__ == "__main__":
    main()
