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
import sys
import urllib.request
from pathlib import Path

NIST_URL = (
    "https://raw.githubusercontent.com/usnistgov/ACVP-Server/master"
    "/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json"
)
LOCAL_JSON = Path(__file__).parent / "mlkem_768_kat_v1.json"
TC_IDS = {26, 27, 28}
PARAMETER_SET = "ML-KEM-768"


def load_local() -> list[dict]:
    with LOCAL_JSON.open() as f:
        data = json.load(f)
    assert data.get("schema") == "mlkem-768-kat-v1", "unexpected schema"
    return {v["tcId"]: v for v in data["vectors"]}


def fetch_nist() -> dict:
    print(f"Fetching {NIST_URL} ...", flush=True)
    with urllib.request.urlopen(NIST_URL, timeout=30) as r:
        data = json.loads(r.read())
    result = {}
    for tg in data.get("testGroups", []):
        if tg.get("parameterSet") == PARAMETER_SET:
            for t in tg["tests"]:
                if t["tcId"] in TC_IDS:
                    result[t["tcId"]] = {
                        "ek": t["ek"].upper(),
                        "dk": t["dk"].upper(),
                        "c":  t["c"].upper(),
                        "k":  t["k"].upper(),
                        "m":  t["m"].upper(),
                    }
    return result


def verify_format(vectors: dict) -> bool:
    ok = True
    for tc_id, v in vectors.items():
        checks = [
            ("dk", len(v.get("dk", "")), 4800),
            ("ek", len(v.get("ek", "")), 2368),
            ("c",  len(v.get("c",  "")), 2176),
            ("k",  len(v.get("k",  "")), 64),
            ("m",  len(v.get("m",  "")), 64),
        ]
        for field, got, want in checks:
            if got != want:
                print(f"  FAIL tcId={tc_id} {field}: got {got} hex chars, want {want}")
                ok = False
    return ok


def main() -> None:
    offline = "--offline" in sys.argv

    local = load_local()
    print(f"Loaded {len(local)} vectors from {LOCAL_JSON.name}")

    if not verify_format(local):
        print("FAIL: local vector format errors")
        sys.exit(1)
    print("Format check: PASS")

    if offline:
        print("Offline mode — skipping NIST source comparison.")
        print("PASS (format only)")
        return

    nist = fetch_nist()
    if len(nist) != len(TC_IDS):
        print(f"FAIL: fetched {len(nist)} vectors from NIST, want {len(TC_IDS)}")
        sys.exit(1)

    failures = []
    for tc_id in sorted(TC_IDS):
        if tc_id not in nist:
            failures.append(f"tcId {tc_id} missing from NIST response")
            continue
        if tc_id not in local:
            failures.append(f"tcId {tc_id} missing from local file")
            continue
        for field in ("ek", "dk", "c", "k", "m"):
            lv = local[tc_id].get(field, "")
            nv = nist[tc_id].get(field, "")
            if lv != nv:
                failures.append(
                    f"tcId {tc_id} field '{field}' mismatch\n"
                    f"  local:  {lv[:32]}...\n"
                    f"  nist:   {nv[:32]}..."
                )

    if failures:
        for f in failures:
            print(f"FAIL: {f}")
        sys.exit(1)

    print(f"NIST source comparison: {len(TC_IDS)} vectors match — PASS")


if __name__ == "__main__":
    main()
