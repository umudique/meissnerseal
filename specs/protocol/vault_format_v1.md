# Arcanum Vault Binary Wire Format v1

**Profile:** `SCHEMA_ARCANUM_RECORDS_V1 = 0x0001`
**Status:** Specification — MVP-0
**Fuzz targets:** `fuzz/fuzz_targets/vault_header.rs`, `fuzz/fuzz_targets/encrypted_item.rs`
**Test vectors:** `test-vectors/vault_format_v1.json`

---

## 1. Design Decisions

- Little-endian throughout
- TLV framing for extensibility
- No `repr(Rust)`, no platform alignment, no implicit struct serialization
- Parsers must reject: non-minimal encodings, truncated sections, trailing garbage, unknown critical TLV tags
- All integer fields are fixed-width

---

## 2. File Prefix

```
magic[8]         = 0x41 0x52 0x43 0x41 0x4e 0x55 0x4d 0x01   # "ARCANUM\x01"
format_version   = u16le          # MVP-0 = 1
header_len       = u32le
record_table_len = u32le
body_len         = u64le
```

Total prefix: **26 bytes**

---

## 3. Header TLV Map

```
HeaderTlv := tag:u16le || flags:u8 || len:u32le || value:bytes[len]
flags bit 0 = critical
```

### Required MVP-0 Tags

| Tag | Name | Encoding | Critical |
|---:|---|---|:---:|
| `0x0001` | `vault_id` | 128-bit random UUID | Yes |
| `0x0002` | `created_at` | Unix ms u64le | Yes |
| `0x0003` | `kdf_profile` | u16le + param TLVs | Yes |
| `0x0004` | `aead_profile` | u16le enum | Yes |
| `0x0005` | `pqc_profile` | u16le enum, 0=none | No (MVP-0) |
| `0x0006` | `schema_profile` | u16le enum | Yes |
| `0x0007` | `header_nonce` | 192-bit random (24 bytes) | Yes |

### Enum Assignments

```
KDF_ARGON2ID_V1              = 0x0001
AEAD_XCHACHA20_POLY1305_V1   = 0x0001
AEAD_AES_256_GCM_STRICT_V1   = 0x0002
PQC_NONE                     = 0x0000
PQC_MLKEM_768_V1             = 0x0001
PQC_MLKEM_1024_V1            = 0x0002
SCHEMA_ARCANUM_RECORDS_V1    = 0x0001
```

---

## 4. KDF Parameter Encoding v1

```
kdf_profile_value := profile_id:u16le || params_len:u32le || kdf_param_tlv[params_len]
KdfParamTlv := tag:u16le || len:u16le || value:bytes[len]
```

### KDF_ARGON2ID_V1 Parameters

| Tag | Name | Type | MVP-0 Value |
|---:|---|---|---:|
| `0x0101` | `m_cost_kib` | u32le | `65536` |
| `0x0102` | `t_cost` | u32le | `3` |
| `0x0103` | `p_lanes` | u32le | `4` |
| `0x0104` | `output_len` | u16le | `32` |
| `0x0105` | `argon2_version` | u32le | `0x13` |

Salt: `"arcanum-argon2id-salt-v1" || vault_id[16]`

---

## 5. Record Table

```
record_count : u32le
repeat record_count:
  record_id[16]
  record_kind : u16le
  revision_id[16]
  frame_offset : u64le
  frame_len : u32le
```

| record_kind | Meaning |
|---:|---|
| `0x0001` | Item |
| `0x0002` | WrappedRootKey |
| `0x0003` | DeviceIdentity |
| `0x0004` | RecoveryKit |
| `0x0005` | AuditEvent |
| `0x0006` | Tombstone |

---

## 6. Encrypted Record Frame

```
frame_version : u16le     # = 1
record_id[16]
revision_id[16]
aead_profile : u16le
nonce_len : u8            # 24 (XChaCha20) or 12 (AES-GCM)
nonce : bytes[nonce_len]
aad_len : u32le
aad : bytes[aad_len]
ciphertext_len : u32le
ciphertext : bytes[ciphertext_len]
```

No implicit padding. Future padding must be an explicit authenticated field.

---

## 7. Associated Data (AAD) v1

```
AAD = "arcanum-aad-v1"      # 14 bytes
   || vault_id              # 16 bytes
   || format_version:u16le  #  2 bytes
   || schema_profile:u16le  #  2 bytes
   || aead_profile:u16le    #  2 bytes
   || kdf_profile:u16le     #  2 bytes
   || pqc_profile:u16le     #  2 bytes
   || record_id             # 16 bytes
   || revision_id           # 16 bytes
   || record_kind:u16le     #  2 bytes
                            # = 74 bytes total
```

**Fixed-width invariant (v1):** All fields are fixed-width. Length-prefixing not required.
Any future variable-length field must include explicit length prefix and new schema_profile version.

---

## 8. Crash-Safe Write Strategy

```
1. Serialize new vault state
2. Encrypt updated records (fresh nonces + record keys)
3. Write to .arcv.tmp
4. fsync .arcv.tmp
5. Atomic rename .arcv.tmp -> .arcv
6. fsync parent directory (where supported)
7. Keep .arcv.bak if backup enabled
```

---

## 9. File Extensions

| Extension | Purpose |
|---|---|
| `.arcv` | Vault file |
| `.arcexp` | Encrypted export bundle |

---

## 10. Parser Rejection Rules

Parsers must reject:
- Wrong magic bytes
- Unsupported format_version
- header_len / record_table_len / body_len exceeding file size
- Unknown critical TLV tags
- nonce_len mismatching AEAD profile
- ciphertext_len exceeding frame boundary
- AEAD authentication failure — no partial plaintext output
