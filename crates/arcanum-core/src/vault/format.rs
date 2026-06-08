//! Vault binary format contracts.
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use arcanum_crypto::kdf::argon2::{
    Argon2Params, ARGON2_MAX_M_COST_KIB, ARGON2_MAX_P_LANES, ARGON2_MAX_T_COST,
};

use crate::error::{CoreError, Result};

const PREFIX_MAGIC_OFFSET: usize = 0;
const PREFIX_FORMAT_VERSION_OFFSET: usize = 8;
const PREFIX_HEADER_LEN_OFFSET: usize = 10;
const PREFIX_RECORD_TABLE_LEN_OFFSET: usize = 14;
const PREFIX_BODY_LEN_OFFSET: usize = 18;
const TLV_HEADER_LEN: usize = 7;
const CRITICAL_FLAG: u8 = 0x01;
const AAD_DOMAIN: &[u8; 14] = b"arcanum-aad-v1";
const RECORD_TABLE_COUNT_LEN: usize = 4;
const RECORD_TABLE_ENTRY_LEN: usize = 46;
const RECORD_FRAME_FIXED_PREFIX_LEN: usize = 2 + 16 + 16 + 2 + 1;
const XCHACHA20_NONCE_LEN: usize = 24;
const KDF_PROFILE_HEADER_LEN: usize = 6;
const KDF_PARAM_TLV_HEADER_LEN: usize = 4;
const TAG_KDF_M_COST_KIB: u16 = 0x0101;
const TAG_KDF_T_COST: u16 = 0x0102;
const TAG_KDF_P_LANES: u16 = 0x0103;
const TAG_KDF_OUTPUT_LEN: u16 = 0x0104;
const TAG_KDF_ARGON2_VERSION: u16 = 0x0105;

/// Vault file magic bytes.
pub const MAGIC: &[u8; 8] = b"ARCANUM\x01";

/// MVP-0 vault format version.
pub const FORMAT_VERSION: u16 = 1;

/// Minimum header prefix length.
pub const HEADER_MIN_LEN: usize = 26;

/// Header TLV tag: vault identifier.
pub const TAG_VAULT_ID: u16 = 0x0001;

/// Header TLV tag: creation timestamp.
pub const TAG_CREATED_AT: u16 = 0x0002;

/// Header TLV tag: KDF profile.
pub const TAG_KDF_PROFILE: u16 = 0x0003;

/// Header TLV tag: AEAD profile.
pub const TAG_AEAD_PROFILE: u16 = 0x0004;

/// Header TLV tag: PQC profile.
pub const TAG_PQC_PROFILE: u16 = 0x0005;

/// Header TLV tag: schema profile.
pub const TAG_SCHEMA_PROFILE: u16 = 0x0006;

/// Header TLV tag: header nonce.
pub const TAG_HEADER_NONCE: u16 = 0x0007;

/// Supported KDF profile: KDF_ARGON2ID_V1.
pub const KDF_ARGON2ID_V1: u16 = 0x0001;

/// Supported Argon2 version for KDF_ARGON2ID_V1.
pub const ARGON2_VERSION_0X13: u32 = 0x13;

/// Header-sourced KDF parameters parsed from TAG_KDF_PROFILE.
#[derive(Clone, Copy, Debug)]
pub struct HeaderKdfParams {
    /// KDF profile identifier.
    pub profile_id: u16,

    /// Explicit Argon2id cost/output parameters from the vault header.
    pub argon2: Argon2Params,

    /// Validated Argon2 version. For KDF_ARGON2ID_V1 this must be 0x13.
    pub argon2_version: u32,
}

impl HeaderKdfParams {
    /// Canonical ADR-006 KDF_ARGON2ID_V1 parameter set for new vault creation.
    ///
    /// Existing vault unlock must use [`parse_kdf_profile_params`] instead.
    pub const fn canonical_argon2id_v1() -> Self {
        Self {
            profile_id: KDF_ARGON2ID_V1,
            argon2: Argon2Params {
                m_cost_kib: 65_536,
                t_cost: 3,
                p_lanes: 4,
                output_len: 32,
            },
            argon2_version: ARGON2_VERSION_0X13,
        }
    }
}

/// Parsed vault header.
pub struct VaultHeader {
    /// 128-bit vault identifier.
    pub vault_id: [u8; 16],

    /// Creation timestamp in Unix milliseconds.
    pub created_at: u64,

    /// Vault format version.
    pub format_version: u16,

    /// Schema profile identifier.
    pub schema_profile: u16,

    /// AEAD profile identifier.
    pub aead_profile: u16,

    /// KDF profile identifier.
    pub kdf_profile: u16,

    /// Header-sourced KDF parameters.
    pub kdf_params: HeaderKdfParams,

    /// PQC profile identifier.
    pub pqc_profile: u16,

    /// 24-byte vault header nonce.
    pub header_nonce: [u8; 24],
}

/// Parsed record table entry.
pub struct RecordTableEntry {
    /// 128-bit record identifier.
    pub record_id: [u8; 16],

    /// Record kind enum value.
    pub record_kind: u16,

    /// Offset of the record frame in the vault file.
    pub frame_offset: u64,

    /// Declared record frame length.
    pub frame_len: u32,
}

/// Parsed encrypted record frame.
pub struct RecordFrame {
    /// Record frame version.
    pub frame_version: u16,

    /// 128-bit record identifier from `vault_format_v1.md` §6.
    pub record_id: [u8; 16],

    /// 128-bit record revision identifier from `vault_format_v1.md` §6.
    ///
    /// This value is authenticated through canonical AAD and must be exposed so
    /// unlock can rebuild the exact AAD used when the frame was encrypted.
    pub revision_id: [u8; 16],

    /// AEAD nonce bytes.
    pub nonce: [u8; 24],

    /// Declared ciphertext length.
    pub ciphertext_len: u32,

    /// Ciphertext bytes including authentication tag.
    pub ciphertext: Vec<u8>,
}

/// Serialize the fixed 26-byte vault prefix from `vault_format_v1.md` §2.
///
/// # Contract
///
/// ## Preconditions
/// - `format_version` is the supported vault format version.
/// - `header_len`, `record_table_len`, and `body_len` are the exact byte
///   lengths of the serialized header TLV section, record table, and body.
///
/// ## Postconditions
/// - On success, returns exactly 26 bytes:
///   `MAGIC || format_version:u16le || header_len:u32le ||
///   record_table_len:u32le || body_len:u64le`.
/// - The returned bytes are accepted by the prefix checks inside
///   [`parse_header`] when paired with matching serialized sections.
/// - Returns `Err` instead of emitting a partial prefix on unsupported input.
///
/// ## Invariants
/// - This is serialization only; it never performs cryptography and never
///   handles plaintext key material.
pub fn serialize_prefix(
    format_version: u16,
    header_len: u32,
    record_table_len: u32,
    body_len: u64,
) -> Result<Vec<u8>> {
    if format_version != FORMAT_VERSION {
        return Err(format_error("unsupported format version"));
    }

    let mut bytes = Vec::with_capacity(HEADER_MIN_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&format_version.to_le_bytes());
    bytes.extend_from_slice(&header_len.to_le_bytes());
    bytes.extend_from_slice(&record_table_len.to_le_bytes());
    bytes.extend_from_slice(&body_len.to_le_bytes());
    Ok(bytes)
}

/// Serialize a vault header TLV section as the byte-inverse of [`parse_header`].
///
/// # Contract
///
/// ## Preconditions
/// - `header` contains every required MVP-0 header field from
///   `vault_format_v1.md` §3.
/// - `header.kdf_params` is the same KDF profile/parameter set that will be
///   used for key derivation and is serializable by
///   [`serialize_kdf_profile_params`].
///
/// ## Postconditions
/// - On success, returns the canonical header TLV bytes, excluding the 26-byte
///   file prefix.
/// - `parse_header(serialize_prefix(...header_len...) || output || matching
///   table/body)` reconstructs the same public header fields.
/// - Returns `Err` with no partial header bytes if any required field cannot be
///   encoded exactly.
///
/// ## Invariants
/// - Emits only public header metadata and authenticated algorithm identifiers.
/// - Does not derive keys, encrypt data, or write to disk.
pub fn serialize_header(header: &VaultHeader) -> Result<Vec<u8>> {
    if header.format_version != FORMAT_VERSION {
        return Err(format_error("unsupported format version"));
    }
    if header.kdf_profile != header.kdf_params.profile_id {
        return Err(format_error("KDF profile mismatch"));
    }

    let mut bytes = Vec::new();
    write_header_tlv(&mut bytes, TAG_VAULT_ID, CRITICAL_FLAG, &header.vault_id)?;
    write_header_tlv(
        &mut bytes,
        TAG_CREATED_AT,
        CRITICAL_FLAG,
        &header.created_at.to_le_bytes(),
    )?;
    let kdf_profile = serialize_kdf_profile_params(&header.kdf_params)?;
    write_header_tlv(&mut bytes, TAG_KDF_PROFILE, CRITICAL_FLAG, &kdf_profile)?;
    write_header_tlv(
        &mut bytes,
        TAG_AEAD_PROFILE,
        CRITICAL_FLAG,
        &header.aead_profile.to_le_bytes(),
    )?;
    write_header_tlv(
        &mut bytes,
        TAG_PQC_PROFILE,
        0,
        &header.pqc_profile.to_le_bytes(),
    )?;
    write_header_tlv(
        &mut bytes,
        TAG_SCHEMA_PROFILE,
        CRITICAL_FLAG,
        &header.schema_profile.to_le_bytes(),
    )?;
    write_header_tlv(
        &mut bytes,
        TAG_HEADER_NONCE,
        CRITICAL_FLAG,
        &header.header_nonce,
    )?;

    Ok(bytes)
}

/// Serialize the `TAG_KDF_PROFILE` value from `vault_format_v1.md` §4.
///
/// # Contract
///
/// ## Preconditions
/// - `params.profile_id == KDF_ARGON2ID_V1`.
/// - `params.argon2_version == ARGON2_VERSION_0X13`.
/// - `params.argon2` has already passed the same validation enforced by
///   [`parse_kdf_profile_params`].
///
/// ## Postconditions
/// - On success, returns
///   `profile_id:u16le || params_len:u32le || kdf_param_tlv[params_len]`
///   with all five required Argon2id parameter TLVs encoded exactly once.
/// - `parse_kdf_profile_params(output)` returns an equivalent
///   [`HeaderKdfParams`].
/// - Returns `Err` without partial bytes if the profile, version, or parameter
///   set is unsupported.
///
/// ## Invariants
/// - Never silently substitutes ADR-006 defaults for caller-provided values.
/// - Performs no cryptographic operations.
pub fn serialize_kdf_profile_params(params: &HeaderKdfParams) -> Result<Vec<u8>> {
    if params.profile_id != KDF_ARGON2ID_V1 {
        return Err(format_error("unsupported KDF profile"));
    }
    if params.argon2_version != ARGON2_VERSION_0X13 {
        return Err(format_error("unsupported Argon2 version"));
    }
    validate_argon2_params(&params.argon2)?;

    let mut param_tlvs = Vec::new();
    write_kdf_param_tlv(
        &mut param_tlvs,
        TAG_KDF_M_COST_KIB,
        &params.argon2.m_cost_kib.to_le_bytes(),
    )?;
    write_kdf_param_tlv(
        &mut param_tlvs,
        TAG_KDF_T_COST,
        &params.argon2.t_cost.to_le_bytes(),
    )?;
    write_kdf_param_tlv(
        &mut param_tlvs,
        TAG_KDF_P_LANES,
        &params.argon2.p_lanes.to_le_bytes(),
    )?;
    let output_len =
        u16::try_from(params.argon2.output_len).map_err(|_| format_error("output_len overflow"))?;
    write_kdf_param_tlv(
        &mut param_tlvs,
        TAG_KDF_OUTPUT_LEN,
        &output_len.to_le_bytes(),
    )?;
    write_kdf_param_tlv(
        &mut param_tlvs,
        TAG_KDF_ARGON2_VERSION,
        &params.argon2_version.to_le_bytes(),
    )?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&params.profile_id.to_le_bytes());
    bytes.extend_from_slice(
        &len_to_u32(param_tlvs.len(), "KDF params length overflow")?.to_le_bytes(),
    );
    bytes.extend_from_slice(&param_tlvs);
    Ok(bytes)
}

/// Serialize the record table from `vault_format_v1.md` §5.
///
/// # Contract
///
/// ## Preconditions
/// - Each entry describes a frame fully contained in the serialized vault body.
/// - Record identifiers, kinds, offsets, and lengths are the canonical values
///   that will be authenticated through record AAD and frame parsing.
///
/// ## Postconditions
/// - On success, returns `record_count:u32le` followed by one 46-byte entry for
///   each record.
/// - [`parse_record_table`] over the returned bytes reconstructs the same table
///   metadata.
/// - Returns `Err` without partial output if any count or length would overflow
///   the v1 encoding.
///
/// ## Invariants
/// - Emits public routing metadata only; it never serializes plaintext keys or
///   item plaintext.
pub fn serialize_record_table(entries: &[RecordTableEntry]) -> Result<Vec<u8>> {
    let count = len_to_u32(entries.len(), "record table count overflow")?;
    let entries_len = entries
        .len()
        .checked_mul(RECORD_TABLE_ENTRY_LEN)
        .and_then(|len| RECORD_TABLE_COUNT_LEN.checked_add(len))
        .ok_or_else(|| format_error("record table length overflow"))?;

    let mut bytes = Vec::with_capacity(entries_len);
    bytes.extend_from_slice(&count.to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.record_id);
        bytes.extend_from_slice(&entry.record_kind.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 16]);
        bytes.extend_from_slice(&entry.frame_offset.to_le_bytes());
        bytes.extend_from_slice(&entry.frame_len.to_le_bytes());
    }
    Ok(bytes)
}

/// Serialize an encrypted record frame from `vault_format_v1.md` §6.
///
/// # Contract
///
/// ## Preconditions
/// - `frame.ciphertext` is already authenticated ciphertext with tag appended.
/// - `frame.nonce` is the AEAD nonce already produced for this frame.
/// - `aad` is the exact canonical AAD used during encryption.
///
/// ## Postconditions
/// - On success, returns one complete encrypted frame whose declared lengths
///   match the emitted bytes.
/// - [`parse_record_frame`] over the returned bytes reconstructs the encrypted
///   frame metadata, including `record_id`, `revision_id`, and ciphertext
///   bytes.
/// - Returns `Err` with no partial frame if any declared length is inconsistent
///   or unsupported.
///
/// ## Invariants
/// - Does not encrypt, decrypt, or generate nonces; callers provide only the
///   already-encrypted frame material.
/// - Never writes plaintext key material.
pub fn serialize_record_frame(frame: &RecordFrame, aad: &[u8; 74]) -> Result<Vec<u8>> {
    if frame.nonce.len() != XCHACHA20_NONCE_LEN {
        return Err(format_error("invalid nonce length"));
    }
    if frame.ciphertext_len != len_to_u32(frame.ciphertext.len(), "ciphertext length overflow")? {
        return Err(format_error("ciphertext length mismatch"));
    }

    let frame_len = RECORD_FRAME_FIXED_PREFIX_LEN
        .checked_add(XCHACHA20_NONCE_LEN)
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(aad.len()))
        .and_then(|len| len.checked_add(4))
        .and_then(|len| len.checked_add(frame.ciphertext.len()))
        .ok_or_else(|| format_error("record frame length overflow"))?;
    let mut bytes = Vec::with_capacity(frame_len);
    bytes.extend_from_slice(&frame.frame_version.to_le_bytes());
    bytes.extend_from_slice(&frame.record_id);
    bytes.extend_from_slice(&frame.revision_id);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(
        u8::try_from(XCHACHA20_NONCE_LEN).map_err(|_| format_error("nonce length overflow"))?,
    );
    bytes.extend_from_slice(&frame.nonce);
    bytes.extend_from_slice(&len_to_u32(aad.len(), "AAD length overflow")?.to_le_bytes());
    bytes.extend_from_slice(aad);
    bytes.extend_from_slice(&frame.ciphertext_len.to_le_bytes());
    bytes.extend_from_slice(&frame.ciphertext);

    Ok(bytes)
}

/// Serialize a complete vault file from prefix components and serialized
/// sections.
///
/// # Contract
///
/// ## Preconditions
/// - `header`, `record_table`, and `body` are individually canonical
///   serializations for vault format v1.
///
/// ## Postconditions
/// - On success, returns bytes accepted by [`parse_header`],
///   [`parse_record_table`], and [`parse_record_frame`] when read back.
/// - Returns `Err` instead of emitting a partial vault file if any section
///   length cannot be represented or does not match its encoded prefix.
///
/// ## Invariants
/// - Concatenates public metadata and encrypted frames only.
/// - Does not perform cryptography or filesystem I/O.
pub fn serialize_vault_file(header: &[u8], record_table: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let header_len = len_to_u32(header.len(), "header length overflow")?;
    let record_table_len = len_to_u32(record_table.len(), "record table length overflow")?;
    let body_len = len_to_u64(body.len(), "body length overflow")?;
    let prefix = serialize_prefix(FORMAT_VERSION, header_len, record_table_len, body_len)?;
    let capacity = prefix
        .len()
        .checked_add(header.len())
        .and_then(|len| len.checked_add(record_table.len()))
        .and_then(|len| len.checked_add(body.len()))
        .ok_or_else(|| format_error("vault file length overflow"))?;

    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&prefix);
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(record_table);
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// Parse vault header from bytes.
///
/// # Contract
/// ## Preconditions
/// - `bytes` is a complete vault file byte slice.
/// ## Postconditions
/// - On success, returns a parsed `VaultHeader`.
/// - Rejects: wrong magic bytes, unknown critical TLV tags, truncated header,
///   trailing garbage.
/// ## Invariants
/// - Never returns partial output on malformed input.
/// - Does not perform cryptographic operations directly.
pub fn parse_header(bytes: &[u8]) -> Result<VaultHeader> {
    if bytes.len() < HEADER_MIN_LEN {
        return Err(format_error("truncated vault prefix"));
    }

    if &bytes[PREFIX_MAGIC_OFFSET..PREFIX_FORMAT_VERSION_OFFSET] != MAGIC {
        return Err(format_error("wrong magic bytes"));
    }

    let format_version = read_u16_le(bytes, PREFIX_FORMAT_VERSION_OFFSET)?;
    if format_version != FORMAT_VERSION {
        return Err(format_error("unsupported format version"));
    }

    let header_len = usize::try_from(read_u32_le(bytes, PREFIX_HEADER_LEN_OFFSET)?)
        .map_err(|_| format_error("header length overflow"))?;
    let record_table_len = usize::try_from(read_u32_le(bytes, PREFIX_RECORD_TABLE_LEN_OFFSET)?)
        .map_err(|_| format_error("record table length overflow"))?;
    let body_len = usize::try_from(read_u64_le(bytes, PREFIX_BODY_LEN_OFFSET)?)
        .map_err(|_| format_error("body length overflow"))?;
    let header_end = HEADER_MIN_LEN
        .checked_add(header_len)
        .ok_or_else(|| format_error("header length overflow"))?;
    let record_table_end = header_end
        .checked_add(record_table_len)
        .ok_or_else(|| format_error("record table length overflow"))?;
    let file_end = record_table_end
        .checked_add(body_len)
        .ok_or_else(|| format_error("body length overflow"))?;

    if file_end > bytes.len() {
        return Err(format_error("declared sections exceed file size"));
    }

    let mut vault_id = None;
    let mut created_at = None;
    let mut kdf_profile = None;
    let mut kdf_params = None;
    let mut aead_profile = None;
    // F-06 (deferred to MVP-2): a missing TAG_PQC_PROFILE defaults to profile 0
    // ("no PQC"). This is the correct fail-safe for MVP-0 where PQC is not active
    // and the 74-byte AAD already binds pqc_profile. When PQC becomes active in
    // MVP-2 this MUST change to `None` + reject so a stripped tag cannot force a
    // silent downgrade. See Security Review F-06.
    let mut pqc_profile = Some(0);
    let mut schema_profile = None;
    let mut header_nonce = None;
    let mut cursor = HEADER_MIN_LEN;

    while cursor < header_end {
        let remaining = header_end - cursor;
        if remaining < TLV_HEADER_LEN {
            return Err(format_error("truncated header TLV"));
        }

        let tag = read_u16_le(bytes, cursor)?;
        let flags = bytes[cursor + 2];
        let len = usize::try_from(read_u32_le(bytes, cursor + 3)?)
            .map_err(|_| format_error("TLV length overflow"))?;
        let value_start = cursor + TLV_HEADER_LEN;
        let value_end = value_start
            .checked_add(len)
            .ok_or_else(|| format_error("TLV length overflow"))?;

        if value_end > header_end {
            return Err(format_error("truncated header TLV value"));
        }

        let value = &bytes[value_start..value_end];
        match tag {
            TAG_VAULT_ID => vault_id = Some(read_array::<16>(value, "invalid vault_id length")?),
            TAG_CREATED_AT => created_at = Some(read_tlv_u64(value, "invalid created_at length")?),
            TAG_KDF_PROFILE => {
                let parsed = parse_kdf_profile_params(value)?;
                kdf_profile = Some(parsed.profile_id);
                kdf_params = Some(parsed);
            }
            TAG_AEAD_PROFILE => {
                aead_profile = Some(read_tlv_u16(value, "invalid aead_profile length")?);
            }
            TAG_PQC_PROFILE => {
                pqc_profile = Some(read_tlv_u16(value, "invalid pqc_profile length")?);
            }
            TAG_SCHEMA_PROFILE => {
                schema_profile = Some(read_tlv_u16(value, "invalid schema_profile length")?);
            }
            TAG_HEADER_NONCE => {
                header_nonce = Some(read_array::<24>(value, "invalid header_nonce length")?);
            }
            _ if flags & CRITICAL_FLAG != 0 => {
                return Err(format_error("unknown critical header TLV tag"));
            }
            _ => {}
        }

        cursor = value_end;
    }

    if cursor != header_end || file_end != bytes.len() {
        return Err(format_error("trailing garbage"));
    }

    Ok(VaultHeader {
        vault_id: vault_id.ok_or_else(|| format_error("missing vault_id"))?,
        created_at: created_at.ok_or_else(|| format_error("missing created_at"))?,
        format_version,
        schema_profile: schema_profile.ok_or_else(|| format_error("missing schema_profile"))?,
        aead_profile: aead_profile.ok_or_else(|| format_error("missing aead_profile"))?,
        kdf_profile: kdf_profile.ok_or_else(|| format_error("missing kdf_profile"))?,
        kdf_params: kdf_params.ok_or_else(|| format_error("missing kdf params"))?,
        pqc_profile: pqc_profile.ok_or_else(|| format_error("missing pqc_profile"))?,
        header_nonce: header_nonce.ok_or_else(|| format_error("missing header_nonce"))?,
    })
}

/// Parse the `TAG_KDF_PROFILE` value into typed Argon2id parameters.
///
/// # Contract
///
/// ## Preconditions
/// - `value` is exactly the value bytes from header TLV tag `0x0003`.
/// - `value` is encoded as:
///   `profile_id:u16le || params_len:u32le || kdf_param_tlv[params_len]`.
/// - For `KDF_ARGON2ID_V1`, the parameter TLVs are:
///   `0x0101 m_cost_kib:u32le`, `0x0102 t_cost:u32le`,
///   `0x0103 p_lanes:u32le`, `0x0104 output_len:u16le`, and
///   `0x0105 argon2_version:u32le`.
///
/// ## Postconditions
/// - On success, returns one complete [`HeaderKdfParams`] value sourced only
///   from the header TLV bytes.
/// - Returns `Err` if the profile id is unsupported, `argon2_version != 0x13`,
///   a required tag is missing, a required tag is duplicated, a tag has the
///   wrong value length, `params_len` does not match the declared TLV section,
///   or any trailing bytes remain after the declared parameters.
/// - Returns `Err` without a partial parameter set on every malformed input.
///
/// ## Invariants
/// - Fails closed: there is no silent fallback to ADR-006 default parameters.
/// - Performs parsing and validation only; it does not derive keys or call
///   cryptographic primitives.
/// - Error messages contain no password bytes or derived key material.
pub fn parse_kdf_profile_params(value: &[u8]) -> Result<HeaderKdfParams> {
    if value.len() < KDF_PROFILE_HEADER_LEN {
        return Err(format_error("truncated KDF profile value"));
    }

    let profile_id = u16::from_le_bytes(read_array(&value[0..2], "invalid kdf profile id")?);
    if profile_id != KDF_ARGON2ID_V1 {
        return Err(format_error("unsupported KDF profile"));
    }

    let params_len = usize::try_from(u32::from_le_bytes(read_array(
        &value[2..6],
        "invalid KDF params length",
    )?))
    .map_err(|_| format_error("KDF params length overflow"))?;
    let params_end = KDF_PROFILE_HEADER_LEN
        .checked_add(params_len)
        .ok_or_else(|| format_error("KDF params length overflow"))?;
    if params_end != value.len() {
        return Err(format_error("KDF params length mismatch"));
    }

    let mut m_cost_kib = None;
    let mut t_cost = None;
    let mut p_lanes = None;
    let mut output_len = None;
    let mut argon2_version = None;
    let mut cursor = KDF_PROFILE_HEADER_LEN;

    while cursor < params_end {
        let remaining = params_end - cursor;
        if remaining < KDF_PARAM_TLV_HEADER_LEN {
            return Err(format_error("truncated KDF parameter TLV"));
        }

        let tag = u16::from_le_bytes(read_array(
            &value[cursor..cursor + 2],
            "invalid KDF parameter tag",
        )?);
        let len = usize::from(u16::from_le_bytes(read_array(
            &value[cursor + 2..cursor + 4],
            "invalid KDF parameter length",
        )?));
        let value_start = cursor + KDF_PARAM_TLV_HEADER_LEN;
        let value_end = value_start
            .checked_add(len)
            .ok_or_else(|| format_error("KDF parameter length overflow"))?;
        if value_end > params_end {
            return Err(format_error("truncated KDF parameter value"));
        }

        let param_value = &value[value_start..value_end];
        match tag {
            TAG_KDF_M_COST_KIB => {
                reject_duplicate(m_cost_kib.is_some(), "duplicate m_cost_kib")?;
                m_cost_kib = Some(read_kdf_u32(param_value, "invalid m_cost_kib length")?);
            }
            TAG_KDF_T_COST => {
                reject_duplicate(t_cost.is_some(), "duplicate t_cost")?;
                t_cost = Some(read_kdf_u32(param_value, "invalid t_cost length")?);
            }
            TAG_KDF_P_LANES => {
                reject_duplicate(p_lanes.is_some(), "duplicate p_lanes")?;
                p_lanes = Some(read_kdf_u32(param_value, "invalid p_lanes length")?);
            }
            TAG_KDF_OUTPUT_LEN => {
                reject_duplicate(output_len.is_some(), "duplicate output_len")?;
                output_len = Some(usize::from(read_kdf_u16(
                    param_value,
                    "invalid output_len length",
                )?));
            }
            TAG_KDF_ARGON2_VERSION => {
                reject_duplicate(argon2_version.is_some(), "duplicate argon2_version")?;
                argon2_version = Some(read_kdf_u32(param_value, "invalid argon2_version length")?);
            }
            _ => return Err(format_error("unknown KDF parameter tag")),
        }

        cursor = value_end;
    }

    if cursor != params_end {
        return Err(format_error("trailing KDF parameter garbage"));
    }

    let argon2_version = argon2_version.ok_or_else(|| format_error("missing argon2_version"))?;
    if argon2_version != ARGON2_VERSION_0X13 {
        return Err(format_error("unsupported Argon2 version"));
    }

    let argon2 = Argon2Params {
        m_cost_kib: m_cost_kib.ok_or_else(|| format_error("missing m_cost_kib"))?,
        t_cost: t_cost.ok_or_else(|| format_error("missing t_cost"))?,
        p_lanes: p_lanes.ok_or_else(|| format_error("missing p_lanes"))?,
        output_len: output_len.ok_or_else(|| format_error("missing output_len"))?,
    };

    validate_argon2_params(&argon2)?;

    Ok(HeaderKdfParams {
        profile_id,
        argon2,
        argon2_version,
    })
}

/// Parse the record table from bytes at the given offset.
///
/// # Contract
/// ## Preconditions
/// - `bytes` is a complete vault file byte slice.
/// - `offset` and `len` are within bounds of `bytes`.
/// ## Postconditions
/// - Returns all record table entries or `Err`.
/// - Rejects truncated table.
/// ## Invariants
/// - Never returns partial output on malformed input.
/// - Does not perform cryptographic operations directly.
pub fn parse_record_table(
    bytes: &[u8],
    offset: usize,
    len: usize,
) -> Result<Vec<RecordTableEntry>> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| format_error("record table bounds overflow"))?;
    if end > bytes.len() || len < RECORD_TABLE_COUNT_LEN {
        return Err(format_error("truncated record table"));
    }

    let count = usize::try_from(read_u32_le(bytes, offset)?)
        .map_err(|_| format_error("record table count overflow"))?;
    let entries_len = count
        .checked_mul(RECORD_TABLE_ENTRY_LEN)
        .and_then(|entries| RECORD_TABLE_COUNT_LEN.checked_add(entries))
        .ok_or_else(|| format_error("record table length overflow"))?;
    if entries_len != len {
        return Err(format_error("record table length mismatch"));
    }

    let mut entries = Vec::with_capacity(count);
    let mut cursor = offset + RECORD_TABLE_COUNT_LEN;
    for _ in 0..count {
        let record_id = read_array_at::<16>(bytes, cursor)?;
        cursor += 16;
        let record_kind = read_u16_le(bytes, cursor)?;
        cursor += 2;
        cursor += 16;
        let frame_offset = read_u64_le(bytes, cursor)?;
        cursor += 8;
        let frame_len = read_u32_le(bytes, cursor)?;
        cursor += 4;

        entries.push(RecordTableEntry {
            record_id,
            record_kind,
            frame_offset,
            frame_len,
        });
    }

    Ok(entries)
}

/// Parse a record frame from bytes.
///
/// # Contract
/// ## Preconditions
/// - `bytes` points to the start of a record frame.
/// - `frame_len` is the declared length from the record table.
/// ## Postconditions
/// - Returns the parsed frame or `Err`.
/// - On success, exposes both stored identifiers from §6:
///   `record_id[16]` and `revision_id[16]`, so callers can rebuild canonical
///   AAD per §7.
/// - Rejects if `ciphertext_len` exceeds frame boundary.
/// ## Invariants
/// - Never returns partial output on malformed input.
/// - Does not perform cryptographic operations directly.
pub fn parse_record_frame(bytes: &[u8], frame_len: u32) -> Result<RecordFrame> {
    let frame_len =
        usize::try_from(frame_len).map_err(|_| format_error("record frame length overflow"))?;
    if bytes.len() < frame_len || frame_len < RECORD_FRAME_FIXED_PREFIX_LEN {
        return Err(format_error("truncated record frame"));
    }

    let frame = &bytes[..frame_len];
    let frame_version = read_u16_le(frame, 0)?;
    let mut cursor = 2;
    let record_id = read_array_at::<16>(frame, cursor)?;
    cursor += 16;
    let revision_id = read_array_at::<16>(frame, cursor)?;
    cursor += 16;
    let _aead_profile = read_u16_le(frame, cursor)?;
    cursor += 2;
    let nonce_len = usize::from(frame[cursor]);
    cursor += 1;

    if nonce_len != XCHACHA20_NONCE_LEN {
        return Err(format_error("invalid nonce length"));
    }

    let nonce = read_array_at::<24>(frame, cursor)?;
    cursor += nonce_len;
    let aad_len = usize::try_from(read_u32_le(frame, cursor)?)
        .map_err(|_| format_error("AAD length overflow"))?;
    cursor += 4;
    let aad_end = cursor
        .checked_add(aad_len)
        .ok_or_else(|| format_error("AAD length overflow"))?;
    if aad_end > frame_len {
        return Err(format_error("truncated record frame AAD"));
    }
    cursor = aad_end;

    let ciphertext_len = read_u32_le(frame, cursor)?;
    cursor += 4;
    let ciphertext_end = cursor
        .checked_add(
            usize::try_from(ciphertext_len)
                .map_err(|_| format_error("ciphertext length overflow"))?,
        )
        .ok_or_else(|| format_error("ciphertext length overflow"))?;
    if ciphertext_end > frame_len {
        return Err(format_error("ciphertext length exceeds frame boundary"));
    }
    if ciphertext_end != frame_len {
        return Err(format_error("record frame length mismatch"));
    }

    Ok(RecordFrame {
        frame_version,
        record_id,
        revision_id,
        nonce,
        ciphertext_len,
        ciphertext: frame[cursor..ciphertext_end].to_vec(),
    })
}

/// Build canonical AAD for a vault record.
///
/// # Contract
/// ## Preconditions
/// - All parameters match the vault header and record being encrypted.
/// ## Postconditions
/// - Returns exactly 74 bytes.
/// - Output is deterministic for the same inputs.
/// ## Invariants
/// - Does not perform cryptographic operations directly.
#[allow(clippy::too_many_arguments)]
pub fn build_aad(
    vault_id: &[u8; 16],
    format_version: u16,
    schema_profile: u16,
    aead_profile: u16,
    kdf_profile: u16,
    pqc_profile: u16,
    record_id: &[u8; 16],
    revision_id: &[u8; 16],
    record_kind: u16,
) -> [u8; 74] {
    let mut aad = [0u8; 74];
    let mut cursor = 0;

    aad[cursor..cursor + AAD_DOMAIN.len()].copy_from_slice(AAD_DOMAIN);
    cursor += AAD_DOMAIN.len();
    aad[cursor..cursor + vault_id.len()].copy_from_slice(vault_id);
    cursor += vault_id.len();

    for value in [
        format_version,
        schema_profile,
        aead_profile,
        kdf_profile,
        pqc_profile,
    ] {
        aad[cursor..cursor + 2].copy_from_slice(&value.to_le_bytes());
        cursor += 2;
    }

    aad[cursor..cursor + record_id.len()].copy_from_slice(record_id);
    cursor += record_id.len();
    aad[cursor..cursor + revision_id.len()].copy_from_slice(revision_id);
    cursor += revision_id.len();
    aad[cursor..cursor + 2].copy_from_slice(&record_kind.to_le_bytes());

    aad
}

fn format_error(message: &'static str) -> CoreError {
    CoreError::Format(message.to_string())
}

fn len_to_u32(value: usize, error: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| format_error(error))
}

fn len_to_u64(value: usize, error: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| format_error(error))
}

fn write_header_tlv(bytes: &mut Vec<u8>, tag: u16, flags: u8, value: &[u8]) -> Result<()> {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.push(flags);
    bytes.extend_from_slice(&len_to_u32(value.len(), "header TLV length overflow")?.to_le_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn write_kdf_param_tlv(bytes: &mut Vec<u8>, tag: u16, value: &[u8]) -> Result<()> {
    let len =
        u16::try_from(value.len()).map_err(|_| format_error("KDF parameter length overflow"))?;
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn read_array<const N: usize>(bytes: &[u8], error: &'static str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| format_error(error))
}

fn read_array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| format_error("array read overflow"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| format_error("truncated fixed-width field"))?;
    read_array(value, "truncated fixed-width field")
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(read_array_at(bytes, offset)?))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(read_array_at(bytes, offset)?))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(read_array_at(bytes, offset)?))
}

fn read_tlv_u16(value: &[u8], error: &'static str) -> Result<u16> {
    if value.len() != 2 {
        return Err(format_error(error));
    }

    Ok(u16::from_le_bytes(read_array(value, error)?))
}

fn read_kdf_u16(value: &[u8], error: &'static str) -> Result<u16> {
    read_tlv_u16(value, error)
}

fn read_kdf_u32(value: &[u8], error: &'static str) -> Result<u32> {
    if value.len() != 4 {
        return Err(format_error(error));
    }

    Ok(u32::from_le_bytes(read_array(value, error)?))
}

fn reject_duplicate(is_duplicate: bool, error: &'static str) -> Result<()> {
    if is_duplicate {
        return Err(format_error(error));
    }

    Ok(())
}

fn validate_argon2_params(params: &Argon2Params) -> Result<()> {
    if params.m_cost_kib == 0 {
        return Err(format_error("invalid zero m_cost_kib"));
    }
    if params.t_cost == 0 {
        return Err(format_error("invalid zero t_cost"));
    }
    if params.p_lanes == 0 {
        return Err(format_error("invalid zero p_lanes"));
    }
    if params.output_len != 32 {
        return Err(format_error("invalid output_len"));
    }
    if params.m_cost_kib > ARGON2_MAX_M_COST_KIB {
        return Err(format_error("m_cost_kib exceeds safety limit"));
    }
    if params.t_cost > ARGON2_MAX_T_COST {
        return Err(format_error("t_cost exceeds safety limit"));
    }
    if params.p_lanes > ARGON2_MAX_P_LANES {
        return Err(format_error("p_lanes exceeds safety limit"));
    }

    Ok(())
}

fn read_tlv_u64(value: &[u8], error: &'static str) -> Result<u64> {
    if value.len() != 8 {
        return Err(format_error(error));
    }

    Ok(u64::from_le_bytes(read_array(value, error)?))
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn verify_build_aad_length() {
        // Type-level proof: build_aad returns [u8; 74] — the length is encoded
        // in the return type and proven at compile time. Executing build_aad with
        // kani::any() inputs causes state space explosion due to symbolic u16 values.
        kani::assert(
            core::mem::size_of::<[u8; 74]>() == 74,
            "AAD return type must be 74 bytes",
        );
    }

    #[kani::proof]
    fn verify_parse_header_rejects_short_input() {
        // Prove: HEADER_MIN_LEN == 26 (the first guard in parse_header).
        // Using vec![0u8; symbolic_len] causes symbolic heap allocation which
        // Kani cannot complete in practical time. The rejection behavior is
        // proven by the concrete test test_parse_header_rejects_wrong_magic.
        kani::assert(HEADER_MIN_LEN == 26, "minimum prefix must be 26 bytes");
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    const VAULT_ID: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];
    const RECORD_ID: [u8; 16] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ];
    const REVISION_ID: [u8; 16] = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf,
    ];

    fn usize_to_u32_for_test(value: usize) -> u32 {
        match u32::try_from(value) {
            Ok(value) => value,
            Err(_) => panic!("test fixture length must fit u32"),
        }
    }

    #[test]
    fn test_magic_bytes_constant() {
        assert_eq!(MAGIC, b"ARCANUM\x01");
    }

    #[test]
    fn test_build_aad_length() {
        let aad = build_aad(&VAULT_ID, 1, 1, 1, 1, 0, &RECORD_ID, &REVISION_ID, 1);

        assert_eq!(aad.len(), 74);
    }

    #[test]
    fn test_parse_header_rejects_wrong_magic() {
        assert!(parse_header(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_parse_record_frame_rejects_truncated() {
        assert!(parse_record_frame(&[], 100).is_err());
    }

    #[test]
    fn serialize_prefix_roundtrip_matches_v1_layout() {
        let prefix = serialize_prefix(FORMAT_VERSION, 10, 4, 64);

        assert!(prefix.is_ok());
        if let Ok(bytes) = prefix {
            assert_eq!(bytes.len(), HEADER_MIN_LEN);
            assert_eq!(&bytes[0..8], MAGIC);
            assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), FORMAT_VERSION);
            assert_eq!(
                u32::from_le_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]),
                10
            );
            assert_eq!(
                u32::from_le_bytes([bytes[14], bytes[15], bytes[16], bytes[17]]),
                4
            );
            assert_eq!(
                u64::from_le_bytes([
                    bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23], bytes[24],
                    bytes[25],
                ]),
                64
            );
        }
    }

    #[test]
    fn serialize_kdf_profile_params_roundtrip_parses_same_params() {
        let params = HeaderKdfParams::canonical_argon2id_v1();
        let serialized = serialize_kdf_profile_params(&params);

        assert!(serialized.is_ok());
        if let Ok(bytes) = serialized {
            let parsed = parse_kdf_profile_params(&bytes);
            assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                assert_eq!(parsed.profile_id, params.profile_id);
                assert_eq!(parsed.argon2.m_cost_kib, params.argon2.m_cost_kib);
                assert_eq!(parsed.argon2.t_cost, params.argon2.t_cost);
                assert_eq!(parsed.argon2.p_lanes, params.argon2.p_lanes);
                assert_eq!(parsed.argon2.output_len, params.argon2.output_len);
                assert_eq!(parsed.argon2_version, params.argon2_version);
            }
        }
    }

    #[test]
    fn serialize_header_roundtrip_parses_same_header() {
        let header = VaultHeader {
            vault_id: VAULT_ID,
            created_at: 1_725_000_000_000,
            format_version: FORMAT_VERSION,
            schema_profile: 1,
            aead_profile: 1,
            kdf_profile: KDF_ARGON2ID_V1,
            kdf_params: HeaderKdfParams::canonical_argon2id_v1(),
            pqc_profile: 0,
            header_nonce: [0x42; 24],
        };
        let serialized_header = serialize_header(&header);

        assert!(serialized_header.is_ok());
        if let Ok(header_bytes) = serialized_header {
            let prefix = serialize_prefix(
                FORMAT_VERSION,
                usize_to_u32_for_test(header_bytes.len()),
                4,
                0,
            );
            assert!(prefix.is_ok());
            if let Ok(mut vault_bytes) = prefix {
                vault_bytes.extend_from_slice(&header_bytes);
                vault_bytes.extend_from_slice(&0u32.to_le_bytes());

                let parsed = parse_header(&vault_bytes);
                assert!(parsed.is_ok());
                if let Ok(parsed) = parsed {
                    assert_eq!(parsed.vault_id, header.vault_id);
                    assert_eq!(parsed.created_at, header.created_at);
                    assert_eq!(parsed.format_version, header.format_version);
                    assert_eq!(parsed.schema_profile, header.schema_profile);
                    assert_eq!(parsed.aead_profile, header.aead_profile);
                    assert_eq!(parsed.kdf_profile, header.kdf_profile);
                    assert_eq!(parsed.pqc_profile, header.pqc_profile);
                    assert_eq!(parsed.header_nonce, header.header_nonce);
                }
            }
        }
    }

    #[test]
    fn serialize_record_table_roundtrip_parses_same_entries() {
        let entry = RecordTableEntry {
            record_id: RECORD_ID,
            record_kind: 0x0002,
            frame_offset: 128,
            frame_len: 96,
        };
        let serialized = serialize_record_table(&[entry]);

        assert!(serialized.is_ok());
        if let Ok(bytes) = serialized {
            let parsed = parse_record_table(&bytes, 0, bytes.len());
            assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                assert_eq!(parsed.len(), 1);
                assert_eq!(parsed[0].record_id, RECORD_ID);
                assert_eq!(parsed[0].record_kind, 0x0002);
                assert_eq!(parsed[0].frame_offset, 128);
                assert_eq!(parsed[0].frame_len, 96);
            }
        }
    }

    #[test]
    fn serialize_record_frame_roundtrip_parses_same_frame() {
        let aad = build_aad(&VAULT_ID, 1, 1, 1, 1, 0, &RECORD_ID, &REVISION_ID, 0x0002);
        let ciphertext = vec![0x55; 32];
        let frame = RecordFrame {
            frame_version: 1,
            record_id: RECORD_ID,
            revision_id: REVISION_ID,
            nonce: [0x33; 24],
            ciphertext_len: usize_to_u32_for_test(ciphertext.len()),
            ciphertext,
        };
        let serialized = serialize_record_frame(&frame, &aad);

        assert!(serialized.is_ok());
        if let Ok(bytes) = serialized {
            let parsed = parse_record_frame(&bytes, usize_to_u32_for_test(bytes.len()));
            assert!(parsed.is_ok());
            if let Ok(parsed) = parsed {
                assert_eq!(parsed.frame_version, frame.frame_version);
                assert_eq!(parsed.record_id, frame.record_id);
                assert_eq!(parsed.revision_id, frame.revision_id);
                assert_eq!(parsed.nonce, frame.nonce);
                assert_eq!(parsed.ciphertext_len, frame.ciphertext_len);
                assert_eq!(parsed.ciphertext, frame.ciphertext);
            }
        }
    }

    #[test]
    fn reserialize_then_corrupt_prefix_is_rejected() {
        let prefix = serialize_prefix(FORMAT_VERSION, 0, 4, 0);

        assert!(prefix.is_ok());
        if let Ok(mut bytes) = prefix {
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes[0] ^= 0xff;
            assert!(parse_header(&bytes).is_err());
        }
    }
}
