// SPDX-License-Identifier: Apache-2.0
//! Transfer protocol surface.

pub mod envelope;
pub mod protocol;

pub use envelope::{
    compute_transcript_hash, create_envelope, open_envelope, validate_envelope,
    CreateEnvelopeParams, Nonce, OpenEnvelopeParams, TranscriptParams, TransferEnvelope,
    TRANSFER_ENVELOPE_SIGNING_DOMAIN,
};
pub use protocol::{
    EnvelopeId, TransferError, TransferProfileId, CLASSICAL_ALG_ID_X25519, PQC_ALG_ID_MLKEM768,
    TRANSFER_PROFILE_V1_ID,
};
