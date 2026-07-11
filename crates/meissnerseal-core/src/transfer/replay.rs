// SPDX-License-Identifier: Apache-2.0
//! Replay protection for accepted transfer envelope IDs.

use crate::{
    keys::device::Timestamp,
    transfer::protocol::{EnvelopeId, TransferError},
};

const MAX_REPLAY_ENTRIES: u32 = 65_536;

/// Store of previously accepted transfer envelope IDs.
///
/// # Contract
///
/// ## Preconditions
/// - Callers must invoke `check_and_insert` after AEAD decryption and sender
///   signature verification, not before key derivation.
/// - Stored `expires_at` values use Unix time in milliseconds.
///
/// ## Postconditions
/// - Expired entries are evicted before every replay check.
/// - A repeated live `EnvelopeId` returns `Err(ReplayedEnvelopeId)`.
///
/// ## Invariants
/// - The store exposes no public fields; mutation goes through
///   `check_and_insert`.
/// - Parser failures return `Err` with no partial store exposed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SeenEnvelopeIds {
    entries: Vec<(EnvelopeId, Option<Timestamp>)>,
}

impl SeenEnvelopeIds {
    /// Create an empty seen-envelope store.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - None.
    ///
    /// ## Postconditions
    /// - Returns a store containing no accepted envelope IDs.
    ///
    /// ## Invariants
    /// - No IDs can be inserted except through `check_and_insert`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Check whether `id` has already been accepted, then insert it.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - `id` must be the transcript-bound envelope ID from a validated
    ///   transfer envelope.
    /// - `expires_at` must be the same expiry value carried by that envelope.
    ///
    /// ## Postconditions
    /// - Evicts entries whose expiry is in the past before checking `id`.
    /// - Returns `Err(ReplayedEnvelopeId)` when a non-expired matching ID is
    ///   already present.
    /// - Returns `Err(ExpiredEnvelope)` when `expires_at` is already in the
    ///   past and does not insert the ID.
    /// - Inserts `(id, expires_at)` exactly once on success.
    ///
    /// ## Invariants
    /// - Does not log, print, or expose envelope payload data.
    /// - Callers that deserialize a store through `from_bytes` must either
    ///   call `evict_expired()` before relying on the live set, or use
    ///   `check_and_insert()`, which performs eviction eagerly.
    pub fn check_and_insert(
        &mut self,
        id: &EnvelopeId,
        expires_at: Option<Timestamp>,
    ) -> Result<(), TransferError> {
        self.evict_expired();
        let now = unix_time_millis();
        if expires_at.is_some_and(|expires| expires <= now) {
            return Err(TransferError::ExpiredEnvelope);
        }
        if self.entries.iter().any(|(seen_id, _)| seen_id == id) {
            return Err(TransferError::ReplayedEnvelopeId);
        }
        self.entries.push((*id, expires_at));
        Ok(())
    }

    /// Serialize the store to a compact binary representation.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - The store may contain only IDs inserted through `check_and_insert` or
    ///   parsed through `from_bytes`.
    ///
    /// ## Postconditions
    /// - Returns `count:u32le || count * (envelope_id[16] || expires_at:u64le)`.
    /// - `expires_at` is encoded as zero when absent.
    ///
    /// ## Invariants
    /// - Serialization contains only envelope IDs and expiry timestamps, never
    ///   payload plaintext or key material.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for (id, expires_at) in &self.entries {
            out.extend_from_slice(id);
            out.extend_from_slice(&expires_at.unwrap_or(0).to_le_bytes());
        }
        out
    }

    /// Parse a replay store from bytes produced by `to_bytes`.
    ///
    /// # Contract
    ///
    /// ## Preconditions
    /// - `bytes` must use the `count:u32le || entries` format.
    ///
    /// ## Postconditions
    /// - Returns `Err(MalformedReplayStore)` for truncated input or trailing garbage.
    /// - On success, reproduces every serialized ID and expiry value.
    ///
    /// ## Invariants
    /// - Parser is fail-closed and returns no partial store on malformed input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransferError> {
        let mut parser = ReplayByteParser::new(bytes);
        let count = parser.take_u32_le()?;
        if count > MAX_REPLAY_ENTRIES {
            return Err(TransferError::MalformedReplayStore);
        }
        let count = count as usize;
        let mut entries = Vec::with_capacity(count);
        let mut seen_ids = std::collections::HashSet::with_capacity(count);
        for _ in 0..count {
            let id: EnvelopeId = parser.take_array()?;
            let expires_at = match parser.take_u64_le()? {
                0 => None,
                millis => Some(millis),
            };
            if !seen_ids.insert(id) {
                return Err(TransferError::MalformedReplayStore);
            }
            entries.push((id, expires_at));
        }
        if !parser.is_empty() {
            return Err(TransferError::MalformedReplayStore);
        }
        Ok(Self { entries })
    }

    fn evict_expired(&mut self) {
        let now = unix_time_millis();
        self.entries
            .retain(|(_, expires_at)| expires_at.is_none_or(|expires| expires > now));
    }
}

struct ReplayByteParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ReplayByteParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], TransferError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(TransferError::MalformedReplayStore)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(TransferError::MalformedReplayStore)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_u32_le(&mut self) -> Result<u32, TransferError> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    fn take_u64_le(&mut self) -> Result<u64, TransferError> {
        Ok(u64::from_le_bytes(self.take_array()?))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], TransferError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TransferError::MalformedReplayStore)
    }
}

fn unix_time_millis() -> Timestamp {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Timestamp::try_from(millis).unwrap_or(Timestamp::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn seen_ids_allows_different_envelope_ids(first in any::<EnvelopeId>(), second in any::<EnvelopeId>()) {
            prop_assume!(first != second);
            let mut seen = SeenEnvelopeIds::new();

            prop_assert_eq!(seen.check_and_insert(&first, None), Ok(()));
            prop_assert_eq!(seen.check_and_insert(&second, None), Ok(()));
        }

        #[test]
        fn seen_ids_repeated_insert_is_not_idempotent(id in any::<EnvelopeId>()) {
            let mut seen = SeenEnvelopeIds::new();

            prop_assert_eq!(seen.check_and_insert(&id, None), Ok(()));
            prop_assert_eq!(
                seen.check_and_insert(&id, None),
                Err(TransferError::ReplayedEnvelopeId)
            );
        }
    }

    #[test]
    fn seen_ids_rejects_duplicate_envelope_id() {
        let mut seen = SeenEnvelopeIds::new();
        let id = [0xA5; 16];

        assert_eq!(seen.check_and_insert(&id, None), Ok(()));
        assert_eq!(
            seen.check_and_insert(&id, None),
            Err(TransferError::ReplayedEnvelopeId)
        );
    }

    #[test]
    fn seen_ids_evicts_expired_entries_before_check() {
        let mut seen = SeenEnvelopeIds {
            entries: vec![([0x11; 16], Some(past_timestamp()))],
        };
        let id = [0x11; 16];

        assert_eq!(seen.check_and_insert(&id, None), Ok(()));
    }

    #[test]
    fn seen_ids_retains_non_expired_entries() {
        let mut seen = SeenEnvelopeIds::new();
        let id = [0x22; 16];

        assert_eq!(seen.check_and_insert(&id, Some(future_timestamp())), Ok(()));
        assert_eq!(
            seen.check_and_insert(&id, Some(future_timestamp())),
            Err(TransferError::ReplayedEnvelopeId)
        );
    }

    #[test]
    fn insert_on_expired_entry_returns_err() {
        let mut seen = SeenEnvelopeIds::new();
        let id = [0x23; 16];

        assert_eq!(
            seen.check_and_insert(&id, Some(past_timestamp())),
            Err(TransferError::ExpiredEnvelope)
        );
        assert_eq!(seen.to_bytes(), 0u32.to_le_bytes());
    }

    #[test]
    fn seen_ids_roundtrip_serialization() {
        let mut seen = SeenEnvelopeIds::new();
        let first = [0x33; 16];
        let second = [0x44; 16];
        seen.check_and_insert(&first, None).expect("first insert");
        seen.check_and_insert(&second, Some(future_timestamp()))
            .expect("second insert");

        let parsed = SeenEnvelopeIds::from_bytes(&seen.to_bytes()).expect("parse");

        assert_eq!(seen, parsed);
    }

    #[test]
    fn seen_ids_from_bytes_rejects_truncated_input() {
        let mut seen = SeenEnvelopeIds::new();
        seen.check_and_insert(&[0x55; 16], None).expect("insert");
        let mut bytes = seen.to_bytes();
        bytes.pop();

        assert_eq!(
            SeenEnvelopeIds::from_bytes(&bytes),
            Err(TransferError::MalformedReplayStore)
        );
    }

    #[test]
    fn seen_ids_from_bytes_rejects_trailing_garbage() {
        let mut bytes = SeenEnvelopeIds::new().to_bytes();
        bytes.push(0xFF);

        assert_eq!(
            SeenEnvelopeIds::from_bytes(&bytes),
            Err(TransferError::MalformedReplayStore)
        );
    }

    #[test]
    fn seen_ids_from_bytes_rejects_u32_max_entry_count_before_allocation() {
        let bytes = u32::MAX.to_le_bytes();

        assert_eq!(
            SeenEnvelopeIds::from_bytes(&bytes),
            Err(TransferError::MalformedReplayStore)
        );
    }

    #[test]
    fn seen_ids_from_bytes_accepts_max_entry_count() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MAX_REPLAY_ENTRIES.to_le_bytes());
        for value in 0..MAX_REPLAY_ENTRIES {
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.extend_from_slice(&0u64.to_le_bytes());
        }

        let parsed = SeenEnvelopeIds::from_bytes(&bytes).expect("max-count store must parse");
        assert_eq!(parsed.entries.len(), MAX_REPLAY_ENTRIES as usize);
    }

    #[test]
    fn seen_ids_from_bytes_rejects_max_plus_one_entry_count() {
        let bytes = MAX_REPLAY_ENTRIES.saturating_add(1).to_le_bytes();

        assert_eq!(
            SeenEnvelopeIds::from_bytes(&bytes),
            Err(TransferError::MalformedReplayStore)
        );
    }

    #[test]
    fn seen_ids_roundtrip_empty_store() {
        let seen = SeenEnvelopeIds::new();
        assert_eq!(seen.to_bytes(), 0u32.to_le_bytes());
        assert_eq!(
            SeenEnvelopeIds::from_bytes(&seen.to_bytes()).expect("empty parse"),
            seen
        );
    }

    #[test]
    fn seen_ids_to_bytes_matches_known_layout() {
        let seen = SeenEnvelopeIds {
            entries: vec![
                ([0x11; 16], None),
                ([0x22; 16], Some(0x0102_0304_0506_0708)),
            ],
        };

        let mut expected = Vec::new();
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&0u64.to_le_bytes());
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(seen.to_bytes(), expected);
    }

    #[test]
    fn evict_expired_drops_entries_with_expiry_equal_to_now() {
        let now = unix_time_millis();
        let future = future_timestamp();
        let mut seen = SeenEnvelopeIds {
            entries: vec![([0x10; 16], Some(now)), ([0x20; 16], Some(future))],
        };

        seen.evict_expired();

        assert_eq!(seen.entries, vec![([0x20; 16], Some(future))]);
    }

    #[test]
    fn from_bytes_rejects_duplicate_ids() {
        let id = [0xAB; 16];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&id);
        bytes.extend_from_slice(&0u64.to_le_bytes());

        assert_eq!(
            SeenEnvelopeIds::from_bytes(&bytes),
            Err(TransferError::MalformedReplayStore)
        );
    }

    fn past_timestamp() -> Timestamp {
        unix_time_millis().saturating_sub(1_000)
    }

    fn future_timestamp() -> Timestamp {
        unix_time_millis().checked_add(60_000).expect("timestamp")
    }
}
