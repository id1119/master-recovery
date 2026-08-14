//! Minimal in-memory storage adapters used by both the simulator and tests.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use gp_types::{ConfigCapsule, GuardianRecord, Id32, SignerPolicy};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum StorageError {
    #[error("record was not found")]
    NotFound,
    #[error("stale configuration version")]
    StaleVersion,
    #[error("request is for another signer configuration")]
    WrongConfiguration,
    #[error("request id or nonce has already been observed")]
    Replay,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignerState {
    pub signer_id: u16,
    pub mailbox: String,
    pub authorization_share: Zeroizing<Vec<u8>>,
    pub signing_seed: Id32,
    pub signing_public_key: [u8; 32],
    pub membership_proof: Vec<u8>,
    pub policy: SignerPolicy,
    pub seen_requests: BTreeMap<String, Id32>,
    pub seen_nonces: BTreeSet<Id32>,
}

impl fmt::Debug for SignerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignerState")
            .field("signer_id", &self.signer_id)
            .field("mailbox", &self.mailbox)
            .field("authorization_share", &"[REDACTED]")
            .field("signing_seed", &"[REDACTED]")
            .field("signing_public_key", &self.signing_public_key)
            .field("membership_proof", &self.membership_proof)
            .field("policy", &self.policy)
            .field("seen_requests", &self.seen_requests)
            .field("seen_nonces", &self.seen_nonces)
            .finish()
    }
}

impl SignerState {
    pub fn observe_request(
        &mut self,
        config_id: Id32,
        config_version: u64,
        request_id: Id32,
        nonce: Id32,
        request_digest: Id32,
    ) -> Result<(), StorageError> {
        self.validate_config(config_id, config_version)?;
        let request_key = hex::encode(request_id);
        if self.seen_requests.contains_key(&request_key) || !self.seen_nonces.insert(nonce) {
            return Err(StorageError::Replay);
        }
        self.seen_requests.insert(request_key, request_digest);
        Ok(())
    }

    fn validate_config(&self, config_id: Id32, config_version: u64) -> Result<(), StorageError> {
        if self.policy.config_id != config_id || self.policy.config_version != config_version {
            Err(StorageError::WrongConfiguration)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianState {
    pub guardian_id: u16,
    pub mailbox: String,
    pub signing_seed: Id32,
    records: BTreeMap<Id32, GuardianRecord>,
}

impl GuardianState {
    #[must_use]
    pub fn new(guardian_id: u16, mailbox: String, signing_seed: Id32) -> Self {
        Self {
            guardian_id,
            mailbox,
            signing_seed,
            records: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, record: GuardianRecord) {
        self.records.insert(record.opaque_slot_id, record);
    }

    pub fn get(&self, slot: &Id32) -> Result<&GuardianRecord, StorageError> {
        self.records.get(slot).ok_or(StorageError::NotFound)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfigStore {
    capsules: BTreeMap<Id32, ConfigCapsule>,
}

impl ConfigStore {
    pub fn put(&mut self, capsule: ConfigCapsule) -> Result<(), StorageError> {
        if let Some(existing) = self.capsules.get(&capsule.config_id)
            && capsule.config_version <= existing.config_version
        {
            return Err(StorageError::StaleVersion);
        }
        self.capsules.insert(capsule.config_id, capsule);
        Ok(())
    }

    pub fn get(&self, config_id: &Id32) -> Result<&ConfigCapsule, StorageError> {
        self.capsules.get(config_id).ok_or(StorageError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_rejects_replayed_nonce_and_stale_config() {
        let mut signer = SignerState {
            signer_id: 1,
            mailbox: "opaque".into(),
            authorization_share: Zeroizing::new(vec![1]),
            signing_seed: [2; 32],
            signing_public_key: [4; 32],
            membership_proof: vec![],
            policy: SignerPolicy {
                config_id: [5; 32],
                config_version: 2,
                signer_set_commitment: [6; 32],
                signer_threshold: 2,
            },
            seen_requests: BTreeMap::new(),
            seen_nonces: BTreeSet::new(),
        };
        signer
            .observe_request([5; 32], 2, [8; 32], [9; 32], [10; 32])
            .unwrap();
        assert_eq!(
            signer.observe_request([5; 32], 2, [11; 32], [9; 32], [12; 32]),
            Err(StorageError::Replay)
        );
        assert_eq!(
            signer.observe_request([5; 32], 1, [13; 32], [14; 32], [15; 32]),
            Err(StorageError::WrongConfiguration)
        );
    }

    #[test]
    fn signer_debug_output_redacts_secret_material() {
        let signer = SignerState {
            signer_id: 1,
            mailbox: "opaque".into(),
            authorization_share: Zeroizing::new(vec![0xa5; 33]),
            signing_seed: [0xb6; 32],
            signing_public_key: [0xc7; 32],
            membership_proof: vec![],
            policy: SignerPolicy {
                config_id: [0xd8; 32],
                config_version: 1,
                signer_set_commitment: [0xe9; 32],
                signer_threshold: 1,
            },
            seen_requests: BTreeMap::new(),
            seen_nonces: BTreeSet::new(),
        };

        let debug = format!("{signer:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("165, 165"));
        assert!(!debug.contains("182, 182"));
    }

    #[test]
    fn zeroizing_signer_share_preserves_the_storage_format() {
        let signer = SignerState {
            signer_id: 1,
            mailbox: "opaque".into(),
            authorization_share: Zeroizing::new(vec![1, 2, 3]),
            signing_seed: [4; 32],
            signing_public_key: [5; 32],
            membership_proof: vec![6],
            policy: SignerPolicy {
                config_id: [7; 32],
                config_version: 1,
                signer_set_commitment: [8; 32],
                signer_threshold: 1,
            },
            seen_requests: BTreeMap::new(),
            seen_nonces: BTreeSet::new(),
        };

        let encoded = serde_json::to_vec(&signer).unwrap();
        let decoded: SignerState = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.authorization_share.as_slice(), [1, 2, 3]);
    }
}
