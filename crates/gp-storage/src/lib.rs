//! Minimal in-memory storage adapters used by both the simulator and tests.

use std::collections::{BTreeMap, BTreeSet};

use gp_types::{ConfigCapsule, GuardianRecord, Id32, SignerPolicy};
use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerState {
    pub signer_id: u16,
    pub mailbox: String,
    pub authorization_share: Vec<u8>,
    pub signing_seed: Id32,
    pub signing_public_key: [u8; 32],
    pub membership_proof: Vec<u8>,
    pub policy: SignerPolicy,
    pub seen_requests: BTreeMap<String, Id32>,
    pub seen_nonces: BTreeSet<Id32>,
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
            authorization_share: vec![1],
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
}
