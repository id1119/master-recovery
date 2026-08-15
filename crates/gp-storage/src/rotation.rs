//! Atomic protocol-v3 rotation persistence models.
//!
//! Production file/database adapters are expected to serialize one complete
//! value per transaction (write-temp, fsync, rename, fsync-directory). These
//! types make the security-relevant transaction boundaries explicit and are
//! shared by the simulator and network persistence layer.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use gp_types::{
    AeadCiphertext, ConfigRef, EpochActivationQc, GuardianEpochState, GuardianRecordV3, Id32,
    RotationState,
};
use serde::{Deserialize, Serialize};

use crate::StorageError;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationTombstone {
    pub rotation_id: Id32,
    pub plan_hash: Id32,
    pub predecessor_capsule_hash: Id32,
    pub terminal_state: RotationState,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DpssSessionJournal {
    pub rotation_id: Id32,
    pub plan_hash: Id32,
    pub session_id: Id32,
    pub qualified_set_digest: Id32,
    pub phase: u16,
    pub next_sequence: u64,
    pub provider_public_journal: Vec<u8>,
    /// Provider secret state encrypted under a node-local, rotation-bound key.
    /// The storage layer never receives its plaintext representation.
    pub encrypted_provider_secret_journal: AeadCiphertext,
}

impl fmt::Debug for DpssSessionJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DpssSessionJournal")
            .field("rotation_id", &self.rotation_id)
            .field("plan_hash", &self.plan_hash)
            .field("session_id", &self.session_id)
            .field("qualified_set_digest", &self.qualified_set_digest)
            .field("phase", &self.phase)
            .field("next_sequence", &self.next_sequence)
            .field("provider_public_journal", &self.provider_public_journal)
            .field("encrypted_provider_secret_journal", &"[ENCRYPTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedGuardianEpoch {
    pub rotation_id: Id32,
    pub plan_hash: Id32,
    pub record: GuardianRecordV3,
    pub durable_write_generation: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DrainingGuardianEpoch {
    pub record: GuardianRecordV3,
    pub capsule_hash: Id32,
    pub drain_deadline: u64,
    pub pending_request_ids: BTreeSet<Id32>,
}

/// One guardian's ACTIVE/PREPARED/DRAINING records. `transaction` is the only
/// mutation primitive intended for backing adapters: failures leave the old
/// value byte-for-byte unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianEpochStore {
    pub config_id: Id32,
    pub expected_predecessor: ConfigRef,
    pub expected_predecessor_capsule_hash: Id32,
    pub active: Option<GuardianRecordV3>,
    pub active_capsule_hash: Option<Id32>,
    pub prepared: Option<PreparedGuardianEpoch>,
    pub draining: BTreeMap<u64, DrainingGuardianEpoch>,
    pub dpss_journal: Option<DpssSessionJournal>,
    pub rotation_tombstones: BTreeMap<String, RotationTombstone>,
    pub recovery_cancellation_tombstones: BTreeMap<String, Id32>,
    pub activation_qc: Option<EpochActivationQc>,
    next_write_generation: u64,
}

impl GuardianEpochStore {
    #[must_use]
    pub fn new(mut active: GuardianRecordV3, active_capsule_hash: Id32) -> Self {
        active.policy.epoch_state = GuardianEpochState::Active;
        let expected_predecessor = active.policy.config_ref;
        Self {
            config_id: expected_predecessor.config_id,
            expected_predecessor,
            expected_predecessor_capsule_hash: active_capsule_hash,
            active: Some(active),
            active_capsule_hash: Some(active_capsule_hash),
            prepared: None,
            draining: BTreeMap::new(),
            dpss_journal: None,
            rotation_tombstones: BTreeMap::new(),
            recovery_cancellation_tombstones: BTreeMap::new(),
            activation_qc: None,
            next_write_generation: 1,
        }
    }

    /// Creates storage for a guardian outside the predecessor roster. It has
    /// no recovery authority until an exact direct-successor QC is committed.
    #[must_use]
    pub fn new_candidate(predecessor: ConfigRef, predecessor_capsule_hash: Id32) -> Self {
        Self {
            config_id: predecessor.config_id,
            expected_predecessor: predecessor,
            expected_predecessor_capsule_hash: predecessor_capsule_hash,
            active: None,
            active_capsule_hash: None,
            prepared: None,
            draining: BTreeMap::new(),
            dpss_journal: None,
            rotation_tombstones: BTreeMap::new(),
            recovery_cancellation_tombstones: BTreeMap::new(),
            activation_qc: None,
            next_write_generation: 1,
        }
    }

    pub fn transaction<T>(
        &mut self,
        inject_failure: bool,
        mutate: impl FnOnce(&mut Self) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let mut candidate = self.clone();
        let result = mutate(&mut candidate)?;
        if inject_failure {
            return Err(StorageError::InjectedFailure);
        }
        *self = candidate;
        Ok(result)
    }

    pub fn prepare_successor(
        &mut self,
        rotation_id: Id32,
        plan_hash: Id32,
        mut record: GuardianRecordV3,
        journal: DpssSessionJournal,
    ) -> Result<u64, StorageError> {
        if self
            .rotation_tombstones
            .contains_key(&hex::encode(rotation_id))
        {
            return Err(StorageError::Replay);
        }
        if self.prepared.is_some() {
            return Err(StorageError::Conflict);
        }
        if !record
            .policy
            .config_ref
            .is_direct_successor_of(&self.expected_predecessor)
            || record.policy.predecessor_capsule_hash != self.expected_predecessor_capsule_hash
            || journal.rotation_id != rotation_id
            || journal.plan_hash != plan_hash
        {
            return Err(StorageError::InvalidEpoch);
        }
        record.policy.epoch_state = GuardianEpochState::Prepared;
        let generation = self.next_write_generation;
        self.next_write_generation = self.next_write_generation.saturating_add(1);
        self.prepared = Some(PreparedGuardianEpoch {
            rotation_id,
            plan_hash,
            record,
            durable_write_generation: generation,
        });
        self.dpss_journal = Some(journal);
        Ok(generation)
    }

    pub fn prepared_ack_generation(
        &self,
        rotation_id: Id32,
        plan_hash: Id32,
    ) -> Result<u64, StorageError> {
        let prepared = self
            .prepared
            .as_ref()
            .ok_or(StorageError::NoPreparedSuccessor)?;
        if prepared.rotation_id != rotation_id || prepared.plan_hash != plan_hash {
            return Err(StorageError::Conflict);
        }
        if prepared.durable_write_generation == 0 {
            return Err(StorageError::NotDurable);
        }
        Ok(prepared.durable_write_generation)
    }

    pub fn activate_successor(
        &mut self,
        rotation_id: Id32,
        plan_hash: Id32,
        qc: EpochActivationQc,
        activation_qc_hash: Id32,
        drain_deadline: u64,
        pending_old_requests: BTreeSet<Id32>,
    ) -> Result<(), StorageError> {
        let prepared = self
            .prepared
            .take()
            .ok_or(StorageError::NoPreparedSuccessor)?;
        if prepared.rotation_id != rotation_id
            || prepared.plan_hash != plan_hash
            || qc.rotation_id != rotation_id
            || qc.predecessor_epoch != self.expected_predecessor.guardian_epoch
            || qc.predecessor_capsule_hash != self.expected_predecessor_capsule_hash
            || qc.successor_epoch != prepared.record.policy.config_ref.guardian_epoch
        {
            self.prepared = Some(prepared);
            return Err(StorageError::InvalidEpoch);
        }

        let predecessor_hash = self.expected_predecessor_capsule_hash;
        if let Some(mut old) = self.active.take() {
            let old_epoch = old.policy.config_ref.guardian_epoch;
            let old_capsule_hash = self
                .active_capsule_hash
                .take()
                .ok_or(StorageError::InvalidEpoch)?;
            old.policy.epoch_state = GuardianEpochState::Draining;
            old.policy.drain_deadline = Some(drain_deadline);
            self.draining.insert(
                old_epoch,
                DrainingGuardianEpoch {
                    record: old,
                    capsule_hash: old_capsule_hash,
                    drain_deadline,
                    pending_request_ids: pending_old_requests,
                },
            );
        } else if !pending_old_requests.is_empty() {
            self.prepared = Some(prepared);
            return Err(StorageError::InvalidEpoch);
        }

        let mut new_active = prepared.record;
        new_active.policy.epoch_state = GuardianEpochState::Active;
        new_active.policy.activation_qc_hash = Some(activation_qc_hash);
        let successor_capsule_hash = qc.successor_capsule_hash;
        self.expected_predecessor = new_active.policy.config_ref;
        self.expected_predecessor_capsule_hash = successor_capsule_hash;
        self.active = Some(new_active);
        self.active_capsule_hash = Some(successor_capsule_hash);
        self.activation_qc = Some(qc);
        self.dpss_journal = None;
        self.rotation_tombstones.insert(
            hex::encode(rotation_id),
            RotationTombstone {
                rotation_id,
                plan_hash,
                predecessor_capsule_hash: predecessor_hash,
                terminal_state: RotationState::Active,
            },
        );
        Ok(())
    }

    pub fn abort_prepared(
        &mut self,
        rotation_id: Id32,
        plan_hash: Id32,
    ) -> Result<(), StorageError> {
        if self.activation_qc.as_ref().map(|qc| qc.rotation_id) == Some(rotation_id) {
            return Err(StorageError::AlreadyActivated);
        }
        if let Some(prepared) = &self.prepared
            && (prepared.rotation_id != rotation_id || prepared.plan_hash != plan_hash)
        {
            return Err(StorageError::Conflict);
        }
        self.prepared = None;
        self.dpss_journal = None;
        self.rotation_tombstones.insert(
            hex::encode(rotation_id),
            RotationTombstone {
                rotation_id,
                plan_hash,
                predecessor_capsule_hash: self.expected_predecessor_capsule_hash,
                terminal_state: RotationState::Aborted,
            },
        );
        Ok(())
    }

    /// Applies a valid successor QC to a guardian removed from the roster. It
    /// retains only its predecessor record for exact draining recoveries.
    pub fn observe_replacement_activation(
        &mut self,
        rotation_id: Id32,
        plan_hash: Id32,
        qc: EpochActivationQc,
        activation_qc_hash: Id32,
        drain_deadline: u64,
        pending_old_requests: BTreeSet<Id32>,
    ) -> Result<(), StorageError> {
        if self.prepared.is_some() || self.active.is_none() {
            return Err(StorageError::Conflict);
        }
        if qc.rotation_id != rotation_id
            || qc.predecessor_epoch != self.expected_predecessor.guardian_epoch
            || qc.predecessor_capsule_hash != self.expected_predecessor_capsule_hash
            || qc.successor_epoch != self.expected_predecessor.guardian_epoch.saturating_add(1)
        {
            return Err(StorageError::InvalidEpoch);
        }
        let mut old = self.active.take().ok_or(StorageError::NotFound)?;
        let old_hash = self
            .active_capsule_hash
            .take()
            .ok_or(StorageError::InvalidEpoch)?;
        let old_epoch = old.policy.config_ref.guardian_epoch;
        old.policy.epoch_state = GuardianEpochState::Draining;
        old.policy.drain_deadline = Some(drain_deadline);
        old.policy.activation_qc_hash = Some(activation_qc_hash);
        self.draining.insert(
            old_epoch,
            DrainingGuardianEpoch {
                record: old,
                capsule_hash: old_hash,
                drain_deadline,
                pending_request_ids: pending_old_requests,
            },
        );
        self.activation_qc = Some(qc);
        self.dpss_journal = None;
        self.rotation_tombstones.insert(
            hex::encode(rotation_id),
            RotationTombstone {
                rotation_id,
                plan_hash,
                predecessor_capsule_hash: old_hash,
                terminal_state: RotationState::Draining,
            },
        );
        Ok(())
    }

    pub fn finish_draining_request(
        &mut self,
        guardian_epoch: u64,
        request_id: Id32,
    ) -> Result<(), StorageError> {
        let draining = self
            .draining
            .get_mut(&guardian_epoch)
            .ok_or(StorageError::NotFound)?;
        draining.pending_request_ids.remove(&request_id);
        Ok(())
    }

    pub fn retire_epoch(
        &mut self,
        guardian_epoch: u64,
        monotonic_now: u64,
    ) -> Result<Id32, StorageError> {
        let draining = self
            .draining
            .get(&guardian_epoch)
            .ok_or(StorageError::NotFound)?;
        if monotonic_now < draining.drain_deadline || !draining.pending_request_ids.is_empty() {
            return Err(StorageError::NotDurable);
        }
        let tombstone_hash = draining.capsule_hash;
        self.draining.remove(&guardian_epoch);
        Ok(tombstone_hash)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRotationStore {
    pub predecessor_plan_locks: BTreeMap<String, Id32>,
    #[serde(default)]
    pub intents: BTreeMap<String, gp_types::RotationIntent>,
    pub intent_votes: BTreeMap<String, Id32>,
    pub begin_votes: BTreeMap<String, Id32>,
    pub release_votes: BTreeMap<String, Id32>,
    pub activate_votes: BTreeMap<String, Id32>,
    pub cancelled_rotations: BTreeMap<String, Id32>,
    pub highest_observed_epoch: BTreeMap<String, u64>,
}

impl SignerRotationStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            predecessor_plan_locks: BTreeMap::new(),
            intents: BTreeMap::new(),
            intent_votes: BTreeMap::new(),
            begin_votes: BTreeMap::new(),
            release_votes: BTreeMap::new(),
            activate_votes: BTreeMap::new(),
            cancelled_rotations: BTreeMap::new(),
            highest_observed_epoch: BTreeMap::new(),
        }
    }

    pub fn lock_plan(
        &mut self,
        predecessor_hash: Id32,
        plan_hash: Id32,
    ) -> Result<(), StorageError> {
        let key = hex::encode(predecessor_hash);
        match self.predecessor_plan_locks.get(&key) {
            Some(existing) if existing != &plan_hash => Err(StorageError::Conflict),
            Some(_) => Ok(()),
            None => {
                self.predecessor_plan_locks.insert(key, plan_hash);
                Ok(())
            }
        }
    }

    pub fn record_vote(
        votes: &mut BTreeMap<String, Id32>,
        rotation_id: Id32,
        transcript_hash: Id32,
    ) -> Result<(), StorageError> {
        let key = hex::encode(rotation_id);
        match votes.get(&key) {
            Some(existing) if existing != &transcript_hash => Err(StorageError::Conflict),
            Some(_) => Ok(()),
            None => {
                votes.insert(key, transcript_hash);
                Ok(())
            }
        }
    }
}

impl Default for SignerRotationStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessEpochStore {
    pub config_id: Id32,
    pub highest_guardian_epoch: u64,
    pub highest_capsule_hash: Id32,
    pub predecessor_locks: BTreeMap<String, Id32>,
    pub seen_read_nonces: BTreeSet<Id32>,
}

impl WitnessEpochStore {
    #[must_use]
    pub fn new(config_ref: ConfigRef, capsule_hash: Id32) -> Self {
        Self {
            config_id: config_ref.config_id,
            highest_guardian_epoch: config_ref.guardian_epoch,
            highest_capsule_hash: capsule_hash,
            predecessor_locks: BTreeMap::new(),
            seen_read_nonces: BTreeSet::new(),
        }
    }

    /// Models the atomic "store successor, then acknowledge" witness write.
    pub fn persist_successor_before_ack(
        &mut self,
        predecessor: ConfigRef,
        predecessor_capsule_hash: Id32,
        successor: ConfigRef,
        successor_capsule_hash: Id32,
    ) -> Result<(), StorageError> {
        if !successor.is_direct_successor_of(&predecessor) {
            return Err(StorageError::InvalidEpoch);
        }
        let predecessor_key = hex::encode(predecessor_capsule_hash);
        if let Some(existing) = self.predecessor_locks.get(&predecessor_key) {
            return if existing == &successor_capsule_hash {
                Ok(())
            } else {
                Err(StorageError::Conflict)
            };
        }
        if predecessor.config_id != self.config_id
            || predecessor.guardian_epoch != self.highest_guardian_epoch
            || predecessor_capsule_hash != self.highest_capsule_hash
        {
            return Err(StorageError::InvalidEpoch);
        }
        self.predecessor_locks
            .insert(predecessor_key, successor_capsule_hash);
        self.highest_guardian_epoch = successor.guardian_epoch;
        self.highest_capsule_hash = successor_capsule_hash;
        Ok(())
    }

    /// Releases a merely pending one-child lock after an authenticated owner
    /// rotation cancellation. An already activated successor cannot be
    /// reverted through this path.
    pub fn cancel_pending_successor(
        &mut self,
        predecessor_epoch: u64,
        predecessor_capsule_hash: Id32,
        successor_epoch: u64,
        successor_capsule_hash: Id32,
    ) -> Result<(), StorageError> {
        let predecessor_key = hex::encode(predecessor_capsule_hash);
        if successor_epoch != predecessor_epoch.saturating_add(1)
            || self.highest_guardian_epoch != successor_epoch
            || self.highest_capsule_hash != successor_capsule_hash
            || self.predecessor_locks.get(&predecessor_key) != Some(&successor_capsule_hash)
        {
            return Err(StorageError::Conflict);
        }
        self.predecessor_locks.remove(&predecessor_key);
        self.highest_guardian_epoch = predecessor_epoch;
        self.highest_capsule_hash = predecessor_capsule_hash;
        Ok(())
    }

    pub fn observe_read_nonce(&mut self, nonce: Id32) -> Result<(), StorageError> {
        if self.seen_read_nonces.insert(nonce) {
            Ok(())
        } else {
            Err(StorageError::Replay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_types::{DpssSuiteId, GuardianPolicyV3};

    fn config(epoch: u64, marker: u8) -> ConfigRef {
        ConfigRef {
            config_id: [1; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: epoch,
            epoch_binding: [marker; 32],
        }
    }

    fn record(epoch: u64, marker: u8) -> GuardianRecordV3 {
        let config_ref = config(epoch, marker);
        GuardianRecordV3 {
            opaque_slot_id: [marker; 32],
            guardian_index: 1,
            fragment_index: 1,
            encrypted_ciphertext_fragment: gp_types::AeadCiphertext {
                nonce: [marker.wrapping_add(1); 24],
                ciphertext: vec![marker; 32],
            },
            encrypted_dek_share: gp_types::AeadCiphertext {
                nonce: [marker; 24],
                ciphertext: vec![marker; 32],
            },
            merkle_path_proof: vec![],
            custody_root: [marker; 32],
            policy: GuardianPolicyV3 {
                config_ref,
                epoch_state: GuardianEpochState::Prepared,
                signer_set_commitment: [2; 32],
                signer_count: 3,
                signer_threshold: 2,
                owner_cancel_public_key: [3; 32],
                minimum_recovery_delay: 10,
                guardian_material_root: [4; 32],
                dpss_suite: DpssSuiteId::default(),
                dpss_public_commitment: [5; 32],
                predecessor_capsule_hash: if epoch == 1 { [0; 32] } else { [1; 32] },
                activation_qc_hash: None,
                drain_deadline: None,
            },
        }
    }

    fn journal() -> DpssSessionJournal {
        DpssSessionJournal {
            rotation_id: [6; 32],
            plan_hash: [7; 32],
            session_id: [8; 32],
            qualified_set_digest: [9; 32],
            phase: 1,
            next_sequence: 1,
            provider_public_journal: vec![10],
            encrypted_provider_secret_journal: AeadCiphertext {
                nonce: [10; 24],
                ciphertext: vec![11; 48],
            },
        }
    }

    #[test]
    fn failed_atomic_prepare_leaves_old_active_and_no_prepared_record() {
        let mut store = GuardianEpochStore::new(record(1, 1), [1; 32]);
        let before = serde_json::to_vec(&store).unwrap();
        assert_eq!(
            store.transaction(true, |candidate| {
                candidate.prepare_successor([6; 32], [7; 32], record(2, 2), journal())
            }),
            Err(StorageError::InjectedFailure)
        );
        assert_eq!(before, serde_json::to_vec(&store).unwrap());
        assert_eq!(
            store.active.as_ref().unwrap().policy.epoch_state,
            GuardianEpochState::Active
        );
        assert!(store.prepared.is_none());
    }

    #[test]
    fn prepared_ack_is_available_only_after_transaction_commit() {
        let mut store = GuardianEpochStore::new(record(1, 1), [1; 32]);
        let generation = store
            .transaction(false, |candidate| {
                candidate.prepare_successor([6; 32], [7; 32], record(2, 2), journal())
            })
            .unwrap();
        assert_eq!(
            store.prepared_ack_generation([6; 32], [7; 32]),
            Ok(generation)
        );
        assert_eq!(
            store.active.as_ref().unwrap().policy.epoch_state,
            GuardianEpochState::Active
        );
        assert_eq!(
            store.prepared.as_ref().unwrap().record.policy.epoch_state,
            GuardianEpochState::Prepared
        );
    }

    #[test]
    fn abort_erases_prepared_and_secret_journal_but_preserves_active() {
        let mut store = GuardianEpochStore::new(record(1, 1), [1; 32]);
        store
            .prepare_successor([6; 32], [7; 32], record(2, 2), journal())
            .unwrap();
        store.abort_prepared([6; 32], [7; 32]).unwrap();
        assert!(store.prepared.is_none());
        assert!(store.dpss_journal.is_none());
        assert_eq!(
            store.active.as_ref().unwrap().policy.config_ref,
            config(1, 1)
        );
        assert_eq!(
            store.rotation_tombstones[&hex::encode([6; 32])].terminal_state,
            RotationState::Aborted
        );
    }

    #[test]
    fn witness_lock_survives_retry_and_rejects_sibling() {
        let old = config(1, 1);
        let next = config(2, 2);
        let sibling = config(2, 3);
        let mut witness = WitnessEpochStore::new(old, [1; 32]);
        witness
            .persist_successor_before_ack(old, [1; 32], next, [2; 32])
            .unwrap();
        assert_eq!(
            witness.persist_successor_before_ack(old, [1; 32], next, [2; 32]),
            Ok(())
        );
        assert_eq!(
            witness.persist_successor_before_ack(old, [1; 32], sibling, [3; 32]),
            Err(StorageError::Conflict)
        );
        let encoded = serde_json::to_vec(&witness).unwrap();
        let mut rebooted: WitnessEpochStore = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            rebooted.persist_successor_before_ack(old, [1; 32], sibling, [3; 32]),
            Err(StorageError::Conflict)
        );
    }

    #[test]
    fn owner_cancel_releases_only_the_exact_pending_witness_child() {
        let old = config(1, 1);
        let next = config(2, 2);
        let sibling = config(2, 3);
        let mut witness = WitnessEpochStore::new(old, [1; 32]);
        witness
            .persist_successor_before_ack(old, [1; 32], next, [2; 32])
            .unwrap();
        assert_eq!(
            witness.cancel_pending_successor(1, [1; 32], 2, [3; 32]),
            Err(StorageError::Conflict)
        );
        witness
            .cancel_pending_successor(1, [1; 32], 2, [2; 32])
            .unwrap();
        witness
            .persist_successor_before_ack(old, [1; 32], sibling, [3; 32])
            .unwrap();
        assert_eq!(witness.highest_capsule_hash, [3; 32]);
    }

    #[test]
    fn encrypted_dpss_journal_debug_does_not_expose_ciphertext_bytes() {
        let debug = format!("{:?}", journal());
        assert!(debug.contains("[ENCRYPTED]"));
        assert!(!debug.contains("11, 11"));
    }
}
