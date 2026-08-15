//! Protocol-v3 guardian-epoch and rotation data types.
//!
//! These structures contain no cryptography or I/O. Public capsule/card types
//! deliberately contain commitments only; the guardian roster exists solely
//! in [`RecoveryDescriptorV3`] and private [`RotationPlan`] messages.

use serde::{Deserialize, Serialize};

use crate::{AeadCiphertext, Id32, MerkleProofBytes, SealedMessage, SignatureBytes};

pub const MAX_ROTATION_ACTORS: u16 = 4096;
pub const MAX_CONFIG_WITNESSES: u16 = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ConfigRef {
    pub config_id: Id32,
    pub payload_generation: u64,
    pub authorization_epoch: u64,
    pub guardian_epoch: u64,
    /// Fresh per-epoch value chosen before descriptor/share encryption. The
    /// computed capsule hash is deliberately separate to avoid self-reference.
    pub epoch_binding: Id32,
}

impl ConfigRef {
    #[must_use]
    pub fn is_direct_successor_of(&self, predecessor: &Self) -> bool {
        self.config_id == predecessor.config_id
            && self.payload_generation == predecessor.payload_generation
            && self.authorization_epoch == predecessor.authorization_epoch
            && self.guardian_epoch == predecessor.guardian_epoch.saturating_add(1)
            && self.epoch_binding != predecessor.epoch_binding
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum RotationState {
    #[default]
    Proposed,
    DelayPending,
    Preparing,
    Ready,
    Activating,
    Active,
    Draining,
    Retired,
    Aborted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuardianEpochState {
    #[default]
    Prepared,
    Active,
    Draining,
    Retired,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuardianLifecycle {
    #[default]
    Candidate,
    Healthy,
    Suspect,
    Unavailable,
    Malicious,
    Exiting,
    Retired,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum RotationReason {
    PlannedExit,
    CustodyFailure,
    Unavailable,
    SuspectedCompromise,
    DiversityPolicy,
    #[default]
    ProactiveRefresh,
    SecurityUpgrade,
    OwnerAssistedMigration,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum DpssSuiteId {
    /// Zcash Foundation FROST over Ristretto255: repairable threshold sharing,
    /// followed by its refresh-DKG. Classical and not yet externally audited
    /// for this integration.
    #[default]
    ZfFrostRistretto255RtsRefreshV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum DpssPhase {
    RepairRound1,
    RepairRound2,
    RepairRound3,
    RefreshRound1,
    RefreshRound2,
    Finalize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuardianHealthState {
    #[default]
    Unknown,
    Healthy,
    Degraded,
    Failed,
}

/// Common replay and recipient binding included by every rotation message.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationContext {
    pub protocol_version: u16,
    pub config_ref: ConfigRef,
    pub rotation_id: Id32,
    pub predecessor_capsule_hash: Id32,
    pub recipient_key: Vec<u8>,
    pub nonce: Id32,
    pub issued_at: u64,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianRouteV3 {
    pub guardian_index: u16,
    pub opaque_slot_id: Id32,
    pub mailbox: String,
    pub guardian_public_key: [u8; 32],
    pub session_recipient_key: Vec<u8>,
    pub operator_domain_commitment: Id32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationIntent {
    pub context: RotationContext,
    pub reason: RotationReason,
    pub old_guardian_count: u16,
    pub old_guardian_threshold: u16,
    pub allowed_new_guardian_count: Vec<u16>,
    pub allowed_new_guardian_threshold: Vec<u16>,
    pub allowed_dpss_suites: Vec<DpssSuiteId>,
    pub selection_constraints_commitment: Id32,
    pub witness_read_qc_hash: Id32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRotationIntentContribution {
    pub context: RotationContext,
    pub intent_hash: Id32,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub encrypted_authorization_share: SealedMessage,
    pub signer_signature: SignatureBytes,
}

/// Private, end-to-end sealed plan. Never store this in a public capsule or
/// config-witness record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationPlan {
    pub context: RotationContext,
    pub intent_hash: Id32,
    pub predecessor: ConfigRef,
    pub successor: ConfigRef,
    pub old_roster: Vec<GuardianRouteV3>,
    pub new_roster: Vec<GuardianRouteV3>,
    pub old_roster_commitment: Id32,
    pub new_roster_commitment: Id32,
    pub old_guardian_threshold: u16,
    pub new_guardian_threshold: u16,
    pub data_shards: u16,
    pub total_shards: u16,
    pub dpss_suite: DpssSuiteId,
    pub dpss_session_id: Id32,
    pub dpss_qualified_set_commitment: Id32,
    pub minimum_delay_secs: u64,
    pub preparation_deadline: u64,
    pub drain_deadline: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRotationBeginVote {
    pub context: RotationContext,
    pub intent_hash: Id32,
    pub plan_hash: Id32,
    pub old_roster_commitment: Id32,
    pub new_roster_commitment: Id32,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub signer_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeginRotationCertificate {
    pub context: RotationContext,
    pub intent_hash: Id32,
    pub plan_hash: Id32,
    pub old_roster_commitment: Id32,
    pub new_roster_commitment: Id32,
    pub not_before_wall: u64,
    pub votes: Vec<SignerRotationBeginVote>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerRotationCancelCertificate {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub reason_code: u16,
    pub cancel_response_recipient_key: Vec<u8>,
    pub owner_cancel_public_key: [u8; 32],
    pub owner_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerRotationCancelAck {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub cancel_certificate_hash: Id32,
    pub guardian_index: u16,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRotationReleaseVote {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub begin_certificate_hash: Id32,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub signer_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationReleaseCertificate {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub begin_certificate_hash: Id32,
    pub votes: Vec<SignerRotationReleaseVote>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OldShareUnlockGrant {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub release_certificate_hash: Id32,
    pub old_guardian_index: u16,
    pub encrypted_unwrap_key: SealedMessage,
    /// Independent key for opening the epoch storage envelope around F_i.
    pub encrypted_fragment_key: SealedMessage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewShareWrapGrant {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub release_certificate_hash: Id32,
    pub new_guardian_index: u16,
    pub encrypted_wrap_key: SealedMessage,
    /// Independent key for the successor fragment storage envelope.
    pub encrypted_fragment_key: SealedMessage,
}

/// Authenticated envelope for provider-owned FROST messages. The protocol does
/// not interpret or recreate the provider payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DpssProtocolMessage {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub dpss_suite: DpssSuiteId,
    pub dpss_session_id: Id32,
    pub qualified_set_commitment: Id32,
    pub phase: DpssPhase,
    pub sender_index: u16,
    pub recipient_index: u16,
    pub sequence: u64,
    pub provider_payload: Vec<u8>,
    pub sender_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CiphertextFragmentContribution {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub release_certificate_hash: Id32,
    pub old_guardian_index: u16,
    pub fragment_index: u16,
    pub ciphertext_fragment: Vec<u8>,
    pub fragment_commitment: Id32,
    pub prepared_record_leaf: PreparedRecordLeaf,
    pub merkle_path_proof: MerkleProofBytes,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PreparedRecordLeaf {
    pub guardian_index: u16,
    pub fragment_index: u16,
    pub opaque_slot_id: Id32,
    pub encrypted_share_hash: Id32,
    pub fragment_hash: Id32,
    pub policy_hash: Id32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewGuardianPreparedAck {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub dpss_result_commitment: Id32,
    pub guardian_material_root: Id32,
    pub new_guardian_index: u16,
    pub prepared_record_leaf: PreparedRecordLeaf,
    pub durable_write_generation: u64,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OldGuardianHandoffAck {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub dpss_result_commitment: Id32,
    pub qualified_set_commitment: Id32,
    pub old_guardian_index: u16,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationReadyCertificate {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub successor: ConfigRef,
    pub dpss_result_commitment: Id32,
    pub guardian_material_root: Id32,
    pub encrypted_descriptor_hash: Id32,
    pub prepared_acks: Vec<NewGuardianPreparedAck>,
    pub old_handoff_acks: Vec<OldGuardianHandoffAck>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRotationActivateVote {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub ready_certificate_hash: Id32,
    pub successor_capsule_hash: Id32,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub signer_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationActivateCertificate {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub ready_certificate_hash: Id32,
    pub successor: ConfigRef,
    pub successor_capsule_hash: Id32,
    pub votes: Vec<SignerRotationActivateVote>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessActivationAck {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub activation_certificate_hash: Id32,
    pub witness_id: u16,
    pub predecessor_epoch: u64,
    pub predecessor_capsule_hash: Id32,
    pub successor_epoch: u64,
    pub successor_capsule_hash: Id32,
    pub witness_public_key: [u8; 32],
    pub witness_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessRotationCancelAck {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub rotation_id: Id32,
    pub plan_hash: Id32,
    pub cancel_certificate_hash: Id32,
    pub witness_id: u16,
    pub witness_public_key: [u8; 32],
    pub witness_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochActivationQc {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub rotation_id: Id32,
    pub predecessor_epoch: u64,
    pub predecessor_capsule_hash: Id32,
    pub successor_epoch: u64,
    pub successor_capsule_hash: Id32,
    pub activation_certificate_hash: Id32,
    pub witness_fault_bound: u16,
    pub witness_acks: Vec<WitnessActivationAck>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochReadChallenge {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub client_nonce: Id32,
    pub response_recipient_key: Vec<u8>,
    pub issued_at: u64,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessEpochReadResponse {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub client_nonce: Id32,
    pub witness_id: u16,
    pub highest_guardian_epoch: u64,
    pub capsule_hash: Id32,
    pub witness_public_key: [u8; 32],
    pub witness_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetirementNotice {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub activation_qc_hash: Id32,
    pub retired_epoch: u64,
    pub drain_deadline: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetirementAck {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub activation_qc_hash: Id32,
    pub guardian_index: u16,
    pub retired_epoch: u64,
    pub tombstone_hash: Id32,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRotationAbortVote {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub state_at_abort: RotationState,
    pub reason_code: u16,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub signer_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AbortRotationCertificate {
    pub context: RotationContext,
    pub plan_hash: Id32,
    pub state_at_abort: RotationState,
    pub reason_code: u16,
    pub votes: Vec<SignerRotationAbortVote>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryRequestV3 {
    pub protocol_version: u16,
    pub config_ref: ConfigRef,
    pub request_id: Id32,
    pub recovery_recipient_key: Vec<u8>,
    pub requested_at: u64,
    pub nonce: Id32,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRecoveryContributionV3 {
    pub request: RecoveryRequestV3,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub encrypted_authorization_share: SealedMessage,
    pub signer_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeginRecoveryCertificateV3 {
    pub request: RecoveryRequestV3,
    pub request_digest: Id32,
    pub signer_contributions: Vec<SignerRecoveryContributionV3>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerRecoveryReleaseVoteV3 {
    pub request: RecoveryRequestV3,
    pub request_digest: Id32,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub signer_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryReleaseCertificateV3 {
    pub request: RecoveryRequestV3,
    pub request_digest: Id32,
    pub votes: Vec<SignerRecoveryReleaseVoteV3>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerRecoveryCancelCertificateV3 {
    pub request: RecoveryRequestV3,
    pub request_digest: Id32,
    pub reason_code: u16,
    pub cancel_response_recipient_key: Vec<u8>,
    pub owner_cancel_public_key: [u8; 32],
    pub owner_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerRecoveryCancelAckV3 {
    pub config_ref: ConfigRef,
    pub request_id: Id32,
    pub request_digest: Id32,
    pub cancel_certificate_hash: Id32,
    pub guardian_index: u16,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianRecoveryContributionV3 {
    pub config_ref: ConfigRef,
    pub request_id: Id32,
    pub request_digest: Id32,
    pub recovery_recipient_key: Vec<u8>,
    pub nonce: Id32,
    pub guardian_index: u16,
    pub fragment_index: u16,
    pub encrypted_ciphertext_fragment: AeadCiphertext,
    pub encrypted_dek_share: AeadCiphertext,
    pub merkle_path_proof: MerkleProofBytes,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryDescriptorV3 {
    pub config_ref: ConfigRef,
    pub guardians: Vec<GuardianRouteV3>,
    pub guardian_material_root: Id32,
    pub data_shards: u16,
    pub total_shards: u16,
    pub ciphertext_len: u64,
    pub payload_nonce: [u8; 24],
    pub dpss_suite: DpssSuiteId,
    pub dpss_public_package: Vec<u8>,
    pub dpss_public_commitment: Id32,
}

/// Public authenticated epoch object. It contains no guardian routes, public
/// guardian keys, opaque slots, or other roster mapping.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigCapsuleV3 {
    pub protocol_version: u16,
    pub config_ref: ConfigRef,
    pub capsule_hash: Id32,
    pub predecessor_capsule_hash: Id32,
    pub signer_count: u16,
    pub signer_threshold: u16,
    pub guardian_count: u16,
    pub guardian_threshold: u16,
    pub minimum_recovery_delay: u64,
    pub max_request_lifetime: u64,
    pub signer_set_commitment: Id32,
    pub owner_cancel_public_key: [u8; 32],
    pub dpss_suite: DpssSuiteId,
    pub dpss_public_commitment: Id32,
    /// Stable commitment to the complete raw ciphertext-fragment set for this
    /// payload generation. Routine guardian rotation retains it.
    pub ciphertext_fragment_root: Id32,
    pub guardian_material_root: Id32,
    pub encrypted_recovery_descriptor: AeadCiphertext,
    pub activation_certificate: Option<RotationActivateCertificate>,
    pub activation_qc: Option<EpochActivationQc>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessPin {
    pub witness_id: u16,
    pub mailbox: String,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryCardV3 {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub signer_mailboxes: Vec<String>,
    pub signer_set_commitment: Id32,
    pub owner_cancel_public_key: [u8; 32],
    pub witness_fault_bound: u16,
    pub witnesses: Vec<WitnessPin>,
    pub relay_bases: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianPolicyV3 {
    pub config_ref: ConfigRef,
    pub epoch_state: GuardianEpochState,
    pub signer_set_commitment: Id32,
    pub signer_count: u16,
    pub signer_threshold: u16,
    pub owner_cancel_public_key: [u8; 32],
    pub minimum_recovery_delay: u64,
    pub guardian_material_root: Id32,
    pub dpss_suite: DpssSuiteId,
    pub dpss_public_commitment: Id32,
    pub predecessor_capsule_hash: Id32,
    pub activation_qc_hash: Option<Id32>,
    pub drain_deadline: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianRecordV3 {
    pub opaque_slot_id: Id32,
    pub guardian_index: u16,
    pub fragment_index: u16,
    pub encrypted_ciphertext_fragment: AeadCiphertext,
    pub encrypted_dek_share: AeadCiphertext,
    pub merkle_path_proof: MerkleProofBytes,
    pub custody_root: Id32,
    pub policy: GuardianPolicyV3,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustodyChallenge {
    pub protocol_version: u16,
    pub config_ref: ConfigRef,
    pub opaque_slot_id: Id32,
    pub challenge_id: Id32,
    pub block_indices: Vec<u32>,
    pub nonce: Id32,
    pub response_recipient_key: Vec<u8>,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustodyBlockProof {
    pub block_index: u32,
    pub block: Vec<u8>,
    pub merkle_path: MerkleProofBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustodyResponse {
    pub protocol_version: u16,
    pub config_ref: ConfigRef,
    pub opaque_slot_id: Id32,
    pub challenge_id: Id32,
    pub nonce: Id32,
    pub guardian_index: u16,
    pub proofs: Vec<CustodyBlockProof>,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianHealthRecord {
    pub config_ref: ConfigRef,
    pub guardian_index: u16,
    pub state: GuardianHealthState,
    pub consecutive_failures: u16,
    pub last_challenge_id: Option<Id32>,
    pub last_success_at: Option<u64>,
    pub evidence_hashes: Vec<Id32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successor_requires_only_guardian_epoch_to_advance() {
        let old = ConfigRef {
            config_id: [1; 32],
            payload_generation: 7,
            authorization_epoch: 4,
            guardian_epoch: 9,
            epoch_binding: [2; 32],
        };
        let mut next = old;
        next.guardian_epoch += 1;
        next.epoch_binding = [3; 32];
        assert!(next.is_direct_successor_of(&old));
        next.payload_generation += 1;
        assert!(!next.is_direct_successor_of(&old));
    }

    #[test]
    fn public_capsule_serialization_has_no_roster_fields() {
        let capsule = ConfigCapsuleV3 {
            protocol_version: crate::PROTOCOL_VERSION_V3,
            config_ref: ConfigRef {
                config_id: [1; 32],
                payload_generation: 1,
                authorization_epoch: 1,
                guardian_epoch: 1,
                epoch_binding: [2; 32],
            },
            capsule_hash: [9; 32],
            predecessor_capsule_hash: [0; 32],
            signer_count: 3,
            signer_threshold: 2,
            guardian_count: 8,
            guardian_threshold: 5,
            minimum_recovery_delay: 10,
            max_request_lifetime: 20,
            signer_set_commitment: [3; 32],
            owner_cancel_public_key: [4; 32],
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: [5; 32],
            ciphertext_fragment_root: [10; 32],
            guardian_material_root: [6; 32],
            encrypted_recovery_descriptor: AeadCiphertext {
                nonce: [7; 24],
                ciphertext: vec![8],
            },
            activation_certificate: None,
            activation_qc: None,
        };
        let value = serde_json::to_value(capsule).unwrap();
        assert!(value.get("guardians").is_none());
        assert!(value.get("old_roster").is_none());
        assert!(value.get("new_roster").is_none());
    }
}
