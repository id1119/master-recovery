//! Protocol data types. This crate intentionally contains no cryptography or I/O.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 2;
pub const PRODUCTION_MIN_DELAY_SECS: u64 = 24 * 60 * 60;

pub type Id32 = [u8; 32];
pub type SignatureBytes = Vec<u8>;
pub type MerkleProofBytes = Vec<u8>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoSuite {
    #[default]
    XWingXChaCha20Poly1305Ed25519,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataMode {
    #[default]
    Off,
    Basic,
    Strong,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum RecoveryState {
    #[default]
    Created,
    AwaitingApprovals,
    Authorized,
    DelayPending,
    Cancelled,
    Releasing,
    Completed,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub protocol_version: u16,
    pub crypto_suite: CryptoSuite,
    pub config_id: Id32,
    pub config_version: u64,
    pub request_id: Id32,
    pub recovery_recipient_key: Vec<u8>,
    pub requested_at: u64,
    pub nonce: Id32,
    pub expiry: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerContribution {
    pub request: RecoveryRequest,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_signature: SignatureBytes,
    pub signer_membership_proof: MerkleProofBytes,
    pub encrypted_a_share: SealedMessage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BeginRecoveryCertificate {
    pub request: RecoveryRequest,
    pub signer_contributions: Vec<SignerContribution>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerCancelCertificate {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub config_version: u64,
    pub request_id: Id32,
    pub request_digest: Id32,
    pub recovery_recipient_key: Vec<u8>,
    pub cancel_response_recipient_key: Vec<u8>,
    pub reason_code: u16,
    pub nonce: Id32,
    pub issued_at: u64,
    pub owner_cancel_public_key: [u8; 32],
    pub owner_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OwnerCancelAck {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub config_version: u64,
    pub request_id: Id32,
    pub request_digest: Id32,
    pub owner_cancel_transcript_digest: Id32,
    pub guardian_index: u16,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseVote {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub config_version: u64,
    pub request_id: Id32,
    pub request_digest: Id32,
    pub recovery_recipient_key: Vec<u8>,
    pub nonce: Id32,
    pub signer_id: u16,
    pub signer_public_key: [u8; 32],
    pub signer_membership_proof: MerkleProofBytes,
    pub signer_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseCertificate {
    pub votes: Vec<ReleaseVote>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingRecovery {
    pub request_id: Id32,
    pub config_id: Id32,
    pub config_version: u64,
    pub recipient: Vec<u8>,
    pub started_at_monotonic: u64,
    pub not_before: u64,
    pub state: RecoveryState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianContribution {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub config_version: u64,
    pub request_id: Id32,
    pub request_digest: Id32,
    pub guardian_index: u16,
    pub ciphertext_fragment: Vec<u8>,
    pub encrypted_dek_share: AeadCiphertext,
    pub merkle_path_proof: MerkleProofBytes,
    pub guardian_signature: SignatureBytes,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryDescriptor {
    pub guardians: Vec<GuardianRoute>,
    pub guardian_material_root: Id32,
    pub data_shards: u16,
    pub total_shards: u16,
    pub ciphertext_len: u64,
    pub payload_nonce: [u8; 24],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianRoute {
    pub mailbox: String,
    pub opaque_slot_id: Id32,
    pub guardian_index: u16,
    pub guardian_public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigCapsule {
    pub protocol_version: u16,
    pub crypto_suite: CryptoSuite,
    pub config_id: Id32,
    pub config_version: u64,
    pub signer_count: u16,
    pub signer_threshold: u16,
    pub guardian_count: u16,
    pub guardian_threshold: u16,
    pub minimum_recovery_delay: u64,
    pub signer_set_commitment: Id32,
    pub owner_cancel_public_key: [u8; 32],
    pub guardian_material_commitment: Id32,
    pub encrypted_recovery_descriptor: AeadCiphertext,
    pub max_request_lifetime: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryCard {
    pub config_id: Id32,
    /// Locators for all redundant config stores that mirror the Config Capsule.
    #[serde(default)]
    pub capsule_locators: Vec<String>,
    /// Backward-compatible single locator used by early protocol-v2 cards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capsule_locator: Option<String>,
    pub signer_mailboxes: Vec<String>,
    /// Relay bases that mirror every mailbox route; a client fails over across them.
    #[serde(default)]
    pub relay_bases: Vec<String>,
    pub signer_set_commitment: Id32,
    pub owner_cancel_public_key: [u8; 32],
}

impl RecoveryCard {
    pub fn all_capsule_locators(&self) -> Vec<&str> {
        let mut locators = Vec::new();
        if let Some(locator) = self.capsule_locator.as_deref() {
            locators.push(locator);
        }
        for locator in &self.capsule_locators {
            if !locators.contains(&locator.as_str()) {
                locators.push(locator);
            }
        }
        locators
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignerPolicy {
    pub config_id: Id32,
    pub config_version: u64,
    pub signer_set_commitment: Id32,
    pub signer_threshold: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianPolicy {
    pub config_id: Id32,
    pub config_version: u64,
    pub signer_set_commitment: Id32,
    pub signer_count: u16,
    pub signer_threshold: u16,
    pub owner_cancel_public_key: [u8; 32],
    pub minimum_recovery_delay: u64,
    pub guardian_material_root: Id32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardianRecord {
    pub opaque_slot_id: Id32,
    pub guardian_index: u16,
    pub ciphertext_fragment: Vec<u8>,
    pub encrypted_dek_share: AeadCiphertext,
    pub merkle_path_proof: MerkleProofBytes,
    pub policy: GuardianPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AeadCiphertext {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SealedMessage {
    pub kem_ciphertext: Vec<u8>,
    pub payload: AeadCiphertext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SetupPolicy {
    pub signer_count: u16,
    pub signer_threshold: u16,
    pub guardian_count: u16,
    pub guardian_threshold: u16,
    pub minimum_recovery_delay: u64,
}

impl Default for SetupPolicy {
    fn default() -> Self {
        Self {
            signer_count: 3,
            signer_threshold: 2,
            guardian_count: 8,
            guardian_threshold: 5,
            minimum_recovery_delay: PRODUCTION_MIN_DELAY_SECS,
        }
    }
}
