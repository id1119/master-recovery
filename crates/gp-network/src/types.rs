use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use gp_storage::SignerState;
use gp_types::{
    BeginRecoveryCertificate, ConfigCapsule, GuardianContribution, GuardianRecord, Id32,
    OwnerCancelAck, OwnerCancelCertificate, RecoveryRequest, ReleaseCertificate, ReleaseVote,
    SealedMessage, SignerContribution,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub protocol_version: u16,
    pub node_id: String,
    pub role: String,
    pub transport_public_key: Vec<u8>,
    #[serde(default)]
    pub signing_public_key: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "role", content = "state", rename_all = "snake_case")]
pub enum ProvisionPayload {
    Signer(SignerState),
    Guardian(GuardianProvision),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianProvision {
    pub mailbox: String,
    pub guardian_id: u16,
    pub signing_seed: Id32,
    pub record: GuardianRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", content = "body", rename_all = "snake_case")]
pub enum MailboxRequest {
    SignerApprove {
        request: RecoveryRequest,
    },
    SignerRelease {
        request: RecoveryRequest,
    },
    GuardianBegin {
        certificate: BeginRecoveryCertificate,
    },
    GuardianCancel {
        request: RecoveryRequest,
        certificate: Box<OwnerCancelCertificate>,
    },
    GuardianRelease {
        request: RecoveryRequest,
        certificate: ReleaseCertificate,
    },
}

impl MailboxRequest {
    pub fn request(&self) -> &RecoveryRequest {
        match self {
            Self::SignerApprove { request }
            | Self::SignerRelease { request }
            | Self::GuardianCancel { request, .. }
            | Self::GuardianRelease { request, .. } => request,
            Self::GuardianBegin { certificate } => &certificate.request,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "body", rename_all = "snake_case")]
pub enum MailboxResponse {
    SignerContribution(SignerContribution),
    ReleaseVote(ReleaseVote),
    BeginAccepted { not_before_monotonic: u64 },
    CancellationAccepted(OwnerCancelAck),
    ReleaseRefused { reason: String },
    GuardianContribution(GuardianContribution),
}

impl MailboxResponse {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SignerContribution(_) => "signer_contribution",
            Self::ReleaseVote(_) => "release_vote",
            Self::BeginAccepted { .. } => "begin_accepted",
            Self::CancellationAccepted(_) => "cancellation_accepted",
            Self::ReleaseRefused { .. } => "release_refused",
            Self::GuardianContribution(_) => "guardian_contribution",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteRegistration {
    pub mailbox: String,
    pub target_url: String,
    pub transport_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteRecord {
    pub target_url: String,
    pub transport_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelayDisk {
    pub routes: BTreeMap<String, RouteRecord>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfigDisk {
    pub capsules: BTreeMap<String, ConfigCapsule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessConfigProvision {
    pub witness_id: u16,
    pub capsule: gp_types::ConfigCapsuleV3,
    pub signer_public_keys: BTreeMap<u16, [u8; 32]>,
    pub witness_public_keys: BTreeMap<u16, [u8; 32]>,
    pub witness_fault_bound: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessConfigEntry {
    pub witness_id: u16,
    pub register: gp_storage::WitnessEpochStore,
    /// Highest globally activated capsule. Reads never expose a merely stored
    /// successor which has not yet obtained a 2f+1 activation QC.
    pub capsule: gp_types::ConfigCapsuleV3,
    pub pending_capsule: Option<gp_types::ConfigCapsuleV3>,
    pub pending_ack: Option<gp_types::WitnessActivationAck>,
    #[serde(default)]
    pub rotation_cancellations: BTreeMap<String, WitnessRotationCancellation>,
    pub signer_public_keys: BTreeMap<u16, [u8; 32]>,
    pub witness_public_keys: BTreeMap<u16, [u8; 32]>,
    pub witness_fault_bound: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessRotationCancellation {
    pub plan_hash: Id32,
    pub cancel_certificate_hash: Id32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WitnessDisk {
    pub entries: BTreeMap<String, WitnessConfigEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessActivationRequest {
    pub capsule: gp_types::ConfigCapsuleV3,
    pub activation_certificate: gp_types::RotationActivateCertificate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessFinalizeRequest {
    pub activation_qc: gp_types::EpochActivationQc,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessRotationCancelRequest {
    pub certificate: gp_types::OwnerRotationCancelCertificate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessReadEnvelope {
    pub response: gp_types::WitnessEpochReadResponse,
    pub capsule: gp_types::ConfigCapsuleV3,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignerDisk {
    pub entries: BTreeMap<String, SignerState>,
    #[serde(default)]
    pub last_approval_at: BTreeMap<String, u64>,
    #[serde(default)]
    pub rotation_entries: BTreeMap<String, SignerRotationEntryV3>,
}

#[derive(Serialize, Deserialize)]
pub struct OwnerControlFileV3 {
    pub protocol_version: u16,
    pub config_ref: gp_types::ConfigRef,
    pub owner_cancel_signing_seed: Id32,
    pub owner_cancel_public_key: [u8; 32],
    pub guardian_targets: BTreeMap<u16, String>,
    pub relay_bases: Vec<String>,
}

impl Drop for OwnerControlFileV3 {
    fn drop(&mut self) {
        self.owner_cancel_signing_seed.zeroize();
    }
}

impl std::fmt::Debug for OwnerControlFileV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnerControlFileV3")
            .field("protocol_version", &self.protocol_version)
            .field("config_ref", &self.config_ref)
            .field("owner_cancel_signing_seed", &"[REDACTED]")
            .field("owner_cancel_public_key", &self.owner_cancel_public_key)
            .field("guardian_targets", &self.guardian_targets)
            .field("relay_bases", &self.relay_bases)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SignerRotationProvisionV3 {
    pub mailbox: String,
    pub signer_id: u16,
    pub authorization_share: Zeroizing<Vec<u8>>,
    pub signing_seed: Id32,
    pub signing_public_key: [u8; 32],
    pub membership_proof: Vec<u8>,
    pub recovery_card: gp_types::RecoveryCardV3,
    pub active_capsule: gp_types::ConfigCapsuleV3,
}

impl std::fmt::Debug for SignerRotationProvisionV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignerRotationProvisionV3")
            .field("mailbox", &self.mailbox)
            .field("signer_id", &self.signer_id)
            .field("authorization_share", &"[REDACTED]")
            .field("signing_seed", &"[REDACTED]")
            .field("signing_public_key", &self.signing_public_key)
            .field("membership_proof", &self.membership_proof)
            .field("recovery_card", &self.recovery_card)
            .field("active_capsule", &self.active_capsule)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerRotationEntryV3 {
    pub provision: SignerRotationProvisionV3,
    pub security_state: gp_storage::SignerRotationStore,
    pub recovery_requests: BTreeMap<String, Id32>,
    pub recovery_nonces: BTreeSet<Id32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", content = "body", rename_all = "snake_case")]
pub enum SignerRecoveryRequestV3 {
    Approve {
        request: gp_types::RecoveryRequestV3,
        witness_challenge: gp_types::EpochReadChallenge,
        witness_reads: Vec<WitnessReadEnvelope>,
    },
    Release {
        request: gp_types::RecoveryRequestV3,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "body", rename_all = "snake_case")]
pub enum SignerRecoveryResponseV3 {
    Contribution(gp_types::SignerRecoveryContributionV3),
    ReleaseVote(gp_types::SignerRecoveryReleaseVoteV3),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", content = "body", rename_all = "snake_case")]
pub enum SignerRotationRequestV3 {
    Intent {
        intent: gp_types::RotationIntent,
        witness_challenge: gp_types::EpochReadChallenge,
        witness_reads: Vec<WitnessReadEnvelope>,
    },
    Begin {
        intent_hash: Id32,
        plan: gp_types::RotationPlan,
    },
    Release {
        plan: gp_types::RotationPlan,
        begin_certificate: gp_types::BeginRotationCertificate,
    },
    Activate {
        plan: gp_types::RotationPlan,
        ready_certificate: gp_types::RotationReadyCertificate,
        successor_capsule: Box<gp_types::ConfigCapsuleV3>,
    },
    Abort {
        plan: gp_types::RotationPlan,
        state_at_abort: gp_types::RotationState,
        reason_code: u16,
        response_recipient_key: Vec<u8>,
    },
    FinalizeAbort {
        plan: gp_types::RotationPlan,
        certificate: gp_types::AbortRotationCertificate,
        response_recipient_key: Vec<u8>,
    },
    FinalizeOwnerCancel {
        plan: gp_types::RotationPlan,
        certificate: gp_types::OwnerRotationCancelCertificate,
        witness_acks: Vec<gp_types::WitnessRotationCancelAck>,
        response_recipient_key: Vec<u8>,
    },
}

impl SignerRotationRequestV3 {
    pub fn context(&self) -> &gp_types::RotationContext {
        match self {
            Self::Intent { intent, .. } => &intent.context,
            Self::Begin { plan, .. } | Self::Release { plan, .. } | Self::Activate { plan, .. } => {
                &plan.context
            }
            Self::Abort { plan, .. }
            | Self::FinalizeAbort { plan, .. }
            | Self::FinalizeOwnerCancel { plan, .. } => &plan.context,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "body", rename_all = "snake_case")]
pub enum SignerRotationResponseV3 {
    IntentContribution(gp_types::SignerRotationIntentContribution),
    BeginVote(gp_types::SignerRotationBeginVote),
    ReleaseVote(gp_types::SignerRotationReleaseVote),
    ActivateVote(gp_types::SignerRotationActivateVote),
    AbortVote(gp_types::SignerRotationAbortVote),
    AbortFinalized,
    OwnerCancelFinalized,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingNetworkRecovery {
    pub request: RecoveryRequest,
    pub request_digest: Id32,
    pub accepted_wall_time: u64,
    pub started_monotonic: u64,
    pub not_before_monotonic: u64,
    pub boot_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianEntry {
    pub provision: GuardianProvision,
    pub pending: BTreeMap<String, PendingNetworkRecovery>,
    pub cancelled: BTreeMap<String, Id32>,
    #[serde(default)]
    pub released: BTreeMap<String, Id32>,
    pub seen_nonces: BTreeSet<Id32>,
}

impl GuardianEntry {
    pub fn new(provision: GuardianProvision) -> Self {
        Self {
            provision,
            pending: BTreeMap::new(),
            cancelled: BTreeMap::new(),
            released: BTreeMap::new(),
            seen_nonces: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GuardianDisk {
    pub entries: BTreeMap<String, GuardianEntry>,
    #[serde(default)]
    pub rotation_entries: BTreeMap<String, GuardianRotationEntryV3>,
    #[serde(default)]
    pub rotation_aliases: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianRouteAliasV3 {
    pub mailbox: String,
    pub existing_mailbox: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianRotationProvisionV3 {
    pub mailbox: String,
    pub signing_seed: Id32,
    pub signing_public_key: [u8; 32],
    pub recovery_card: gp_types::RecoveryCardV3,
    pub predecessor_capsule: gp_types::ConfigCapsuleV3,
    pub signer_public_keys: BTreeMap<u16, [u8; 32]>,
    pub epoch_store: gp_storage::GuardianEpochStore,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StagedGuardianMaterialV3 {
    pub record_draft: Box<gp_types::GuardianRecordV3>,
    pub leaf: gp_types::PreparedRecordLeaf,
    pub dpss_result_commitment: Id32,
}

impl fmt::Debug for StagedGuardianMaterialV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedGuardianMaterialV3")
            .field("record_draft", &"[LOCAL ENCRYPTED RECORD]")
            .field("leaf", &self.leaf)
            .field("dpss_result_commitment", &self.dpss_result_commitment)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianRotationSessionV3 {
    pub rotation_machine: gp_core::RotationMachine,
    pub plan_hash: Id32,
    pub begin_certificate_hash: Id32,
    pub accepted_wall_time: u64,
    pub started_monotonic: u64,
    pub not_before_monotonic: u64,
    pub boot_id: String,
    pub cancelled: bool,
    pub next_outgoing_sequences: BTreeMap<String, u64>,
    pub next_incoming_sequences: BTreeMap<String, u64>,
    pub encrypted_local_state: Option<gp_types::AeadCiphertext>,
    pub staged_material: Option<StagedGuardianMaterialV3>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardianRotationEntryV3 {
    pub provision: GuardianRotationProvisionV3,
    pub sessions: BTreeMap<String, GuardianRotationSessionV3>,
    pub recoveries: BTreeMap<String, PendingNetworkRecoveryV3>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingNetworkRecoveryV3 {
    pub request: gp_types::RecoveryRequestV3,
    pub request_digest: Id32,
    pub accepted_wall_time: u64,
    pub started_monotonic: u64,
    pub not_before_monotonic: u64,
    pub boot_id: String,
    pub cancelled: bool,
    pub released: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", content = "body", rename_all = "snake_case")]
pub enum GuardianRecoveryRequestV3 {
    Begin {
        certificate: gp_types::BeginRecoveryCertificateV3,
    },
    Cancel {
        request: gp_types::RecoveryRequestV3,
        certificate: gp_types::OwnerRecoveryCancelCertificateV3,
    },
    Release {
        request: gp_types::RecoveryRequestV3,
        certificate: gp_types::RecoveryReleaseCertificateV3,
    },
}

impl GuardianRecoveryRequestV3 {
    pub fn request(&self) -> &gp_types::RecoveryRequestV3 {
        match self {
            Self::Begin { certificate } => &certificate.request,
            Self::Cancel { request, .. } | Self::Release { request, .. } => request,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "body", rename_all = "snake_case")]
pub enum GuardianRecoveryResponseV3 {
    BeginAccepted { not_before_monotonic: u64 },
    Cancelled(gp_types::OwnerRecoveryCancelAckV3),
    Contribution(gp_types::GuardianRecoveryContributionV3),
    Refused { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DpssDeliveryV3 {
    pub target_mailbox: String,
    pub sealed_message: SealedMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "action", content = "body", rename_all = "snake_case")]
pub enum GuardianRotationRequestV3 {
    Begin {
        plan: gp_types::RotationPlan,
        certificate: gp_types::BeginRotationCertificate,
    },
    Cancel {
        plan: gp_types::RotationPlan,
        certificate: gp_types::OwnerRotationCancelCertificate,
    },
    RepairRound1 {
        plan: gp_types::RotationPlan,
        begin_certificate: gp_types::BeginRotationCertificate,
        release_certificate: gp_types::RotationReleaseCertificate,
        unlock_grant: gp_types::OldShareUnlockGrant,
        helper_ids: Vec<u16>,
        replacement_id: u16,
    },
    RepairRound2 {
        plan: gp_types::RotationPlan,
        incoming: Vec<SealedMessage>,
        replacement_id: u16,
    },
    RepairFinalize {
        plan: gp_types::RotationPlan,
        incoming: Vec<SealedMessage>,
        old_public_package: Vec<u8>,
    },
    RefreshRound1 {
        plan: gp_types::RotationPlan,
        begin_certificate: Option<gp_types::BeginRotationCertificate>,
        release_certificate: Option<gp_types::RotationReleaseCertificate>,
        old_share_grant: Option<gp_types::OldShareUnlockGrant>,
    },
    RefreshRound2 {
        plan: gp_types::RotationPlan,
        incoming: Vec<SealedMessage>,
    },
    RefreshFinalize {
        plan: gp_types::RotationPlan,
        incoming: Vec<SealedMessage>,
        old_public_package: Vec<u8>,
    },
    StageMaterial {
        plan: gp_types::RotationPlan,
        wrap_grant: gp_types::NewShareWrapGrant,
        fragment_index: u16,
        ciphertext_fragment: Vec<u8>,
        ciphertext_fragment_proof: Vec<u8>,
        policy: gp_types::GuardianPolicyV3,
        opaque_slot_id: Id32,
    },
    PrepareCommit {
        plan: gp_types::RotationPlan,
        guardian_material_root: Id32,
        merkle_path_proof: Vec<u8>,
        dpss_result_commitment: Id32,
    },
    HandoffComplete {
        plan: gp_types::RotationPlan,
        dpss_result_commitment: Id32,
    },
    Activate {
        plan: gp_types::RotationPlan,
        activated_capsule: gp_types::ConfigCapsuleV3,
        drain_deadline: u64,
    },
    Abort {
        plan: gp_types::RotationPlan,
        certificate: gp_types::AbortRotationCertificate,
    },
    Retire {
        notice: gp_types::RetirementNotice,
        monotonic_now: u64,
    },
}

impl GuardianRotationRequestV3 {
    pub fn context(&self) -> &gp_types::RotationContext {
        match self {
            Self::Begin { plan, .. }
            | Self::Cancel { plan, .. }
            | Self::RepairRound1 { plan, .. }
            | Self::RepairRound2 { plan, .. }
            | Self::RepairFinalize { plan, .. }
            | Self::RefreshRound1 { plan, .. }
            | Self::RefreshRound2 { plan, .. }
            | Self::RefreshFinalize { plan, .. }
            | Self::StageMaterial { plan, .. }
            | Self::PrepareCommit { plan, .. }
            | Self::HandoffComplete { plan, .. }
            | Self::Activate { plan, .. }
            | Self::Abort { plan, .. } => &plan.context,
            Self::Retire { notice, .. } => &notice.context,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", content = "body", rename_all = "snake_case")]
pub enum GuardianRotationResponseV3 {
    BeginAccepted {
        not_before_monotonic: u64,
    },
    Cancelled(gp_types::OwnerRotationCancelAck),
    DpssDeliveries {
        deliveries: Vec<DpssDeliveryV3>,
        fragment: Option<gp_types::CiphertextFragmentContribution>,
    },
    RepairStored {
        guardian_index: u16,
        expanded_public_package: Vec<u8>,
    },
    RefreshFinalized {
        guardian_index: u16,
        public_package: Vec<u8>,
        dpss_result_commitment: Id32,
    },
    RefreshMaterialStaged {
        leaf: gp_types::PreparedRecordLeaf,
        public_package: Vec<u8>,
        dpss_result_commitment: Id32,
    },
    Prepared(gp_types::NewGuardianPreparedAck),
    Handoff(gp_types::OldGuardianHandoffAck),
    Activated {
        guardian_epoch: u64,
    },
    Aborted,
    Retired(gp_types::RetirementAck),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityDisk {
    pub node_id: String,
    pub kem_seed: Id32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvisionAck {
    pub mailbox: String,
    pub stored: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Health {
    pub status: String,
    pub role: String,
    pub node_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkDemoResult {
    pub config_id: String,
    pub request_id: String,
    pub recovered_secret: Option<String>,
    pub signer_contributions: usize,
    pub guardian_contributions: usize,
    pub rejected_guardians: Vec<u16>,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerCancelResult {
    pub config_id: String,
    pub request_id: String,
    pub guardian_acknowledgements: usize,
    pub permanently_cancelled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedMailboxBody {
    pub sealed: SealedMessage,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OwnerControlFile {
    pub protocol_version: u16,
    pub config_id: Id32,
    pub config_version: u64,
    pub owner_cancel_signing_seed: Id32,
    pub owner_cancel_public_key: [u8; 32],
    pub guardian_count: u16,
    pub guardian_threshold: u16,
    pub guardian_routes: Vec<gp_types::GuardianRoute>,
    #[serde(default)]
    pub relay_bases: Vec<String>,
}

impl Drop for OwnerControlFile {
    fn drop(&mut self) {
        self.owner_cancel_signing_seed.fill(0);
    }
}
