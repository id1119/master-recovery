use std::collections::{BTreeMap, BTreeSet};

use gp_storage::SignerState;
use gp_types::{
    BeginRecoveryCertificate, ConfigCapsule, GuardianContribution, GuardianRecord, Id32,
    OwnerCancelAck, OwnerCancelCertificate, RecoveryRequest, ReleaseCertificate, ReleaseVote,
    SealedMessage, SignerContribution,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeInfo {
    pub protocol_version: u16,
    pub node_id: String,
    pub role: String,
    pub transport_public_key: Vec<u8>,
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignerDisk {
    pub entries: BTreeMap<String, SignerState>,
    #[serde(default)]
    pub last_approval_at: BTreeMap<String, u64>,
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
}

impl Drop for OwnerControlFile {
    fn drop(&mut self) {
        self.owner_cancel_signing_seed.fill(0);
    }
}
