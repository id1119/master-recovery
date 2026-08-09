use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gp_core::GuardianMachine;
use gp_crypto::{
    RecipientKeyPair, XWING_PUBLIC_KEY_LEN, seal_to_recipient, sha256, sign, signing_key,
};
use gp_types::{
    GuardianContribution, OwnerCancelAck, PRODUCTION_MIN_DELAY_SECS, PROTOCOL_VERSION, ReleaseVote,
    SealedMessage, SignerContribution,
};
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::Mutex;

use crate::{
    protocol::{
        random_id, random_nonce, request_digest, sign_guardian_contribution,
        validate_begin_for_policy, validate_owner_cancel_for_policy, validate_release_for_policy,
        wall_now,
    },
    types::{
        ConfigDisk, GuardianDisk, GuardianEntry, Health, IdentityDisk, MailboxRequest,
        MailboxResponse, NodeInfo, PendingNetworkRecovery, ProvisionAck, ProvisionPayload,
        RelayDisk, RouteRecord, RouteRegistration, SealedMailboxBody, SignerDisk,
    },
};

#[derive(Clone, Copy, Debug)]
pub enum NodeRole {
    Relay,
    ConfigStore,
    Signer,
    Guardian,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::ConfigStore => "config_store",
            Self::Signer => "signer",
            Self::Guardian => "guardian",
        }
    }
}

pub struct ServeConfig {
    pub role: NodeRole,
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub relay_token: String,
    pub admin_token: String,
    pub allow_insecure_demo_delay: bool,
    pub auto_approve: bool,
    pub corrupt_contribution: bool,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: error.to_string(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn rate_limited(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}

struct Persisted<T> {
    path: PathBuf,
    data: T,
}

impl<T: Serialize> Persisted<T> {
    fn save(&self) -> Result<()> {
        save_json(&self.path, &self.data)
    }
}

fn load_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn load_identity(data_dir: &Path) -> Result<IdentityDisk> {
    let path = data_dir.join("identity.json");
    if path.exists() {
        return Ok(serde_json::from_slice(&fs::read(path)?)?);
    }
    let identity = IdentityDisk {
        node_id: hex::encode(random_id()),
        kem_seed: random_id(),
    };
    save_json(&path, &identity)?;
    Ok(identity)
}

fn node_info(identity: &IdentityDisk, role: NodeRole) -> NodeInfo {
    let key = RecipientKeyPair::from_seed(identity.kem_seed);
    NodeInfo {
        protocol_version: PROTOCOL_VERSION,
        node_id: identity.node_id.clone(),
        role: role.as_str().into(),
        transport_public_key: key.public_key().to_vec(),
    }
}

pub async fn serve(config: ServeConfig) -> Result<()> {
    fs::create_dir_all(&config.data_dir)?;
    let identity = Arc::new(load_identity(&config.data_dir)?);
    let router = match config.role {
        NodeRole::Relay => relay_router(
            identity,
            config
                .data_dir
                .join(format!("relay-state-v{PROTOCOL_VERSION}.json")),
            config.relay_token,
        )?,
        NodeRole::ConfigStore => config_router(
            identity,
            config
                .data_dir
                .join(format!("config-state-v{PROTOCOL_VERSION}.json")),
            config.admin_token,
        )?,
        NodeRole::Signer => signer_router(
            identity,
            config
                .data_dir
                .join(format!("signer-state-v{PROTOCOL_VERSION}.json")),
            config.auto_approve,
            config.admin_token,
        )?,
        NodeRole::Guardian => guardian_router(
            identity,
            config
                .data_dir
                .join(format!("guardian-state-v{PROTOCOL_VERSION}.json")),
            config.allow_insecure_demo_delay,
            config.corrupt_contribution,
            config.admin_token,
        )?,
    }
    .layer(DefaultBodyLimit::max(20 * 1024 * 1024));
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    println!(
        "gp-network {} node {} listening on {}",
        config.role.as_str(),
        listener.local_addr()?,
        config.listen
    );
    axum::serve(listener, router).await?;
    Ok(())
}

#[derive(Clone)]
struct RelayState {
    identity: Arc<IdentityDisk>,
    routes: Arc<Mutex<Persisted<RelayDisk>>>,
    token: Arc<String>,
    client: reqwest::Client,
}

fn relay_router(identity: Arc<IdentityDisk>, path: PathBuf, token: String) -> Result<Router> {
    let state = RelayState {
        identity,
        routes: Arc::new(Mutex::new(Persisted {
            data: load_json(&path)?,
            path,
        })),
        token: Arc::new(token),
        client: reqwest::Client::new(),
    };
    Ok(Router::new()
        .route("/v1/health", get(relay_health))
        .route("/v1/node-info", get(relay_info))
        .route("/v1/register", post(relay_register))
        .route("/v1/mailboxes/{mailbox}/key", get(relay_key))
        .route("/v1/mailboxes/{mailbox}", post(relay_forward))
        .with_state(state))
}

async fn relay_health(State(state): State<RelayState>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        role: "relay".into(),
        node_id: state.identity.node_id.clone(),
    })
}

async fn relay_info(State(state): State<RelayState>) -> Json<NodeInfo> {
    Json(node_info(&state.identity, NodeRole::Relay))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

async fn relay_register(
    State(state): State<RelayState>,
    headers: HeaderMap,
    Json(registration): Json<RouteRegistration>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.token.is_empty() || bearer(&headers) != Some(state.token.as_str()) {
        return Err(ApiError::forbidden("invalid relay registration token"));
    }
    if registration.mailbox.len() < 32
        || registration.target_url.is_empty()
        || registration.transport_public_key.len() != XWING_PUBLIC_KEY_LEN
    {
        return Err(ApiError::bad_request("invalid route registration"));
    }
    let mut routes = state.routes.lock().await;
    if routes.data.routes.contains_key(&registration.mailbox) {
        return Err(ApiError::bad_request("mailbox is already registered"));
    }
    routes.data.routes.insert(
        registration.mailbox.clone(),
        RouteRecord {
            target_url: registration.target_url.trim_end_matches('/').into(),
            transport_public_key: registration.transport_public_key,
        },
    );
    routes.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox: registration.mailbox,
        stored: true,
    }))
}

async fn relay_key(
    State(state): State<RelayState>,
    AxumPath(mailbox): AxumPath<String>,
) -> Result<Json<Vec<u8>>, ApiError> {
    let routes = state.routes.lock().await;
    let route = routes
        .data
        .routes
        .get(&mailbox)
        .ok_or_else(|| ApiError::not_found("unknown mailbox"))?;
    Ok(Json(route.transport_public_key.clone()))
}

async fn relay_forward(
    State(state): State<RelayState>,
    AxumPath(mailbox): AxumPath<String>,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<SealedMailboxBody>, ApiError> {
    let target = {
        let routes = state.routes.lock().await;
        routes
            .data
            .routes
            .get(&mailbox)
            .map(|route| route.target_url.clone())
            .ok_or_else(|| ApiError::not_found("unknown mailbox"))?
    };
    let response = state
        .client
        .post(format!("{target}/v1/mailbox/{mailbox}"))
        .json(&body)
        .send()
        .await
        .map_err(ApiError::bad_request)?;
    println!("relay forwarded sealed mailbox {}…", &mailbox[..10]);
    let status = response.status();
    if !status.is_success() {
        let message = response.text().await.unwrap_or_default();
        return Err(ApiError {
            status: StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
            message,
        });
    }
    response
        .json::<SealedMailboxBody>()
        .await
        .map(Json)
        .map_err(ApiError::bad_request)
}

#[derive(Clone)]
struct ConfigState {
    identity: Arc<IdentityDisk>,
    store: Arc<Mutex<Persisted<ConfigDisk>>>,
    admin_token: Arc<String>,
}

fn config_router(
    identity: Arc<IdentityDisk>,
    path: PathBuf,
    admin_token: String,
) -> Result<Router> {
    let state = ConfigState {
        identity,
        store: Arc::new(Mutex::new(Persisted {
            data: load_json(&path)?,
            path,
        })),
        admin_token: Arc::new(admin_token),
    };
    Ok(Router::new()
        .route("/v1/health", get(config_health))
        .route("/v1/node-info", get(config_info))
        .route("/v1/configs/{config_id}", get(config_get).put(config_put))
        .with_state(state))
}

async fn config_health(State(state): State<ConfigState>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        role: "config_store".into(),
        node_id: state.identity.node_id.clone(),
    })
}

async fn config_info(State(state): State<ConfigState>) -> Json<NodeInfo> {
    Json(node_info(&state.identity, NodeRole::ConfigStore))
}

async fn config_get(
    State(state): State<ConfigState>,
    AxumPath(config_id): AxumPath<String>,
) -> Result<Json<gp_types::ConfigCapsule>, ApiError> {
    let store = state.store.lock().await;
    store
        .data
        .capsules
        .get(&config_id)
        .cloned()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("Config Capsule was not found"))
}

async fn config_put(
    State(state): State<ConfigState>,
    AxumPath(config_id): AxumPath<String>,
    headers: HeaderMap,
    Json(capsule): Json<gp_types::ConfigCapsule>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.admin_token.is_empty() || bearer(&headers) != Some(state.admin_token.as_str()) {
        return Err(ApiError::forbidden("invalid config-store write token"));
    }
    if hex::encode(capsule.config_id) != config_id {
        return Err(ApiError::bad_request("config id path/body mismatch"));
    }
    let mut store = state.store.lock().await;
    if store.data.capsules.contains_key(&config_id) {
        return Err(ApiError::bad_request(
            "Config Capsule is immutable in the network MVP; signed rotation is not implemented",
        ));
    }
    store.data.capsules.insert(config_id.clone(), capsule);
    store.save().map_err(ApiError::bad_request)?;
    println!("config-store published capsule {}…", &config_id[..10]);
    Ok(Json(ProvisionAck {
        mailbox: config_id,
        stored: true,
    }))
}

#[derive(Clone)]
struct SignerServerState {
    identity: Arc<IdentityDisk>,
    store: Arc<Mutex<Persisted<SignerDisk>>>,
    auto_approve: bool,
    admin_token: Arc<String>,
}

fn signer_router(
    identity: Arc<IdentityDisk>,
    path: PathBuf,
    auto_approve: bool,
    admin_token: String,
) -> Result<Router> {
    let state = SignerServerState {
        identity,
        store: Arc::new(Mutex::new(Persisted {
            data: load_json(&path)?,
            path,
        })),
        auto_approve,
        admin_token: Arc::new(admin_token),
    };
    Ok(Router::new()
        .route("/v1/health", get(signer_health))
        .route("/v1/node-info", get(signer_info))
        .route("/v1/provision", post(signer_provision))
        .route("/v1/mailbox/{mailbox}", post(signer_mailbox))
        .with_state(state))
}

async fn signer_health(State(state): State<SignerServerState>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        role: "signer".into(),
        node_id: state.identity.node_id.clone(),
    })
}

async fn signer_info(State(state): State<SignerServerState>) -> Json<NodeInfo> {
    Json(node_info(&state.identity, NodeRole::Signer))
}

fn open_provision(
    identity: &IdentityDisk,
    role: &str,
    sealed: &SealedMessage,
) -> Result<ProvisionPayload> {
    let recipient = RecipientKeyPair::from_seed(identity.kem_seed);
    let plaintext = recipient.open(
        sealed,
        &gp_wire::node_provision_context(&identity.node_id, role)?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}

async fn signer_provision(
    State(state): State<SignerServerState>,
    headers: HeaderMap,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.admin_token.is_empty() || bearer(&headers) != Some(state.admin_token.as_str()) {
        return Err(ApiError::forbidden("invalid node provisioning token"));
    }
    let ProvisionPayload::Signer(signer) =
        open_provision(&state.identity, "signer", &body.sealed).map_err(ApiError::bad_request)?
    else {
        return Err(ApiError::bad_request("wrong provisioning role"));
    };
    let mailbox = mailbox_id(&signer.mailbox).map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    if store.data.entries.contains_key(&mailbox) {
        return Err(ApiError::bad_request(
            "signer mailbox is already provisioned",
        ));
    }
    store.data.entries.insert(mailbox.clone(), signer);
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox,
        stored: true,
    }))
}

fn open_mailbox_request(
    identity: &IdentityDisk,
    mailbox: &str,
    body: &SealedMailboxBody,
) -> Result<MailboxRequest> {
    let recipient = RecipientKeyPair::from_seed(identity.kem_seed);
    let plaintext = recipient.open(
        &body.sealed,
        &gp_wire::mailbox_transport_context(mailbox, "request")?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn seal_mailbox_response(
    mailbox: &str,
    response_recipient_key: &[u8],
    response: &MailboxResponse,
) -> Result<SealedMailboxBody> {
    let bytes = serde_json::to_vec(response)?;
    Ok(SealedMailboxBody {
        sealed: seal_to_recipient(
            response_recipient_key,
            random_id(),
            random_nonce(),
            &bytes,
            &gp_wire::mailbox_transport_context(mailbox, "response")?,
        )?,
    })
}

fn validate_signer_request(
    signer: &gp_storage::SignerState,
    request: &gp_types::RecoveryRequest,
    now: u64,
) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION
        || request.config_id != signer.policy.config_id
        || request.config_version != signer.policy.config_version
        || request.recovery_recipient_key.len() != XWING_PUBLIC_KEY_LEN
        || request.requested_at > now
        || request.expiry <= now
    {
        bail!("signer rejected stale, expired, or malformed RecoveryRequest");
    }
    Ok(())
}

async fn signer_mailbox(
    State(state): State<SignerServerState>,
    AxumPath(mailbox): AxumPath<String>,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<SealedMailboxBody>, ApiError> {
    if !state.auto_approve {
        return Err(ApiError::forbidden(
            "automatic social approval is disabled on this signer",
        ));
    }
    let action =
        open_mailbox_request(&state.identity, &mailbox, &body).map_err(ApiError::bad_request)?;
    let request = action.request().clone();
    let now = wall_now().map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    if !store.data.entries.contains_key(&mailbox) {
        return Err(ApiError::not_found("signer mailbox is not provisioned"));
    }
    validate_signer_request(
        store
            .data
            .entries
            .get(&mailbox)
            .expect("mailbox presence checked above"),
        &request,
        now,
    )
    .map_err(ApiError::bad_request)?;
    if matches!(&action, MailboxRequest::SignerApprove { .. }) {
        if store
            .data
            .last_approval_at
            .get(&mailbox)
            .is_some_and(|last| now < last.saturating_add(1))
        {
            return Err(ApiError::rate_limited(
                "signer mailbox accepts at most one approval request per second",
            ));
        }
        store.data.last_approval_at.insert(mailbox.clone(), now);
    }
    let signer = store
        .data
        .entries
        .get_mut(&mailbox)
        .expect("mailbox presence checked above");
    let digest = request_digest(&request).map_err(ApiError::bad_request)?;
    let response = match action {
        MailboxRequest::SignerApprove { .. } => {
            signer
                .observe_request(
                    request.config_id,
                    request.config_version,
                    request.request_id,
                    request.nonce,
                    digest,
                )
                .map_err(ApiError::bad_request)?;
            let encrypted_a_share = seal_to_recipient(
                &request.recovery_recipient_key,
                random_id(),
                random_nonce(),
                &signer.authorization_share,
                &gp_wire::recipient_share_context(&request, signer.signer_id)
                    .map_err(ApiError::bad_request)?,
            )
            .map_err(ApiError::bad_request)?;
            let mut contribution = SignerContribution {
                request: request.clone(),
                signer_id: signer.signer_id,
                signer_public_key: signer.signing_public_key,
                signer_signature: vec![],
                signer_membership_proof: signer.membership_proof.clone(),
                encrypted_a_share,
            };
            contribution.signer_signature = sign(
                &signing_key(signer.signing_seed),
                &gp_wire::signer_approval(
                    &request,
                    signer.signer_id,
                    &contribution.encrypted_a_share,
                )
                .map_err(ApiError::bad_request)?,
            );
            MailboxResponse::SignerContribution(contribution)
        }
        MailboxRequest::SignerRelease { .. } => {
            if signer.seen_requests.get(&hex::encode(request.request_id)) != Some(&digest) {
                return Err(ApiError::bad_request(
                    "signer never approved this exact request",
                ));
            }
            let mut vote = ReleaseVote {
                protocol_version: PROTOCOL_VERSION,
                config_id: request.config_id,
                config_version: request.config_version,
                request_id: request.request_id,
                request_digest: digest,
                recovery_recipient_key: request.recovery_recipient_key.clone(),
                nonce: request.nonce,
                signer_id: signer.signer_id,
                signer_public_key: signer.signing_public_key,
                signer_membership_proof: signer.membership_proof.clone(),
                signer_signature: vec![],
            };
            vote.signer_signature = sign(
                &signing_key(signer.signing_seed),
                &gp_wire::release_vote(&vote).map_err(ApiError::bad_request)?,
            );
            MailboxResponse::ReleaseVote(vote)
        }
        _ => return Err(ApiError::bad_request("request is not valid for a signer")),
    };
    store.save().map_err(ApiError::bad_request)?;
    println!(
        "signer handled {} on mailbox {}…",
        response.kind(),
        &mailbox[..10]
    );
    drop(store);
    seal_mailbox_response(&mailbox, &request.recovery_recipient_key, &response)
        .map(Json)
        .map_err(ApiError::bad_request)
}

#[derive(Clone)]
struct GuardianServerState {
    identity: Arc<IdentityDisk>,
    store: Arc<Mutex<Persisted<GuardianDisk>>>,
    allow_insecure_demo_delay: bool,
    corrupt_contribution: bool,
    admin_token: Arc<String>,
}

fn guardian_router(
    identity: Arc<IdentityDisk>,
    path: PathBuf,
    allow_insecure_demo_delay: bool,
    corrupt_contribution: bool,
    admin_token: String,
) -> Result<Router> {
    let state = GuardianServerState {
        identity,
        store: Arc::new(Mutex::new(Persisted {
            data: load_json(&path)?,
            path,
        })),
        allow_insecure_demo_delay,
        corrupt_contribution,
        admin_token: Arc::new(admin_token),
    };
    Ok(Router::new()
        .route("/v1/health", get(guardian_health))
        .route("/v1/node-info", get(guardian_info))
        .route("/v1/provision", post(guardian_provision))
        .route("/v1/mailbox/{mailbox}", post(guardian_mailbox))
        .with_state(state))
}

async fn guardian_health(State(state): State<GuardianServerState>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        role: "guardian".into(),
        node_id: state.identity.node_id.clone(),
    })
}

async fn guardian_info(State(state): State<GuardianServerState>) -> Json<NodeInfo> {
    Json(node_info(&state.identity, NodeRole::Guardian))
}

async fn guardian_provision(
    State(state): State<GuardianServerState>,
    headers: HeaderMap,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.admin_token.is_empty() || bearer(&headers) != Some(state.admin_token.as_str()) {
        return Err(ApiError::forbidden("invalid node provisioning token"));
    }
    let ProvisionPayload::Guardian(provision) =
        open_provision(&state.identity, "guardian", &body.sealed).map_err(ApiError::bad_request)?
    else {
        return Err(ApiError::bad_request("wrong provisioning role"));
    };
    if provision.record.policy.minimum_recovery_delay < PRODUCTION_MIN_DELAY_SECS
        && !state.allow_insecure_demo_delay
    {
        return Err(ApiError::forbidden(
            "guardian refuses a delay below 24 hours outside explicit demo mode",
        ));
    }
    let mailbox = mailbox_id(&provision.mailbox).map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    if store.data.entries.contains_key(&mailbox) {
        return Err(ApiError::bad_request(
            "guardian mailbox is already provisioned",
        ));
    }
    store
        .data
        .entries
        .insert(mailbox.clone(), GuardianEntry::new(provision));
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox,
        stored: true,
    }))
}

fn monotonic_now() -> Result<u64> {
    if let Ok(contents) = fs::read_to_string("/proc/uptime")
        && let Some(value) = contents.split_whitespace().next()
    {
        return Ok(value.parse::<f64>()?.floor() as u64);
    }
    static START: OnceLock<Instant> = OnceLock::new();
    Ok(START.get_or_init(Instant::now).elapsed().as_secs())
}

fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| format!("process-{}", std::process::id()))
}

async fn guardian_mailbox(
    State(state): State<GuardianServerState>,
    AxumPath(mailbox): AxumPath<String>,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<SealedMailboxBody>, ApiError> {
    let action =
        open_mailbox_request(&state.identity, &mailbox, &body).map_err(ApiError::bad_request)?;
    let request = action.request().clone();
    let response_recipient_key = match &action {
        MailboxRequest::GuardianCancel { certificate, .. } => {
            certificate.cancel_response_recipient_key.clone()
        }
        _ => request.recovery_recipient_key.clone(),
    };
    let wall = wall_now().map_err(ApiError::bad_request)?;
    let monotonic = monotonic_now().map_err(ApiError::bad_request)?;
    let current_boot = boot_id();
    let digest = request_digest(&request).map_err(ApiError::bad_request)?;
    let key = hex::encode(request.request_id);
    let mut store = state.store.lock().await;
    let entry = store
        .data
        .entries
        .get_mut(&mailbox)
        .ok_or_else(|| ApiError::not_found("guardian mailbox is not provisioned"))?;
    let policy = &entry.provision.record.policy;
    let response = if matches!(&action, MailboxRequest::GuardianRelease { .. })
        && entry.cancelled.get(&key) == Some(&digest)
    {
        MailboxResponse::ReleaseRefused {
            reason: "cancelled".into(),
        }
    } else {
        match action {
            MailboxRequest::GuardianBegin { certificate } => {
                validate_begin_for_policy(&certificate, policy, wall)
                    .map_err(ApiError::bad_request)?;
                if entry.cancelled.get(&key) == Some(&digest) {
                    return Err(ApiError::bad_request("request was permanently cancelled"));
                }
                if entry.pending.contains_key(&key) || !entry.seen_nonces.insert(request.nonce) {
                    return Err(ApiError::bad_request("replayed request id or nonce"));
                }
                let mut machine = GuardianMachine::new(policy.config_id, policy.config_version);
                let not_before = machine
                    .begin_at(
                        &request,
                        digest,
                        wall,
                        monotonic,
                        policy.minimum_recovery_delay,
                        true,
                    )
                    .map_err(ApiError::bad_request)?;
                entry.pending.insert(
                    key,
                    PendingNetworkRecovery {
                        request: request.clone(),
                        request_digest: digest,
                        accepted_wall_time: wall,
                        started_monotonic: monotonic,
                        not_before_monotonic: not_before,
                        boot_id: current_boot,
                    },
                );
                MailboxResponse::BeginAccepted {
                    not_before_monotonic: not_before,
                }
            }
            MailboxRequest::GuardianCancel { certificate, .. } => {
                validate_owner_cancel_for_policy(&certificate, policy, &request, wall)
                    .map_err(ApiError::bad_request)?;
                if entry.released.get(&key) == Some(&digest) {
                    return Err(ApiError::bad_request(
                        "guardian already released material for this request",
                    ));
                }
                if entry
                    .cancelled
                    .get(&key)
                    .is_some_and(|stored| stored != &digest)
                {
                    return Err(ApiError::bad_request("cancellation digest conflict"));
                }
                entry.cancelled.insert(key, digest);
                let mut ack = OwnerCancelAck {
                    protocol_version: PROTOCOL_VERSION,
                    config_id: request.config_id,
                    config_version: request.config_version,
                    request_id: request.request_id,
                    request_digest: digest,
                    owner_cancel_transcript_digest: sha256(
                        &gp_wire::owner_cancel(&certificate).map_err(ApiError::bad_request)?,
                    ),
                    guardian_index: entry.provision.record.guardian_index,
                    guardian_signature: vec![],
                };
                ack.guardian_signature = sign(
                    &signing_key(entry.provision.signing_seed),
                    &gp_wire::owner_cancel_ack(&ack).map_err(ApiError::bad_request)?,
                );
                MailboxResponse::CancellationAccepted(ack)
            }
            MailboxRequest::GuardianRelease { certificate, .. } => {
                validate_release_for_policy(&certificate, policy, &request, wall)
                    .map_err(ApiError::bad_request)?;
                let pending = entry
                    .pending
                    .get(&key)
                    .ok_or_else(|| ApiError::bad_request("Begin was not observed"))?;
                if pending.boot_id != current_boot {
                    return Err(ApiError::bad_request(
                        "guardian rebooted during delay and fails closed",
                    ));
                }
                let mut machine = GuardianMachine::new(policy.config_id, policy.config_version);
                machine
                    .begin_at(
                        &pending.request,
                        pending.request_digest,
                        pending.accepted_wall_time,
                        pending.started_monotonic,
                        policy.minimum_recovery_delay,
                        true,
                    )
                    .map_err(ApiError::bad_request)?;
                machine
                    .authorize_release_at(request.request_id, digest, wall, monotonic, true, true)
                    .map_err(ApiError::bad_request)?;
                let record = &entry.provision.record;
                let mut contribution = GuardianContribution {
                    protocol_version: PROTOCOL_VERSION,
                    config_id: request.config_id,
                    config_version: request.config_version,
                    request_id: request.request_id,
                    request_digest: digest,
                    guardian_index: record.guardian_index,
                    ciphertext_fragment: record.ciphertext_fragment.clone(),
                    encrypted_dek_share: record.encrypted_dek_share.clone(),
                    merkle_path_proof: record.merkle_path_proof.clone(),
                    guardian_signature: vec![],
                };
                if state.corrupt_contribution
                    && let Some(byte) = contribution.ciphertext_fragment.first_mut()
                {
                    *byte ^= 1;
                }
                let contribution =
                    sign_guardian_contribution(contribution, entry.provision.signing_seed)
                        .map_err(ApiError::bad_request)?;
                entry.released.insert(key, digest);
                MailboxResponse::GuardianContribution(contribution)
            }
            _ => return Err(ApiError::bad_request("request is not valid for a guardian")),
        }
    };
    store.save().map_err(ApiError::bad_request)?;
    println!(
        "guardian handled {} on mailbox {}…",
        response.kind(),
        &mailbox[..10]
    );
    drop(store);
    seal_mailbox_response(&mailbox, &response_recipient_key, &response)
        .map(Json)
        .map_err(ApiError::bad_request)
}

fn mailbox_id(mailbox_url: &str) -> Result<String> {
    mailbox_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|value| value.len() >= 32)
        .map(str::to_owned)
        .context("invalid opaque mailbox URL")
}
