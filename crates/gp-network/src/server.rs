use std::{
    collections::{BTreeMap, BTreeSet},
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
    RecipientKeyPair, XWING_PUBLIC_KEY_LEN, merkle_commit, merkle_verify, seal_to_recipient,
    sha256, sign, signing_key, verify, verifying_key_bytes,
};
use gp_types::{
    GuardianContribution, OwnerCancelAck, PRODUCTION_MIN_DELAY_SECS, PROTOCOL_VERSION,
    PROTOCOL_VERSION_V3, ReleaseVote, SealedMessage, SignerContribution,
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
        ConfigDisk, GuardianDisk, GuardianEntry, GuardianRecoveryRequestV3,
        GuardianRotationEntryV3, GuardianRotationProvisionV3, GuardianRotationRequestV3,
        GuardianRouteAliasV3, Health, IdentityDisk, MailboxRequest, MailboxResponse, NodeInfo,
        PendingNetworkRecovery, ProvisionAck, ProvisionPayload, RelayDisk, RouteRecord,
        RouteRegistration, SealedMailboxBody, SignerDisk, SignerRecoveryRequestV3,
        SignerRotationEntryV3, SignerRotationProvisionV3, SignerRotationRequestV3,
        WitnessActivationRequest, WitnessConfigProvision, WitnessDisk, WitnessFinalizeRequest,
        WitnessReadEnvelope, WitnessRotationCancelRequest, WitnessRotationCancellation,
    },
};

#[derive(Clone, Copy, Debug)]
pub enum NodeRole {
    Relay,
    ConfigStore,
    Signer,
    Guardian,
    Witness,
}

impl NodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::ConfigStore => "config_store",
            Self::Signer => "signer",
            Self::Guardian => "guardian",
            Self::Witness => "witness",
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

/// Bumped whenever a persisted state file gains a field an older build would
/// silently discard. Serde ignores unknown fields, so an older binary that
/// loads a newer file and then saves would erase the fields it does not know
/// about, permanently losing guardian rotation records.
const STATE_SCHEMA_VERSION: u64 = 1;
const SCHEMA_VERSION_FIELD: &str = "schema_version";

fn load_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    let document: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
    let found = document
        .get(SCHEMA_VERSION_FIELD)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(STATE_SCHEMA_VERSION);
    if found > STATE_SCHEMA_VERSION {
        anyhow::bail!(
            "state file {} has schema v{found}, newer than the v{} this build              understands; refusing to load because saving would drop unknown fields",
            path.display(),
            STATE_SCHEMA_VERSION
        );
    }
    Ok(serde_json::from_value(document)?)
}

fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    let mut document = serde_json::to_value(value)?;
    if let Some(object) = document.as_object_mut() {
        object.insert(
            SCHEMA_VERSION_FIELD.to_string(),
            serde_json::Value::from(STATE_SCHEMA_VERSION),
        );
    }
    let bytes = serde_json::to_vec_pretty(&document)?;
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    {
        use std::io::Write;
        // fsync on every platform: the previous non-unix path used fs::write
        // with no sync, so a crash after rename could expose a truncated file.
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    fs::rename(temporary, path)?;
    #[cfg(unix)]
    {
        let directory = fs::File::open(parent)?;
        directory.sync_all()?;
    }
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
        protocol_version: if matches!(role, NodeRole::Witness) {
            PROTOCOL_VERSION_V3
        } else {
            PROTOCOL_VERSION
        },
        node_id: identity.node_id.clone(),
        role: role.as_str().into(),
        transport_public_key: key.public_key().to_vec(),
        signing_public_key: matches!(role, NodeRole::Witness)
            .then(|| verifying_key_bytes(&signing_key(identity.kem_seed))),
    }
}

fn node_info_v3(identity: &IdentityDisk, role: NodeRole) -> NodeInfo {
    let key = RecipientKeyPair::from_seed(identity.kem_seed);
    NodeInfo {
        protocol_version: PROTOCOL_VERSION_V3,
        node_id: identity.node_id.clone(),
        role: role.as_str().into(),
        transport_public_key: key.public_key().to_vec(),
        signing_public_key: Some(verifying_key_bytes(&signing_key(identity.kem_seed))),
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
        NodeRole::Witness => witness_router(
            identity,
            config.data_dir.join("witness-state-v3.json"),
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
        .route("/v3/mailboxes/{mailbox}/key", get(relay_key))
        .route("/v3/mailboxes/{mailbox}", post(relay_forward_v3))
        .route(
            "/v3/recovery-mailboxes/{mailbox}",
            post(relay_forward_recovery_v3),
        )
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

async fn relay_forward_v3(
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
        .post(format!("{target}/v3/mailbox/{mailbox}"))
        .json(&body)
        .send()
        .await
        .map_err(ApiError::bad_request)?;
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

async fn relay_forward_recovery_v3(
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
        .post(format!("{target}/v3/recovery/{mailbox}"))
        .json(&body)
        .send()
        .await
        .map_err(ApiError::bad_request)?;
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
            "protocol-v2 Config Capsules are immutable; rotation uses protocol-v3 witnesses",
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
struct WitnessServerState {
    identity: Arc<IdentityDisk>,
    store: Arc<Mutex<Persisted<WitnessDisk>>>,
    admin_token: Arc<String>,
}

fn witness_router(
    identity: Arc<IdentityDisk>,
    path: PathBuf,
    admin_token: String,
) -> Result<Router> {
    let state = WitnessServerState {
        identity,
        store: Arc::new(Mutex::new(Persisted {
            data: load_json(&path)?,
            path,
        })),
        admin_token: Arc::new(admin_token),
    };
    Ok(Router::new()
        .route("/v3/health", get(witness_health))
        .route("/v3/node-info", get(witness_info))
        .route("/v3/witness/configs", post(witness_provision))
        .route(
            "/v3/witness/configs/{config_id}/activate",
            post(witness_activate),
        )
        .route(
            "/v3/witness/configs/{config_id}/finalize",
            post(witness_finalize),
        )
        .route(
            "/v3/witness/configs/{config_id}/cancel-rotation",
            post(witness_cancel_rotation),
        )
        .route("/v3/witness/configs/{config_id}/read", post(witness_read))
        .with_state(state))
}

async fn witness_health(State(state): State<WitnessServerState>) -> Json<Health> {
    Json(Health {
        status: "ok".into(),
        role: "witness".into(),
        node_id: state.identity.node_id.clone(),
    })
}

async fn witness_info(State(state): State<WitnessServerState>) -> Json<NodeInfo> {
    Json(node_info(&state.identity, NodeRole::Witness))
}

async fn witness_provision(
    State(state): State<WitnessServerState>,
    headers: HeaderMap,
    Json(provision): Json<WitnessConfigProvision>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.admin_token.is_empty() || bearer(&headers) != Some(state.admin_token.as_str()) {
        return Err(ApiError::forbidden("invalid witness provisioning token"));
    }
    if provision.witness_id == 0
        || provision.capsule.protocol_version != PROTOCOL_VERSION_V3
        || provision.capsule.config_ref.guardian_epoch == 0
        || provision.signer_public_keys.len() != usize::from(provision.capsule.signer_count)
        || provision.witness_fault_bound == 0
    {
        return Err(ApiError::bad_request("invalid witness genesis policy"));
    }
    let computed_hash = sha256(
        &gp_wire::config_capsule_body_v3(&provision.capsule).map_err(ApiError::bad_request)?,
    );
    if computed_hash != provision.capsule.capsule_hash {
        return Err(ApiError::bad_request("invalid genesis capsule hash"));
    }
    let expected_signer_ids = (1..=provision.capsule.signer_count).collect::<BTreeSet<_>>();
    if provision
        .signer_public_keys
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != expected_signer_ids
    {
        return Err(ApiError::bad_request("signer ids are not canonical"));
    }
    let signer_leaves = provision
        .signer_public_keys
        .iter()
        .map(|(id, key)| gp_wire::signer_leaf(*id, key).map(|leaf| sha256(&leaf)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::bad_request)?;
    let (signer_root, _) = merkle_commit(&signer_leaves).map_err(ApiError::bad_request)?;
    if signer_root != provision.capsule.signer_set_commitment {
        return Err(ApiError::bad_request(
            "pinned signer keys do not match signer-set commitment",
        ));
    }
    let required_witnesses = usize::from(provision.witness_fault_bound)
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| ApiError::bad_request("witness policy overflow"))?;
    let own_witness_key = verifying_key_bytes(&signing_key(state.identity.kem_seed));
    if provision.witness_public_keys.len() < required_witnesses
        || provision.witness_public_keys.get(&provision.witness_id) != Some(&own_witness_key)
        || provision
            .witness_public_keys
            .values()
            .collect::<BTreeSet<_>>()
            .len()
            != provision.witness_public_keys.len()
    {
        return Err(ApiError::bad_request("invalid pinned witness roster"));
    }
    let key = hex::encode(provision.capsule.config_ref.config_id);
    let mut store = state.store.lock().await;
    if store.data.entries.contains_key(&key) {
        return Err(ApiError::bad_request(
            "witness configuration is already provisioned",
        ));
    }
    store.data.entries.insert(
        key.clone(),
        crate::types::WitnessConfigEntry {
            witness_id: provision.witness_id,
            register: gp_storage::WitnessEpochStore::new(
                provision.capsule.config_ref,
                provision.capsule.capsule_hash,
            ),
            capsule: provision.capsule,
            pending_capsule: None,
            pending_ack: None,
            rotation_cancellations: BTreeMap::new(),
            signer_public_keys: provision.signer_public_keys,
            witness_public_keys: provision.witness_public_keys,
            witness_fault_bound: provision.witness_fault_bound,
        },
    );
    // save_json uses file fsync + rename + directory fsync. The provision is
    // durable before this acknowledgement is returned.
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox: key,
        stored: true,
    }))
}

async fn witness_cancel_rotation(
    State(state): State<WitnessServerState>,
    AxumPath(config_id): AxumPath<String>,
    Json(request): Json<WitnessRotationCancelRequest>,
) -> Result<Json<gp_types::WitnessRotationCancelAck>, ApiError> {
    let certificate = request.certificate;
    let now = wall_now().map_err(ApiError::bad_request)?;
    if certificate.context.protocol_version != PROTOCOL_VERSION_V3
        || hex::encode(certificate.context.config_ref.config_id) != config_id
        || certificate.context.issued_at > now
        || certificate.context.expiry <= now
        || certificate.cancel_response_recipient_key.len() != XWING_PUBLIC_KEY_LEN
    {
        return Err(ApiError::bad_request(
            "owner witness cancellation is malformed or expired",
        ));
    }
    let cancel_transcript =
        gp_wire::owner_rotation_cancel_certificate(&certificate).map_err(ApiError::bad_request)?;
    let cancel_hash = sha256(&cancel_transcript);
    let mut store = state.store.lock().await;
    let entry = store
        .data
        .entries
        .get_mut(&config_id)
        .ok_or_else(|| ApiError::not_found("witness configuration was not found"))?;
    if certificate.context.config_ref != entry.capsule.config_ref
        || certificate.context.predecessor_capsule_hash != entry.capsule.capsule_hash
        || certificate.owner_cancel_public_key != entry.capsule.owner_cancel_public_key
    {
        return Err(ApiError::bad_request(
            "owner cancellation does not bind the witness's active predecessor",
        ));
    }
    verify(
        &entry.capsule.owner_cancel_public_key,
        &cancel_transcript,
        &certificate.owner_signature,
    )
    .map_err(ApiError::bad_request)?;
    let cancellation_key = hex::encode(certificate.context.rotation_id);
    if let Some(existing) = entry.rotation_cancellations.get(&cancellation_key) {
        if existing.plan_hash != certificate.plan_hash
            || existing.cancel_certificate_hash != cancel_hash
        {
            return Err(ApiError::bad_request(
                "witness has a conflicting cancellation for this rotation id",
            ));
        }
    } else {
        if let Some(pending) = &entry.pending_capsule {
            let activation = pending.activation_certificate.as_ref().ok_or_else(|| {
                ApiError::bad_request("pending successor lacks an activation certificate")
            })?;
            if activation.context.rotation_id != certificate.context.rotation_id
                || activation.plan_hash != certificate.plan_hash
                || pending.predecessor_capsule_hash != entry.capsule.capsule_hash
            {
                return Err(ApiError::bad_request(
                    "owner cancellation does not bind the pending successor",
                ));
            }
            entry
                .register
                .cancel_pending_successor(
                    entry.capsule.config_ref.guardian_epoch,
                    entry.capsule.capsule_hash,
                    pending.config_ref.guardian_epoch,
                    pending.capsule_hash,
                )
                .map_err(ApiError::bad_request)?;
            entry.pending_capsule = None;
            entry.pending_ack = None;
        }
        entry.rotation_cancellations.insert(
            cancellation_key,
            WitnessRotationCancellation {
                plan_hash: certificate.plan_hash,
                cancel_certificate_hash: cancel_hash,
            },
        );
    }
    let witness_key = signing_key(state.identity.kem_seed);
    let mut ack = gp_types::WitnessRotationCancelAck {
        protocol_version: PROTOCOL_VERSION_V3,
        config_id: certificate.context.config_ref.config_id,
        rotation_id: certificate.context.rotation_id,
        plan_hash: certificate.plan_hash,
        cancel_certificate_hash: cancel_hash,
        witness_id: entry.witness_id,
        witness_public_key: verifying_key_bytes(&witness_key),
        witness_signature: vec![],
    };
    ack.witness_signature = sign(
        &witness_key,
        &gp_wire::witness_rotation_cancel_ack(&ack).map_err(ApiError::bad_request)?,
    );
    // Tombstone and any pending-child rollback are durable before the signed
    // acknowledgement leaves this witness.
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ack))
}

async fn witness_activate(
    State(state): State<WitnessServerState>,
    AxumPath(config_id): AxumPath<String>,
    Json(request): Json<WitnessActivationRequest>,
) -> Result<Json<gp_types::WitnessActivationAck>, ApiError> {
    if hex::encode(request.capsule.config_ref.config_id) != config_id {
        return Err(ApiError::bad_request("config id path/body mismatch"));
    }
    let capsule_hash =
        sha256(&gp_wire::config_capsule_body_v3(&request.capsule).map_err(ApiError::bad_request)?);
    if capsule_hash != request.capsule.capsule_hash
        || request.activation_certificate.successor != request.capsule.config_ref
        || request.activation_certificate.successor_capsule_hash != capsule_hash
        || request.capsule.predecessor_capsule_hash
            != request
                .activation_certificate
                .context
                .predecessor_capsule_hash
    {
        return Err(ApiError::bad_request(
            "activation certificate does not bind the exact capsule",
        ));
    }
    let activation_transcript =
        gp_wire::rotation_activate_certificate(&request.activation_certificate)
            .map_err(ApiError::bad_request)?;
    let activation_hash = sha256(&activation_transcript);
    let mut store = state.store.lock().await;
    let entry = store
        .data
        .entries
        .get_mut(&config_id)
        .ok_or_else(|| ApiError::not_found("witness configuration was not found"))?;
    if entry.rotation_cancellations.contains_key(&hex::encode(
        request.activation_certificate.context.rotation_id,
    )) {
        return Err(ApiError::bad_request(
            "witness permanently rejected this owner-cancelled rotation",
        ));
    }
    if let Some(pending) = &entry.pending_capsule {
        if pending.capsule_hash == request.capsule.capsule_hash {
            return entry
                .pending_ack
                .clone()
                .map(Json)
                .ok_or_else(|| ApiError::bad_request("pending witness write has no durable ack"));
        }
        return Err(ApiError::bad_request(
            "witness is already locked to another successor",
        ));
    }
    if request.activation_certificate.context.config_ref != entry.capsule.config_ref
        || request.capsule.predecessor_capsule_hash != entry.capsule.capsule_hash
        || request.capsule.signer_count != entry.capsule.signer_count
        || request.capsule.signer_threshold != entry.capsule.signer_threshold
        || request.capsule.signer_set_commitment != entry.capsule.signer_set_commitment
        || request.capsule.owner_cancel_public_key != entry.capsule.owner_cancel_public_key
        || request.capsule.minimum_recovery_delay < entry.capsule.minimum_recovery_delay
        || request.capsule.max_request_lifetime != entry.capsule.max_request_lifetime
        || request.capsule.dpss_suite != entry.capsule.dpss_suite
        || request.activation_certificate.votes.len() < usize::from(entry.capsule.signer_threshold)
    {
        return Err(ApiError::bad_request(
            "stale predecessor, immutable-policy downgrade, or signer quorum failure",
        ));
    }
    for vote in &request.activation_certificate.votes {
        if entry.signer_public_keys.get(&vote.signer_id) != Some(&vote.signer_public_key) {
            return Err(ApiError::bad_request(
                "activate vote is not from a pinned signer",
            ));
        }
        verify(
            &vote.signer_public_key,
            &gp_wire::signer_rotation_activate_vote(vote).map_err(ApiError::bad_request)?,
            &vote.signer_signature,
        )
        .map_err(ApiError::bad_request)?;
    }
    entry
        .register
        .persist_successor_before_ack(
            entry.capsule.config_ref,
            entry.capsule.capsule_hash,
            request.capsule.config_ref,
            request.capsule.capsule_hash,
        )
        .map_err(ApiError::bad_request)?;
    let predecessor = entry.capsule.clone();
    let witness_id = entry.witness_id;
    let successor_epoch = request.capsule.config_ref.guardian_epoch;
    let mut stored_capsule = request.capsule;
    stored_capsule.activation_certificate = Some(request.activation_certificate.clone());
    stored_capsule.activation_qc = None;

    let witness_key = signing_key(state.identity.kem_seed);
    let mut ack = gp_types::WitnessActivationAck {
        context: request.activation_certificate.context,
        plan_hash: request.activation_certificate.plan_hash,
        activation_certificate_hash: activation_hash,
        witness_id,
        predecessor_epoch: predecessor.config_ref.guardian_epoch,
        predecessor_capsule_hash: predecessor.capsule_hash,
        successor_epoch,
        successor_capsule_hash: capsule_hash,
        witness_public_key: verifying_key_bytes(&witness_key),
        witness_signature: vec![],
    };
    let transcript = gp_wire::witness_activation_ack(&ack).map_err(ApiError::bad_request)?;
    ack.witness_signature = sign(&witness_key, &transcript);
    entry.pending_capsule = Some(stored_capsule);
    entry.pending_ack = Some(ack.clone());
    // Persist the successor, one-child lock, and signed ack before returning.
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ack))
}

async fn witness_finalize(
    State(state): State<WitnessServerState>,
    AxumPath(config_id): AxumPath<String>,
    Json(request): Json<WitnessFinalizeRequest>,
) -> Result<Json<ProvisionAck>, ApiError> {
    let mut store = state.store.lock().await;
    let entry = store
        .data
        .entries
        .get_mut(&config_id)
        .ok_or_else(|| ApiError::not_found("witness configuration was not found"))?;
    let pending = entry
        .pending_capsule
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("witness has no pending successor"))?;
    let pending_ack = entry
        .pending_ack
        .as_ref()
        .ok_or_else(|| ApiError::bad_request("pending successor has no witness ack"))?;
    let qc = &request.activation_qc;
    if entry
        .rotation_cancellations
        .contains_key(&hex::encode(qc.rotation_id))
    {
        return Err(ApiError::bad_request(
            "witness refuses to finalize an owner-cancelled rotation",
        ));
    }
    gp_wire::epoch_activation_qc(qc).map_err(ApiError::bad_request)?;
    if qc.config_id != pending.config_ref.config_id
        || hex::encode(qc.config_id) != config_id
        || qc.witness_fault_bound != entry.witness_fault_bound
        || qc.rotation_id != pending_ack.context.rotation_id
        || qc.predecessor_epoch != pending_ack.predecessor_epoch
        || qc.predecessor_capsule_hash != pending_ack.predecessor_capsule_hash
        || qc.successor_epoch != pending.config_ref.guardian_epoch
        || qc.successor_capsule_hash != pending.capsule_hash
        || qc.activation_certificate_hash != pending_ack.activation_certificate_hash
    {
        return Err(ApiError::bad_request(
            "activation QC does not bind the pending successor",
        ));
    }
    let required = usize::from(entry.witness_fault_bound)
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| ApiError::bad_request("witness quorum overflow"))?;
    let mut witness_ids = BTreeSet::new();
    for ack in &qc.witness_acks {
        let pinned = entry
            .witness_public_keys
            .get(&ack.witness_id)
            .ok_or_else(|| ApiError::bad_request("QC contains an unpinned witness"))?;
        if !witness_ids.insert(ack.witness_id) || pinned != &ack.witness_public_key {
            return Err(ApiError::bad_request(
                "QC contains duplicate or substituted witnesses",
            ));
        }
        verify(
            pinned,
            &gp_wire::witness_activation_ack(ack).map_err(ApiError::bad_request)?,
            &ack.witness_signature,
        )
        .map_err(ApiError::bad_request)?;
    }
    if witness_ids.len() < required
        || !qc
            .witness_acks
            .iter()
            .any(|ack| ack.witness_id == entry.witness_id && ack == pending_ack)
    {
        return Err(ApiError::bad_request(
            "QC has no 2f+1 quorum or omits this witness's exact ack",
        ));
    }
    let mut activated = entry
        .pending_capsule
        .take()
        .expect("pending capsule checked above");
    activated.activation_qc = Some(request.activation_qc);
    entry.capsule = activated;
    entry.pending_ack = None;
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox: config_id,
        stored: true,
    }))
}

async fn witness_read(
    State(state): State<WitnessServerState>,
    AxumPath(config_id): AxumPath<String>,
    Json(challenge): Json<gp_types::EpochReadChallenge>,
) -> Result<Json<WitnessReadEnvelope>, ApiError> {
    if challenge.protocol_version != PROTOCOL_VERSION_V3
        || hex::encode(challenge.config_id) != config_id
    {
        return Err(ApiError::bad_request("invalid witness read challenge"));
    }
    let now = wall_now().map_err(ApiError::bad_request)?;
    if challenge.issued_at > now || now >= challenge.expiry {
        return Err(ApiError::bad_request("expired witness read challenge"));
    }
    gp_wire::epoch_read_challenge(&challenge).map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    let entry = store
        .data
        .entries
        .get_mut(&config_id)
        .ok_or_else(|| ApiError::not_found("witness configuration was not found"))?;
    entry
        .register
        .observe_read_nonce(challenge.client_nonce)
        .map_err(ApiError::bad_request)?;
    let capsule = entry.capsule.clone();
    let witness_id = entry.witness_id;
    store.save().map_err(ApiError::bad_request)?;
    let witness_key = signing_key(state.identity.kem_seed);
    let mut response = gp_types::WitnessEpochReadResponse {
        protocol_version: PROTOCOL_VERSION_V3,
        config_id: challenge.config_id,
        client_nonce: challenge.client_nonce,
        witness_id,
        highest_guardian_epoch: capsule.config_ref.guardian_epoch,
        capsule_hash: capsule.capsule_hash,
        witness_public_key: verifying_key_bytes(&witness_key),
        witness_signature: vec![],
    };
    let transcript =
        gp_wire::witness_epoch_read_response(&response).map_err(ApiError::bad_request)?;
    response.witness_signature = sign(&witness_key, &transcript);
    Ok(Json(WitnessReadEnvelope { response, capsule }))
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
        .route("/v3/node-info", get(signer_info_v3))
        .route("/v1/provision", post(signer_provision))
        .route("/v1/mailbox/{mailbox}", post(signer_mailbox))
        .route("/v3/provision", post(signer_rotation_provision))
        .route("/v3/mailbox/{mailbox}", post(signer_rotation_mailbox))
        .route("/v3/recovery/{mailbox}", post(signer_recovery_mailbox_v3))
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

async fn signer_info_v3(State(state): State<SignerServerState>) -> Json<NodeInfo> {
    Json(node_info_v3(&state.identity, NodeRole::Signer))
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

async fn signer_rotation_provision(
    State(state): State<SignerServerState>,
    headers: HeaderMap,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.admin_token.is_empty() || bearer(&headers) != Some(state.admin_token.as_str()) {
        return Err(ApiError::forbidden("invalid node provisioning token"));
    }
    let recipient = RecipientKeyPair::from_seed(state.identity.kem_seed);
    let plaintext = recipient
        .open(
            &body.sealed,
            &gp_wire::node_provision_context(&state.identity.node_id, "signer-v3")
                .map_err(ApiError::bad_request)?,
        )
        .map_err(ApiError::bad_request)?;
    let provision: SignerRotationProvisionV3 =
        serde_json::from_slice(&plaintext).map_err(ApiError::bad_request)?;
    crate::rotation_protocol::validate_activated_capsule_v3(
        &provision.recovery_card,
        &provision.active_capsule,
    )
    .map_err(ApiError::bad_request)?;
    if provision.signer_id == 0
        || provision.signer_id > provision.active_capsule.signer_count
        || provision.signing_public_key != verifying_key_bytes(&signing_key(provision.signing_seed))
    {
        return Err(ApiError::bad_request("invalid protocol-v3 signer identity"));
    }
    let signer_leaf = sha256(
        &gp_wire::signer_leaf(provision.signer_id, &provision.signing_public_key)
            .map_err(ApiError::bad_request)?,
    );
    merkle_verify(
        provision.active_capsule.signer_set_commitment,
        signer_leaf,
        usize::from(provision.signer_id - 1),
        usize::from(provision.active_capsule.signer_count),
        &provision.membership_proof,
    )
    .map_err(ApiError::bad_request)?;
    let mailbox = mailbox_id(&provision.mailbox).map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    if store.data.rotation_entries.contains_key(&mailbox) {
        return Err(ApiError::bad_request(
            "protocol-v3 signer mailbox is already provisioned",
        ));
    }
    store.data.rotation_entries.insert(
        mailbox.clone(),
        SignerRotationEntryV3 {
            provision,
            security_state: gp_storage::SignerRotationStore::new(),
            recovery_requests: BTreeMap::new(),
            recovery_nonces: BTreeSet::new(),
        },
    );
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox,
        stored: true,
    }))
}

async fn signer_rotation_mailbox(
    State(state): State<SignerServerState>,
    AxumPath(mailbox): AxumPath<String>,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<SealedMailboxBody>, ApiError> {
    if !state.auto_approve {
        return Err(ApiError::forbidden(
            "automatic social approval is disabled on this signer",
        ));
    }
    let recipient = RecipientKeyPair::from_seed(state.identity.kem_seed);
    let plaintext = recipient
        .open(
            &body.sealed,
            &gp_wire::mailbox_transport_context(&mailbox, "rotation-request")
                .map_err(ApiError::bad_request)?,
        )
        .map_err(ApiError::bad_request)?;
    let request: SignerRotationRequestV3 =
        serde_json::from_slice(&plaintext).map_err(ApiError::bad_request)?;
    let response_recipient_key = match &request {
        SignerRotationRequestV3::Abort {
            response_recipient_key,
            ..
        }
        | SignerRotationRequestV3::FinalizeAbort {
            response_recipient_key,
            ..
        }
        | SignerRotationRequestV3::FinalizeOwnerCancel {
            response_recipient_key,
            ..
        } => response_recipient_key.clone(),
        _ => request.context().recipient_key.clone(),
    };
    let now = wall_now().map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    let entry = store
        .data
        .rotation_entries
        .get_mut(&mailbox)
        .ok_or_else(|| ApiError::not_found("protocol-v3 signer mailbox is not provisioned"))?;
    let response = crate::rotation_runtime::handle_signer_rotation_v3(entry, request, now)
        .map_err(ApiError::bad_request)?;
    store.save().map_err(ApiError::bad_request)?;
    let bytes = serde_json::to_vec(&response).map_err(ApiError::bad_request)?;
    let sealed = seal_to_recipient(
        &response_recipient_key,
        random_id(),
        random_nonce(),
        &bytes,
        &gp_wire::mailbox_transport_context(&mailbox, "rotation-response")
            .map_err(ApiError::bad_request)?,
    )
    .map_err(ApiError::bad_request)?;
    Ok(Json(SealedMailboxBody { sealed }))
}

async fn signer_recovery_mailbox_v3(
    State(state): State<SignerServerState>,
    AxumPath(mailbox): AxumPath<String>,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<SealedMailboxBody>, ApiError> {
    if !state.auto_approve {
        return Err(ApiError::forbidden(
            "automatic social approval is disabled on this signer",
        ));
    }
    let recipient = RecipientKeyPair::from_seed(state.identity.kem_seed);
    let plaintext = recipient
        .open(
            &body.sealed,
            &gp_wire::mailbox_transport_context(&mailbox, "recovery-request-v3")
                .map_err(ApiError::bad_request)?,
        )
        .map_err(ApiError::bad_request)?;
    let request: SignerRecoveryRequestV3 =
        serde_json::from_slice(&plaintext).map_err(ApiError::bad_request)?;
    let response_recipient_key = match &request {
        SignerRecoveryRequestV3::Approve { request, .. }
        | SignerRecoveryRequestV3::Release { request } => request.recovery_recipient_key.clone(),
    };
    let now = wall_now().map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    let entry = store
        .data
        .rotation_entries
        .get_mut(&mailbox)
        .ok_or_else(|| ApiError::not_found("protocol-v3 signer mailbox is not provisioned"))?;
    let response = crate::recovery_runtime::handle_signer_recovery_v3(entry, request, now)
        .map_err(ApiError::bad_request)?;
    store.save().map_err(ApiError::bad_request)?;
    let sealed = seal_to_recipient(
        &response_recipient_key,
        random_id(),
        random_nonce(),
        &serde_json::to_vec(&response).map_err(ApiError::bad_request)?,
        &gp_wire::mailbox_transport_context(&mailbox, "recovery-response-v3")
            .map_err(ApiError::bad_request)?,
    )
    .map_err(ApiError::bad_request)?;
    Ok(Json(SealedMailboxBody { sealed }))
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
        .route("/v3/node-info", get(guardian_info_v3))
        .route("/v1/provision", post(guardian_provision))
        .route("/v1/mailbox/{mailbox}", post(guardian_mailbox))
        .route("/v3/provision", post(guardian_rotation_provision))
        .route("/v3/aliases", post(guardian_rotation_alias))
        .route("/v3/mailbox/{mailbox}", post(guardian_rotation_mailbox))
        .route("/v3/recovery/{mailbox}", post(guardian_recovery_mailbox_v3))
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

async fn guardian_info_v3(State(state): State<GuardianServerState>) -> Json<NodeInfo> {
    Json(node_info_v3(&state.identity, NodeRole::Guardian))
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

async fn guardian_rotation_provision(
    State(state): State<GuardianServerState>,
    headers: HeaderMap,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.admin_token.is_empty() || bearer(&headers) != Some(state.admin_token.as_str()) {
        return Err(ApiError::forbidden("invalid node provisioning token"));
    }
    let recipient = RecipientKeyPair::from_seed(state.identity.kem_seed);
    let plaintext = recipient
        .open(
            &body.sealed,
            &gp_wire::node_provision_context(&state.identity.node_id, "guardian-v3")
                .map_err(ApiError::bad_request)?,
        )
        .map_err(ApiError::bad_request)?;
    let provision: GuardianRotationProvisionV3 =
        serde_json::from_slice(&plaintext).map_err(ApiError::bad_request)?;
    crate::rotation_protocol::validate_activated_capsule_v3(
        &provision.recovery_card,
        &provision.predecessor_capsule,
    )
    .map_err(ApiError::bad_request)?;
    if provision.signing_public_key != verifying_key_bytes(&signing_key(provision.signing_seed))
        || provision.epoch_store.config_id != provision.predecessor_capsule.config_ref.config_id
        || provision.epoch_store.expected_predecessor != provision.predecessor_capsule.config_ref
        || provision.epoch_store.expected_predecessor_capsule_hash
            != provision.predecessor_capsule.capsule_hash
    {
        return Err(ApiError::bad_request(
            "guardian provision does not bind the exact predecessor and identity",
        ));
    }
    for (id, key) in &provision.signer_public_keys {
        if *id == 0 || *id > provision.predecessor_capsule.signer_count {
            return Err(ApiError::bad_request("guardian signer pin is out of range"));
        }
        // A partial cache is only an optimization. Every certificate carries
        // a Merkle proof against the capsule-pinned root.
        let _ = gp_wire::signer_leaf(*id, key).map_err(ApiError::bad_request)?;
    }
    if provision.predecessor_capsule.minimum_recovery_delay < PRODUCTION_MIN_DELAY_SECS
        && !state.allow_insecure_demo_delay
    {
        return Err(ApiError::forbidden(
            "guardian refuses a v3 delay below 24 hours outside explicit demo mode",
        ));
    }
    let mailbox = mailbox_id(&provision.mailbox).map_err(ApiError::bad_request)?;
    let mut store = state.store.lock().await;
    if store.data.rotation_entries.contains_key(&mailbox) {
        return Err(ApiError::bad_request(
            "protocol-v3 guardian mailbox is already provisioned",
        ));
    }
    store.data.rotation_entries.insert(
        mailbox.clone(),
        GuardianRotationEntryV3 {
            provision,
            sessions: BTreeMap::new(),
            recoveries: BTreeMap::new(),
        },
    );
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox,
        stored: true,
    }))
}

async fn guardian_rotation_alias(
    State(state): State<GuardianServerState>,
    headers: HeaderMap,
    Json(alias): Json<GuardianRouteAliasV3>,
) -> Result<Json<ProvisionAck>, ApiError> {
    if state.admin_token.is_empty() || bearer(&headers) != Some(state.admin_token.as_str()) {
        return Err(ApiError::forbidden("invalid node provisioning token"));
    }
    if alias.mailbox.len() < 32 || alias.existing_mailbox.len() < 32 {
        return Err(ApiError::bad_request(
            "invalid opaque guardian mailbox alias",
        ));
    }
    let mut store = state.store.lock().await;
    let existing_primary = store
        .data
        .rotation_aliases
        .get(&alias.existing_mailbox)
        .cloned()
        .unwrap_or_else(|| alias.existing_mailbox.clone());
    if !store.data.rotation_entries.contains_key(&existing_primary)
        || store.data.rotation_entries.contains_key(&alias.mailbox)
        || store.data.rotation_aliases.contains_key(&alias.mailbox)
        || alias.mailbox == existing_primary
    {
        return Err(ApiError::bad_request(
            "alias target is missing or alias already exists",
        ));
    }
    store
        .data
        .rotation_aliases
        .insert(alias.mailbox.clone(), existing_primary);
    store.save().map_err(ApiError::bad_request)?;
    Ok(Json(ProvisionAck {
        mailbox: alias.mailbox,
        stored: true,
    }))
}

async fn guardian_rotation_mailbox(
    State(state): State<GuardianServerState>,
    AxumPath(mailbox): AxumPath<String>,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<SealedMailboxBody>, ApiError> {
    let recipient = RecipientKeyPair::from_seed(state.identity.kem_seed);
    let plaintext = recipient
        .open(
            &body.sealed,
            &gp_wire::mailbox_transport_context(&mailbox, "rotation-request")
                .map_err(ApiError::bad_request)?,
        )
        .map_err(ApiError::bad_request)?;
    let request: GuardianRotationRequestV3 =
        serde_json::from_slice(&plaintext).map_err(ApiError::bad_request)?;
    let response_recipient_key = match &request {
        GuardianRotationRequestV3::Cancel { certificate, .. } => {
            certificate.cancel_response_recipient_key.clone()
        }
        _ => request.context().recipient_key.clone(),
    };
    let wall = wall_now().map_err(ApiError::bad_request)?;
    let monotonic = monotonic_now().map_err(ApiError::bad_request)?;
    let current_boot = boot_id();
    let mut store = state.store.lock().await;
    let primary_mailbox = store
        .data
        .rotation_aliases
        .get(&mailbox)
        .cloned()
        .unwrap_or_else(|| mailbox.clone());
    let entry = store
        .data
        .rotation_entries
        .get_mut(&primary_mailbox)
        .ok_or_else(|| ApiError::not_found("protocol-v3 guardian mailbox is not provisioned"))?;
    let response = crate::guardian_runtime::handle_guardian_rotation_v3(
        entry,
        &state.identity.kem_seed,
        request,
        wall,
        monotonic,
        &current_boot,
        state.allow_insecure_demo_delay,
    )
    .map_err(ApiError::bad_request)?;
    // Persist ACTIVE/PREPARED state, replay counters and encrypted provider
    // journal before returning any ack or outbound DPSS message.
    store.save().map_err(ApiError::bad_request)?;
    let bytes = serde_json::to_vec(&response).map_err(ApiError::bad_request)?;
    let sealed = seal_to_recipient(
        &response_recipient_key,
        random_id(),
        random_nonce(),
        &bytes,
        &gp_wire::mailbox_transport_context(&mailbox, "rotation-response")
            .map_err(ApiError::bad_request)?,
    )
    .map_err(ApiError::bad_request)?;
    Ok(Json(SealedMailboxBody { sealed }))
}

async fn guardian_recovery_mailbox_v3(
    State(state): State<GuardianServerState>,
    AxumPath(mailbox): AxumPath<String>,
    Json(body): Json<SealedMailboxBody>,
) -> Result<Json<SealedMailboxBody>, ApiError> {
    let recipient = RecipientKeyPair::from_seed(state.identity.kem_seed);
    let plaintext = recipient
        .open(
            &body.sealed,
            &gp_wire::mailbox_transport_context(&mailbox, "recovery-request-v3")
                .map_err(ApiError::bad_request)?,
        )
        .map_err(ApiError::bad_request)?;
    let request: GuardianRecoveryRequestV3 =
        serde_json::from_slice(&plaintext).map_err(ApiError::bad_request)?;
    let response_recipient_key = match &request {
        GuardianRecoveryRequestV3::Cancel { certificate, .. } => {
            certificate.cancel_response_recipient_key.clone()
        }
        _ => request.request().recovery_recipient_key.clone(),
    };
    let wall = wall_now().map_err(ApiError::bad_request)?;
    let monotonic = monotonic_now().map_err(ApiError::bad_request)?;
    let current_boot = boot_id();
    let mut store = state.store.lock().await;
    let primary_mailbox = store
        .data
        .rotation_aliases
        .get(&mailbox)
        .cloned()
        .unwrap_or_else(|| mailbox.clone());
    let entry = store
        .data
        .rotation_entries
        .get_mut(&primary_mailbox)
        .ok_or_else(|| ApiError::not_found("protocol-v3 guardian mailbox is not provisioned"))?;
    let response = crate::recovery_runtime::handle_guardian_recovery_v3(
        entry,
        request,
        wall,
        monotonic,
        &current_boot,
        state.allow_insecure_demo_delay,
    )
    .map_err(ApiError::bad_request)?;
    // Delay/cancellation/release state is durable before any response leaves.
    store.save().map_err(ApiError::bad_request)?;
    let sealed = seal_to_recipient(
        &response_recipient_key,
        random_id(),
        random_nonce(),
        &serde_json::to_vec(&response).map_err(ApiError::bad_request)?,
        &gp_wire::mailbox_transport_context(&mailbox, "recovery-response-v3")
            .map_err(ApiError::bad_request)?,
    )
    .map_err(ApiError::bad_request)?;
    Ok(Json(SealedMailboxBody { sealed }))
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

#[cfg(test)]
mod rotation_tests {
    use super::*;
    use std::collections::BTreeMap;

    use gp_types::{
        AeadCiphertext, ConfigCapsuleV3, ConfigRef, DpssSuiteId, EpochActivationQc,
        EpochReadChallenge, Id32, OwnerRotationCancelCertificate, RotationActivateCertificate,
        RotationContext, SignerRotationActivateVote,
    };

    fn config_ref(epoch: u64, marker: u8) -> ConfigRef {
        ConfigRef {
            config_id: [1; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: epoch,
            epoch_binding: [marker; 32],
        }
    }

    fn capsule(config_ref: ConfigRef, predecessor: Id32) -> ConfigCapsuleV3 {
        let mut value = ConfigCapsuleV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref,
            capsule_hash: [0; 32],
            predecessor_capsule_hash: predecessor,
            signer_count: 3,
            signer_threshold: 2,
            guardian_count: 8,
            guardian_threshold: 5,
            minimum_recovery_delay: 10,
            max_request_lifetime: 100,
            signer_set_commitment: [3; 32],
            owner_cancel_public_key: [4; 32],
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: [5; 32],
            ciphertext_fragment_root: [9; 32],
            guardian_material_root: [6; 32],
            encrypted_recovery_descriptor: AeadCiphertext {
                nonce: [7; 24],
                ciphertext: vec![8; 64],
            },
            activation_certificate: None,
            activation_qc: None,
        };
        value.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&value).unwrap());
        value
    }

    fn activation(
        predecessor: &ConfigCapsuleV3,
        successor: &ConfigCapsuleV3,
        signer_seeds: &[Id32],
        membership_proofs: &[Vec<u8>],
        rotation_id: Id32,
    ) -> RotationActivateCertificate {
        let now = wall_now().unwrap();
        let context = RotationContext {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: predecessor.config_ref,
            rotation_id,
            predecessor_capsule_hash: predecessor.capsule_hash,
            recipient_key: vec![11; 32],
            nonce: [12; 32],
            issued_at: now,
            expiry: now + 100,
        };
        let mut votes = Vec::new();
        for ((offset, seed), proof) in signer_seeds.iter().enumerate().zip(membership_proofs) {
            let key = signing_key(*seed);
            let mut vote = SignerRotationActivateVote {
                context: context.clone(),
                plan_hash: [13; 32],
                ready_certificate_hash: [14; 32],
                successor_capsule_hash: successor.capsule_hash,
                signer_id: u16::try_from(offset + 1).unwrap(),
                signer_public_key: verifying_key_bytes(&key),
                signer_membership_proof: proof.clone(),
                signer_signature: vec![],
            };
            vote.signer_signature = sign(
                &key,
                &gp_wire::signer_rotation_activate_vote(&vote).unwrap(),
            );
            votes.push(vote);
        }
        RotationActivateCertificate {
            context,
            plan_hash: [13; 32],
            ready_certificate_hash: [14; 32],
            successor: successor.config_ref,
            successor_capsule_hash: successor.capsule_hash,
            votes,
        }
    }

    #[tokio::test]
    async fn witness_persists_one_child_and_nonce_bound_reads_across_restart() {
        let temp =
            std::env::temp_dir().join(format!("gp-witness-test-{}", hex::encode(random_id())));
        fs::create_dir_all(&temp).unwrap();
        let path = temp.join("state.json");
        let identity = Arc::new(IdentityDisk {
            node_id: "witness-test".into(),
            kem_seed: [20; 32],
        });
        let state = WitnessServerState {
            identity,
            store: Arc::new(Mutex::new(Persisted {
                path: path.clone(),
                data: WitnessDisk::default(),
            })),
            admin_token: Arc::new("test-token".into()),
        };
        let signer_seeds = [[21; 32], [22; 32], [23; 32]];
        let signer_public_keys = signer_seeds
            .iter()
            .enumerate()
            .map(|(offset, seed)| {
                (
                    u16::try_from(offset + 1).unwrap(),
                    verifying_key_bytes(&signing_key(*seed)),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let signer_leaves = signer_public_keys
            .iter()
            .map(|(id, key)| sha256(&gp_wire::signer_leaf(*id, key).unwrap()))
            .collect::<Vec<_>>();
        let (signer_root, signer_proofs) = merkle_commit(&signer_leaves).unwrap();
        let mut genesis = capsule(config_ref(1, 1), [0; 32]);
        genesis.signer_set_commitment = signer_root;
        let owner_cancel_seed = [44; 32];
        genesis.owner_cancel_public_key = verifying_key_bytes(&signing_key(owner_cancel_seed));
        genesis.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&genesis).unwrap());
        let witness_seeds = [[20; 32], [40; 32], [41; 32], [42; 32]];
        let witness_public_keys = witness_seeds
            .iter()
            .enumerate()
            .map(|(offset, seed)| {
                (
                    u16::try_from(offset + 1).unwrap(),
                    verifying_key_bytes(&signing_key(*seed)),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer test-token".parse().unwrap());
        let _ = witness_provision(
            State(state.clone()),
            headers,
            Json(WitnessConfigProvision {
                witness_id: 1,
                capsule: genesis.clone(),
                signer_public_keys,
                witness_public_keys,
                witness_fault_bound: 1,
            }),
        )
        .await
        .unwrap();

        let mut successor = capsule(config_ref(2, 2), genesis.capsule_hash);
        successor.signer_set_commitment = signer_root;
        successor.owner_cancel_public_key = genesis.owner_cancel_public_key;
        successor.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&successor).unwrap());
        let certificate = activation(
            &genesis,
            &successor,
            &signer_seeds[..2],
            &signer_proofs[..2],
            [10; 32],
        );
        let ack = witness_activate(
            State(state.clone()),
            AxumPath(hex::encode(genesis.config_ref.config_id)),
            Json(WitnessActivationRequest {
                capsule: successor.clone(),
                activation_certificate: certificate.clone(),
            }),
        )
        .await
        .unwrap()
        .0;
        verify(
            &ack.witness_public_key,
            &gp_wire::witness_activation_ack(&ack).unwrap(),
            &ack.witness_signature,
        )
        .unwrap();

        // A merely stored successor has no recovery authority before 2f+1 QC.
        let before_qc_challenge = EpochReadChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: genesis.config_ref.config_id,
            client_nonce: [29; 32],
            response_recipient_key: vec![31; 32],
            issued_at: wall_now().unwrap(),
            expiry: wall_now().unwrap() + 100,
        };
        let before_qc = witness_read(
            State(state.clone()),
            AxumPath(hex::encode(genesis.config_ref.config_id)),
            Json(before_qc_challenge),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(before_qc.response.highest_guardian_epoch, 1);

        // Owner cancellation wins immediately before QC finalization, rolls
        // back only the pending witness child, and permanently rejects the
        // cancelled rotation id.
        let cancel_recipient = RecipientKeyPair::from_seed([45; 32]);
        let mut cancellation = OwnerRotationCancelCertificate {
            context: certificate.context.clone(),
            plan_hash: certificate.plan_hash,
            reason_code: 1,
            cancel_response_recipient_key: cancel_recipient.public_key().to_vec(),
            owner_cancel_public_key: genesis.owner_cancel_public_key,
            owner_signature: vec![],
        };
        cancellation.owner_signature = sign(
            &signing_key(owner_cancel_seed),
            &gp_wire::owner_rotation_cancel_certificate(&cancellation).unwrap(),
        );
        let mut forged_cancellation = cancellation.clone();
        forged_cancellation.owner_signature[0] ^= 1;
        assert!(
            witness_cancel_rotation(
                State(state.clone()),
                AxumPath(hex::encode(genesis.config_ref.config_id)),
                Json(WitnessRotationCancelRequest {
                    certificate: forged_cancellation,
                }),
            )
            .await
            .is_err()
        );
        let cancel_ack = witness_cancel_rotation(
            State(state.clone()),
            AxumPath(hex::encode(genesis.config_ref.config_id)),
            Json(WitnessRotationCancelRequest {
                certificate: cancellation,
            }),
        )
        .await
        .unwrap()
        .0;
        verify(
            &cancel_ack.witness_public_key,
            &gp_wire::witness_rotation_cancel_ack(&cancel_ack).unwrap(),
            &cancel_ack.witness_signature,
        )
        .unwrap();
        assert!(
            witness_activate(
                State(state.clone()),
                AxumPath(hex::encode(genesis.config_ref.config_id)),
                Json(WitnessActivationRequest {
                    capsule: successor,
                    activation_certificate: certificate,
                }),
            )
            .await
            .is_err()
        );

        let mut successor = capsule(config_ref(2, 3), genesis.capsule_hash);
        successor.signer_set_commitment = signer_root;
        successor.owner_cancel_public_key = genesis.owner_cancel_public_key;
        successor.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&successor).unwrap());
        let certificate = activation(
            &genesis,
            &successor,
            &signer_seeds[..2],
            &signer_proofs[..2],
            [15; 32],
        );
        let ack = witness_activate(
            State(state.clone()),
            AxumPath(hex::encode(genesis.config_ref.config_id)),
            Json(WitnessActivationRequest {
                capsule: successor.clone(),
                activation_certificate: certificate,
            }),
        )
        .await
        .unwrap()
        .0;

        let activation_certificate_hash = ack.activation_certificate_hash;
        let mut acks = vec![ack.clone()];
        for (offset, seed) in witness_seeds[1..3].iter().enumerate() {
            let key = signing_key(*seed);
            let mut other = ack.clone();
            other.witness_id = u16::try_from(offset + 2).unwrap();
            other.witness_public_key = verifying_key_bytes(&key);
            other.witness_signature = sign(&key, &gp_wire::witness_activation_ack(&other).unwrap());
            acks.push(other);
        }
        let qc = EpochActivationQc {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: genesis.config_ref.config_id,
            rotation_id: ack.context.rotation_id,
            predecessor_epoch: 1,
            predecessor_capsule_hash: genesis.capsule_hash,
            successor_epoch: 2,
            successor_capsule_hash: successor.capsule_hash,
            activation_certificate_hash,
            witness_fault_bound: 1,
            witness_acks: acks,
        };
        let _ = witness_finalize(
            State(state.clone()),
            AxumPath(hex::encode(genesis.config_ref.config_id)),
            Json(WitnessFinalizeRequest { activation_qc: qc }),
        )
        .await
        .unwrap();

        let now = wall_now().unwrap();
        let challenge = EpochReadChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: genesis.config_ref.config_id,
            client_nonce: [30; 32],
            response_recipient_key: vec![31; 32],
            issued_at: now,
            expiry: now + 100,
        };
        let read = witness_read(
            State(state.clone()),
            AxumPath(hex::encode(genesis.config_ref.config_id)),
            Json(challenge.clone()),
        )
        .await
        .unwrap()
        .0;
        assert_eq!(read.response.highest_guardian_epoch, 2);
        assert_eq!(read.capsule.capsule_hash, successor.capsule_hash);
        assert!(
            witness_read(
                State(state.clone()),
                AxumPath(hex::encode(genesis.config_ref.config_id)),
                Json(challenge),
            )
            .await
            .is_err()
        );

        let rebooted: WitnessDisk = load_json(&path).unwrap();
        let entry = &rebooted.entries[&hex::encode(genesis.config_ref.config_id)];
        assert_eq!(entry.register.highest_guardian_epoch, 2);
        assert_eq!(entry.register.highest_capsule_hash, successor.capsule_hash);
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn state_files_carry_a_schema_version_and_refuse_newer_ones() {
        let temp = std::env::temp_dir().join(format!(
            "gp-schema-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp).unwrap();
        let path = temp.join("state.json");

        // every save stamps the current schema version
        let mut disk = SignerDisk::default();
        disk.last_approval_at.insert("mailbox".into(), 7);
        save_json(&path, &disk).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            raw.get(SCHEMA_VERSION_FIELD).and_then(|v| v.as_u64()),
            Some(STATE_SCHEMA_VERSION)
        );

        // and it round-trips through the version check
        let loaded: SignerDisk = load_json(&path).unwrap();
        assert_eq!(loaded.last_approval_at.get("mailbox"), Some(&7));

        // a file written by a newer build is refused rather than silently
        // re-saved with the unknown fields dropped
        let mut newer = raw.clone();
        newer.as_object_mut().unwrap().insert(
            SCHEMA_VERSION_FIELD.to_string(),
            serde_json::Value::from(STATE_SCHEMA_VERSION + 1),
        );
        newer
            .as_object_mut()
            .unwrap()
            .insert("field_from_the_future".into(), serde_json::Value::from(1));
        fs::write(&path, serde_json::to_vec(&newer).unwrap()).unwrap();
        let refused = load_json::<SignerDisk>(&path);
        assert!(refused.is_err(), "newer schema must not load");

        // a legacy file with no version field still loads
        let mut legacy = raw.clone();
        legacy.as_object_mut().unwrap().remove(SCHEMA_VERSION_FIELD);
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let legacy_loaded: SignerDisk = load_json(&path).unwrap();
        assert_eq!(legacy_loaded.last_approval_at.get("mailbox"), Some(&7));

        fs::remove_dir_all(temp).unwrap();
    }
}
