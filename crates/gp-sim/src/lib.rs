//! Deterministic end-to-end protocol simulator.

use std::collections::{BTreeMap, BTreeSet};

use gp_core::{CoreError, GuardianMachine, RecoveryEvent, RecoveryMachine};
use gp_crypto::{
    CryptoError, RecipientKeyPair, SecretVec, XWING_PUBLIC_KEY_LEN, aead_decrypt, aead_encrypt,
    descriptor_key, erasure_encode, erasure_reconstruct, guardian_share_key, hash_aead,
    merkle_commit, merkle_verify, recover_secret, sha256, sign, signing_key, split_secret, verify,
    verifying_key_bytes,
};
use gp_storage::{ConfigStore, GuardianState, SignerState, StorageError};
use gp_transport::{ObserverSummary, TransportConfig, protect_payload, simulate_observer};
use gp_types::{
    AeadCiphertext, BeginRecoveryCertificate, CancelCertificate, CancelVote, ConfigCapsule,
    CryptoSuite, GuardianContribution, GuardianPolicy, GuardianRecord, GuardianRoute, Id32,
    MetadataMode, PRODUCTION_MIN_DELAY_SECS, PROTOCOL_VERSION, RecoveryCard, RecoveryDescriptor,
    RecoveryRequest, RecoveryState, ReleaseCertificate, ReleaseVote, SetupPolicy,
    SignerContribution, SignerPolicy,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Wire(#[from] gp_wire::WireError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("protocol threshold was not reached")]
    Threshold,
    #[error("certificate validation failed")]
    InvalidCertificate,
    #[error("guardian contribution was not bound to this request")]
    RequestBinding,
    #[error("recovered secret did not match")]
    RecoveryMismatch,
    #[error("invalid simulator options: {0}")]
    InvalidOptions(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DemoOptions {
    pub seed: u64,
    pub mode: MetadataMode,
    pub secret: String,
    pub offline_signer: Option<u16>,
    pub offline_guardian: Option<u16>,
    pub corrupt_guardian: Option<u16>,
    pub cancel_before_release: bool,
    pub simulated_delay_secs: u64,
    pub signer_count: u16,
    pub signer_threshold: u16,
    pub cancellation_threshold: u16,
    pub guardian_count: u16,
    pub guardian_threshold: u16,
    pub network_latency_ms: u64,
    pub packet_loss_percent: u8,
    pub packet_duplication_percent: u8,
    pub mix_drop_percent: u8,
    pub cover_rate: u16,
}

impl Default for DemoOptions {
    fn default() -> Self {
        Self {
            seed: 424_242,
            mode: MetadataMode::Strong,
            secret: "correct horse battery staple".into(),
            offline_signer: Some(3),
            offline_guardian: None,
            corrupt_guardian: Some(1),
            cancel_before_release: false,
            simulated_delay_secs: 5,
            signer_count: 3,
            signer_threshold: 2,
            cancellation_threshold: 2,
            guardian_count: 8,
            guardian_threshold: 5,
            network_latency_ms: 120,
            packet_loss_percent: 0,
            packet_duplication_percent: 0,
            mix_drop_percent: 0,
            cover_rate: 3,
        }
    }
}

impl DemoOptions {
    pub fn validate(&self) -> Result<(), SimError> {
        if self.secret.is_empty() {
            return Err(SimError::InvalidOptions(
                "enter a secret or choose a small file".into(),
            ));
        }
        if self.secret.len() > 1024 * 1024 {
            return Err(SimError::InvalidOptions(
                "the demo accepts files up to 1 MiB".into(),
            ));
        }
        if self.signer_count == 0 || self.signer_count > 255 {
            return Err(SimError::InvalidOptions(
                "signer count must be between 1 and 255".into(),
            ));
        }
        if self.signer_threshold == 0 || self.signer_threshold > self.signer_count {
            return Err(SimError::InvalidOptions(
                "signer threshold must be between 1 and the signer count".into(),
            ));
        }
        if self.cancellation_threshold == 0 || self.cancellation_threshold > self.signer_count {
            return Err(SimError::InvalidOptions(
                "cancellation threshold must be between 1 and the signer count".into(),
            ));
        }
        if self.guardian_count == 0 || self.guardian_count > 255 {
            return Err(SimError::InvalidOptions(
                "guardian count must be between 1 and 255".into(),
            ));
        }
        if self.guardian_threshold == 0 || self.guardian_threshold > self.guardian_count {
            return Err(SimError::InvalidOptions(
                "guardian threshold must be between 1 and the guardian count".into(),
            ));
        }
        if self
            .offline_signer
            .is_some_and(|index| index == 0 || index > self.signer_count)
        {
            return Err(SimError::InvalidOptions(
                "offline signer index must identify an existing signer".into(),
            ));
        }
        if self
            .offline_guardian
            .is_some_and(|index| index == 0 || index > self.guardian_count)
            || self
                .corrupt_guardian
                .is_some_and(|index| index == 0 || index > self.guardian_count)
        {
            return Err(SimError::InvalidOptions(
                "guardian failure index must identify an existing guardian".into(),
            ));
        }
        let available_signers = self.signer_count - u16::from(self.offline_signer.is_some());
        if available_signers < self.signer_threshold {
            return Err(SimError::InvalidOptions(
                "not enough online signers to reach the approval threshold".into(),
            ));
        }
        if self.cancel_before_release && available_signers < self.cancellation_threshold {
            return Err(SimError::InvalidOptions(
                "not enough online signers to reach the cancellation threshold".into(),
            ));
        }
        let unavailable_guardians = match (self.offline_guardian, self.corrupt_guardian) {
            (Some(first), Some(second)) if first != second => 2,
            (Some(_), _) | (_, Some(_)) => 1,
            _ => 0,
        };
        if self.guardian_count.saturating_sub(unavailable_guardians) < self.guardian_threshold {
            return Err(SimError::InvalidOptions(
                "not enough valid guardians remain to reach the recovery threshold".into(),
            ));
        }
        if self.packet_loss_percent > 100
            || self.packet_duplication_percent > 100
            || self.mix_drop_percent > 100
        {
            return Err(SimError::InvalidOptions(
                "network percentages must be between 0 and 100".into(),
            ));
        }
        if self.simulated_delay_secs > 300 {
            return Err(SimError::InvalidOptions(
                "compressed delay must be 300 seconds or less".into(),
            ));
        }
        if self.cover_rate > 100 {
            return Err(SimError::InvalidOptions(
                "cover rate must be 100 cells per epoch or less".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimEvent {
    pub at: u64,
    pub phase: String,
    pub actor: String,
    pub message: String,
    pub state: Option<RecoveryState>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DemoResult {
    pub seed: u64,
    pub mode: MetadataMode,
    pub success: bool,
    pub cancelled: bool,
    pub final_state: RecoveryState,
    pub recovered_secret: Option<String>,
    pub config_id_hex: String,
    pub request_id_hex: String,
    pub signer_threshold: u16,
    pub guardian_threshold: u16,
    pub valid_guardians: usize,
    pub rejected_guardians: Vec<u16>,
    pub rotated_config_version: Option<u64>,
    pub observer: ObserverSummary,
    pub events: Vec<SimEvent>,
    pub security_notice: String,
}

struct DemoWorld {
    card: RecoveryCard,
    signers: Vec<SignerState>,
    guardians: Vec<GuardianState>,
    config_store: ConfigStore,
    authorization_key: SecretVec,
}

pub fn run_demo(options: &DemoOptions) -> Result<DemoResult, SimError> {
    options.validate()?;
    let mut rng = ChaCha20Rng::seed_from_u64(options.seed);
    let policy = SetupPolicy {
        signer_count: options.signer_count,
        signer_threshold: options.signer_threshold,
        cancellation_threshold: options.cancellation_threshold,
        guardian_count: options.guardian_count,
        guardian_threshold: options.guardian_threshold,
        minimum_recovery_delay: gp_types::PRODUCTION_MIN_DELAY_SECS,
    };
    let mut events = Vec::new();
    let mut at = 0;
    log(
        &mut events,
        at,
        "SETUP",
        "owner",
        "Generated independent authorization key A and payload DEK.",
        Some(RecoveryState::Created),
    );
    let mut world = setup_world(options.secret.as_bytes(), &policy, &mut rng, None)?;
    log(
        &mut events,
        at,
        "SETUP",
        "guardians",
        "Stored ciphertext fragments and A-wrapped DEK shares; no plaintext secret or DEK share was stored.",
        None,
    );
    log(
        &mut events,
        at,
        "SETUP",
        "config-store",
        "Published a pseudonymous Config Capsule; the guardian roster remains sealed under A.",
        None,
    );

    // The recovery path uses only the non-secret Recovery Card and the config store.
    let capsule = world.config_store.get(&world.card.config_id)?.clone();
    validate_capsule_against_card(&capsule, &world.card)?;
    let recipient = RecipientKeyPair::from_seed(random_id(&mut rng));
    let request = RecoveryRequest {
        protocol_version: PROTOCOL_VERSION,
        crypto_suite: CryptoSuite::default(),
        config_id: capsule.config_id,
        config_version: capsule.config_version,
        request_id: random_id(&mut rng),
        recovery_recipient_key: recipient.public_key().to_vec(),
        requested_at: at,
        nonce: random_id(&mut rng),
        expiry: at.saturating_add(capsule.max_request_lifetime),
    };
    let request_digest = sha256(&gp_wire::request_digest_preimage(&request)?);
    let mut recovery_machine = RecoveryMachine::default();
    recovery_machine.apply(
        RecoveryEvent::RequestCreated,
        at,
        options.simulated_delay_secs,
    )?;
    at += 1;
    validate_recovery_request(&request, &capsule, at)?;
    log(
        &mut events,
        at,
        "RECOVERY",
        "fresh-client",
        "Scanned Recovery Card, fetched capsule, and generated a fresh one-time X-Wing recipient keypair.",
        Some(recovery_machine.state()),
    );

    let contributions = collect_signer_approvals(
        &mut world.signers,
        &request,
        options.offline_signer,
        capsule.signer_threshold,
        &mut rng,
    )?;
    let begin = BeginRecoveryCertificate {
        request: request.clone(),
        signer_contributions: contributions,
    };
    let a = validate_approvals_and_reconstruct(&begin, &capsule, &recipient, at)?;
    recovery_machine.apply(
        RecoveryEvent::ApprovalThresholdReached,
        at,
        options.simulated_delay_secs,
    )?;
    log(
        &mut events,
        at,
        "RECOVERY",
        "fresh-client",
        &format!(
            "{} valid signer contributions reconstructed A locally.",
            capsule.signer_threshold
        ),
        Some(recovery_machine.state()),
    );
    if *a != *world.authorization_key {
        return Err(SimError::RecoveryMismatch);
    }

    let descriptor = open_descriptor(&capsule, &a)?;
    log(
        &mut events,
        at,
        "RECOVERY",
        "fresh-client",
        "Decrypted the private Recovery Descriptor and learned opaque guardian routes locally.",
        None,
    );
    validate_begin_certificate(&begin, &capsule, at)?;

    let mut guardian_machines = Vec::with_capacity(descriptor.guardians.len());
    for route in &descriptor.guardians {
        let guardian = world
            .guardians
            .get(usize::from(route.guardian_index - 1))
            .ok_or(SimError::InvalidCertificate)?;
        let record = guardian.get(&route.opaque_slot_id)?;
        validate_guardian_policy(&record.policy, &capsule)?;
        guardian_machines.push(GuardianMachine::new(
            record.policy.config_id,
            record.policy.config_version,
        ));
    }
    for machine in &mut guardian_machines {
        machine.begin(
            &request,
            request_digest,
            at,
            options.simulated_delay_secs,
            true,
        )?;
    }
    recovery_machine.apply(
        RecoveryEvent::BeginAccepted,
        at,
        options.simulated_delay_secs,
    )?;
    log(
        &mut events,
        at,
        "DELAY",
        "guardians",
        &format!(
            "Begin certificate accepted. Production policy is 24 hours; simulator delay is {} seconds.",
            options.simulated_delay_secs
        ),
        Some(recovery_machine.state()),
    );

    if options.cancel_before_release {
        at += options.simulated_delay_secs.saturating_sub(1);
        let cancel = make_cancel_certificate(
            &mut world.signers,
            &request,
            request_digest,
            options.offline_signer,
            capsule.cancellation_threshold,
        )?;
        validate_cancel_certificate(&cancel, &capsule, &request, at)?;
        for machine in &mut guardian_machines {
            machine.cancel(request.request_id, request_digest, true)?;
        }
        recovery_machine.apply(
            RecoveryEvent::CancelCertificateObserved,
            at,
            options.simulated_delay_secs,
        )?;
        log(
            &mut events,
            at,
            "CANCEL",
            "signers",
            "Threshold-valid cancellation permanently killed the exact request; release attempt refused.",
            Some(recovery_machine.state()),
        );
        let refused = guardian_machines[0].authorize_release(
            request.request_id,
            request_digest,
            at + options.simulated_delay_secs,
            true,
            true,
        );
        if refused != Err(CoreError::Cancelled) {
            return Err(SimError::InvalidCertificate);
        }
        return Ok(finish_result(
            options,
            &capsule,
            &request,
            DemoOutcome {
                state: recovery_machine.state(),
                recovered_secret: None,
                valid_guardians: 0,
                rejected_guardians: vec![],
                rotated_config_version: None,
                events,
            },
        ));
    }

    at += options.simulated_delay_secs;
    let release = make_release_certificate(
        &world.signers,
        &request,
        request_digest,
        options.offline_signer,
        capsule.signer_threshold,
    )?;
    validate_release_certificate(&release, &capsule, &request, at)?;
    recovery_machine.apply(
        RecoveryEvent::ReleaseCertificateReady,
        at,
        options.simulated_delay_secs,
    )?;
    log(
        &mut events,
        at,
        "RELEASE",
        "signers",
        "Fresh threshold ReleaseCertificate validated for the unchanged recipient and request digest.",
        Some(recovery_machine.state()),
    );

    let mut valid_fragments = Vec::new();
    let mut valid_dek_shares = Vec::new();
    let mut rejected = Vec::new();
    for route in &descriptor.guardians {
        if options.offline_guardian == Some(route.guardian_index) {
            rejected.push(route.guardian_index);
            log(
                &mut events,
                at,
                "RELEASE",
                &format!("guardian-{}", route.guardian_index),
                "Offline; client requested a replacement guardian.",
                None,
            );
            continue;
        }
        let machine = &mut guardian_machines[usize::from(route.guardian_index - 1)];
        machine.authorize_release(request.request_id, request_digest, at, true, true)?;
        let guardian = &world.guardians[usize::from(route.guardian_index - 1)];
        let record = guardian.get(&route.opaque_slot_id)?;
        let mut contribution = GuardianContribution {
            protocol_version: PROTOCOL_VERSION,
            config_id: request.config_id,
            config_version: request.config_version,
            request_id: request.request_id,
            request_digest,
            guardian_index: route.guardian_index,
            ciphertext_fragment: record.ciphertext_fragment.clone(),
            encrypted_dek_share: record.encrypted_dek_share.clone(),
            merkle_path_proof: record.merkle_path_proof.clone(),
            guardian_signature: vec![],
        };
        if options.corrupt_guardian == Some(route.guardian_index)
            && let Some(byte) = contribution.ciphertext_fragment.first_mut()
        {
            *byte ^= 1;
        }
        let signing = signing_key(guardian.signing_seed);
        contribution.guardian_signature =
            sign(&signing, &gp_wire::guardian_contribution(&contribution)?);
        let context = gp_wire::guardian_release_context(&request, route.guardian_index)?;
        let serialized = serde_json::to_vec(&contribution)?;
        let sealed = protect_payload(
            recipient.public_key(),
            random_id(&mut rng),
            random_nonce(&mut rng),
            &serialized,
            &context,
        )?;
        let opened = recipient.open(&sealed, &context)?;
        let received: GuardianContribution = serde_json::from_slice(&opened)?;
        match validate_guardian_contribution(&received, route, &descriptor, &request, &a) {
            Ok(dek_share) => {
                valid_fragments.push((received.guardian_index, received.ciphertext_fragment));
                valid_dek_shares.push(dek_share);
                log(
                    &mut events,
                    at,
                    "RELEASE",
                    &format!("guardian-{}", route.guardian_index),
                    "Signature, request binding, Merkle proof, and wrapped-share AEAD verified.",
                    None,
                );
            }
            Err(_) => {
                rejected.push(route.guardian_index);
                log(
                    &mut events,
                    at,
                    "RELEASE",
                    &format!("guardian-{}", route.guardian_index),
                    "Contribution failed integrity validation and was treated as an erasure; replacement requested.",
                    None,
                );
            }
        }
        if valid_fragments.len() >= usize::from(capsule.guardian_threshold) {
            break;
        }
    }
    if valid_fragments.len() < usize::from(capsule.guardian_threshold) {
        return Err(SimError::Threshold);
    }

    let dek = recover_secret(&valid_dek_shares, capsule.guardian_threshold)?;
    let ciphertext = erasure_reconstruct(
        &valid_fragments,
        descriptor.data_shards,
        descriptor.total_shards,
        usize::try_from(descriptor.ciphertext_len).map_err(|_| SimError::RecoveryMismatch)?,
    )?;
    let payload = AeadCiphertext {
        nonce: descriptor.payload_nonce,
        ciphertext,
    };
    let plaintext = aead_decrypt(
        dek.as_slice()
            .try_into()
            .map_err(|_| SimError::RecoveryMismatch)?,
        &payload,
        &gp_wire::payload_context(&capsule.config_id, capsule.config_version)?,
    )?;
    if plaintext.as_slice() != options.secret.as_bytes() {
        return Err(SimError::RecoveryMismatch);
    }
    recovery_machine.apply(
        RecoveryEvent::GuardianThresholdReached,
        at,
        options.simulated_delay_secs,
    )?;
    log(
        &mut events,
        at,
        "COMPLETE",
        "fresh-client",
        "Reconstructed DEK and encrypted payload from threshold-valid material; decrypted plaintext locally and zeroized intermediates.",
        Some(recovery_machine.state()),
    );
    let rotated = setup_world(
        &plaintext,
        &policy,
        &mut rng,
        Some((capsule.config_id, capsule.config_version + 1)),
    )?;
    let rotated_version = rotated.config_store.get(&capsule.config_id)?.config_version;
    log(
        &mut events,
        at,
        "ROTATE",
        "owner",
        "Generated fresh A, DEK, shares, fragments, commitments, and opaque slots; invalidated version-1 request state.",
        None,
    );
    Ok(finish_result(
        options,
        &capsule,
        &request,
        DemoOutcome {
            state: recovery_machine.state(),
            recovered_secret: Some(String::from_utf8_lossy(&plaintext).into_owned()),
            valid_guardians: valid_fragments.len(),
            rejected_guardians: rejected,
            rotated_config_version: Some(rotated_version),
            events,
        },
    ))
}

fn setup_world(
    secret: &[u8],
    policy: &SetupPolicy,
    rng: &mut ChaCha20Rng,
    rotation: Option<(Id32, u64)>,
) -> Result<DemoWorld, SimError> {
    let (config_id, config_version) = rotation.unwrap_or_else(|| (random_id(rng), 1));
    let authorization_key = SecretVec::new(random_id(rng).to_vec());
    let dek = SecretVec::new(random_id(rng).to_vec());
    let a_shares = split_secret(
        &authorization_key,
        policy.signer_threshold,
        policy.signer_count,
        random_id(rng),
    )?;
    let mut signers = Vec::new();
    let mut signer_leaves = Vec::new();
    for index in 1..=policy.signer_count {
        let seed = random_id(rng);
        let key = signing_key(seed);
        let public = verifying_key_bytes(&key);
        signer_leaves.push(sha256(&gp_wire::signer_leaf(index, &public)?));
        signers.push(SignerState {
            signer_id: index,
            mailbox: opaque_mailbox(rng),
            authorization_share: a_shares[usize::from(index - 1)].clone(),
            signing_seed: seed,
            signing_public_key: public,
            membership_proof: vec![],
            policy: SignerPolicy {
                config_id,
                config_version,
                signer_set_commitment: [0; 32],
                signer_threshold: policy.signer_threshold,
                cancellation_threshold: policy.cancellation_threshold,
            },
            seen_requests: BTreeMap::new(),
            seen_nonces: BTreeSet::new(),
            cancelled_requests: BTreeMap::new(),
        });
    }
    let (signer_root, signer_proofs) = merkle_commit(&signer_leaves)?;
    for (signer, proof) in signers.iter_mut().zip(signer_proofs) {
        signer.membership_proof = proof;
        signer.policy.signer_set_commitment = signer_root;
    }

    let payload_nonce = random_nonce(rng);
    let payload_context = gp_wire::payload_context(&config_id, config_version)?;
    let payload = aead_encrypt(
        dek.as_slice()
            .try_into()
            .map_err(|_| SimError::RecoveryMismatch)?,
        payload_nonce,
        secret,
        &payload_context,
    )?;
    let fragments = erasure_encode(
        &payload.ciphertext,
        policy.guardian_threshold,
        policy.guardian_count,
    )?;
    let dek_shares = split_secret(
        &dek,
        policy.guardian_threshold,
        policy.guardian_count,
        random_id(rng),
    )?;

    let mut raw_records = Vec::new();
    let mut guardian_seeds = Vec::new();
    let mut routes = Vec::new();
    let mut leaves = Vec::new();
    for index in 1..=policy.guardian_count {
        let share_context = gp_wire::guardian_share_context(&config_id, config_version, index)?;
        let key = guardian_share_key(
            authorization_key
                .as_slice()
                .try_into()
                .map_err(|_| SimError::RecoveryMismatch)?,
            &config_id,
            config_version,
            index,
        )?;
        let encrypted_dek_share = aead_encrypt(
            &key,
            random_nonce(rng),
            &dek_shares[usize::from(index - 1)],
            &share_context,
        )?;
        let fragment = fragments[usize::from(index - 1)].clone();
        let leaf = sha256(&gp_wire::guardian_leaf(
            &config_id,
            config_version,
            index,
            &sha256(&fragment),
            &hash_aead(&encrypted_dek_share),
        )?);
        leaves.push(leaf);
        let signing_seed = random_id(rng);
        let guardian_public_key = verifying_key_bytes(&signing_key(signing_seed));
        let slot = random_id(rng);
        let mailbox = opaque_mailbox(rng);
        routes.push(GuardianRoute {
            mailbox: mailbox.clone(),
            opaque_slot_id: slot,
            guardian_index: index,
            guardian_public_key,
        });
        guardian_seeds.push((signing_seed, mailbox));
        raw_records.push((slot, index, fragment, encrypted_dek_share));
    }
    let (guardian_root, guardian_proofs) = merkle_commit(&leaves)?;
    let mut guardians = Vec::new();
    for ((slot, index, fragment, encrypted_share), proof) in
        raw_records.into_iter().zip(guardian_proofs)
    {
        let (seed, mailbox) = guardian_seeds[usize::from(index - 1)].clone();
        let mut guardian = GuardianState::new(index, mailbox, seed);
        guardian.insert(GuardianRecord {
            opaque_slot_id: slot,
            guardian_index: index,
            ciphertext_fragment: fragment,
            encrypted_dek_share: encrypted_share,
            merkle_path_proof: proof,
            policy: GuardianPolicy {
                config_id,
                config_version,
                signer_set_commitment: signer_root,
                signer_threshold: policy.signer_threshold,
                cancellation_threshold: policy.cancellation_threshold,
                minimum_recovery_delay: policy.minimum_recovery_delay,
                guardian_material_root: guardian_root,
            },
        });
        guardians.push(guardian);
    }

    let descriptor = RecoveryDescriptor {
        guardians: routes,
        guardian_material_root: guardian_root,
        data_shards: policy.guardian_threshold,
        total_shards: policy.guardian_count,
        ciphertext_len: payload.ciphertext.len() as u64,
        payload_nonce,
    };
    let descriptor_plaintext = serde_json::to_vec(&descriptor)?;
    let key = descriptor_key(
        authorization_key
            .as_slice()
            .try_into()
            .map_err(|_| SimError::RecoveryMismatch)?,
        &config_id,
        config_version,
    )?;
    let descriptor_context = gp_wire::descriptor_context(&config_id, config_version)?;
    let encrypted_recovery_descriptor = aead_encrypt(
        &key,
        random_nonce(rng),
        &descriptor_plaintext,
        &descriptor_context,
    )?;
    let capsule = ConfigCapsule {
        protocol_version: PROTOCOL_VERSION,
        crypto_suite: CryptoSuite::default(),
        config_id,
        config_version,
        signer_count: policy.signer_count,
        signer_threshold: policy.signer_threshold,
        cancellation_threshold: policy.cancellation_threshold,
        guardian_count: policy.guardian_count,
        guardian_threshold: policy.guardian_threshold,
        minimum_recovery_delay: policy.minimum_recovery_delay,
        signer_set_commitment: signer_root,
        guardian_material_commitment: guardian_root,
        encrypted_recovery_descriptor,
        max_request_lifetime: 86_400 * 7,
    };
    let card = RecoveryCard {
        config_id,
        capsule_locator: format!("config://{}", hex::encode(config_id)),
        signer_mailboxes: signers
            .iter()
            .map(|signer| signer.mailbox.clone())
            .collect(),
        signer_set_commitment: signer_root,
    };
    let mut config_store = ConfigStore::default();
    config_store.put(capsule.clone())?;
    Ok(DemoWorld {
        card,
        signers,
        guardians,
        config_store,
        authorization_key,
    })
}

fn validate_capsule_against_card(
    capsule: &ConfigCapsule,
    card: &RecoveryCard,
) -> Result<(), SimError> {
    let invalid_thresholds = capsule.signer_count == 0
        || capsule.signer_threshold == 0
        || capsule.signer_threshold > capsule.signer_count
        || capsule.cancellation_threshold == 0
        || capsule.cancellation_threshold > capsule.signer_count
        || capsule.guardian_count == 0
        || capsule.guardian_threshold == 0
        || capsule.guardian_threshold > capsule.guardian_count;
    if capsule.protocol_version != PROTOCOL_VERSION
        || capsule.crypto_suite != CryptoSuite::default()
        || capsule.config_id != card.config_id
        || capsule.signer_set_commitment != card.signer_set_commitment
        || invalid_thresholds
        || capsule.minimum_recovery_delay < PRODUCTION_MIN_DELAY_SECS
        || capsule.max_request_lifetime == 0
    {
        return Err(SimError::InvalidCertificate);
    }
    Ok(())
}

fn validate_recovery_request(
    request: &RecoveryRequest,
    capsule: &ConfigCapsule,
    now: u64,
) -> Result<(), SimError> {
    let lifetime = request
        .expiry
        .checked_sub(request.requested_at)
        .ok_or(SimError::InvalidCertificate)?;
    if request.protocol_version != PROTOCOL_VERSION
        || request.protocol_version != capsule.protocol_version
        || request.crypto_suite != capsule.crypto_suite
        || request.config_id != capsule.config_id
        || request.config_version != capsule.config_version
        || request.recovery_recipient_key.len() != XWING_PUBLIC_KEY_LEN
        || request.requested_at > now
        || now >= request.expiry
        || lifetime == 0
        || lifetime > capsule.max_request_lifetime
    {
        return Err(SimError::InvalidCertificate);
    }
    Ok(())
}

fn validate_signer_membership(
    signer_id: u16,
    signer_public_key: &[u8; 32],
    membership_proof: &[u8],
    capsule: &ConfigCapsule,
) -> Result<(), SimError> {
    if signer_id == 0 || signer_id > capsule.signer_count {
        return Err(SimError::InvalidCertificate);
    }
    let leaf = sha256(&gp_wire::signer_leaf(signer_id, signer_public_key)?);
    merkle_verify(
        capsule.signer_set_commitment,
        leaf,
        usize::from(signer_id - 1),
        usize::from(capsule.signer_count),
        membership_proof,
    )?;
    Ok(())
}

fn validate_descriptor(
    descriptor: &RecoveryDescriptor,
    capsule: &ConfigCapsule,
) -> Result<(), SimError> {
    if descriptor.guardian_material_root != capsule.guardian_material_commitment
        || descriptor.data_shards != capsule.guardian_threshold
        || descriptor.total_shards != capsule.guardian_count
        || descriptor.guardians.len() != usize::from(capsule.guardian_count)
        || descriptor.ciphertext_len < 16
    {
        return Err(SimError::InvalidCertificate);
    }
    let mut indices = BTreeSet::new();
    let mut slots = BTreeSet::new();
    let mut mailboxes = BTreeSet::new();
    for route in &descriptor.guardians {
        if route.guardian_index == 0
            || route.guardian_index > capsule.guardian_count
            || !indices.insert(route.guardian_index)
            || !slots.insert(route.opaque_slot_id)
            || route.mailbox.is_empty()
            || !mailboxes.insert(route.mailbox.clone())
        {
            return Err(SimError::InvalidCertificate);
        }
    }
    Ok(())
}

fn validate_guardian_policy(
    policy: &GuardianPolicy,
    capsule: &ConfigCapsule,
) -> Result<(), SimError> {
    if policy.config_id != capsule.config_id
        || policy.config_version != capsule.config_version
        || policy.signer_set_commitment != capsule.signer_set_commitment
        || policy.signer_threshold != capsule.signer_threshold
        || policy.cancellation_threshold != capsule.cancellation_threshold
        || policy.minimum_recovery_delay != capsule.minimum_recovery_delay
        || policy.guardian_material_root != capsule.guardian_material_commitment
    {
        return Err(SimError::InvalidCertificate);
    }
    Ok(())
}

fn collect_signer_approvals(
    signers: &mut [SignerState],
    request: &RecoveryRequest,
    offline: Option<u16>,
    threshold: u16,
    rng: &mut ChaCha20Rng,
) -> Result<Vec<SignerContribution>, SimError> {
    let mut output = Vec::new();
    let request_digest = sha256(&gp_wire::request_digest_preimage(request)?);
    for signer in signers {
        if offline == Some(signer.signer_id) {
            continue;
        }
        signer.observe_request(
            request.config_id,
            request.config_version,
            request.request_id,
            request.nonce,
            request_digest,
        )?;
        let context = gp_wire::recipient_share_context(request, signer.signer_id)?;
        let encrypted_a_share = protect_payload(
            &request.recovery_recipient_key,
            random_id(rng),
            random_nonce(rng),
            &signer.authorization_share,
            &context,
        )?;
        let signing = signing_key(signer.signing_seed);
        let transcript = gp_wire::signer_approval(request, signer.signer_id, &encrypted_a_share)?;
        output.push(SignerContribution {
            request: request.clone(),
            signer_id: signer.signer_id,
            signer_public_key: signer.signing_public_key,
            signer_signature: sign(&signing, &transcript),
            signer_membership_proof: signer.membership_proof.clone(),
            encrypted_a_share,
        });
        if output.len() == usize::from(threshold) {
            break;
        }
    }
    if output.len() < usize::from(threshold) {
        Err(SimError::Threshold)
    } else {
        Ok(output)
    }
}

fn validate_approvals_and_reconstruct(
    certificate: &BeginRecoveryCertificate,
    capsule: &ConfigCapsule,
    recipient: &RecipientKeyPair,
    now: u64,
) -> Result<SecretVec, SimError> {
    validate_recovery_request(&certificate.request, capsule, now)?;
    let mut ids = BTreeSet::new();
    let mut shares = Vec::new();
    for contribution in &certificate.signer_contributions {
        if contribution.request != certificate.request || !ids.insert(contribution.signer_id) {
            return Err(SimError::InvalidCertificate);
        }
        validate_signer_membership(
            contribution.signer_id,
            &contribution.signer_public_key,
            &contribution.signer_membership_proof,
            capsule,
        )?;
        verify(
            &contribution.signer_public_key,
            &gp_wire::signer_approval(
                &contribution.request,
                contribution.signer_id,
                &contribution.encrypted_a_share,
            )?,
            &contribution.signer_signature,
        )?;
        let context =
            gp_wire::recipient_share_context(&contribution.request, contribution.signer_id)?;
        shares.push(
            recipient
                .open(&contribution.encrypted_a_share, &context)?
                .to_vec(),
        );
    }
    recover_secret(&shares, capsule.signer_threshold).map_err(Into::into)
}

fn validate_begin_certificate(
    certificate: &BeginRecoveryCertificate,
    capsule: &ConfigCapsule,
    now: u64,
) -> Result<(), SimError> {
    validate_recovery_request(&certificate.request, capsule, now)?;
    let mut ids = BTreeSet::new();
    for contribution in &certificate.signer_contributions {
        if contribution.request != certificate.request || !ids.insert(contribution.signer_id) {
            return Err(SimError::InvalidCertificate);
        }
        validate_signer_membership(
            contribution.signer_id,
            &contribution.signer_public_key,
            &contribution.signer_membership_proof,
            capsule,
        )?;
        verify(
            &contribution.signer_public_key,
            &gp_wire::signer_approval(
                &certificate.request,
                contribution.signer_id,
                &contribution.encrypted_a_share,
            )?,
            &contribution.signer_signature,
        )?;
    }
    if ids.len() < usize::from(capsule.signer_threshold) {
        Err(SimError::Threshold)
    } else {
        Ok(())
    }
}

fn open_descriptor(
    capsule: &ConfigCapsule,
    authorization_key: &[u8],
) -> Result<RecoveryDescriptor, SimError> {
    let a: &[u8; 32] = authorization_key
        .try_into()
        .map_err(|_| SimError::RecoveryMismatch)?;
    let key = descriptor_key(a, &capsule.config_id, capsule.config_version)?;
    let plaintext = aead_decrypt(
        &key,
        &capsule.encrypted_recovery_descriptor,
        &gp_wire::descriptor_context(&capsule.config_id, capsule.config_version)?,
    )?;
    let descriptor: RecoveryDescriptor = serde_json::from_slice(&plaintext)?;
    validate_descriptor(&descriptor, capsule)?;
    Ok(descriptor)
}

fn make_release_certificate(
    signers: &[SignerState],
    request: &RecoveryRequest,
    request_digest: Id32,
    offline: Option<u16>,
    threshold: u16,
) -> Result<ReleaseCertificate, SimError> {
    let mut votes = Vec::new();
    for signer in signers {
        if offline == Some(signer.signer_id) {
            continue;
        }
        signer.may_release(
            request.config_id,
            request.config_version,
            &request.request_id,
            &request_digest,
        )?;
        let mut vote = ReleaseVote {
            protocol_version: PROTOCOL_VERSION,
            config_id: request.config_id,
            config_version: request.config_version,
            request_id: request.request_id,
            request_digest,
            recovery_recipient_key: request.recovery_recipient_key.clone(),
            nonce: request.nonce,
            signer_id: signer.signer_id,
            signer_public_key: signer.signing_public_key,
            signer_membership_proof: signer.membership_proof.clone(),
            signer_signature: vec![],
        };
        vote.signer_signature = sign(
            &signing_key(signer.signing_seed),
            &gp_wire::release_vote(&vote)?,
        );
        votes.push(vote);
        if votes.len() == usize::from(threshold) {
            break;
        }
    }
    if votes.len() < usize::from(threshold) {
        Err(SimError::Threshold)
    } else {
        Ok(ReleaseCertificate { votes })
    }
}

fn validate_release_certificate(
    certificate: &ReleaseCertificate,
    capsule: &ConfigCapsule,
    request: &RecoveryRequest,
    now: u64,
) -> Result<(), SimError> {
    validate_recovery_request(request, capsule, now)?;
    let request_digest = sha256(&gp_wire::request_digest_preimage(request)?);
    let mut ids = BTreeSet::new();
    for vote in &certificate.votes {
        if vote.protocol_version != PROTOCOL_VERSION
            || vote.config_id != request.config_id
            || vote.config_version != request.config_version
            || vote.request_id != request.request_id
            || vote.request_digest != request_digest
            || vote.recovery_recipient_key != request.recovery_recipient_key
            || vote.nonce != request.nonce
            || !ids.insert(vote.signer_id)
        {
            return Err(SimError::InvalidCertificate);
        }
        validate_signer_membership(
            vote.signer_id,
            &vote.signer_public_key,
            &vote.signer_membership_proof,
            capsule,
        )?;
        verify(
            &vote.signer_public_key,
            &gp_wire::release_vote(vote)?,
            &vote.signer_signature,
        )?;
    }
    if ids.len() < usize::from(capsule.signer_threshold) {
        Err(SimError::Threshold)
    } else {
        Ok(())
    }
}

fn make_cancel_certificate(
    signers: &mut [SignerState],
    request: &RecoveryRequest,
    request_digest: Id32,
    offline: Option<u16>,
    threshold: u16,
) -> Result<CancelCertificate, SimError> {
    let mut votes = Vec::new();
    for signer in signers.iter_mut() {
        if offline == Some(signer.signer_id) {
            continue;
        }
        let mut vote = CancelVote {
            protocol_version: PROTOCOL_VERSION,
            config_id: request.config_id,
            config_version: request.config_version,
            request_id: request.request_id,
            request_digest,
            reason_code: 1,
            nonce: request.nonce,
            signer_id: signer.signer_id,
            signer_public_key: signer.signing_public_key,
            signer_membership_proof: signer.membership_proof.clone(),
            signer_signature: vec![],
        };
        vote.signer_signature = sign(
            &signing_key(signer.signing_seed),
            &gp_wire::cancel_vote(&vote)?,
        );
        signer.mark_cancelled(
            request.config_id,
            request.config_version,
            request.request_id,
            request_digest,
        )?;
        votes.push(vote);
        if votes.len() == usize::from(threshold) {
            break;
        }
    }
    if votes.len() < usize::from(threshold) {
        Err(SimError::Threshold)
    } else {
        Ok(CancelCertificate { votes })
    }
}

fn validate_cancel_certificate(
    certificate: &CancelCertificate,
    capsule: &ConfigCapsule,
    request: &RecoveryRequest,
    now: u64,
) -> Result<(), SimError> {
    validate_recovery_request(request, capsule, now)?;
    let request_digest = sha256(&gp_wire::request_digest_preimage(request)?);
    let mut ids = BTreeSet::new();
    for vote in &certificate.votes {
        if vote.protocol_version != PROTOCOL_VERSION
            || vote.config_id != request.config_id
            || vote.config_version != request.config_version
            || vote.request_id != request.request_id
            || vote.request_digest != request_digest
            || vote.nonce != request.nonce
            || !ids.insert(vote.signer_id)
        {
            return Err(SimError::InvalidCertificate);
        }
        validate_signer_membership(
            vote.signer_id,
            &vote.signer_public_key,
            &vote.signer_membership_proof,
            capsule,
        )?;
        verify(
            &vote.signer_public_key,
            &gp_wire::cancel_vote(vote)?,
            &vote.signer_signature,
        )?;
    }
    if ids.len() < usize::from(capsule.cancellation_threshold) {
        Err(SimError::Threshold)
    } else {
        Ok(())
    }
}

fn validate_guardian_contribution(
    contribution: &GuardianContribution,
    route: &GuardianRoute,
    descriptor: &RecoveryDescriptor,
    request: &RecoveryRequest,
    authorization_key: &[u8],
) -> Result<Vec<u8>, SimError> {
    let request_digest = sha256(&gp_wire::request_digest_preimage(request)?);
    if contribution.config_id != request.config_id
        || contribution.protocol_version != PROTOCOL_VERSION
        || contribution.config_version != request.config_version
        || contribution.request_id != request.request_id
        || contribution.request_digest != request_digest
        || contribution.guardian_index != route.guardian_index
    {
        return Err(SimError::RequestBinding);
    }
    verify(
        &route.guardian_public_key,
        &gp_wire::guardian_contribution(contribution)?,
        &contribution.guardian_signature,
    )?;
    let leaf = sha256(&gp_wire::guardian_leaf(
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
        &sha256(&contribution.ciphertext_fragment),
        &hash_aead(&contribution.encrypted_dek_share),
    )?);
    merkle_verify(
        descriptor.guardian_material_root,
        leaf,
        usize::from(contribution.guardian_index - 1),
        usize::from(descriptor.total_shards),
        &contribution.merkle_path_proof,
    )?;
    let a: &[u8; 32] = authorization_key
        .try_into()
        .map_err(|_| SimError::RecoveryMismatch)?;
    let key = guardian_share_key(
        a,
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
    )?;
    let plaintext = aead_decrypt(
        &key,
        &contribution.encrypted_dek_share,
        &gp_wire::guardian_share_context(
            &contribution.config_id,
            contribution.config_version,
            contribution.guardian_index,
        )?,
    )?;
    Ok(plaintext.to_vec())
}

struct DemoOutcome {
    state: RecoveryState,
    recovered_secret: Option<String>,
    valid_guardians: usize,
    rejected_guardians: Vec<u16>,
    rotated_config_version: Option<u64>,
    events: Vec<SimEvent>,
}

fn finish_result(
    options: &DemoOptions,
    capsule: &ConfigCapsule,
    request: &RecoveryRequest,
    outcome: DemoOutcome,
) -> DemoResult {
    let mut transport = TransportConfig::for_mode(options.mode);
    transport.base_latency_ms = options.network_latency_ms;
    transport.cover_rate = options.cover_rate;
    transport.loss_percent = options.packet_loss_percent;
    transport.duplicate_percent = options.packet_duplication_percent;
    transport.mix_drop_percent = options.mix_drop_percent;
    let observer = simulate_observer(&transport, options.seed, outcome.events.len().max(1), 1800);
    DemoResult {
        seed: options.seed,
        mode: options.mode,
        success: outcome.state == RecoveryState::Completed,
        cancelled: outcome.state == RecoveryState::Cancelled,
        final_state: outcome.state,
        recovered_secret: outcome.recovered_secret,
        config_id_hex: hex::encode(capsule.config_id),
        request_id_hex: hex::encode(request.request_id),
        signer_threshold: capsule.signer_threshold,
        guardian_threshold: capsule.guardian_threshold,
        valid_guardians: outcome.valid_guardians,
        rejected_guardians: outcome.rejected_guardians,
        rotated_config_version: outcome.rotated_config_version,
        observer,
        events: outcome.events,
        security_notice: "Working hackathon prototype: real threshold sharing, encryption, integrity, exact-recipient binding, cancellation, and local reconstruction. Metadata transport is simulated; Ed25519 is classical/non-PQ; no perfect-anonymity claim.".into(),
    }
}

fn random_id(rng: &mut ChaCha20Rng) -> Id32 {
    let mut value = [0_u8; 32];
    rng.fill(&mut value);
    value
}

fn random_nonce(rng: &mut ChaCha20Rng) -> [u8; 24] {
    let mut value = [0_u8; 24];
    rng.fill(&mut value);
    value
}

fn opaque_mailbox(rng: &mut ChaCha20Rng) -> String {
    format!("mbx-{}", hex::encode(random_id(rng)))
}

fn log(
    events: &mut Vec<SimEvent>,
    at: u64,
    phase: &str,
    actor: &str,
    message: &str,
    state: Option<RecoveryState>,
) {
    events.push(SimEvent {
        at,
        phase: phase.into(),
        actor: actor.into(),
        message: message.into(),
        state,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (DemoWorld, ConfigCapsule, RecipientKeyPair, RecoveryRequest) {
        let options = DemoOptions::default();
        let policy = SetupPolicy {
            signer_count: options.signer_count,
            signer_threshold: options.signer_threshold,
            cancellation_threshold: options.cancellation_threshold,
            guardian_count: options.guardian_count,
            guardian_threshold: options.guardian_threshold,
            minimum_recovery_delay: PRODUCTION_MIN_DELAY_SECS,
        };
        let mut rng = ChaCha20Rng::seed_from_u64(options.seed);
        let world = setup_world(options.secret.as_bytes(), &policy, &mut rng, None).unwrap();
        let capsule = world
            .config_store
            .get(&world.card.config_id)
            .unwrap()
            .clone();
        let recipient = RecipientKeyPair::from_seed(random_id(&mut rng));
        let request = RecoveryRequest {
            protocol_version: PROTOCOL_VERSION,
            crypto_suite: capsule.crypto_suite,
            config_id: capsule.config_id,
            config_version: capsule.config_version,
            request_id: random_id(&mut rng),
            recovery_recipient_key: recipient.public_key().to_vec(),
            requested_at: 10,
            nonce: random_id(&mut rng),
            expiry: 10 + capsule.max_request_lifetime,
        };
        (world, capsule, recipient, request)
    }

    #[test]
    fn end_to_end_recovery() {
        let result = run_demo(&DemoOptions {
            corrupt_guardian: None,
            ..DemoOptions::default()
        })
        .unwrap();
        assert!(result.success);
        assert_eq!(
            result.recovered_secret.as_deref(),
            Some("correct horse battery staple")
        );
        assert_eq!(result.rotated_config_version, Some(2));
    }

    #[test]
    fn malicious_and_offline_guardians_are_replaced() {
        let result = run_demo(&DemoOptions {
            offline_guardian: Some(2),
            corrupt_guardian: Some(1),
            ..DemoOptions::default()
        })
        .unwrap();
        assert!(result.success);
        assert_eq!(result.valid_guardians, 5);
        assert_eq!(result.rejected_guardians, vec![1, 2]);
    }

    #[test]
    fn cancellation_before_release_fails_closed() {
        let result = run_demo(&DemoOptions {
            cancel_before_release: true,
            offline_signer: Some(1),
            corrupt_guardian: None,
            ..DemoOptions::default()
        })
        .unwrap();
        assert!(result.cancelled);
        assert!(!result.success);
        assert_eq!(result.final_state, RecoveryState::Cancelled);
    }

    #[test]
    fn invalid_options_fail_before_protocol_execution() {
        let impossible_signers = DemoOptions {
            signer_count: 2,
            signer_threshold: 2,
            offline_signer: Some(1),
            ..DemoOptions::default()
        };
        assert!(matches!(
            run_demo(&impossible_signers),
            Err(SimError::InvalidOptions(_))
        ));

        let invalid_actor = DemoOptions {
            offline_guardian: Some(0),
            ..DemoOptions::default()
        };
        assert!(matches!(
            run_demo(&invalid_actor),
            Err(SimError::InvalidOptions(_))
        ));
    }

    #[test]
    fn seeded_replay_is_identical() {
        let options = DemoOptions::default();
        assert_eq!(run_demo(&options).unwrap(), run_demo(&options).unwrap());
    }

    #[test]
    fn configurable_thresholds_drive_the_same_state_machine() {
        let result = run_demo(&DemoOptions {
            signer_count: 4,
            signer_threshold: 3,
            offline_signer: Some(4),
            guardian_count: 6,
            guardian_threshold: 4,
            corrupt_guardian: Some(1),
            ..DemoOptions::default()
        })
        .unwrap();
        assert!(result.success);
        assert_eq!(result.signer_threshold, 3);
        assert_eq!(result.guardian_threshold, 4);
    }

    #[test]
    fn cancel_certificate_is_bound_to_exact_request_id_and_nonce() {
        let (mut world, capsule, _recipient, request) = fixture();
        let digest = sha256(&gp_wire::request_digest_preimage(&request).unwrap());
        let mut certificate =
            make_cancel_certificate(&mut world.signers, &request, digest, None, 2).unwrap();
        certificate.votes[0].request_id[0] ^= 1;
        let signer = &world.signers[usize::from(certificate.votes[0].signer_id - 1)];
        certificate.votes[0].signer_signature = sign(
            &signing_key(signer.signing_seed),
            &gp_wire::cancel_vote(&certificate.votes[0]).unwrap(),
        );
        assert!(validate_cancel_certificate(&certificate, &capsule, &request, 11).is_err());
    }

    #[test]
    fn release_certificate_requires_valid_signer_membership() {
        let (world, capsule, _recipient, request) = fixture();
        let digest = sha256(&gp_wire::request_digest_preimage(&request).unwrap());
        let mut certificate =
            make_release_certificate(&world.signers, &request, digest, None, 2).unwrap();
        certificate.votes[0].signer_membership_proof[0] ^= 1;
        let signer = &world.signers[usize::from(certificate.votes[0].signer_id - 1)];
        certificate.votes[0].signer_signature = sign(
            &signing_key(signer.signing_seed),
            &gp_wire::release_vote(&certificate.votes[0]).unwrap(),
        );
        assert!(validate_release_certificate(&certificate, &capsule, &request, 11).is_err());
    }

    #[test]
    fn request_lifetime_and_descriptor_commitment_are_enforced() {
        let (world, mut capsule, _recipient, mut request) = fixture();
        request.expiry = request.requested_at;
        assert!(validate_recovery_request(&request, &capsule, request.requested_at).is_err());

        capsule.guardian_material_commitment[0] ^= 1;
        assert!(open_descriptor(&capsule, &world.authorization_key).is_err());
    }

    #[test]
    fn mailbox_handles_do_not_encode_actor_role_or_index() {
        let (world, capsule, _recipient, _request) = fixture();
        for mailbox in &world.card.signer_mailboxes {
            assert!(mailbox.starts_with("mbx-"));
            assert_eq!(mailbox.len(), 68);
            assert!(!mailbox.contains("signer"));
        }
        let descriptor = open_descriptor(&capsule, &world.authorization_key).unwrap();
        for route in descriptor.guardians {
            assert!(route.mailbox.starts_with("mbx-"));
            assert_eq!(route.mailbox.len(), 68);
            assert!(!route.mailbox.contains("guardian"));
        }
    }
}
