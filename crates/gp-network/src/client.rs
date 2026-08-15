use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use gp_crypto::{
    EpochFrostShare, RecipientKeyPair, XWING_PUBLIC_KEY_LEN, aead_decrypt, aead_encrypt,
    custody_commit, descriptor_key_v3, erasure_encode, erasure_reconstruct, frost_dealer_split,
    frost_public_package_digest, frost_recover_dek_for_epoch, frost_verify_share,
    guardian_fragment_key_v3, guardian_share_key_v3, hash_aead, merkle_commit, merkle_verify,
    recover_secret, seal_to_recipient, sha256, signing_key, split_secret, verify,
    verifying_key_bytes, zeroize_id,
};
use gp_types::{
    AeadCiphertext, BeginRecoveryCertificate, BeginRecoveryCertificateV3, ConfigCapsule,
    ConfigCapsuleV3, ConfigRef, DpssSuiteId, EpochReadChallenge, GuardianEpochState,
    GuardianPolicyV3, GuardianRecordV3, GuardianRouteV3, RecoveryCard, RecoveryCardV3,
    RecoveryDescriptorV3, RecoveryReleaseCertificateV3, RecoveryRequest, RecoveryRequestV3,
    ReleaseCertificate, SetupPolicy, WitnessPin,
};

use crate::{
    protocol::{
        create_setup, make_owner_cancel_certificate, open_descriptor, random_id, random_nonce,
        reconstruct_a, reconstruct_payload, validate_capsule, validate_guardian_contribution,
        validate_owner_cancel_ack, wall_now,
    },
    types::{
        GuardianRecoveryRequestV3, GuardianRecoveryResponseV3, GuardianRotationProvisionV3,
        MailboxRequest, MailboxResponse, NetworkDemoResult, NodeInfo, OwnerCancelResult,
        OwnerControlFile, OwnerControlFileV3, ProvisionPayload, RouteRegistration,
        SealedMailboxBody, SignerRecoveryRequestV3, SignerRecoveryResponseV3,
        SignerRotationProvisionV3, WitnessConfigProvision, WitnessReadEnvelope,
    },
};

/// Performs a nonce-bound read against every card-pinned config witness and
/// returns only a capsule accepted by the 2f+1 rollback-protection rules.
pub async fn discover_latest_epoch_v3(
    client: &reqwest::Client,
    card: &RecoveryCardV3,
) -> Result<ConfigCapsuleV3> {
    crate::rotation_protocol::validate_recovery_card_v3(card)?;
    let recipient = RecipientKeyPair::from_seed(random_id());
    let (capsule, _, _) = read_latest_epoch_v3(client, card, &recipient).await?;
    Ok(capsule)
}

pub(crate) async fn read_latest_epoch_v3(
    client: &reqwest::Client,
    card: &RecoveryCardV3,
    recipient: &RecipientKeyPair,
) -> Result<(
    ConfigCapsuleV3,
    EpochReadChallenge,
    Vec<WitnessReadEnvelope>,
)> {
    crate::rotation_protocol::validate_recovery_card_v3(card)?;
    let now = wall_now()?;
    let challenge = EpochReadChallenge {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_id: card.config_id,
        client_nonce: random_id(),
        response_recipient_key: recipient.public_key().to_vec(),
        issued_at: now,
        expiry: now.saturating_add(60),
    };
    let mut envelopes = Vec::new();
    for witness in &card.witnesses {
        let url = if witness.mailbox.ends_with("/read") {
            witness.mailbox.clone()
        } else {
            format!(
                "{}/v3/witness/configs/{}/read",
                witness.mailbox.trim_end_matches('/'),
                hex::encode(card.config_id)
            )
        };
        if let Ok(response) = client.post(url).json(&challenge).send().await
            && let Ok(response) = response.error_for_status()
            && let Ok(envelope) = response.json::<WitnessReadEnvelope>().await
        {
            envelopes.push(envelope);
        }
    }
    let capsule = crate::rotation_protocol::select_latest_epoch_v3(card, &challenge, &envelopes)?;
    Ok((capsule, challenge, envelopes))
}

pub struct SetupOptions {
    pub secret: Vec<u8>,
    pub config_stores: Vec<String>,
    pub relays: Vec<String>,
    pub relay_token: String,
    pub admin_token: String,
    pub signers: Vec<String>,
    pub guardians: Vec<String>,
    pub signer_threshold: u16,
    pub guardian_threshold: u16,
    pub delay_secs: u64,
    pub card_path: String,
    pub owner_control_path: String,
}

pub struct SetupV3Options {
    pub secret: Vec<u8>,
    pub relays: Vec<String>,
    pub relay_token: String,
    pub admin_token: String,
    pub signers: Vec<String>,
    pub guardians: Vec<String>,
    pub witnesses: Vec<String>,
    pub signer_threshold: u16,
    pub guardian_threshold: u16,
    pub witness_fault_bound: u16,
    pub delay_secs: u64,
    pub card_path: String,
    pub owner_control_path: String,
}

pub struct RecoverOptions {
    pub card_path: String,
    pub output_path: Option<String>,
    pub request_out_path: Option<String>,
    pub cancel_before_release: bool,
    pub owner_control_path: String,
}

pub struct RecoverV3Options {
    pub card_path: String,
    pub output_path: Option<String>,
    pub request_out_path: Option<String>,
}

pub struct CancelOptions {
    pub request_path: String,
    pub owner_control_path: String,
}

pub async fn setup_v3(options: SetupV3Options) -> Result<RecoveryCardV3> {
    let client = reqwest::Client::new();
    let signer_count = u16::try_from(options.signers.len())?;
    let guardian_count = u16::try_from(options.guardians.len())?;
    let required_witnesses = usize::from(options.witness_fault_bound)
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .context("witness roster size overflow")?;
    if options.relays.is_empty()
        || signer_count < options.signer_threshold
        || options.signer_threshold == 0
        || guardian_count < options.guardian_threshold
        || options.guardian_threshold < 2
        || options.witness_fault_bound == 0
        || options.witnesses.len() < required_witnesses
    {
        bail!("invalid protocol-v3 setup actor counts or thresholds");
    }
    let relay_bases = options
        .relays
        .iter()
        .map(|relay| relay.trim_end_matches('/').to_owned())
        .collect::<Vec<_>>();
    let _signer_infos = fetch_node_infos_v3(&client, &options.signers, "signer").await?;
    let guardian_infos = fetch_node_infos_v3(&client, &options.guardians, "guardian").await?;
    let witness_infos = fetch_node_infos_v3(&client, &options.witnesses, "witness").await?;

    let authorization_key = zeroize::Zeroizing::new(random_id().to_vec());
    let authorization_shares = split_secret(
        &authorization_key,
        options.signer_threshold,
        signer_count,
        random_id(),
    )?;
    let signer_seeds = (0..signer_count)
        .map(|_| zeroize::Zeroizing::new(random_id()))
        .collect::<Vec<_>>();
    let signer_public_keys = signer_seeds
        .iter()
        .enumerate()
        .map(|(offset, seed)| {
            (
                u16::try_from(offset + 1).expect("signer count fits u16"),
                verifying_key_bytes(&signing_key(**seed)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let signer_leaves = signer_public_keys
        .iter()
        .map(|(id, key)| sha256(&gp_wire::signer_leaf(*id, key).expect("valid signer leaf")))
        .collect::<Vec<_>>();
    let (signer_root, signer_proofs) = merkle_commit(&signer_leaves)?;
    let owner_cancel_signing_seed = zeroize::Zeroizing::new(random_id());
    let owner_cancel_public_key = verifying_key_bytes(&signing_key(*owner_cancel_signing_seed));
    let config_ref = ConfigRef {
        config_id: random_id(),
        payload_generation: 1,
        authorization_epoch: 1,
        guardian_epoch: 1,
        epoch_binding: random_id(),
    };
    let signer_mailboxes = (0..usize::from(signer_count))
        .map(|_| mailbox_url_v3(&relay_bases[0]))
        .collect::<Vec<_>>();
    let guardian_seeds = (0..usize::from(guardian_count))
        .map(|_| zeroize::Zeroizing::new(random_id()))
        .collect::<Vec<_>>();
    let guardian_routes = guardian_infos
        .iter()
        .enumerate()
        .map(|(offset, info)| GuardianRouteV3 {
            guardian_index: u16::try_from(offset + 1).expect("guardian count fits u16"),
            opaque_slot_id: random_id(),
            mailbox: mailbox_url_v3(&relay_bases[0]),
            guardian_public_key: verifying_key_bytes(&signing_key(*guardian_seeds[offset])),
            session_recipient_key: info.transport_public_key.clone(),
            operator_domain_commitment: sha256(info.node_id.as_bytes()),
        })
        .collect::<Vec<_>>();
    let frost = frost_dealer_split(options.guardian_threshold, guardian_count, random_id())?;
    let payload_ciphertext = aead_encrypt(
        frost.dek.as_slice().try_into()?,
        random_nonce(),
        &options.secret,
        &gp_wire::payload_context_v3(&config_ref.config_id, config_ref.payload_generation)?,
    )?;
    let fragments = erasure_encode(
        &payload_ciphertext.ciphertext,
        options.guardian_threshold,
        guardian_count,
    )?;
    let dpss_public_commitment = frost_public_package_digest(&frost.public_package)?;
    let mut records = Vec::with_capacity(usize::from(guardian_count));
    let mut prepared_leaves = Vec::with_capacity(usize::from(guardian_count));
    for (offset, route) in guardian_routes.iter().enumerate() {
        let index = route.guardian_index;
        let policy = GuardianPolicyV3 {
            config_ref,
            epoch_state: GuardianEpochState::Active,
            signer_set_commitment: signer_root,
            signer_count,
            signer_threshold: options.signer_threshold,
            owner_cancel_public_key,
            minimum_recovery_delay: options.delay_secs,
            guardian_material_root: [0; 32],
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment,
            predecessor_capsule_hash: [0; 32],
            activation_qc_hash: None,
            drain_deadline: None,
        };
        let encrypted_dek_share = aead_encrypt(
            &guardian_share_key_v3(authorization_key.as_slice().try_into()?, &config_ref, index)?,
            random_nonce(),
            &frost.shares[offset],
            &gp_wire::guardian_share_context_v3(&config_ref, index)?,
        )?;
        let fragment_index = u16::try_from(offset + 1)?;
        let encrypted_ciphertext_fragment = aead_encrypt(
            &guardian_fragment_key_v3(
                authorization_key.as_slice().try_into()?,
                &config_ref,
                index,
            )?,
            random_nonce(),
            &fragments[offset],
            &gp_wire::guardian_fragment_context_v3(&config_ref, index, fragment_index)?,
        )?;
        let mut custody_bytes = encrypted_dek_share.nonce.to_vec();
        custody_bytes.extend_from_slice(&encrypted_dek_share.ciphertext);
        custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.nonce);
        custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.ciphertext);
        let record = GuardianRecordV3 {
            opaque_slot_id: route.opaque_slot_id,
            guardian_index: index,
            fragment_index,
            encrypted_ciphertext_fragment,
            encrypted_dek_share,
            merkle_path_proof: vec![],
            custody_root: custody_commit(&custody_bytes)?.root,
            policy,
        };
        prepared_leaves.push(gp_types::PreparedRecordLeaf {
            guardian_index: index,
            fragment_index,
            opaque_slot_id: record.opaque_slot_id,
            encrypted_share_hash: hash_aead(&record.encrypted_dek_share),
            fragment_hash: hash_aead(&record.encrypted_ciphertext_fragment),
            policy_hash: sha256(&gp_wire::guardian_policy_body_v3(&record.policy)?),
        });
        records.push(record);
    }
    let leaf_hashes = prepared_leaves
        .iter()
        .map(|leaf| Ok(sha256(&gp_wire::prepared_record_leaf_v3(leaf)?)))
        .collect::<Result<Vec<_>>>()?;
    let (guardian_material_root, record_proofs) = merkle_commit(&leaf_hashes)?;
    for (record, proof) in records.iter_mut().zip(record_proofs) {
        record.policy.guardian_material_root = guardian_material_root;
        record.merkle_path_proof = proof;
    }
    let descriptor = RecoveryDescriptorV3 {
        config_ref,
        guardians: guardian_routes.clone(),
        guardian_material_root,
        data_shards: options.guardian_threshold,
        total_shards: guardian_count,
        ciphertext_len: u64::try_from(payload_ciphertext.ciphertext.len())?,
        payload_nonce: payload_ciphertext.nonce,
        dpss_suite: DpssSuiteId::default(),
        dpss_public_package: frost.public_package,
        dpss_public_commitment,
    };
    let encrypted_recovery_descriptor = aead_encrypt(
        &descriptor_key_v3(authorization_key.as_slice().try_into()?, &config_ref)?,
        random_nonce(),
        &serde_json::to_vec(&descriptor)?,
        &gp_wire::descriptor_context_v3(&config_ref)?,
    )?;
    let mut capsule = ConfigCapsuleV3 {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_ref,
        capsule_hash: [0; 32],
        predecessor_capsule_hash: [0; 32],
        signer_count,
        signer_threshold: options.signer_threshold,
        guardian_count,
        guardian_threshold: options.guardian_threshold,
        minimum_recovery_delay: options.delay_secs,
        max_request_lifetime: 7 * 24 * 60 * 60,
        signer_set_commitment: signer_root,
        owner_cancel_public_key,
        dpss_suite: DpssSuiteId::default(),
        dpss_public_commitment,
        guardian_material_root,
        encrypted_recovery_descriptor,
        activation_certificate: None,
        activation_qc: None,
    };
    capsule.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&capsule)?);
    let witnesses = witness_infos
        .iter()
        .enumerate()
        .map(|(offset, info)| {
            Ok(WitnessPin {
                witness_id: u16::try_from(offset + 1)?,
                mailbox: options.witnesses[offset].trim_end_matches('/').to_owned(),
                public_key: info
                    .signing_public_key
                    .context("v3 witness did not expose a signing public key")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let card = RecoveryCardV3 {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_id: config_ref.config_id,
        signer_mailboxes: signer_mailboxes.clone(),
        signer_set_commitment: signer_root,
        owner_cancel_public_key,
        witness_fault_bound: options.witness_fault_bound,
        witnesses,
        relay_bases: relay_bases.clone(),
    };
    crate::rotation_protocol::validate_activated_capsule_v3(&card, &capsule)?;

    for (offset, target) in options.signers.iter().enumerate() {
        let provision = SignerRotationProvisionV3 {
            mailbox: mailbox_id(&signer_mailboxes[offset])?,
            signer_id: u16::try_from(offset + 1)?,
            authorization_share: authorization_shares[offset].clone(),
            signing_seed: *signer_seeds[offset],
            signing_public_key: signer_public_keys[&u16::try_from(offset + 1)?],
            membership_proof: signer_proofs[offset].clone(),
            recovery_card: card.clone(),
            active_capsule: capsule.clone(),
        };
        provision_actor_v3(
            &client,
            target,
            "signer-v3",
            &provision,
            &options.admin_token,
        )
        .await?;
        for relay in &relay_bases {
            register_route(
                &client,
                relay,
                &options.relay_token,
                &signer_mailboxes[offset],
                target,
            )
            .await?;
        }
    }
    for (offset, target) in options.guardians.iter().enumerate() {
        let provision = GuardianRotationProvisionV3 {
            mailbox: mailbox_id(&guardian_routes[offset].mailbox)?,
            signing_seed: *guardian_seeds[offset],
            signing_public_key: guardian_routes[offset].guardian_public_key,
            recovery_card: card.clone(),
            predecessor_capsule: capsule.clone(),
            signer_public_keys: signer_public_keys.clone(),
            epoch_store: gp_storage::GuardianEpochStore::new(
                records[offset].clone(),
                capsule.capsule_hash,
            ),
        };
        provision_actor_v3(
            &client,
            target,
            "guardian-v3",
            &provision,
            &options.admin_token,
        )
        .await?;
        for relay in &relay_bases {
            register_route(
                &client,
                relay,
                &options.relay_token,
                &guardian_routes[offset].mailbox,
                target,
            )
            .await?;
        }
    }
    let witness_public_keys = card
        .witnesses
        .iter()
        .map(|witness| (witness.witness_id, witness.public_key))
        .collect::<BTreeMap<_, _>>();
    for (offset, target) in options.witnesses.iter().enumerate() {
        let response = client
            .post(format!(
                "{}/v3/witness/configs",
                target.trim_end_matches('/')
            ))
            .bearer_auth(&options.admin_token)
            .json(&WitnessConfigProvision {
                witness_id: u16::try_from(offset + 1)?,
                capsule: capsule.clone(),
                signer_public_keys: signer_public_keys.clone(),
                witness_public_keys: witness_public_keys.clone(),
                witness_fault_bound: options.witness_fault_bound,
            })
            .send()
            .await?;
        ensure_success(response, "provision protocol-v3 witness").await?;
    }
    let guardian_targets = options
        .guardians
        .iter()
        .enumerate()
        .map(|(offset, target)| {
            (
                u16::try_from(offset + 1).expect("guardian count fits u16"),
                target.trim_end_matches('/').to_owned(),
            )
        })
        .collect();
    let mut owner_control = OwnerControlFileV3 {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_ref,
        owner_cancel_signing_seed: *owner_cancel_signing_seed,
        owner_cancel_public_key,
        guardian_targets,
        relay_bases,
    };
    write_private_json(Path::new(&options.card_path), &card)?;
    write_private_json(Path::new(&options.owner_control_path), &owner_control)?;
    zeroize_id(&mut owner_control.owner_cancel_signing_seed);
    println!(
        "SETUP v3 config={} epoch=1: {} signers, {} guardians, {} witnesses",
        hex::encode(config_ref.config_id),
        signer_count,
        guardian_count,
        options.witnesses.len()
    );
    Ok(card)
}

async fn fetch_node_infos_v3(
    client: &reqwest::Client,
    targets: &[String],
    expected_role: &str,
) -> Result<Vec<NodeInfo>> {
    let mut infos = Vec::with_capacity(targets.len());
    let mut normalized_targets = BTreeSet::new();
    let mut node_ids = BTreeSet::new();
    let mut transport_keys = BTreeSet::new();
    let mut signing_keys = BTreeSet::new();
    for target in targets {
        let normalized = target.trim_end_matches('/');
        if normalized.is_empty() || !normalized_targets.insert(normalized.to_owned()) {
            bail!("duplicate or empty {expected_role} target");
        }
        let info = client
            .get(format!("{normalized}/v3/node-info"))
            .send()
            .await?
            .error_for_status()?
            .json::<NodeInfo>()
            .await?;
        if info.protocol_version != gp_types::PROTOCOL_VERSION_V3
            || info.role != expected_role
            || info.node_id.is_empty()
            || info.transport_public_key.len() != XWING_PUBLIC_KEY_LEN
            || info.signing_public_key.is_none()
            || !node_ids.insert(info.node_id.clone())
            || !transport_keys.insert(info.transport_public_key.clone())
            || !signing_keys.insert(info.signing_public_key.expect("checked above"))
        {
            bail!(
                "node {target} is malformed, duplicated, or has role {}, expected {expected_role}",
                info.role
            );
        }
        infos.push(info);
    }
    Ok(infos)
}

async fn provision_actor_v3<T: serde::Serialize>(
    client: &reqwest::Client,
    target: &str,
    provision_role: &str,
    provision: &T,
    admin_token: &str,
) -> Result<()> {
    let role = provision_role.trim_end_matches("-v3");
    let info = client
        .get(format!("{}/v3/node-info", target.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<NodeInfo>()
        .await?;
    if info.role != role || info.protocol_version != gp_types::PROTOCOL_VERSION_V3 {
        bail!("v3 provisioning target has the wrong role");
    }
    let sealed = seal_to_recipient(
        &info.transport_public_key,
        random_id(),
        random_nonce(),
        &serde_json::to_vec(provision)?,
        &gp_wire::node_provision_context(&info.node_id, provision_role)?,
    )?;
    let response = client
        .post(format!("{}/v3/provision", target.trim_end_matches('/')))
        .bearer_auth(admin_token)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    ensure_success(response, "provision protocol-v3 actor").await?;
    Ok(())
}

pub async fn setup(options: SetupOptions) -> Result<RecoveryCard> {
    let client = reqwest::Client::new();
    if options.signers.is_empty()
        || options.guardians.is_empty()
        || options.relays.is_empty()
        || options.config_stores.is_empty()
    {
        bail!("at least one signer, guardian, relay, and config store is required");
    }
    let relay_bases = options
        .relays
        .iter()
        .map(|relay| relay.trim_end_matches('/').to_string())
        .collect::<Vec<_>>();
    let signer_count = u16::try_from(options.signers.len())?;
    let guardian_count = u16::try_from(options.guardians.len())?;
    let signer_mailboxes = (0..options.signers.len())
        .map(|_| mailbox_url(&relay_bases[0]))
        .collect::<Vec<_>>();
    let guardian_mailboxes = (0..options.guardians.len())
        .map(|_| mailbox_url(&relay_bases[0]))
        .collect::<Vec<_>>();
    let policy = SetupPolicy {
        signer_count,
        signer_threshold: options.signer_threshold,
        guardian_count,
        guardian_threshold: options.guardian_threshold,
        minimum_recovery_delay: options.delay_secs,
    };
    let bundle = create_setup(
        &options.secret,
        &policy,
        signer_mailboxes,
        guardian_mailboxes,
        &options.config_stores,
        &relay_bases,
    )?;
    let mut owner_control = OwnerControlFile {
        protocol_version: bundle.capsule.protocol_version,
        config_id: bundle.capsule.config_id,
        config_version: bundle.capsule.config_version,
        owner_cancel_signing_seed: bundle
            .owner_cancel_signing_seed
            .as_slice()
            .try_into()
            .context("invalid owner cancellation signing seed")?,
        owner_cancel_public_key: bundle.capsule.owner_cancel_public_key,
        guardian_count: bundle.capsule.guardian_count,
        guardian_threshold: bundle.capsule.guardian_threshold,
        guardian_routes: bundle.owner_guardian_routes.clone(),
        relay_bases: relay_bases.clone(),
    };

    println!("SETUP config={}", hex::encode(bundle.capsule.config_id));
    for ((target, signer), mailbox) in options
        .signers
        .iter()
        .zip(bundle.signers)
        .zip(bundle.card.signer_mailboxes.iter())
    {
        provision_actor(
            &client,
            target,
            "signer",
            ProvisionPayload::Signer(signer),
            &options.admin_token,
        )
        .await?;
        for relay in &relay_bases {
            register_route(&client, relay, &options.relay_token, mailbox, target).await?;
        }
        println!(
            "  provisioned signer mailbox {} on {} relay(s)",
            short_mailbox(mailbox),
            relay_bases.len()
        );
    }
    for (target, guardian) in options.guardians.iter().zip(bundle.guardians) {
        let mailbox = guardian.mailbox.clone();
        provision_actor(
            &client,
            target,
            "guardian",
            ProvisionPayload::Guardian(guardian),
            &options.admin_token,
        )
        .await?;
        for relay in &relay_bases {
            register_route(&client, relay, &options.relay_token, &mailbox, target).await?;
        }
        println!(
            "  provisioned guardian mailbox {} on {} relay(s)",
            short_mailbox(&mailbox),
            relay_bases.len()
        );
    }

    let config_id = hex::encode(bundle.capsule.config_id);
    for store in &options.config_stores {
        let response = client
            .put(format!(
                "{}/v1/configs/{config_id}",
                store.trim_end_matches('/')
            ))
            .bearer_auth(&options.admin_token)
            .json(&bundle.capsule)
            .send()
            .await?;
        ensure_success(response, "publish Config Capsule").await?;
    }
    write_private_json(Path::new(&options.card_path), &bundle.card)?;
    write_private_json(Path::new(&options.owner_control_path), &owner_control)?;
    zeroize_id(&mut owner_control.owner_cancel_signing_seed);
    println!(
        "  published Config Capsule to {} config store(s) and wrote {} plus private owner control {}",
        options.config_stores.len(),
        options.card_path,
        options.owner_control_path
    );
    Ok(bundle.card)
}

async fn provision_actor(
    client: &reqwest::Client,
    target: &str,
    expected_role: &str,
    payload: ProvisionPayload,
    admin_token: &str,
) -> Result<()> {
    let info = client
        .get(format!("{}/v1/node-info", target.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<NodeInfo>()
        .await?;
    if info.protocol_version != gp_types::PROTOCOL_VERSION || info.role != expected_role {
        bail!(
            "node {target} has role {}, expected {expected_role}",
            info.role
        );
    }
    let bytes = serde_json::to_vec(&payload)?;
    let sealed = seal_to_recipient(
        &info.transport_public_key,
        random_id(),
        random_nonce(),
        &bytes,
        &gp_wire::node_provision_context(&info.node_id, expected_role)?,
    )?;
    let response = client
        .post(format!("{}/v1/provision", target.trim_end_matches('/')))
        .bearer_auth(admin_token)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    ensure_success(response, "provision actor").await?;
    Ok(())
}

pub(crate) async fn register_route(
    client: &reqwest::Client,
    relay: &str,
    token: &str,
    mailbox_url: &str,
    target: &str,
) -> Result<()> {
    let info = client
        .get(format!("{}/v1/node-info", target.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<NodeInfo>()
        .await?;
    let registration = RouteRegistration {
        mailbox: mailbox_id(mailbox_url)?,
        target_url: target.trim_end_matches('/').into(),
        transport_public_key: info.transport_public_key,
    };
    let response = client
        .post(format!("{}/v1/register", relay.trim_end_matches('/')))
        .bearer_auth(token)
        .json(&registration)
        .send()
        .await?;
    ensure_success(response, "register relay mailbox").await?;
    Ok(())
}

pub async fn recover(options: RecoverOptions) -> Result<NetworkDemoResult> {
    let client = reqwest::Client::new();
    let card: RecoveryCard = serde_json::from_slice(&fs::read(&options.card_path)?)?;
    let capsule_locators = card.all_capsule_locators();
    if capsule_locators.is_empty() {
        bail!("Recovery Card contains no config store locators");
    }
    let mut last_store_error: Option<anyhow::Error> = None;
    let mut capsule = None;
    for locator in capsule_locators {
        match client.get(locator).send().await {
            Ok(response) => {
                let status = response.status();
                match response.error_for_status() {
                    Ok(response) => match response.json::<ConfigCapsule>().await {
                        Ok(value) => match validate_capsule(&card, &value) {
                            Ok(()) => {
                                capsule = Some(value);
                                println!("  fetched Config Capsule from {locator}");
                                break;
                            }
                            Err(error) => {
                                last_store_error = Some(error.context(format!(
                                    "config store {locator} returned a capsule that does not match the Recovery Card"
                                )))
                            }
                        },
                        Err(error) => last_store_error = Some(error.into()),
                    },
                    Err(error) => {
                        last_store_error = Some(
                            anyhow::Error::new(error)
                                .context(format!("config store {locator} responded with {status}")),
                        )
                    }
                }
            }
            Err(error) => {
                last_store_error = Some(
                    anyhow::Error::new(error)
                        .context(format!("config store {locator} unreachable")),
                )
            }
        }
    }
    let capsule = capsule.ok_or_else(|| {
        let detail = last_store_error
            .as_ref()
            .map_or_else(|| "unknown".to_string(), |error| error.to_string());
        anyhow::anyhow!("no config store responded: {detail}")
    })?;
    let recipient = RecipientKeyPair::from_seed(random_id());
    let now = wall_now()?;
    let request = RecoveryRequest {
        protocol_version: gp_types::PROTOCOL_VERSION,
        crypto_suite: capsule.crypto_suite,
        config_id: capsule.config_id,
        config_version: capsule.config_version,
        request_id: random_id(),
        recovery_recipient_key: recipient.public_key().to_vec(),
        requested_at: now,
        nonce: random_id(),
        expiry: now.saturating_add(capsule.max_request_lifetime),
    };
    if let Some(path) = &options.request_out_path {
        write_private_json(Path::new(path), &request)?;
        println!("  wrote public recovery transcript to {path} for owner monitoring");
    }
    println!("RECOVERY request={}", hex::encode(request.request_id));

    let mut signer_contributions = Vec::new();
    for mailbox in &card.signer_mailboxes {
        match send_mailbox_mirrored(
            &client,
            mailbox,
            &card.relay_bases,
            &MailboxRequest::SignerApprove {
                request: request.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::SignerContribution(value)) => {
                signer_contributions.push(value);
                println!("  signer approval via {}", short_mailbox(mailbox));
            }
            Ok(_) => println!(
                "  signer {} returned the wrong response",
                short_mailbox(mailbox)
            ),
            Err(error) => println!("  signer {} unavailable: {error}", short_mailbox(mailbox)),
        }
        if signer_contributions.len() >= usize::from(capsule.signer_threshold) {
            break;
        }
    }
    if signer_contributions.len() < usize::from(capsule.signer_threshold) {
        bail!("signer approval threshold was not reached");
    }
    let begin = BeginRecoveryCertificate {
        request: request.clone(),
        signer_contributions,
    };
    let authorization_key = reconstruct_a(&begin, &capsule, &recipient, wall_now()?)?;
    let descriptor = open_descriptor(&capsule, &authorization_key)?;
    println!("  reconstructed A and opened private guardian descriptor locally");

    let mut begin_count = 0_usize;
    for route in &descriptor.guardians {
        match send_mailbox_mirrored(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &MailboxRequest::GuardianBegin {
                certificate: begin.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::BeginAccepted { .. }) => {
                begin_count += 1;
                println!("  guardian {} accepted Begin", route.guardian_index);
            }
            Ok(_) => println!(
                "  guardian {} returned the wrong response",
                route.guardian_index
            ),
            Err(error) => println!("  guardian {} unavailable: {error}", route.guardian_index),
        }
    }
    if begin_count < usize::from(capsule.guardian_threshold) {
        bail!("not enough guardians accepted Begin");
    }

    if options.cancel_before_release {
        // Capture a threshold-valid release certificate before the owner's hard cancel to model
        // a hostile recovery client racing an older certificate against the owner tombstone.
        let mut pre_cancel_release_votes = Vec::new();
        for mailbox in &card.signer_mailboxes {
            if let Ok(MailboxResponse::ReleaseVote(vote)) = send_mailbox_mirrored(
                &client,
                mailbox,
                &card.relay_bases,
                &MailboxRequest::SignerRelease {
                    request: request.clone(),
                },
                &recipient,
            )
            .await
            {
                pre_cancel_release_votes.push(vote);
            }
            if pre_cancel_release_votes.len() >= usize::from(capsule.signer_threshold) {
                break;
            }
        }
        if pre_cancel_release_votes.len() < usize::from(capsule.signer_threshold) {
            bail!("could not construct the cancellation-race release certificate");
        }
        let raced_release = ReleaseCertificate {
            votes: pre_cancel_release_votes,
        };
        let mut owner_control: OwnerControlFile =
            serde_json::from_slice(&fs::read(&options.owner_control_path)?)?;
        if owner_control.protocol_version != gp_types::PROTOCOL_VERSION
            || owner_control.config_id != request.config_id
            || owner_control.config_version != request.config_version
            || owner_control.owner_cancel_public_key != capsule.owner_cancel_public_key
            || owner_control.guardian_count != capsule.guardian_count
            || owner_control.guardian_threshold != capsule.guardian_threshold
            || owner_control.guardian_routes != descriptor.guardians
            || owner_control.relay_bases != card.relay_bases
        {
            bail!("owner control file does not match this recovery configuration");
        }
        let cancel_recipient = RecipientKeyPair::from_seed(random_id());
        let certificate_result = make_owner_cancel_certificate(
            &request,
            owner_control.owner_cancel_signing_seed,
            cancel_recipient.public_key().to_vec(),
            1,
            wall_now()?,
        );
        zeroize_id(&mut owner_control.owner_cancel_signing_seed);
        let certificate = certificate_result?;
        let mut cancelled_guardians = BTreeSet::new();
        for route in &descriptor.guardians {
            if let Ok(MailboxResponse::CancellationAccepted(ack)) = send_mailbox_mirrored(
                &client,
                &route.mailbox,
                &card.relay_bases,
                &MailboxRequest::GuardianCancel {
                    request: request.clone(),
                    certificate: Box::new(certificate.clone()),
                },
                &cancel_recipient,
            )
            .await
                && validate_owner_cancel_ack(&ack, &certificate, &request, route).is_ok()
            {
                cancelled_guardians.insert(ack.guardian_index);
            }
        }
        let required_acks = required_cancel_acks(
            usize::from(capsule.guardian_count),
            usize::from(capsule.guardian_threshold),
        )?;
        if cancelled_guardians.len() < required_acks {
            bail!("cancellation did not reach enough guardians");
        }
        println!(
            "  owner hard-cancel tombstone stored by {} guardians",
            cancelled_guardians.len()
        );
        tokio::time::sleep(Duration::from_secs(
            capsule.minimum_recovery_delay.saturating_add(1),
        ))
        .await;
        let mut observed_refusal = false;
        for route in &descriptor.guardians {
            match send_mailbox_mirrored(
                &client,
                &route.mailbox,
                &card.relay_bases,
                &MailboxRequest::GuardianRelease {
                    request: request.clone(),
                    certificate: raced_release.clone(),
                },
                &recipient,
            )
            .await
            {
                Ok(MailboxResponse::GuardianContribution(_)) => {
                    bail!("cancelled guardian released material")
                }
                Ok(MailboxResponse::ReleaseRefused { reason }) if reason == "cancelled" => {
                    observed_refusal = true;
                    println!(
                        "  guardian {} refused the raced release certificate",
                        route.guardian_index
                    );
                    break;
                }
                Ok(_) | Err(_) => {}
            }
        }
        if !observed_refusal {
            bail!("no guardian produced an authenticated cancellation refusal");
        }
        return Ok(NetworkDemoResult {
            config_id: hex::encode(capsule.config_id),
            request_id: hex::encode(request.request_id),
            recovered_secret: None,
            signer_contributions: usize::from(capsule.signer_threshold),
            guardian_contributions: 0,
            rejected_guardians: vec![],
            cancelled: true,
        });
    }

    println!(
        "  waiting {} real seconds for guardian-local monotonic delays",
        capsule.minimum_recovery_delay
    );
    tokio::time::sleep(Duration::from_secs(
        capsule.minimum_recovery_delay.saturating_add(1),
    ))
    .await;

    let mut release_votes = Vec::new();
    for mailbox in &card.signer_mailboxes {
        match send_mailbox_mirrored(
            &client,
            mailbox,
            &card.relay_bases,
            &MailboxRequest::SignerRelease {
                request: request.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::ReleaseVote(vote)) => release_votes.push(vote),
            Ok(_) => {}
            Err(error) => println!("  release signer unavailable: {error}"),
        }
        if release_votes.len() >= usize::from(capsule.signer_threshold) {
            break;
        }
    }
    if release_votes.len() < usize::from(capsule.signer_threshold) {
        bail!("release vote threshold was not reached");
    }
    let release = ReleaseCertificate {
        votes: release_votes,
    };

    let mut fragments = Vec::new();
    let mut dek_shares = Vec::new();
    let mut rejected = Vec::new();
    for route in &descriptor.guardians {
        match send_mailbox_mirrored(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &MailboxRequest::GuardianRelease {
                request: request.clone(),
                certificate: release.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(MailboxResponse::GuardianContribution(contribution)) => {
                match validate_guardian_contribution(
                    &contribution,
                    route,
                    &descriptor,
                    &request,
                    &authorization_key,
                ) {
                    Ok(share) => {
                        fragments.push((
                            contribution.guardian_index,
                            contribution.ciphertext_fragment,
                        ));
                        dek_shares.push(share);
                        println!("  guardian {} contribution verified", route.guardian_index);
                    }
                    Err(error) => {
                        rejected.push(route.guardian_index);
                        println!("  guardian {} rejected: {error}", route.guardian_index);
                    }
                }
            }
            Ok(_) => rejected.push(route.guardian_index),
            Err(error) => {
                rejected.push(route.guardian_index);
                println!("  guardian {} unavailable: {error}", route.guardian_index);
            }
        }
        if fragments.len() >= usize::from(capsule.guardian_threshold) {
            break;
        }
    }
    if fragments.len() < usize::from(capsule.guardian_threshold) {
        bail!("guardian threshold was not reached");
    }
    let plaintext = reconstruct_payload(&capsule, &descriptor, &fragments, &dek_shares)?;
    let recovered = String::from_utf8_lossy(&plaintext).into_owned();
    if let Some(path) = &options.output_path {
        fs::write(path, &*plaintext)?;
    }
    println!("  reconstructed DEK, ciphertext, and plaintext on the recovery client");
    Ok(NetworkDemoResult {
        config_id: hex::encode(capsule.config_id),
        request_id: hex::encode(request.request_id),
        recovered_secret: Some(recovered),
        signer_contributions: usize::from(capsule.signer_threshold),
        guardian_contributions: fragments.len(),
        rejected_guardians: rejected,
        cancelled: false,
    })
}

/// Executes recovery against the witness-selected protocol-v3 guardian epoch.
/// Plaintext A, DEK and payload bytes exist only in this client function.
pub async fn recover_v3(options: RecoverV3Options) -> Result<NetworkDemoResult> {
    let client = reqwest::Client::new();
    let card: RecoveryCardV3 = serde_json::from_slice(&fs::read(&options.card_path)?)?;
    let recipient = RecipientKeyPair::from_seed(random_id());
    let (capsule, witness_challenge, witness_reads) =
        read_latest_epoch_v3(&client, &card, &recipient).await?;
    let now = wall_now()?;
    let request = RecoveryRequestV3 {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_ref: capsule.config_ref,
        request_id: random_id(),
        recovery_recipient_key: recipient.public_key().to_vec(),
        requested_at: now,
        nonce: random_id(),
        expiry: now.saturating_add(capsule.max_request_lifetime),
    };
    if let Some(path) = &options.request_out_path {
        write_private_json(Path::new(path), &request)?;
    }
    println!(
        "RECOVERY v3 request={} epoch={}",
        hex::encode(request.request_id),
        request.config_ref.guardian_epoch
    );

    let mut signer_contributions = Vec::new();
    for mailbox in &card.signer_mailboxes {
        let action = SignerRecoveryRequestV3::Approve {
            request: request.clone(),
            witness_challenge: witness_challenge.clone(),
            witness_reads: witness_reads.clone(),
        };
        match send_recovery_mailbox_v3::<_, SignerRecoveryResponseV3>(
            &client,
            mailbox,
            &card.relay_bases,
            &action,
            &recipient,
        )
        .await
        {
            Ok(SignerRecoveryResponseV3::Contribution(contribution)) => {
                signer_contributions.push(contribution)
            }
            Ok(_) => {}
            Err(error) => println!("  v3 signer unavailable: {error}"),
        }
        if signer_contributions.len() >= usize::from(capsule.signer_threshold) {
            break;
        }
    }
    if signer_contributions.len() < usize::from(capsule.signer_threshold) {
        bail!("protocol-v3 signer approval threshold was not reached");
    }
    let request_digest = crate::rotation_protocol::recovery_request_digest_v3(&request)?;
    let begin = BeginRecoveryCertificateV3 {
        request: request.clone(),
        request_digest,
        signer_contributions,
    };
    crate::rotation_protocol::validate_begin_recovery_certificate_v3(
        &begin,
        &capsule,
        wall_now()?,
    )?;
    let authorization_shares = begin
        .signer_contributions
        .iter()
        .map(|contribution| -> Result<_> {
            Ok(recipient.open(
                &contribution.encrypted_authorization_share,
                &gp_wire::recovery_authorization_share_context_v3(
                    &request,
                    contribution.signer_id,
                )?,
            )?)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let authorization_key = recover_secret(&authorization_shares, capsule.signer_threshold)?;
    let descriptor_plaintext = aead_decrypt(
        &descriptor_key_v3(
            authorization_key
                .as_slice()
                .try_into()
                .context("reconstructed A has the wrong length")?,
            &capsule.config_ref,
        )?,
        &capsule.encrypted_recovery_descriptor,
        &gp_wire::descriptor_context_v3(&capsule.config_ref)?,
    )?;
    let descriptor: RecoveryDescriptorV3 = serde_json::from_slice(&descriptor_plaintext)?;
    validate_recovery_descriptor_v3(&descriptor, &capsule)?;
    println!("  reconstructed A and opened the epoch-bound private descriptor locally");

    let mut begin_count = 0_usize;
    for route in &descriptor.guardians {
        match send_recovery_mailbox_v3::<_, GuardianRecoveryResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRecoveryRequestV3::Begin {
                certificate: begin.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(GuardianRecoveryResponseV3::BeginAccepted { .. }) => begin_count += 1,
            Ok(_) => {}
            Err(error) => println!(
                "  v3 guardian {} rejected Begin: {error}",
                route.guardian_index
            ),
        }
    }
    if begin_count < usize::from(capsule.guardian_threshold) {
        bail!("not enough protocol-v3 guardians accepted Begin");
    }
    println!(
        "  waiting {} real seconds for guardian-local monotonic delays",
        capsule.minimum_recovery_delay
    );
    tokio::time::sleep(Duration::from_secs(
        capsule.minimum_recovery_delay.saturating_add(1),
    ))
    .await;

    let mut release_votes = Vec::new();
    for mailbox in &card.signer_mailboxes {
        match send_recovery_mailbox_v3::<_, SignerRecoveryResponseV3>(
            &client,
            mailbox,
            &card.relay_bases,
            &SignerRecoveryRequestV3::Release {
                request: request.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(SignerRecoveryResponseV3::ReleaseVote(vote)) => release_votes.push(vote),
            Ok(_) => {}
            Err(error) => println!("  v3 release signer unavailable: {error}"),
        }
        if release_votes.len() >= usize::from(capsule.signer_threshold) {
            break;
        }
    }
    if release_votes.len() < usize::from(capsule.signer_threshold) {
        bail!("protocol-v3 signer Release threshold was not reached");
    }
    let release = RecoveryReleaseCertificateV3 {
        request: request.clone(),
        request_digest,
        votes: release_votes,
    };
    crate::rotation_protocol::validate_recovery_release_certificate_for_ref_v3(
        &release,
        &capsule,
        &capsule.config_ref,
        wall_now()?,
    )?;

    let mut shares = Vec::new();
    let mut fragments = Vec::new();
    let mut rejected = Vec::new();
    for route in &descriptor.guardians {
        match send_recovery_mailbox_v3::<_, GuardianRecoveryResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRecoveryRequestV3::Release {
                request: request.clone(),
                certificate: release.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(GuardianRecoveryResponseV3::Contribution(contribution)) => {
                match open_guardian_contribution_v3(
                    &contribution,
                    route,
                    &descriptor,
                    &capsule,
                    &request,
                    authorization_key.as_slice().try_into()?,
                ) {
                    Ok((share, fragment)) => {
                        shares.push(EpochFrostShare {
                            config_ref: capsule.config_ref,
                            encoded_share: share,
                        });
                        fragments.push((contribution.fragment_index, fragment));
                    }
                    Err(error) => {
                        rejected.push(route.guardian_index);
                        println!("  v3 guardian {} rejected: {error}", route.guardian_index);
                    }
                }
            }
            Ok(_) | Err(_) => rejected.push(route.guardian_index),
        }
        if shares.len() >= usize::from(capsule.guardian_threshold) {
            break;
        }
    }
    if shares.len() < usize::from(capsule.guardian_threshold) {
        bail!("protocol-v3 guardian threshold was not reached");
    }
    let dek =
        frost_recover_dek_for_epoch(&shares, &capsule.config_ref, capsule.guardian_threshold)?;
    let ciphertext = erasure_reconstruct(
        &fragments,
        descriptor.data_shards,
        descriptor.total_shards,
        usize::try_from(descriptor.ciphertext_len)?,
    )?;
    let plaintext = aead_decrypt(
        dek.as_slice().try_into()?,
        &AeadCiphertext {
            nonce: descriptor.payload_nonce,
            ciphertext,
        },
        &gp_wire::payload_context_v3(
            &capsule.config_ref.config_id,
            capsule.config_ref.payload_generation,
        )?,
    )?;
    if let Some(path) = &options.output_path {
        fs::write(path, &*plaintext)?;
    }
    println!("  reconstructed DEK, ciphertext, and plaintext only on the recovery client");
    Ok(NetworkDemoResult {
        config_id: hex::encode(capsule.config_ref.config_id),
        request_id: hex::encode(request.request_id),
        recovered_secret: Some(String::from_utf8_lossy(&plaintext).into_owned()),
        signer_contributions: usize::from(capsule.signer_threshold),
        guardian_contributions: shares.len(),
        rejected_guardians: rejected,
        cancelled: false,
    })
}

fn validate_recovery_descriptor_v3(
    descriptor: &RecoveryDescriptorV3,
    capsule: &ConfigCapsuleV3,
) -> Result<()> {
    let route_ids = descriptor
        .guardians
        .iter()
        .map(|route| route.guardian_index)
        .collect::<BTreeSet<_>>();
    if descriptor.config_ref != capsule.config_ref
        || descriptor.guardian_material_root != capsule.guardian_material_root
        || descriptor.data_shards != capsule.guardian_threshold
        || descriptor.total_shards != capsule.guardian_count
        || descriptor.guardians.len() != usize::from(capsule.guardian_count)
        || route_ids.len() != descriptor.guardians.len()
        || descriptor.dpss_suite != capsule.dpss_suite
        || descriptor.dpss_public_commitment != capsule.dpss_public_commitment
        || gp_crypto::frost_public_package_digest(&descriptor.dpss_public_package)?
            != capsule.dpss_public_commitment
    {
        bail!("Recovery Descriptor does not match the authenticated v3 capsule");
    }
    Ok(())
}

fn open_guardian_contribution_v3(
    contribution: &gp_types::GuardianRecoveryContributionV3,
    route: &gp_types::GuardianRouteV3,
    descriptor: &RecoveryDescriptorV3,
    capsule: &ConfigCapsuleV3,
    request: &RecoveryRequestV3,
    authorization_key: &[u8; 32],
) -> Result<(gp_crypto::SecretVec, Vec<u8>)> {
    if contribution.config_ref != request.config_ref
        || contribution.request_id != request.request_id
        || contribution.request_digest
            != crate::rotation_protocol::recovery_request_digest_v3(request)?
        || contribution.recovery_recipient_key != request.recovery_recipient_key
        || contribution.nonce != request.nonce
        || contribution.guardian_index != route.guardian_index
    {
        bail!("guardian contribution is not bound to the exact recovery transcript");
    }
    verify(
        &route.guardian_public_key,
        &gp_wire::guardian_recovery_contribution_v3(contribution)?,
        &contribution.guardian_signature,
    )?;
    let policy = GuardianPolicyV3 {
        config_ref: capsule.config_ref,
        epoch_state: GuardianEpochState::Active,
        signer_set_commitment: capsule.signer_set_commitment,
        signer_count: capsule.signer_count,
        signer_threshold: capsule.signer_threshold,
        owner_cancel_public_key: capsule.owner_cancel_public_key,
        minimum_recovery_delay: capsule.minimum_recovery_delay,
        guardian_material_root: capsule.guardian_material_root,
        dpss_suite: capsule.dpss_suite,
        dpss_public_commitment: capsule.dpss_public_commitment,
        predecessor_capsule_hash: capsule.predecessor_capsule_hash,
        activation_qc_hash: capsule
            .activation_qc
            .as_ref()
            .map(|qc| sha256(&gp_wire::epoch_activation_qc(qc).unwrap_or_default())),
        drain_deadline: None,
    };
    let leaf = gp_types::PreparedRecordLeaf {
        guardian_index: contribution.guardian_index,
        fragment_index: contribution.fragment_index,
        opaque_slot_id: route.opaque_slot_id,
        encrypted_share_hash: hash_aead(&contribution.encrypted_dek_share),
        fragment_hash: hash_aead(&contribution.encrypted_ciphertext_fragment),
        policy_hash: sha256(&gp_wire::guardian_policy_body_v3(&policy)?),
    };
    let position = descriptor
        .guardians
        .iter()
        .position(|candidate| candidate.guardian_index == contribution.guardian_index)
        .context("guardian contribution is outside the descriptor roster")?;
    merkle_verify(
        descriptor.guardian_material_root,
        sha256(&gp_wire::prepared_record_leaf_v3(&leaf)?),
        position,
        descriptor.guardians.len(),
        &contribution.merkle_path_proof,
    )?;
    let share = aead_decrypt(
        &guardian_share_key_v3(
            authorization_key,
            &request.config_ref,
            contribution.guardian_index,
        )?,
        &contribution.encrypted_dek_share,
        &gp_wire::guardian_share_context_v3(&request.config_ref, contribution.guardian_index)?,
    )?;
    if frost_verify_share(&share, &descriptor.dpss_public_package)? != contribution.guardian_index {
        bail!("guardian returned a FROST share for another participant");
    }
    let fragment = aead_decrypt(
        &guardian_fragment_key_v3(
            authorization_key,
            &request.config_ref,
            contribution.guardian_index,
        )?,
        &contribution.encrypted_ciphertext_fragment,
        &gp_wire::guardian_fragment_context_v3(
            &request.config_ref,
            contribution.guardian_index,
            contribution.fragment_index,
        )?,
    )?;
    Ok((share, fragment.to_vec()))
}

pub async fn cancel(options: CancelOptions) -> Result<OwnerCancelResult> {
    let client = reqwest::Client::new();
    let request: RecoveryRequest = serde_json::from_slice(&fs::read(&options.request_path)?)?;
    let mut owner_control: OwnerControlFile =
        serde_json::from_slice(&fs::read(&options.owner_control_path)?)?;
    let now = wall_now()?;
    if owner_control.protocol_version != gp_types::PROTOCOL_VERSION
        || request.protocol_version != gp_types::PROTOCOL_VERSION
        || owner_control.config_id != request.config_id
        || owner_control.config_version != request.config_version
        || request.requested_at > now
        || request.expiry <= now
        || usize::from(owner_control.guardian_count) != owner_control.guardian_routes.len()
        || owner_control.guardian_threshold == 0
        || owner_control.guardian_threshold > owner_control.guardian_count
    {
        zeroize_id(&mut owner_control.owner_cancel_signing_seed);
        bail!("owner control file and recovery request do not form a valid active configuration");
    }
    let expected_public = gp_crypto::verifying_key_bytes(&gp_crypto::signing_key(
        owner_control.owner_cancel_signing_seed,
    ));
    if expected_public != owner_control.owner_cancel_public_key {
        zeroize_id(&mut owner_control.owner_cancel_signing_seed);
        bail!("owner control private key does not match its pinned public key");
    }
    let cancel_recipient = RecipientKeyPair::from_seed(random_id());
    let certificate_result = make_owner_cancel_certificate(
        &request,
        owner_control.owner_cancel_signing_seed,
        cancel_recipient.public_key().to_vec(),
        1,
        now,
    );
    zeroize_id(&mut owner_control.owner_cancel_signing_seed);
    let certificate = certificate_result?;
    let mut acknowledgements = BTreeSet::new();
    for route in &owner_control.guardian_routes {
        if let Ok(MailboxResponse::CancellationAccepted(ack)) = send_mailbox_mirrored(
            &client,
            &route.mailbox,
            &owner_control.relay_bases,
            &MailboxRequest::GuardianCancel {
                request: request.clone(),
                certificate: Box::new(certificate.clone()),
            },
            &cancel_recipient,
        )
        .await
            && validate_owner_cancel_ack(&ack, &certificate, &request, route).is_ok()
        {
            acknowledgements.insert(ack.guardian_index);
        }
    }
    let required_acks = required_cancel_acks(
        usize::from(owner_control.guardian_count),
        usize::from(owner_control.guardian_threshold),
    )?;
    if acknowledgements.len() < required_acks {
        bail!(
            "owner hard-cancel reached {} guardians, fewer than the required {required_acks}",
            acknowledgements.len()
        );
    }
    Ok(OwnerCancelResult {
        config_id: hex::encode(request.config_id),
        request_id: hex::encode(request.request_id),
        guardian_acknowledgements: acknowledgements.len(),
        permanently_cancelled: true,
    })
}

fn required_cancel_acks(total_guardians: usize, recovery_threshold: usize) -> Result<usize> {
    if recovery_threshold == 0 || recovery_threshold > total_guardians {
        bail!("invalid guardian threshold in owner control state");
    }
    Ok(total_guardians - recovery_threshold + 1)
}

async fn send_mailbox_mirrored(
    client: &reqwest::Client,
    mailbox: &str,
    relays: &[String],
    action: &MailboxRequest,
    recipient: &RecipientKeyPair,
) -> Result<MailboxResponse> {
    let mut last_error: Option<anyhow::Error> = None;
    let mut tried = 0_usize;
    for candidate in mailbox_replicas(mailbox, relays) {
        tried += 1;
        match send_mailbox(client, &candidate, action, recipient).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error.context(format!(
            "mailbox {} unreachable via {tried} relay replica(s)",
            short_mailbox(mailbox)
        ))),
        None => bail!("no relay replicas configured"),
    }
}

async fn send_recovery_mailbox_v3<T, R>(
    client: &reqwest::Client,
    mailbox: &str,
    relays: &[String],
    action: &T,
    recipient: &RecipientKeyPair,
) -> Result<R>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let mailbox_id = mailbox_id(mailbox)?;
    let mut candidates = Vec::new();
    if mailbox.contains("/v3/recovery-mailboxes/") {
        candidates.push(mailbox.to_owned());
    }
    for relay in relays {
        let candidate = format!(
            "{}/v3/recovery-mailboxes/{mailbox_id}",
            relay.trim_end_matches('/')
        );
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    let mut last_error = None;
    for candidate in candidates {
        match send_recovery_mailbox_once_v3(client, &candidate, action, recipient).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("no protocol-v3 relay replicas configured"))
        .context(format!(
            "v3 mailbox {} is unreachable",
            short_mailbox(mailbox)
        )))
}

async fn send_recovery_mailbox_once_v3<T, R>(
    client: &reqwest::Client,
    mailbox: &str,
    action: &T,
    recipient: &RecipientKeyPair,
) -> Result<R>
where
    T: serde::Serialize,
    R: serde::de::DeserializeOwned,
{
    let key_url = format!(
        "{}/key",
        mailbox
            .trim_end_matches('/')
            .replace("/v3/recovery-mailboxes/", "/v3/mailboxes/")
    );
    let transport_key = client
        .get(key_url)
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<u8>>()
        .await?;
    let mailbox_id = mailbox_id(mailbox)?;
    let sealed = seal_to_recipient(
        &transport_key,
        random_id(),
        random_nonce(),
        &serde_json::to_vec(action)?,
        &gp_wire::mailbox_transport_context(&mailbox_id, "recovery-request-v3")?,
    )?;
    let response = client
        .post(mailbox)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    let response = ensure_success(response, "protocol-v3 recovery mailbox request")
        .await?
        .json::<SealedMailboxBody>()
        .await?;
    let plaintext = recipient.open(
        &response.sealed,
        &gp_wire::mailbox_transport_context(&mailbox_id, "recovery-response-v3")?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn mailbox_replicas(mailbox: &str, relay_bases: &[String]) -> Vec<String> {
    let mut replicas = vec![mailbox.to_string()];
    let Ok(id) = mailbox_id(mailbox) else {
        return replicas;
    };
    for base in relay_bases {
        let candidate = format!("{}/v1/mailboxes/{}", base.trim_end_matches('/'), id);
        if !replicas.contains(&candidate) {
            replicas.push(candidate);
        }
    }
    replicas
}

async fn send_mailbox(
    client: &reqwest::Client,
    mailbox: &str,
    action: &MailboxRequest,
    recipient: &RecipientKeyPair,
) -> Result<MailboxResponse> {
    let key = client
        .get(format!("{}/key", mailbox.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<u8>>()
        .await?;
    let mailbox_id = mailbox_id(mailbox)?;
    let bytes = serde_json::to_vec(action)?;
    let sealed = seal_to_recipient(
        &key,
        random_id(),
        random_nonce(),
        &bytes,
        &gp_wire::mailbox_transport_context(&mailbox_id, "request")?,
    )?;
    let response = client
        .post(mailbox)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    let response = ensure_success(response, "mailbox request")
        .await?
        .json::<SealedMailboxBody>()
        .await?;
    let plaintext = recipient.open(
        &response.sealed,
        &gp_wire::mailbox_transport_context(&mailbox_id, "response")?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}

pub(crate) async fn ensure_success(
    response: reqwest::Response,
    operation: &str,
) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    bail!("{operation} failed with {status}: {body}")
}

fn mailbox_url(relay: &str) -> String {
    format!(
        "{}/v1/mailboxes/{}",
        relay.trim_end_matches('/'),
        hex::encode(random_id())
    )
}

fn mailbox_url_v3(relay: &str) -> String {
    format!(
        "{}/v3/mailboxes/{}",
        relay.trim_end_matches('/'),
        hex::encode(random_id())
    )
}

pub(crate) fn mailbox_id(mailbox_url: &str) -> Result<String> {
    mailbox_url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|value| value.len() >= 32)
        .map(str::to_owned)
        .context("invalid mailbox URL")
}

fn short_mailbox(mailbox: &str) -> String {
    mailbox_id(mailbox)
        .map(|value| format!("{}…", &value[..10]))
        .unwrap_or_else(|_| "invalid".into())
}

pub(crate) fn write_private_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        options.mode(0o600);
        let mut file = options.open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{mailbox_replicas, required_cancel_acks};

    #[test]
    fn hard_cancel_requires_enough_tombstones_to_break_recovery_quorum() {
        assert_eq!(required_cancel_acks(8, 5).unwrap(), 4);
        assert_eq!(required_cancel_acks(3, 2).unwrap(), 2);
        assert_eq!(required_cancel_acks(8, 1).unwrap(), 8);
        assert!(required_cancel_acks(8, 0).is_err());
        assert!(required_cancel_acks(3, 4).is_err());
    }

    #[test]
    fn relay_failover_preserves_the_opaque_mailbox_id_without_duplicates() {
        let mailbox = "http://relay-1/v1/mailboxes/0123456789abcdef0123456789abcdef";
        assert_eq!(
            mailbox_replicas(
                mailbox,
                &[
                    "http://relay-1".into(),
                    "http://relay-2/".into(),
                    "http://relay-2".into(),
                ],
            ),
            vec![
                mailbox.to_string(),
                "http://relay-2/v1/mailboxes/0123456789abcdef0123456789abcdef".into(),
            ]
        );
    }
}
