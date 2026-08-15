//! Live protocol-v3 guardian-replacement coordinator.
//!
//! The coordinator is ephemeral. It reconstructs A after signer intent
//! authorization, but receives neither a plaintext DEK share nor payload
//! plaintext. Provider messages remain signed and X-Wing sealed end to end
//! between guardian actors.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use gp_crypto::{
    RecipientKeyPair, aead_decrypt, aead_encrypt, commit_ciphertext_fragments, descriptor_key_v3,
    erasure_reconstruct, guardian_fragment_key_v3, guardian_share_key_v3, merkle_commit,
    merkle_verify, recover_secret, seal_to_recipient, sha256, sign, signing_key, verify,
    verifying_key_bytes,
};
use gp_types::{
    AbortRotationCertificate, AeadCiphertext, BeginRotationCertificate, ConfigCapsuleV3, ConfigRef,
    DpssSuiteId, GuardianEpochState, GuardianPolicyV3, GuardianRouteV3, NewShareWrapGrant,
    OldShareUnlockGrant, OwnerRotationCancelCertificate, RecoveryCardV3, RecoveryDescriptorV3,
    RotationActivateCertificate, RotationContext, RotationIntent, RotationPlan,
    RotationReadyCertificate, RotationReason, RotationReleaseCertificate, RotationState,
};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    client::{
        ensure_success, mailbox_id, read_latest_epoch_v3, register_route, write_private_json,
    },
    protocol::{random_id, random_nonce, wall_now},
    rotation_protocol::{
        validate_abort_rotation_certificate_v3, validate_activated_capsule_v3,
        validate_begin_rotation_certificate_v3, validate_owner_rotation_cancel_witness_quorum_v3,
        validate_rotation_ready_certificate_v3, validate_rotation_release_certificate_v3,
        witness_read_quorum_hash_v3,
    },
    types::{
        DpssDeliveryV3, GuardianRotationProvisionV3, GuardianRotationRequestV3,
        GuardianRotationResponseV3, GuardianRouteAliasV3, NodeInfo, OwnerControlFileV3,
        SealedMailboxBody, SignerRotationRequestV3, SignerRotationResponseV3,
        WitnessActivationRequest, WitnessFinalizeRequest, WitnessRotationCancelRequest,
    },
};

pub struct RotateV3Options {
    pub card_path: String,
    pub owner_control_path: String,
    pub remove_guardian: u16,
    pub replacement_target: String,
    pub relay_token: String,
    pub admin_token: String,
    pub rotation_control_path: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RotationControlFileV3 {
    pub protocol_version: u16,
    pub recovery_card: RecoveryCardV3,
    pub predecessor_capsule: ConfigCapsuleV3,
    pub plan: RotationPlan,
    pub owner_cancel_public_key: [u8; 32],
}

impl std::fmt::Debug for RotationControlFileV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RotationControlFileV3")
            .field("protocol_version", &self.protocol_version)
            .field("config_ref", &self.plan.context.config_ref)
            .field("rotation_id", &self.plan.context.rotation_id)
            .field("private_plan", &"[PRIVATE ROSTER REDACTED]")
            .field("owner_cancel_public_key", &self.owner_cancel_public_key)
            .finish()
    }
}

pub struct CancelRotationV3Options {
    pub rotation_control_path: String,
    pub owner_control_path: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct CancelRotationV3Result {
    pub rotation_id: String,
    pub witness_acknowledgements: usize,
    pub required_witness_acknowledgements: usize,
    pub old_guardian_acknowledgements: usize,
    pub required_old_guardian_acknowledgements: usize,
    pub signer_cancel_finalizations: usize,
    pub permanently_cancelled: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RotateV3Result {
    pub config_id: String,
    pub predecessor_epoch: u64,
    pub successor_epoch: u64,
    pub removed_guardian: u16,
    pub added_guardian: u16,
    pub prepared_guardians: usize,
    pub witness_acknowledgements: usize,
    pub plaintext_decryptions: u64,
}

pub async fn rotate_v3(options: RotateV3Options) -> Result<RotateV3Result> {
    let client = reqwest::Client::new();
    let card: RecoveryCardV3 = serde_json::from_slice(&fs::read(&options.card_path)?)?;
    let mut owner: OwnerControlFileV3 =
        serde_json::from_slice(&fs::read(&options.owner_control_path)?)?;
    if owner.protocol_version != gp_types::PROTOCOL_VERSION_V3
        || owner.config_ref.config_id != card.config_id
        || owner.owner_cancel_public_key != card.owner_cancel_public_key
        || verifying_key_bytes(&signing_key(owner.owner_cancel_signing_seed))
            != owner.owner_cancel_public_key
        || owner.relay_bases != card.relay_bases
    {
        bail!("v3 owner-control file does not match the Recovery Card");
    }
    let coordinator = RecipientKeyPair::from_seed(random_id());
    let (predecessor, witness_challenge, witness_reads) =
        read_latest_epoch_v3(&client, &card, &coordinator).await?;
    if owner.config_ref != predecessor.config_ref {
        bail!("owner-control epoch is stale; refusing rotation");
    }
    let issued_at = wall_now()?;
    let context = RotationContext {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_ref: predecessor.config_ref,
        rotation_id: random_id(),
        predecessor_capsule_hash: predecessor.capsule_hash,
        recipient_key: coordinator.public_key().to_vec(),
        nonce: random_id(),
        issued_at,
        expiry: issued_at
            .saturating_add(predecessor.minimum_recovery_delay)
            .saturating_add(7_200),
    };
    let intent = RotationIntent {
        context: context.clone(),
        reason: RotationReason::PlannedExit,
        old_guardian_count: predecessor.guardian_count,
        old_guardian_threshold: predecessor.guardian_threshold,
        allowed_new_guardian_count: vec![predecessor.guardian_count],
        allowed_new_guardian_threshold: vec![predecessor.guardian_threshold],
        allowed_dpss_suites: vec![DpssSuiteId::default()],
        selection_constraints_commitment: sha256(&options.remove_guardian.to_be_bytes()),
        witness_read_qc_hash: witness_read_quorum_hash_v3(&witness_challenge, &witness_reads)?,
    };
    let intent_hash = sha256(&gp_wire::rotation_intent(&intent)?);
    let mut intent_contributions = Vec::new();
    for mailbox in &card.signer_mailboxes {
        if let Ok(SignerRotationResponseV3::IntentContribution(value)) =
            send_rotation_mailbox::<_, SignerRotationResponseV3>(
                &client,
                mailbox,
                &card.relay_bases,
                &SignerRotationRequestV3::Intent {
                    intent: intent.clone(),
                    witness_challenge: witness_challenge.clone(),
                    witness_reads: witness_reads.clone(),
                },
                &coordinator,
            )
            .await
        {
            validate_intent_contribution(&value, &intent, intent_hash, &predecessor)?;
            intent_contributions.push(value);
        }
        if intent_contributions.len() >= usize::from(predecessor.signer_threshold) {
            break;
        }
    }
    if intent_contributions.len() < usize::from(predecessor.signer_threshold) {
        bail!("rotation intent did not reach the signer threshold");
    }
    let authorization_shares = intent_contributions
        .iter()
        .map(|contribution| -> Result<_> {
            Ok(coordinator.open(
                &contribution.encrypted_authorization_share,
                &gp_wire::rotation_intent_share_context_v3(
                    &context,
                    &intent_hash,
                    contribution.signer_id,
                )?,
            )?)
        })
        .collect::<Result<Vec<_>>>()?;
    let authorization_key = recover_secret(&authorization_shares, predecessor.signer_threshold)?;
    let descriptor_plaintext = aead_decrypt(
        &descriptor_key_v3(
            authorization_key.as_slice().try_into()?,
            &predecessor.config_ref,
        )?,
        &predecessor.encrypted_recovery_descriptor,
        &gp_wire::descriptor_context_v3(&predecessor.config_ref)?,
    )?;
    let descriptor: RecoveryDescriptorV3 = serde_json::from_slice(&descriptor_plaintext)?;
    validate_descriptor(&descriptor, &predecessor)?;
    let removed_route = descriptor
        .guardians
        .iter()
        .find(|route| route.guardian_index == options.remove_guardian)
        .cloned()
        .context("removed guardian is absent from the active private roster")?;
    owner
        .guardian_targets
        .get(&options.remove_guardian)
        .context("owner control lacks the removed guardian target")?;
    let replacement_info = node_info_v3(&client, &options.replacement_target, "guardian").await?;
    let replacement_domain = sha256(replacement_info.node_id.as_bytes());
    if descriptor.guardians.iter().any(|route| {
        route.operator_domain_commitment == replacement_domain
            || route.session_recipient_key == replacement_info.transport_public_key
    }) || owner.guardian_targets.values().any(|target| {
        target.trim_end_matches('/') == options.replacement_target.trim_end_matches('/')
    }) {
        bail!("replacement guardian must be a new operator and transport endpoint");
    }
    let added_guardian = descriptor
        .guardians
        .iter()
        .map(|route| route.guardian_index)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .context("guardian index overflow")?;
    let successor_ref = ConfigRef {
        guardian_epoch: predecessor.config_ref.guardian_epoch.saturating_add(1),
        epoch_binding: random_id(),
        ..predecessor.config_ref
    };
    let replacement_signing_seed = Zeroizing::new(random_id());
    let replacement_route = GuardianRouteV3 {
        guardian_index: added_guardian,
        opaque_slot_id: random_id(),
        mailbox: new_mailbox(&card.relay_bases[0]),
        guardian_public_key: verifying_key_bytes(&signing_key(*replacement_signing_seed)),
        session_recipient_key: replacement_info.transport_public_key.clone(),
        operator_domain_commitment: replacement_domain,
    };
    let mut new_roster = Vec::with_capacity(descriptor.guardians.len());
    for route in descriptor
        .guardians
        .iter()
        .filter(|route| route.guardian_index != options.remove_guardian)
    {
        let target = owner
            .guardian_targets
            .get(&route.guardian_index)
            .context("owner control lacks an unchanged guardian target")?;
        let fresh = GuardianRouteV3 {
            opaque_slot_id: random_id(),
            mailbox: new_mailbox(&card.relay_bases[0]),
            ..route.clone()
        };
        provision_aliases(
            &client,
            &fresh,
            &route.mailbox,
            target,
            &card.relay_bases,
            &options.relay_token,
            &options.admin_token,
        )
        .await?;
        new_roster.push(fresh);
    }
    new_roster.push(replacement_route.clone());
    new_roster.sort_by_key(|route| route.guardian_index);
    let successor_count = u16::try_from(new_roster.len())?;
    let plan = RotationPlan {
        context: context.clone(),
        intent_hash,
        predecessor: predecessor.config_ref,
        successor: successor_ref,
        old_roster: descriptor.guardians.clone(),
        new_roster: new_roster.clone(),
        old_roster_commitment: sha256(&gp_wire::guardian_roster_v3(&descriptor.guardians)?),
        new_roster_commitment: sha256(&gp_wire::guardian_roster_v3(&new_roster)?),
        old_guardian_threshold: predecessor.guardian_threshold,
        new_guardian_threshold: predecessor.guardian_threshold,
        data_shards: descriptor.data_shards,
        total_shards: successor_count,
        dpss_suite: predecessor.dpss_suite,
        dpss_session_id: random_id(),
        dpss_qualified_set_commitment: sha256(&gp_wire::guardian_roster_v3(&new_roster)?),
        minimum_delay_secs: predecessor.minimum_recovery_delay,
        preparation_deadline: context.expiry.saturating_sub(600),
        drain_deadline: context.expiry,
    };
    let plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
    let candidate_provision = GuardianRotationProvisionV3 {
        mailbox: mailbox_id(&replacement_route.mailbox)?,
        signing_seed: *replacement_signing_seed,
        signing_public_key: replacement_route.guardian_public_key,
        recovery_card: card.clone(),
        predecessor_capsule: predecessor.clone(),
        signer_public_keys: BTreeMap::new(),
        epoch_store: gp_storage::GuardianEpochStore::new_candidate(
            predecessor.config_ref,
            predecessor.capsule_hash,
        ),
    };
    provision_candidate(
        &client,
        &options.replacement_target,
        &replacement_info,
        &candidate_provision,
        &options.admin_token,
    )
    .await?;
    for relay in &card.relay_bases {
        register_route(
            &client,
            relay,
            &options.relay_token,
            &replacement_route.mailbox,
            &options.replacement_target,
        )
        .await?;
    }

    let begin_votes =
        collect_signer_begin_votes(&client, &card, &coordinator, &plan, &predecessor).await?;
    let begin = BeginRotationCertificate {
        context: context.clone(),
        intent_hash,
        plan_hash,
        old_roster_commitment: plan.old_roster_commitment,
        new_roster_commitment: plan.new_roster_commitment,
        not_before_wall: context.issued_at.saturating_add(plan.minimum_delay_secs),
        votes: begin_votes,
    };
    validate_begin_rotation_certificate_v3(&begin, &plan, &predecessor, wall_now()?)?;
    // Only successor guardians are availability-critical. The guardian being
    // replaced may already be lost or malicious, which is the reason for the
    // rotation in the first place.
    let actor_mailboxes = rotation_actor_mailboxes(&new_roster);
    for mailbox in &actor_mailboxes {
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::Begin {
                plan: plan.clone(),
                certificate: begin.clone(),
            },
            &coordinator,
        )
        .await?;
        if !matches!(response, GuardianRotationResponseV3::BeginAccepted { .. }) {
            bail!("guardian returned the wrong Begin response");
        }
    }
    // An online removed guardian gets the same authenticated transition so it
    // can later enter DRAINING and erase on schedule. Its availability is not
    // allowed to gate replacement.
    let _ = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
        &client,
        &removed_route.mailbox,
        &card.relay_bases,
        &GuardianRotationRequestV3::Begin {
            plan: plan.clone(),
            certificate: begin.clone(),
        },
        &coordinator,
    )
    .await;
    write_private_json(
        Path::new(&options.rotation_control_path),
        &RotationControlFileV3 {
            protocol_version: gp_types::PROTOCOL_VERSION_V3,
            recovery_card: card.clone(),
            predecessor_capsule: predecessor.clone(),
            plan: plan.clone(),
            owner_cancel_public_key: owner.owner_cancel_public_key,
        },
    )?;
    tokio::time::sleep(Duration::from_secs(
        plan.minimum_delay_secs.saturating_add(1),
    ))
    .await;
    let release_votes =
        collect_signer_release_votes(&client, &card, &coordinator, &plan, &begin, &predecessor)
            .await?;
    let begin_hash = sha256(&gp_wire::begin_rotation_certificate(&begin)?);
    let release = RotationReleaseCertificate {
        context: context.clone(),
        plan_hash,
        begin_certificate_hash: begin_hash,
        votes: release_votes,
    };
    validate_rotation_release_certificate_v3(&release, &begin, &plan, &predecessor, wall_now()?)?;
    let release_hash = sha256(&gp_wire::rotation_release_certificate(&release)?);
    let helper_ids = descriptor
        .guardians
        .iter()
        .map(|route| route.guardian_index)
        .filter(|id| *id != options.remove_guardian)
        .take(usize::from(predecessor.guardian_threshold))
        .collect::<Vec<_>>();
    if helper_ids.len() < usize::from(predecessor.guardian_threshold) {
        bail!("not enough old guardians remain for FROST RTS");
    }
    let mut repair1 = BTreeMap::<u16, Vec<gp_types::SealedMessage>>::new();
    let mut fragment_contributions = Vec::new();
    for helper_id in &helper_ids {
        let route = route_by_id(&descriptor.guardians, *helper_id)?;
        let grant = old_grant(
            &plan,
            release_hash,
            route,
            authorization_key.as_slice().try_into()?,
        )?;
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::RepairRound1 {
                plan: plan.clone(),
                begin_certificate: begin.clone(),
                release_certificate: release.clone(),
                unlock_grant: grant,
                helper_ids: helper_ids.clone(),
                replacement_id: added_guardian,
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::DpssDeliveries {
            deliveries,
            fragment,
        } = response
        else {
            bail!("guardian returned the wrong RTS round-1 response")
        };
        let fragment = fragment.context("RTS helper omitted its ciphertext fragment")?;
        validate_fragment_contribution(&fragment, route, &descriptor, &plan, release_hash)?;
        fragment_contributions.push(fragment);
        distribute(&mut repair1, deliveries, &descriptor.guardians)?;
    }
    let mut sigmas = Vec::new();
    for helper_id in &helper_ids {
        let route = route_by_id(&descriptor.guardians, *helper_id)?;
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::RepairRound2 {
                plan: plan.clone(),
                incoming: repair1.remove(helper_id).unwrap_or_default(),
                replacement_id: added_guardian,
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::DpssDeliveries { deliveries, .. } = response else {
            bail!("guardian returned the wrong RTS round-2 response")
        };
        sigmas.extend(
            deliveries
                .into_iter()
                .map(|delivery| delivery.sealed_message),
        );
    }
    let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
        &client,
        &replacement_route.mailbox,
        &card.relay_bases,
        &GuardianRotationRequestV3::RepairFinalize {
            plan: plan.clone(),
            incoming: sigmas,
            old_public_package: descriptor.dpss_public_package.clone(),
        },
        &coordinator,
    )
    .await?;
    let GuardianRotationResponseV3::RepairStored {
        expanded_public_package,
        ..
    } = response
    else {
        bail!("replacement guardian did not finalize RTS repair")
    };

    let mut refresh1 = BTreeMap::<u16, Vec<gp_types::SealedMessage>>::new();
    for route in &new_roster {
        let old_route = descriptor
            .guardians
            .iter()
            .find(|old| old.guardian_index == route.guardian_index);
        let (begin_certificate, release_certificate, old_share_grant) = if let Some(old) = old_route
        {
            (
                Some(begin.clone()),
                Some(release.clone()),
                Some(old_grant(
                    &plan,
                    release_hash,
                    old,
                    authorization_key.as_slice().try_into()?,
                )?),
            )
        } else {
            (None, None, None)
        };
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::RefreshRound1 {
                plan: plan.clone(),
                begin_certificate,
                release_certificate,
                old_share_grant,
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::DpssDeliveries { deliveries, .. } = response else {
            bail!("guardian returned the wrong refresh round-1 response")
        };
        distribute(&mut refresh1, deliveries, &new_roster)?;
    }
    let mut refresh2 = BTreeMap::<u16, Vec<gp_types::SealedMessage>>::new();
    for route in &new_roster {
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::RefreshRound2 {
                plan: plan.clone(),
                incoming: refresh1.remove(&route.guardian_index).unwrap_or_default(),
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::DpssDeliveries { deliveries, .. } = response else {
            bail!("guardian returned the wrong refresh round-2 response")
        };
        distribute(&mut refresh2, deliveries, &new_roster)?;
    }
    let mut public_package = None;
    let mut dpss_result_commitment = None;
    for route in &new_roster {
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::RefreshFinalize {
                plan: plan.clone(),
                incoming: refresh2.remove(&route.guardian_index).unwrap_or_default(),
                old_public_package: expanded_public_package.clone(),
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::RefreshFinalized {
            public_package: candidate_public,
            dpss_result_commitment: candidate_commitment,
            ..
        } = response
        else {
            bail!("guardian did not finalize refresh")
        };
        if public_package
            .as_ref()
            .is_some_and(|value| value != &candidate_public)
            || dpss_result_commitment.is_some_and(|value| value != candidate_commitment)
        {
            bail!("successor guardians disagreed on the FROST refresh result");
        }
        public_package = Some(candidate_public);
        dpss_result_commitment = Some(candidate_commitment);
    }
    let public_package = public_package.context("refresh produced no public package")?;
    let dpss_result_commitment =
        dpss_result_commitment.context("refresh produced no commitment")?;
    let ciphertext = erasure_reconstruct(
        &fragment_contributions
            .iter()
            .map(|fragment| {
                (
                    fragment.fragment_index,
                    fragment.ciphertext_fragment.clone(),
                )
            })
            .collect::<Vec<_>>(),
        descriptor.data_shards,
        descriptor.total_shards,
        usize::try_from(descriptor.ciphertext_len)?,
    )?;
    let successor_fragments =
        gp_crypto::erasure_encode(&ciphertext, plan.new_guardian_threshold, plan.total_shards)?;
    let fragment_commitment = commit_ciphertext_fragments(
        &successor_ref.config_id,
        successor_ref.payload_generation,
        &successor_fragments,
    )?;
    if fragment_commitment.root != predecessor.ciphertext_fragment_root {
        bail!("reconstructed ciphertext does not match the predecessor fragment commitment");
    }
    let mut leaves = Vec::new();
    for (offset, route) in new_roster.iter().enumerate() {
        let grant = new_grant(
            &plan,
            release_hash,
            route,
            authorization_key.as_slice().try_into()?,
        )?;
        let policy = GuardianPolicyV3 {
            config_ref: successor_ref,
            epoch_state: GuardianEpochState::Prepared,
            signer_set_commitment: predecessor.signer_set_commitment,
            signer_count: predecessor.signer_count,
            signer_threshold: predecessor.signer_threshold,
            owner_cancel_public_key: predecessor.owner_cancel_public_key,
            minimum_recovery_delay: predecessor.minimum_recovery_delay,
            guardian_material_root: [0; 32],
            dpss_suite: predecessor.dpss_suite,
            dpss_public_commitment: dpss_result_commitment,
            predecessor_capsule_hash: predecessor.capsule_hash,
            activation_qc_hash: None,
            drain_deadline: None,
        };
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::StageMaterial {
                plan: plan.clone(),
                wrap_grant: grant,
                fragment_index: u16::try_from(offset + 1)?,
                ciphertext_fragment: successor_fragments[offset].clone(),
                ciphertext_fragment_proof: fragment_commitment.proofs[offset].clone(),
                policy,
                opaque_slot_id: route.opaque_slot_id,
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::RefreshMaterialStaged {
            leaf,
            public_package: candidate_public,
            dpss_result_commitment: candidate_commitment,
        } = response
        else {
            bail!("guardian did not stage refreshed material")
        };
        if candidate_public != public_package || candidate_commitment != dpss_result_commitment {
            bail!("staged guardian material changed the agreed refresh result");
        }
        leaves.push(leaf);
    }
    let leaf_hashes = leaves
        .iter()
        .map(|leaf| Ok(sha256(&gp_wire::prepared_record_leaf_v3(leaf)?)))
        .collect::<Result<Vec<_>>>()?;
    let (material_root, proofs) = merkle_commit(&leaf_hashes)?;
    let mut prepared_acks = Vec::new();
    for (offset, route) in new_roster.iter().enumerate() {
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::PrepareCommit {
                plan: plan.clone(),
                guardian_material_root: material_root,
                merkle_path_proof: proofs[offset].clone(),
                dpss_result_commitment,
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::Prepared(ack) = response else {
            bail!("guardian did not durably prepare its successor record")
        };
        prepared_acks.push(ack);
    }
    let mut handoff_acks = Vec::new();
    for helper_id in &helper_ids {
        let route = route_by_id(&descriptor.guardians, *helper_id)?;
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::HandoffComplete {
                plan: plan.clone(),
                dpss_result_commitment,
            },
            &coordinator,
        )
        .await?;
        let GuardianRotationResponseV3::Handoff(ack) = response else {
            bail!("old guardian did not acknowledge handoff")
        };
        handoff_acks.push(ack);
    }
    let successor_descriptor = RecoveryDescriptorV3 {
        config_ref: successor_ref,
        guardians: new_roster.clone(),
        guardian_material_root: material_root,
        data_shards: plan.new_guardian_threshold,
        total_shards: plan.total_shards,
        ciphertext_len: descriptor.ciphertext_len,
        payload_nonce: descriptor.payload_nonce,
        dpss_suite: plan.dpss_suite,
        dpss_public_package: public_package,
        dpss_public_commitment: dpss_result_commitment,
    };
    let encrypted_descriptor = aead_encrypt(
        &descriptor_key_v3(authorization_key.as_slice().try_into()?, &successor_ref)?,
        random_nonce(),
        &serde_json::to_vec(&successor_descriptor)?,
        &gp_wire::descriptor_context_v3(&successor_ref)?,
    )?;
    let ready = RotationReadyCertificate {
        context: context.clone(),
        plan_hash,
        successor: successor_ref,
        dpss_result_commitment,
        guardian_material_root: material_root,
        encrypted_descriptor_hash: gp_crypto::hash_aead(&encrypted_descriptor),
        prepared_acks,
        old_handoff_acks: handoff_acks,
    };
    validate_rotation_ready_certificate_v3(&ready, &plan, &predecessor, wall_now()?)?;
    let mut successor = ConfigCapsuleV3 {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_ref: successor_ref,
        capsule_hash: [0; 32],
        predecessor_capsule_hash: predecessor.capsule_hash,
        signer_count: predecessor.signer_count,
        signer_threshold: predecessor.signer_threshold,
        guardian_count: successor_count,
        guardian_threshold: plan.new_guardian_threshold,
        minimum_recovery_delay: predecessor.minimum_recovery_delay,
        max_request_lifetime: predecessor.max_request_lifetime,
        signer_set_commitment: predecessor.signer_set_commitment,
        owner_cancel_public_key: predecessor.owner_cancel_public_key,
        dpss_suite: predecessor.dpss_suite,
        dpss_public_commitment: dpss_result_commitment,
        ciphertext_fragment_root: predecessor.ciphertext_fragment_root,
        guardian_material_root: material_root,
        encrypted_recovery_descriptor: encrypted_descriptor,
        activation_certificate: None,
        activation_qc: None,
    };
    successor.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&successor)?);
    let activate_votes =
        collect_signer_activate_votes(&client, &card, &coordinator, &plan, &ready, &successor)
            .await?;
    let activation = RotationActivateCertificate {
        context: context.clone(),
        plan_hash,
        ready_certificate_hash: sha256(&gp_wire::rotation_ready_certificate(&ready)?),
        successor: successor_ref,
        successor_capsule_hash: successor.capsule_hash,
        votes: activate_votes,
    };
    let activation_hash = sha256(&gp_wire::rotation_activate_certificate(&activation)?);
    let mut witness_acks = Vec::new();
    let required_witnesses = usize::from(card.witness_fault_bound) * 2 + 1;
    for witness in &card.witnesses {
        let response = client
            .post(format!(
                "{}/v3/witness/configs/{}/activate",
                witness.mailbox.trim_end_matches('/'),
                hex::encode(card.config_id)
            ))
            .json(&WitnessActivationRequest {
                capsule: successor.clone(),
                activation_certificate: activation.clone(),
            })
            .send()
            .await;
        if let Ok(response) = response
            && let Ok(response) = response.error_for_status()
            && let Ok(ack) = response.json::<gp_types::WitnessActivationAck>().await
            && validate_witness_activation_ack(
                &ack,
                witness,
                &context,
                plan_hash,
                activation_hash,
                &predecessor,
                &successor,
            )
            .is_ok()
        {
            witness_acks.push(ack);
        }
        if witness_acks.len() >= required_witnesses {
            break;
        }
    }
    if witness_acks.len() < required_witnesses {
        bail!("witness activation quorum was not reached");
    }
    let qc = gp_types::EpochActivationQc {
        protocol_version: gp_types::PROTOCOL_VERSION_V3,
        config_id: card.config_id,
        rotation_id: context.rotation_id,
        predecessor_epoch: predecessor.config_ref.guardian_epoch,
        predecessor_capsule_hash: predecessor.capsule_hash,
        successor_epoch: successor_ref.guardian_epoch,
        successor_capsule_hash: successor.capsule_hash,
        activation_certificate_hash: activation_hash,
        witness_fault_bound: card.witness_fault_bound,
        witness_acks,
    };
    gp_wire::epoch_activation_qc(&qc)?;
    successor.activation_certificate = Some(activation);
    successor.activation_qc = Some(qc.clone());
    validate_activated_capsule_v3(&card, &successor)?;
    let acknowledged_witnesses = qc
        .witness_acks
        .iter()
        .map(|ack| ack.witness_id)
        .collect::<BTreeSet<_>>();
    for witness in card
        .witnesses
        .iter()
        .filter(|witness| acknowledged_witnesses.contains(&witness.witness_id))
    {
        let response = client
            .post(format!(
                "{}/v3/witness/configs/{}/finalize",
                witness.mailbox.trim_end_matches('/'),
                hex::encode(card.config_id)
            ))
            .json(&WitnessFinalizeRequest {
                activation_qc: qc.clone(),
            })
            .send()
            .await?;
        ensure_success(response, "finalize witness activation QC").await?;
    }
    let drain_deadline = wall_now()?.saturating_add(predecessor.max_request_lifetime);
    for mailbox in &actor_mailboxes {
        let response = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            mailbox,
            &card.relay_bases,
            &GuardianRotationRequestV3::Activate {
                plan: plan.clone(),
                activated_capsule: successor.clone(),
                drain_deadline,
            },
            &coordinator,
        )
        .await?;
        if !matches!(response, GuardianRotationResponseV3::Activated { .. }) {
            bail!("guardian did not atomically activate the witness-certified epoch");
        }
    }
    let _ = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
        &client,
        &removed_route.mailbox,
        &card.relay_bases,
        &GuardianRotationRequestV3::Activate {
            plan: plan.clone(),
            activated_capsule: successor.clone(),
            drain_deadline,
        },
        &coordinator,
    )
    .await;
    owner.guardian_targets.remove(&options.remove_guardian);
    owner.guardian_targets.insert(
        added_guardian,
        options.replacement_target.trim_end_matches('/').to_owned(),
    );
    owner.config_ref = successor_ref;
    write_private_json(Path::new(&options.owner_control_path), &owner)?;
    owner.owner_cancel_signing_seed.zeroize();
    Ok(RotateV3Result {
        config_id: hex::encode(card.config_id),
        predecessor_epoch: predecessor.config_ref.guardian_epoch,
        successor_epoch: successor_ref.guardian_epoch,
        removed_guardian: removed_route.guardian_index,
        added_guardian,
        prepared_guardians: new_roster.len(),
        witness_acknowledgements: qc.witness_acks.len(),
        plaintext_decryptions: 0,
    })
}

pub async fn cancel_rotation_v3(
    options: CancelRotationV3Options,
) -> Result<CancelRotationV3Result> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let control: RotationControlFileV3 =
        serde_json::from_slice(&fs::read(&options.rotation_control_path)?)?;
    let mut owner: OwnerControlFileV3 =
        serde_json::from_slice(&fs::read(&options.owner_control_path)?)?;
    if control.protocol_version != gp_types::PROTOCOL_VERSION_V3
        || owner.protocol_version != gp_types::PROTOCOL_VERSION_V3
        || control.predecessor_capsule.config_ref != owner.config_ref
        || control.plan.predecessor != owner.config_ref
        || control.plan.context.config_ref != owner.config_ref
        || control.owner_cancel_public_key != owner.owner_cancel_public_key
        || control.recovery_card.config_id != owner.config_ref.config_id
        || control.recovery_card.relay_bases != owner.relay_bases
        || verifying_key_bytes(&signing_key(owner.owner_cancel_signing_seed))
            != owner.owner_cancel_public_key
    {
        bail!("rotation-control and owner-control files do not describe the same active epoch");
    }
    validate_activated_capsule_v3(&control.recovery_card, &control.predecessor_capsule)?;
    let plan_hash = crate::rotation_protocol::validate_rotation_plan_v3(
        &control.plan,
        &control.predecessor_capsule,
        wall_now()?,
    )?;
    let recipient = RecipientKeyPair::from_seed(random_id());
    let mut certificate = OwnerRotationCancelCertificate {
        context: control.plan.context.clone(),
        plan_hash,
        reason_code: 1,
        cancel_response_recipient_key: recipient.public_key().to_vec(),
        owner_cancel_public_key: owner.owner_cancel_public_key,
        owner_signature: vec![],
    };
    certificate.owner_signature = sign(
        &signing_key(owner.owner_cancel_signing_seed),
        &gp_wire::owner_rotation_cancel_certificate(&certificate)?,
    );
    let cancel_hash = sha256(&gp_wire::owner_rotation_cancel_certificate(&certificate)?);

    let required_witness_acks = usize::from(control.recovery_card.witness_fault_bound)
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .context("witness cancellation threshold overflow")?;
    let mut witness_ack_ids = BTreeSet::new();
    let mut witness_cancel_acks = Vec::new();
    for witness in &control.recovery_card.witnesses {
        let response = client
            .post(format!(
                "{}/v3/witness/configs/{}/cancel-rotation",
                witness.mailbox.trim_end_matches('/'),
                hex::encode(control.recovery_card.config_id)
            ))
            .json(&WitnessRotationCancelRequest {
                certificate: certificate.clone(),
            })
            .send()
            .await;
        if let Ok(response) = response
            && let Ok(response) = response.error_for_status()
            && let Ok(ack) = response.json::<gp_types::WitnessRotationCancelAck>().await
            && validate_witness_rotation_cancel_ack(&ack, witness, &control.plan, cancel_hash)
                .is_ok()
            && witness_ack_ids.insert(ack.witness_id)
        {
            witness_cancel_acks.push(ack);
        }
        if witness_ack_ids.len() >= required_witness_acks {
            break;
        }
    }
    if witness_ack_ids.len() < required_witness_acks {
        owner.owner_cancel_signing_seed.zeroize();
        bail!("owner cancellation did not reach the 2f+1 witness veto quorum");
    }
    validate_owner_rotation_cancel_witness_quorum_v3(
        &certificate,
        &witness_cancel_acks,
        &control.recovery_card,
        &control.plan,
        &control.predecessor_capsule,
        wall_now()?,
    )?;

    let mut old_ack_ids = BTreeSet::new();
    for route in &control.plan.old_roster {
        match send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &control.recovery_card.relay_bases,
            &GuardianRotationRequestV3::Cancel {
                plan: control.plan.clone(),
                certificate: certificate.clone(),
            },
            &recipient,
        )
        .await
        {
            Ok(GuardianRotationResponseV3::Cancelled(ack)) => {
                match validate_owner_rotation_cancel_ack(&ack, route, &control.plan, cancel_hash) {
                    Ok(()) => {
                        old_ack_ids.insert(ack.guardian_index);
                    }
                    Err(error) => eprintln!(
                        "ignored invalid owner-cancel ack from old guardian {}: {error:#}",
                        route.guardian_index
                    ),
                }
            }
            Ok(_) => eprintln!(
                "old guardian {} returned the wrong owner-cancel response",
                route.guardian_index
            ),
            Err(error) => eprintln!(
                "old guardian {} did not acknowledge owner cancellation: {error:#}",
                route.guardian_index
            ),
        }
    }
    let required_old_acks = control
        .plan
        .old_roster
        .len()
        .checked_sub(usize::from(control.plan.old_guardian_threshold))
        .and_then(|value| value.checked_add(1))
        .context("old cancellation threshold overflow")?;
    if old_ack_ids.len() < required_old_acks {
        owner.owner_cancel_signing_seed.zeroize();
        bail!("owner cancellation did not leave fewer than the old handoff threshold");
    }

    let old_ids = control
        .plan
        .old_roster
        .iter()
        .map(|route| route.guardian_index)
        .collect::<BTreeSet<_>>();
    for route in control
        .plan
        .new_roster
        .iter()
        .filter(|route| !old_ids.contains(&route.guardian_index))
    {
        let _ = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
            &client,
            &route.mailbox,
            &control.recovery_card.relay_bases,
            &GuardianRotationRequestV3::Cancel {
                plan: control.plan.clone(),
                certificate: certificate.clone(),
            },
            &recipient,
        )
        .await;
    }

    let abort_votes = collect_signer_abort_votes(
        &client,
        &control.recovery_card,
        &recipient,
        &control.plan,
        &control.predecessor_capsule,
        RotationState::DelayPending,
        1,
    )
    .await;
    if abort_votes.len() >= usize::from(control.predecessor_capsule.signer_threshold) {
        let abort = AbortRotationCertificate {
            context: control.plan.context.clone(),
            plan_hash,
            state_at_abort: RotationState::DelayPending,
            reason_code: 1,
            votes: abort_votes,
        };
        if validate_abort_rotation_certificate_v3(
            &abort,
            &control.plan,
            &control.predecessor_capsule,
            wall_now()?,
        )
        .is_ok()
        {
            let guardian_mailboxes = control
                .plan
                .old_roster
                .iter()
                .chain(control.plan.new_roster.iter())
                .map(|route| route.mailbox.clone())
                .collect::<BTreeSet<_>>();
            for mailbox in guardian_mailboxes {
                let _ = send_rotation_mailbox::<_, GuardianRotationResponseV3>(
                    &client,
                    &mailbox,
                    &control.recovery_card.relay_bases,
                    &GuardianRotationRequestV3::Abort {
                        plan: control.plan.clone(),
                        certificate: abort.clone(),
                    },
                    &recipient,
                )
                .await;
            }
        }
    }
    let mut signer_cancel_ids = BTreeSet::new();
    for mailbox in &control.recovery_card.signer_mailboxes {
        if let Ok(SignerRotationResponseV3::OwnerCancelFinalized) =
            send_rotation_mailbox::<_, SignerRotationResponseV3>(
                &client,
                mailbox,
                &control.recovery_card.relay_bases,
                &SignerRotationRequestV3::FinalizeOwnerCancel {
                    plan: control.plan.clone(),
                    certificate: certificate.clone(),
                    witness_acks: witness_cancel_acks.clone(),
                    response_recipient_key: recipient.public_key().to_vec(),
                },
                &recipient,
            )
            .await
        {
            signer_cancel_ids.insert(mailbox);
        }
    }
    owner.owner_cancel_signing_seed.zeroize();
    Ok(CancelRotationV3Result {
        rotation_id: hex::encode(control.plan.context.rotation_id),
        witness_acknowledgements: witness_ack_ids.len(),
        required_witness_acknowledgements: required_witness_acks,
        old_guardian_acknowledgements: old_ack_ids.len(),
        required_old_guardian_acknowledgements: required_old_acks,
        signer_cancel_finalizations: signer_cancel_ids.len(),
        permanently_cancelled: true,
    })
}

fn validate_descriptor(descriptor: &RecoveryDescriptorV3, capsule: &ConfigCapsuleV3) -> Result<()> {
    if descriptor.config_ref != capsule.config_ref
        || descriptor.guardian_material_root != capsule.guardian_material_root
        || descriptor.data_shards != capsule.guardian_threshold
        || descriptor.total_shards != capsule.guardian_count
        || descriptor.guardians.len() != usize::from(capsule.guardian_count)
        || descriptor.dpss_public_commitment != capsule.dpss_public_commitment
        || gp_crypto::frost_public_package_digest(&descriptor.dpss_public_package)?
            != capsule.dpss_public_commitment
    {
        bail!("active descriptor does not match the witness-authenticated capsule");
    }
    Ok(())
}

fn validate_intent_contribution(
    contribution: &gp_types::SignerRotationIntentContribution,
    intent: &RotationIntent,
    intent_hash: gp_types::Id32,
    capsule: &ConfigCapsuleV3,
) -> Result<()> {
    if contribution.context != intent.context || contribution.intent_hash != intent_hash {
        bail!("signer intent contribution is transcript-mismatched");
    }
    merkle_verify(
        capsule.signer_set_commitment,
        sha256(&gp_wire::signer_leaf(
            contribution.signer_id,
            &contribution.signer_public_key,
        )?),
        usize::from(
            contribution
                .signer_id
                .checked_sub(1)
                .context("zero signer id")?,
        ),
        usize::from(capsule.signer_count),
        &contribution.signer_membership_proof,
    )?;
    verify(
        &contribution.signer_public_key,
        &gp_wire::signer_rotation_intent_contribution(contribution)?,
        &contribution.signer_signature,
    )?;
    Ok(())
}

async fn collect_signer_begin_votes(
    client: &reqwest::Client,
    card: &RecoveryCardV3,
    coordinator: &RecipientKeyPair,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
) -> Result<Vec<gp_types::SignerRotationBeginVote>> {
    let mut votes = Vec::new();
    let mut signer_ids = BTreeSet::new();
    for mailbox in &card.signer_mailboxes {
        if let Ok(SignerRotationResponseV3::BeginVote(vote)) = send_rotation_mailbox::<_, _>(
            client,
            mailbox,
            &card.relay_bases,
            &SignerRotationRequestV3::Begin {
                intent_hash: plan.intent_hash,
                plan: plan.clone(),
            },
            coordinator,
        )
        .await
            && validate_signer_begin_vote(&vote, plan, predecessor).is_ok()
            && signer_ids.insert(vote.signer_id)
        {
            votes.push(vote);
        }
        if votes.len() >= usize::from(predecessor.signer_threshold) {
            break;
        }
    }
    if votes.len() < usize::from(predecessor.signer_threshold) {
        bail!("signer Begin threshold was not reached");
    }
    Ok(votes)
}

async fn collect_signer_release_votes(
    client: &reqwest::Client,
    card: &RecoveryCardV3,
    coordinator: &RecipientKeyPair,
    plan: &RotationPlan,
    begin: &BeginRotationCertificate,
    predecessor: &ConfigCapsuleV3,
) -> Result<Vec<gp_types::SignerRotationReleaseVote>> {
    let mut votes = Vec::new();
    let mut signer_ids = BTreeSet::new();
    let begin_hash = sha256(&gp_wire::begin_rotation_certificate(begin)?);
    for mailbox in &card.signer_mailboxes {
        if let Ok(SignerRotationResponseV3::ReleaseVote(vote)) = send_rotation_mailbox::<_, _>(
            client,
            mailbox,
            &card.relay_bases,
            &SignerRotationRequestV3::Release {
                plan: plan.clone(),
                begin_certificate: begin.clone(),
            },
            coordinator,
        )
        .await
            && validate_signer_release_vote(&vote, plan, begin_hash, predecessor).is_ok()
            && signer_ids.insert(vote.signer_id)
        {
            votes.push(vote);
        }
        if votes.len() >= usize::from(predecessor.signer_threshold) {
            break;
        }
    }
    if votes.len() < usize::from(predecessor.signer_threshold) {
        bail!("signer Release threshold was not reached");
    }
    Ok(votes)
}

async fn collect_signer_activate_votes(
    client: &reqwest::Client,
    card: &RecoveryCardV3,
    coordinator: &RecipientKeyPair,
    plan: &RotationPlan,
    ready: &RotationReadyCertificate,
    successor: &ConfigCapsuleV3,
) -> Result<Vec<gp_types::SignerRotationActivateVote>> {
    let mut votes = Vec::new();
    let mut signer_ids = BTreeSet::new();
    let ready_hash = sha256(&gp_wire::rotation_ready_certificate(ready)?);
    for mailbox in &card.signer_mailboxes {
        if let Ok(SignerRotationResponseV3::ActivateVote(vote)) = send_rotation_mailbox::<_, _>(
            client,
            mailbox,
            &card.relay_bases,
            &SignerRotationRequestV3::Activate {
                plan: plan.clone(),
                ready_certificate: ready.clone(),
                successor_capsule: Box::new(successor.clone()),
            },
            coordinator,
        )
        .await
            && validate_signer_activate_vote(&vote, plan, ready_hash, successor).is_ok()
            && signer_ids.insert(vote.signer_id)
        {
            votes.push(vote);
        }
        if votes.len() >= usize::from(successor.signer_threshold) {
            break;
        }
    }
    if votes.len() < usize::from(successor.signer_threshold) {
        bail!("signer Activate threshold was not reached");
    }
    Ok(votes)
}

async fn collect_signer_abort_votes(
    client: &reqwest::Client,
    card: &RecoveryCardV3,
    coordinator: &RecipientKeyPair,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    state_at_abort: RotationState,
    reason_code: u16,
) -> Vec<gp_types::SignerRotationAbortVote> {
    let mut votes = Vec::new();
    let mut signer_ids = BTreeSet::new();
    for mailbox in &card.signer_mailboxes {
        if let Ok(SignerRotationResponseV3::AbortVote(vote)) =
            send_rotation_mailbox::<_, SignerRotationResponseV3>(
                client,
                mailbox,
                &card.relay_bases,
                &SignerRotationRequestV3::Abort {
                    plan: plan.clone(),
                    state_at_abort,
                    reason_code,
                    response_recipient_key: coordinator.public_key().to_vec(),
                },
                coordinator,
            )
            .await
            && validate_signer_abort_vote(&vote, plan, predecessor, state_at_abort, reason_code)
                .is_ok()
            && signer_ids.insert(vote.signer_id)
        {
            votes.push(vote);
        }
        if votes.len() >= usize::from(predecessor.signer_threshold) {
            break;
        }
    }
    votes
}

fn validate_signer_membership(
    signer_id: u16,
    public_key: &[u8; 32],
    proof: &[u8],
    capsule: &ConfigCapsuleV3,
) -> Result<()> {
    let position = signer_id.checked_sub(1).context("zero signer id")?;
    if signer_id > capsule.signer_count {
        bail!("signer id is outside the committed signer set");
    }
    merkle_verify(
        capsule.signer_set_commitment,
        sha256(&gp_wire::signer_leaf(signer_id, public_key)?),
        usize::from(position),
        usize::from(capsule.signer_count),
        proof,
    )?;
    Ok(())
}

fn validate_signer_begin_vote(
    vote: &gp_types::SignerRotationBeginVote,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
) -> Result<()> {
    let plan_hash = sha256(&gp_wire::rotation_plan(plan)?);
    if vote.context != plan.context
        || vote.intent_hash != plan.intent_hash
        || vote.plan_hash != plan_hash
        || vote.old_roster_commitment != plan.old_roster_commitment
        || vote.new_roster_commitment != plan.new_roster_commitment
    {
        bail!("signer Begin vote does not bind the exact plan");
    }
    validate_signer_membership(
        vote.signer_id,
        &vote.signer_public_key,
        &vote.signer_membership_proof,
        predecessor,
    )?;
    verify(
        &vote.signer_public_key,
        &gp_wire::signer_rotation_begin_vote(vote)?,
        &vote.signer_signature,
    )?;
    Ok(())
}

fn validate_signer_release_vote(
    vote: &gp_types::SignerRotationReleaseVote,
    plan: &RotationPlan,
    begin_hash: gp_types::Id32,
    predecessor: &ConfigCapsuleV3,
) -> Result<()> {
    let plan_hash = sha256(&gp_wire::rotation_plan(plan)?);
    if vote.context != plan.context
        || vote.plan_hash != plan_hash
        || vote.begin_certificate_hash != begin_hash
    {
        bail!("signer Release vote does not bind the exact Begin");
    }
    validate_signer_membership(
        vote.signer_id,
        &vote.signer_public_key,
        &vote.signer_membership_proof,
        predecessor,
    )?;
    verify(
        &vote.signer_public_key,
        &gp_wire::signer_rotation_release_vote(vote)?,
        &vote.signer_signature,
    )?;
    Ok(())
}

fn validate_signer_activate_vote(
    vote: &gp_types::SignerRotationActivateVote,
    plan: &RotationPlan,
    ready_hash: gp_types::Id32,
    successor: &ConfigCapsuleV3,
) -> Result<()> {
    let plan_hash = sha256(&gp_wire::rotation_plan(plan)?);
    if vote.context != plan.context
        || vote.plan_hash != plan_hash
        || vote.ready_certificate_hash != ready_hash
        || vote.successor_capsule_hash != successor.capsule_hash
    {
        bail!("signer Activate vote does not bind the exact successor");
    }
    validate_signer_membership(
        vote.signer_id,
        &vote.signer_public_key,
        &vote.signer_membership_proof,
        successor,
    )?;
    verify(
        &vote.signer_public_key,
        &gp_wire::signer_rotation_activate_vote(vote)?,
        &vote.signer_signature,
    )?;
    Ok(())
}

fn validate_signer_abort_vote(
    vote: &gp_types::SignerRotationAbortVote,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    state_at_abort: RotationState,
    reason_code: u16,
) -> Result<()> {
    let plan_hash = sha256(&gp_wire::rotation_plan(plan)?);
    if vote.context != plan.context
        || vote.plan_hash != plan_hash
        || vote.state_at_abort != state_at_abort
        || vote.reason_code != reason_code
    {
        bail!("signer Abort vote does not bind the exact plan and reason");
    }
    validate_signer_membership(
        vote.signer_id,
        &vote.signer_public_key,
        &vote.signer_membership_proof,
        predecessor,
    )?;
    verify(
        &vote.signer_public_key,
        &gp_wire::signer_rotation_abort_vote(vote)?,
        &vote.signer_signature,
    )?;
    Ok(())
}

fn validate_owner_rotation_cancel_ack(
    ack: &gp_types::OwnerRotationCancelAck,
    route: &GuardianRouteV3,
    plan: &RotationPlan,
    cancel_hash: gp_types::Id32,
) -> Result<()> {
    if ack.context != plan.context
        || ack.plan_hash != sha256(&gp_wire::rotation_plan(plan)?)
        || ack.cancel_certificate_hash != cancel_hash
        || ack.guardian_index != route.guardian_index
    {
        bail!("owner rotation-cancel ack is plan- or guardian-mismatched");
    }
    verify(
        &route.guardian_public_key,
        &gp_wire::owner_rotation_cancel_ack(ack)?,
        &ack.guardian_signature,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_witness_activation_ack(
    ack: &gp_types::WitnessActivationAck,
    witness: &gp_types::WitnessPin,
    context: &RotationContext,
    plan_hash: gp_types::Id32,
    activation_hash: gp_types::Id32,
    predecessor: &ConfigCapsuleV3,
    successor: &ConfigCapsuleV3,
) -> Result<()> {
    if ack.context != *context
        || ack.plan_hash != plan_hash
        || ack.activation_certificate_hash != activation_hash
        || ack.witness_id != witness.witness_id
        || ack.predecessor_epoch != predecessor.config_ref.guardian_epoch
        || ack.predecessor_capsule_hash != predecessor.capsule_hash
        || ack.successor_epoch != successor.config_ref.guardian_epoch
        || ack.successor_capsule_hash != successor.capsule_hash
        || ack.witness_public_key != witness.public_key
    {
        bail!("witness activation ack does not bind the exact successor");
    }
    verify(
        &witness.public_key,
        &gp_wire::witness_activation_ack(ack)?,
        &ack.witness_signature,
    )?;
    Ok(())
}

fn validate_witness_rotation_cancel_ack(
    ack: &gp_types::WitnessRotationCancelAck,
    witness: &gp_types::WitnessPin,
    plan: &RotationPlan,
    cancel_hash: gp_types::Id32,
) -> Result<()> {
    if ack.protocol_version != gp_types::PROTOCOL_VERSION_V3
        || ack.config_id != plan.context.config_ref.config_id
        || ack.rotation_id != plan.context.rotation_id
        || ack.plan_hash != sha256(&gp_wire::rotation_plan(plan)?)
        || ack.cancel_certificate_hash != cancel_hash
        || ack.witness_id != witness.witness_id
        || ack.witness_public_key != witness.public_key
    {
        bail!("witness rotation-cancel ack is transcript-mismatched");
    }
    verify(
        &witness.public_key,
        &gp_wire::witness_rotation_cancel_ack(ack)?,
        &ack.witness_signature,
    )?;
    Ok(())
}

fn route_by_id(routes: &[GuardianRouteV3], id: u16) -> Result<&GuardianRouteV3> {
    routes
        .iter()
        .find(|route| route.guardian_index == id)
        .context("guardian route is missing")
}

fn old_grant(
    plan: &RotationPlan,
    release_hash: gp_types::Id32,
    route: &GuardianRouteV3,
    authorization_key: &[u8; 32],
) -> Result<OldShareUnlockGrant> {
    let mut grant = OldShareUnlockGrant {
        context: plan.context.clone(),
        plan_hash: sha256(&gp_wire::rotation_plan(plan)?),
        release_certificate_hash: release_hash,
        old_guardian_index: route.guardian_index,
        encrypted_unwrap_key: empty_sealed(),
        encrypted_fragment_key: empty_sealed(),
    };
    grant.encrypted_unwrap_key = seal_to_recipient(
        &route.session_recipient_key,
        random_id(),
        random_nonce(),
        &guardian_share_key_v3(authorization_key, &plan.predecessor, route.guardian_index)?,
        &gp_wire::old_share_unlock_grant_payload_context(&grant, false)?,
    )?;
    grant.encrypted_fragment_key = seal_to_recipient(
        &route.session_recipient_key,
        random_id(),
        random_nonce(),
        &guardian_fragment_key_v3(authorization_key, &plan.predecessor, route.guardian_index)?,
        &gp_wire::old_share_unlock_grant_payload_context(&grant, true)?,
    )?;
    Ok(grant)
}

fn new_grant(
    plan: &RotationPlan,
    release_hash: gp_types::Id32,
    route: &GuardianRouteV3,
    authorization_key: &[u8; 32],
) -> Result<NewShareWrapGrant> {
    let mut grant = NewShareWrapGrant {
        context: plan.context.clone(),
        plan_hash: sha256(&gp_wire::rotation_plan(plan)?),
        release_certificate_hash: release_hash,
        new_guardian_index: route.guardian_index,
        encrypted_wrap_key: empty_sealed(),
        encrypted_fragment_key: empty_sealed(),
    };
    grant.encrypted_wrap_key = seal_to_recipient(
        &route.session_recipient_key,
        random_id(),
        random_nonce(),
        &guardian_share_key_v3(authorization_key, &plan.successor, route.guardian_index)?,
        &gp_wire::new_share_wrap_grant_payload_context(&grant, false)?,
    )?;
    grant.encrypted_fragment_key = seal_to_recipient(
        &route.session_recipient_key,
        random_id(),
        random_nonce(),
        &guardian_fragment_key_v3(authorization_key, &plan.successor, route.guardian_index)?,
        &gp_wire::new_share_wrap_grant_payload_context(&grant, true)?,
    )?;
    Ok(grant)
}

fn empty_sealed() -> gp_types::SealedMessage {
    gp_types::SealedMessage {
        kem_ciphertext: vec![],
        payload: AeadCiphertext {
            nonce: [0; 24],
            ciphertext: vec![],
        },
    }
}

fn validate_fragment_contribution(
    contribution: &gp_types::CiphertextFragmentContribution,
    route: &GuardianRouteV3,
    descriptor: &RecoveryDescriptorV3,
    plan: &RotationPlan,
    release_hash: gp_types::Id32,
) -> Result<()> {
    if contribution.context != plan.context
        || contribution.plan_hash != sha256(&gp_wire::rotation_plan(plan)?)
        || contribution.release_certificate_hash != release_hash
        || contribution.old_guardian_index != route.guardian_index
        || contribution.fragment_index != contribution.prepared_record_leaf.fragment_index
        || contribution.fragment_commitment != sha256(&contribution.ciphertext_fragment)
        || contribution.prepared_record_leaf.guardian_index != route.guardian_index
        || contribution.prepared_record_leaf.opaque_slot_id != route.opaque_slot_id
    {
        bail!("ciphertext fragment contribution is not bound to the old committed record");
    }
    verify(
        &route.guardian_public_key,
        &gp_wire::ciphertext_fragment_contribution(contribution)?,
        &contribution.guardian_signature,
    )?;
    let position = descriptor
        .guardians
        .iter()
        .position(|candidate| candidate.guardian_index == route.guardian_index)
        .context("old guardian is absent from the descriptor")?;
    merkle_verify(
        descriptor.guardian_material_root,
        sha256(&gp_wire::prepared_record_leaf_v3(
            &contribution.prepared_record_leaf,
        )?),
        position,
        descriptor.guardians.len(),
        &contribution.merkle_path_proof,
    )?;
    Ok(())
}

fn distribute(
    by_recipient: &mut BTreeMap<u16, Vec<gp_types::SealedMessage>>,
    deliveries: Vec<DpssDeliveryV3>,
    routes: &[GuardianRouteV3],
) -> Result<()> {
    for delivery in deliveries {
        let recipient = routes
            .iter()
            .find(|route| route.mailbox == delivery.target_mailbox)
            .context("DPSS delivery target is outside the expected roster")?;
        by_recipient
            .entry(recipient.guardian_index)
            .or_default()
            .push(delivery.sealed_message);
    }
    Ok(())
}

fn rotation_actor_mailboxes(successors: &[GuardianRouteV3]) -> Vec<String> {
    successors
        .iter()
        .map(|route| route.mailbox.clone())
        .collect()
}

async fn provision_aliases(
    client: &reqwest::Client,
    fresh: &GuardianRouteV3,
    existing_mailbox: &str,
    target: &str,
    relays: &[String],
    relay_token: &str,
    admin_token: &str,
) -> Result<()> {
    let response = client
        .post(format!("{}/v3/aliases", target.trim_end_matches('/')))
        .bearer_auth(admin_token)
        .json(&GuardianRouteAliasV3 {
            mailbox: mailbox_id(&fresh.mailbox)?,
            existing_mailbox: mailbox_id(existing_mailbox)?,
        })
        .send()
        .await?;
    ensure_success(response, "provision fresh guardian alias").await?;
    for relay in relays {
        register_route(client, relay, relay_token, &fresh.mailbox, target).await?;
    }
    Ok(())
}

async fn provision_candidate(
    client: &reqwest::Client,
    target: &str,
    info: &NodeInfo,
    provision: &GuardianRotationProvisionV3,
    admin_token: &str,
) -> Result<()> {
    let sealed = seal_to_recipient(
        &info.transport_public_key,
        random_id(),
        random_nonce(),
        &serde_json::to_vec(provision)?,
        &gp_wire::node_provision_context(&info.node_id, "guardian-v3")?,
    )?;
    let response = client
        .post(format!("{}/v3/provision", target.trim_end_matches('/')))
        .bearer_auth(admin_token)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    ensure_success(response, "provision replacement guardian").await?;
    Ok(())
}

async fn node_info_v3(client: &reqwest::Client, target: &str, role: &str) -> Result<NodeInfo> {
    let info = client
        .get(format!("{}/v3/node-info", target.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<NodeInfo>()
        .await?;
    if info.protocol_version != gp_types::PROTOCOL_VERSION_V3 || info.role != role {
        bail!("replacement node has the wrong protocol version or role");
    }
    Ok(info)
}

fn new_mailbox(relay: &str) -> String {
    format!(
        "{}/v3/mailboxes/{}",
        relay.trim_end_matches('/'),
        hex::encode(random_id())
    )
}

async fn send_rotation_mailbox<T, R>(
    client: &reqwest::Client,
    mailbox: &str,
    relays: &[String],
    action: &T,
    recipient: &RecipientKeyPair,
) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let id = mailbox_id(mailbox)?;
    let mut candidates = Vec::new();
    if mailbox.contains("/v3/mailboxes/") {
        candidates.push(mailbox.to_owned());
    }
    for relay in relays {
        let candidate = format!("{}/v3/mailboxes/{id}", relay.trim_end_matches('/'));
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    let mut last_error = None;
    for candidate in candidates {
        match send_rotation_once(client, &candidate, action, recipient).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no v3 relay replica is configured")))
}

async fn send_rotation_once<T, R>(
    client: &reqwest::Client,
    mailbox: &str,
    action: &T,
    recipient: &RecipientKeyPair,
) -> Result<R>
where
    T: Serialize,
    R: DeserializeOwned,
{
    let key = client
        .get(format!("{}/key", mailbox.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<u8>>()
        .await?;
    let id = mailbox_id(mailbox)?;
    let sealed = seal_to_recipient(
        &key,
        random_id(),
        random_nonce(),
        &serde_json::to_vec(action)?,
        &gp_wire::mailbox_transport_context(&id, "rotation-request")?,
    )?;
    let response = client
        .post(mailbox)
        .json(&SealedMailboxBody { sealed })
        .send()
        .await?;
    let response = ensure_success(response, "protocol-v3 rotation mailbox request")
        .await?
        .json::<SealedMailboxBody>()
        .await?;
    let plaintext = recipient.open(
        &response.sealed,
        &gp_wire::mailbox_transport_context(&id, "rotation-response")?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}
