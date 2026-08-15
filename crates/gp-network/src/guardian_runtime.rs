//! Real protocol-v3 guardian actor operations.
//!
//! The HTTP layer persists the mutated entry before returning any ack or
//! outbound message. Provider secret state is encrypted under a node-local,
//! rotation-bound key before it reaches disk.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use gp_core::{RotationEvent, RotationMachine};
use gp_crypto::{
    RecipientKeyPair, SecretVec, XWING_PUBLIC_KEY_LEN, aead_decrypt, aead_encrypt, custody_commit,
    finalize_new_share, frost_public_add_repaired_share, frost_public_package_digest,
    frost_refresh_part1, frost_refresh_part2, frost_refresh_part3, frost_repair_part2,
    frost_verify_share, hash_aead, merkle_verify, open_local_rotation_journal,
    seal_local_rotation_journal, seal_to_recipient, sha256, sign, signing_key, verify,
    verify_ciphertext_fragment,
};
use gp_types::{
    DpssPhase, DpssProtocolMessage, GuardianEpochState, Id32, NewGuardianPreparedAck,
    OldGuardianHandoffAck, OwnerRotationCancelAck, PROTOCOL_VERSION_V3, PreparedRecordLeaf,
    RetirementAck, RotationPlan,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    protocol::{random_id, random_nonce},
    rotation_protocol::{
        validate_abort_rotation_certificate_v3, validate_activated_capsule_v3,
        validate_begin_rotation_certificate_v3, validate_rotation_plan_v3,
        validate_rotation_release_certificate_v3,
    },
    types::{
        DpssDeliveryV3, GuardianRotationEntryV3, GuardianRotationRequestV3,
        GuardianRotationResponseV3, GuardianRotationSessionV3, StagedGuardianMaterialV3,
    },
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
enum LocalDpssState {
    RepairDealer {
        old_share: Zeroizing<Vec<u8>>,
        self_delta: Zeroizing<Vec<u8>>,
    },
    OldShare {
        share: Zeroizing<Vec<u8>>,
    },
    Repaired {
        share: Zeroizing<Vec<u8>>,
    },
    Refreshed {
        share: Zeroizing<Vec<u8>>,
        public_package: Vec<u8>,
    },
    RefreshRound1 {
        old_share: Zeroizing<Vec<u8>>,
        secret_state: Zeroizing<Vec<u8>>,
    },
    RefreshRound2 {
        old_share: Zeroizing<Vec<u8>>,
        secret_state: Zeroizing<Vec<u8>>,
        round1_messages: Vec<(u16, Vec<u8>)>,
    },
}

fn guardian_route<'a>(
    entry: &GuardianRotationEntryV3,
    plan: &'a RotationPlan,
    successor: bool,
) -> Result<&'a gp_types::GuardianRouteV3> {
    let roster = if successor {
        &plan.new_roster
    } else {
        &plan.old_roster
    };
    let matches = roster
        .iter()
        .filter(|route| route.guardian_public_key == entry.provision.signing_public_key)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        bail!("guardian identity is absent or duplicated in the exact plan roster");
    }
    Ok(matches[0])
}

fn local_journal_context(plan: &RotationPlan, guardian_index: u16) -> Result<Vec<u8>> {
    let mut context = gp_wire::rotation_plan(plan)?;
    context.extend_from_slice(b"gp/network-guardian-local-state/v3");
    context.extend_from_slice(&guardian_index.to_be_bytes());
    Ok(context)
}

fn save_local_state(
    session: &mut GuardianRotationSessionV3,
    identity_seed: &Id32,
    plan: &RotationPlan,
    guardian_index: u16,
    state: &LocalDpssState,
) -> Result<()> {
    let plaintext = Zeroizing::new(serde_json::to_vec(state)?);
    session.encrypted_local_state = Some(seal_local_rotation_journal(
        identity_seed,
        random_nonce(),
        &plaintext,
        &local_journal_context(plan, guardian_index)?,
    )?);
    Ok(())
}

fn open_local_state(
    session: &GuardianRotationSessionV3,
    identity_seed: &Id32,
    plan: &RotationPlan,
    guardian_index: u16,
) -> Result<LocalDpssState> {
    let encrypted = session
        .encrypted_local_state
        .as_ref()
        .context("guardian has no encrypted local DPSS state")?;
    let plaintext = open_local_rotation_journal(
        identity_seed,
        encrypted,
        &local_journal_context(plan, guardian_index)?,
    )?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn sequence_key(sender: u16, recipient: u16) -> String {
    format!("{sender}:{recipient}")
}

fn make_delivery(
    session: &mut GuardianRotationSessionV3,
    signing_seed: Id32,
    plan: &RotationPlan,
    sender_index: u16,
    target: &gp_types::GuardianRouteV3,
    phase: DpssPhase,
    provider_payload: &[u8],
) -> Result<DpssDeliveryV3> {
    let sequence = session
        .next_outgoing_sequences
        .entry(sequence_key(sender_index, target.guardian_index))
        .or_insert(1);
    let mut message = DpssProtocolMessage {
        context: plan.context.clone(),
        plan_hash: sha256(&gp_wire::rotation_plan(plan)?),
        dpss_suite: plan.dpss_suite,
        dpss_session_id: plan.dpss_session_id,
        qualified_set_commitment: plan.dpss_qualified_set_commitment,
        phase,
        sender_index,
        recipient_index: target.guardian_index,
        sequence: *sequence,
        provider_payload: provider_payload.to_vec(),
        sender_signature: vec![],
    };
    *sequence = sequence.saturating_add(1);
    message.sender_signature = sign(
        &signing_key(signing_seed),
        &gp_wire::dpss_protocol_message(&message)?,
    );
    let sealed_message = seal_to_recipient(
        &target.session_recipient_key,
        random_id(),
        random_nonce(),
        &serde_json::to_vec(&message)?,
        &gp_wire::mailbox_transport_context(&target.mailbox, "dpss-direct")?,
    )?;
    Ok(DpssDeliveryV3 {
        target_mailbox: target.mailbox.clone(),
        sealed_message,
    })
}

fn open_deliveries(
    session: &mut GuardianRotationSessionV3,
    identity_seed: &Id32,
    plan: &RotationPlan,
    own_route: &gp_types::GuardianRouteV3,
    sender_routes: &[gp_types::GuardianRouteV3],
    expected_phase: DpssPhase,
    incoming: &[gp_types::SealedMessage],
) -> Result<Vec<(u16, Vec<u8>)>> {
    let recipient = RecipientKeyPair::from_seed(*identity_seed);
    let route_keys = sender_routes
        .iter()
        .map(|route| (route.guardian_index, route.guardian_public_key))
        .collect::<BTreeMap<_, _>>();
    let mut senders = BTreeSet::new();
    let mut opened = Vec::with_capacity(incoming.len());
    for sealed in incoming {
        let plaintext = recipient.open(
            sealed,
            &gp_wire::mailbox_transport_context(&own_route.mailbox, "dpss-direct")?,
        )?;
        let message: DpssProtocolMessage = serde_json::from_slice(&plaintext)?;
        let sender_key = route_keys
            .get(&message.sender_index)
            .context("DPSS message is from an actor outside the expected roster")?;
        let transcript = gp_wire::dpss_protocol_message(&message)?;
        if message.context != plan.context
            || message.plan_hash != sha256(&gp_wire::rotation_plan(plan)?)
            || message.dpss_suite != plan.dpss_suite
            || message.dpss_session_id != plan.dpss_session_id
            || message.qualified_set_commitment != plan.dpss_qualified_set_commitment
            || message.phase != expected_phase
            || message.recipient_index != own_route.guardian_index
            || !senders.insert(message.sender_index)
        {
            bail!("DPSS delivery is replayed or transcript-mismatched");
        }
        let sequence = session
            .next_incoming_sequences
            .entry(sequence_key(message.sender_index, own_route.guardian_index))
            .or_insert(1);
        if message.sequence != *sequence {
            bail!("DPSS delivery is reordered or replayed");
        }
        verify(sender_key, &transcript, &message.sender_signature)?;
        *sequence = sequence.saturating_add(1);
        opened.push((message.sender_index, message.provider_payload));
    }
    Ok(opened)
}

fn session_mut<'a>(
    entry: &'a mut GuardianRotationEntryV3,
    plan: &RotationPlan,
) -> Result<&'a mut GuardianRotationSessionV3> {
    let plan_hash = sha256(&gp_wire::rotation_plan(plan)?);
    let session = entry
        .sessions
        .get_mut(&hex::encode(plan.context.rotation_id))
        .context("guardian has not accepted Begin for this rotation")?;
    if session.plan_hash != plan_hash
        || session.rotation_machine.rotation_id() != plan.context.rotation_id
        || session.rotation_machine.plan_hash() != plan_hash
        || session.rotation_machine.predecessor() != plan.predecessor
        || session.rotation_machine.successor() != plan.successor
        || session.cancelled
    {
        bail!("guardian rotation session is cancelled or plan-mismatched");
    }
    Ok(session)
}

fn advance_to_preparing(session: &mut GuardianRotationSessionV3, monotonic_now: u64) -> Result<()> {
    match session.rotation_machine.state() {
        gp_types::RotationState::DelayPending => {
            session
                .rotation_machine
                .apply(RotationEvent::ReleaseAccepted {
                    monotonic_now,
                    certificate_valid: true,
                    state_unambiguous: true,
                })?;
            Ok(())
        }
        gp_types::RotationState::Preparing => Ok(()),
        state => bail!("rotation Release is invalid from local state {state:?}"),
    }
}

fn open_old_material(
    entry: &GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: &RotationPlan,
    grant: &gp_types::OldShareUnlockGrant,
    release_hash: Id32,
) -> Result<(SecretVec, SecretVec)> {
    let route = guardian_route(entry, plan, false)?;
    if grant.context != plan.context
        || grant.plan_hash != sha256(&gp_wire::rotation_plan(plan)?)
        || grant.release_certificate_hash != release_hash
        || grant.old_guardian_index != route.guardian_index
    {
        bail!("old-share grant does not bind this guardian and release");
    }
    gp_wire::old_share_unlock_grant(grant)?;
    let recipient = RecipientKeyPair::from_seed(*identity_seed);
    let mut share_key = recipient.open(
        &grant.encrypted_unwrap_key,
        &gp_wire::old_share_unlock_grant_payload_context(grant, false)?,
    )?;
    let mut fragment_key = recipient.open(
        &grant.encrypted_fragment_key,
        &gp_wire::old_share_unlock_grant_payload_context(grant, true)?,
    )?;
    if share_key.len() != 32 || fragment_key.len() != 32 {
        bail!("old-share grant contains an invalid key length");
    }
    let record = entry
        .provision
        .epoch_store
        .active
        .as_ref()
        .context("old guardian has no active record")?;
    let share = aead_decrypt(
        share_key.as_slice().try_into()?,
        &record.encrypted_dek_share,
        &gp_wire::guardian_share_context_v3(&record.policy.config_ref, record.guardian_index)?,
    )?;
    let fragment = aead_decrypt(
        fragment_key.as_slice().try_into()?,
        &record.encrypted_ciphertext_fragment,
        &gp_wire::guardian_fragment_context_v3(
            &record.policy.config_ref,
            record.guardian_index,
            record.fragment_index,
        )?,
    )?;
    share_key.zeroize();
    fragment_key.zeroize();
    Ok((share, fragment))
}

fn open_new_keys(
    identity_seed: &Id32,
    plan: &RotationPlan,
    guardian_index: u16,
    grant: &gp_types::NewShareWrapGrant,
) -> Result<(SecretVec, SecretVec)> {
    if grant.context != plan.context
        || grant.plan_hash != sha256(&gp_wire::rotation_plan(plan)?)
        || grant.new_guardian_index != guardian_index
    {
        bail!("new-share grant does not bind this successor guardian");
    }
    gp_wire::new_share_wrap_grant(grant)?;
    let recipient = RecipientKeyPair::from_seed(*identity_seed);
    let share_key = recipient.open(
        &grant.encrypted_wrap_key,
        &gp_wire::new_share_wrap_grant_payload_context(grant, false)?,
    )?;
    let fragment_key = recipient.open(
        &grant.encrypted_fragment_key,
        &gp_wire::new_share_wrap_grant_payload_context(grant, true)?,
    )?;
    if share_key.len() != 32 || fragment_key.len() != 32 {
        bail!("new-share grant contains an invalid key length");
    }
    Ok((share_key, fragment_key))
}

pub fn handle_guardian_rotation_v3(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    request: GuardianRotationRequestV3,
    wall_now: u64,
    monotonic_now: u64,
    boot_id: &str,
    allow_insecure_demo_delay: bool,
) -> Result<GuardianRotationResponseV3> {
    let context = request.context();
    if context.protocol_version != PROTOCOL_VERSION_V3
        || context.config_ref.config_id != entry.provision.predecessor_capsule.config_ref.config_id
        || context.issued_at > wall_now
        || context.expiry <= wall_now
        || context.recipient_key.len() != XWING_PUBLIC_KEY_LEN
    {
        bail!("guardian rejected malformed or expired rotation context");
    }
    match request {
        GuardianRotationRequestV3::Begin { plan, certificate } => {
            let begin_hash = validate_begin_rotation_certificate_v3(
                &certificate,
                &plan,
                &entry.provision.predecessor_capsule,
                wall_now,
            )?;
            if guardian_route(entry, &plan, false).is_err()
                && guardian_route(entry, &plan, true).is_err()
            {
                bail!("guardian is not a participant in this rotation");
            }
            let transport_public_key = RecipientKeyPair::from_seed(*identity_seed)
                .public_key()
                .to_vec();
            for route in plan
                .old_roster
                .iter()
                .chain(plan.new_roster.iter())
                .filter(|route| route.guardian_public_key == entry.provision.signing_public_key)
            {
                if route.session_recipient_key != transport_public_key {
                    bail!("plan substituted this guardian's DPSS session recipient key");
                }
            }
            let plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
            let key = hex::encode(plan.context.rotation_id);
            if entry
                .provision
                .epoch_store
                .rotation_tombstones
                .contains_key(&key)
            {
                bail!("guardian permanently rejected this completed or cancelled rotation id");
            }
            if let Some(existing) = entry.sessions.get(&key) {
                if existing.plan_hash == plan_hash && existing.begin_certificate_hash == begin_hash
                {
                    return Ok(GuardianRotationResponseV3::BeginAccepted {
                        not_before_monotonic: existing.not_before_monotonic,
                    });
                }
                bail!("guardian is already locked to another plan for this rotation id");
            }
            let delay = if allow_insecure_demo_delay {
                plan.minimum_delay_secs.min(2)
            } else {
                plan.minimum_delay_secs
            };
            let mut rotation_machine = RotationMachine::new(
                plan.context.rotation_id,
                plan_hash,
                plan.predecessor,
                plan.successor,
            )?;
            rotation_machine.apply(RotationEvent::BeginAccepted {
                monotonic_now,
                delay_secs: delay,
                certificate_valid: true,
            })?;
            let not_before_monotonic = rotation_machine
                .not_before()
                .context("rotation machine did not persist its delay")?;
            entry.sessions.insert(
                key,
                GuardianRotationSessionV3 {
                    rotation_machine,
                    plan_hash,
                    begin_certificate_hash: begin_hash,
                    accepted_wall_time: wall_now,
                    started_monotonic: monotonic_now,
                    not_before_monotonic,
                    boot_id: boot_id.to_owned(),
                    cancelled: false,
                    next_outgoing_sequences: BTreeMap::new(),
                    next_incoming_sequences: BTreeMap::new(),
                    encrypted_local_state: None,
                    staged_material: None,
                },
            );
            Ok(GuardianRotationResponseV3::BeginAccepted {
                not_before_monotonic,
            })
        }
        GuardianRotationRequestV3::Cancel { plan, certificate } => {
            let plan_hash =
                validate_rotation_plan_v3(&plan, &entry.provision.predecessor_capsule, wall_now)?;
            if certificate.context != plan.context
                || certificate.plan_hash != plan_hash
                || certificate.owner_cancel_public_key
                    != entry.provision.predecessor_capsule.owner_cancel_public_key
                || certificate.cancel_response_recipient_key.len() != XWING_PUBLIC_KEY_LEN
            {
                bail!("owner rotation cancellation is plan-mismatched");
            }
            verify(
                &certificate.owner_cancel_public_key,
                &gp_wire::owner_rotation_cancel_certificate(&certificate)?,
                &certificate.owner_signature,
            )?;
            if guardian_route(entry, &plan, false).is_err()
                && guardian_route(entry, &plan, true).is_err()
            {
                bail!("guardian is not a participant in this cancelled rotation");
            }
            let key = hex::encode(plan.context.rotation_id);
            if let Some(tombstone) = entry.provision.epoch_store.rotation_tombstones.get(&key) {
                if tombstone.plan_hash != plan_hash
                    || tombstone.terminal_state != gp_types::RotationState::Aborted
                {
                    bail!("rotation id already has a conflicting terminal state");
                }
            } else if let Some(session) = entry.sessions.get_mut(&key) {
                if !session.cancelled {
                    session
                        .rotation_machine
                        .apply(RotationEvent::OwnerCancelObserved {
                            certificate_valid: true,
                        })?;
                }
                session.cancelled = true;
                session.encrypted_local_state = None;
                session.staged_material = None;
            } else {
                let mut rotation_machine = RotationMachine::new(
                    plan.context.rotation_id,
                    plan_hash,
                    plan.predecessor,
                    plan.successor,
                )?;
                rotation_machine.apply(RotationEvent::OwnerCancelObserved {
                    certificate_valid: true,
                })?;
            }
            entry
                .provision
                .epoch_store
                .abort_prepared(plan.context.rotation_id, plan_hash)?;
            entry.sessions.remove(&key);
            let guardian_index = entry
                .provision
                .epoch_store
                .active
                .as_ref()
                .map(|record| record.guardian_index)
                .or_else(|| {
                    guardian_route(entry, &plan, true)
                        .ok()
                        .map(|route| route.guardian_index)
                })
                .context("cancel recipient has no guardian index")?;
            let mut ack = OwnerRotationCancelAck {
                context: plan.context,
                plan_hash,
                cancel_certificate_hash: sha256(&gp_wire::owner_rotation_cancel_certificate(
                    &certificate,
                )?),
                guardian_index,
                guardian_signature: vec![],
            };
            ack.guardian_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::owner_rotation_cancel_ack(&ack)?,
            );
            Ok(GuardianRotationResponseV3::Cancelled(ack))
        }
        GuardianRotationRequestV3::RepairRound1 {
            plan,
            begin_certificate,
            release_certificate,
            unlock_grant,
            helper_ids,
            replacement_id,
        } => repair_round1(
            entry,
            identity_seed,
            plan,
            begin_certificate,
            release_certificate,
            unlock_grant,
            helper_ids,
            replacement_id,
            wall_now,
            monotonic_now,
            boot_id,
        ),
        GuardianRotationRequestV3::RepairRound2 {
            plan,
            incoming,
            replacement_id,
        } => repair_round2(entry, identity_seed, plan, incoming, replacement_id),
        GuardianRotationRequestV3::RepairFinalize {
            plan,
            incoming,
            old_public_package,
        } => repair_finalize(entry, identity_seed, plan, incoming, old_public_package),
        GuardianRotationRequestV3::RefreshRound1 {
            plan,
            begin_certificate,
            release_certificate,
            old_share_grant,
        } => refresh_round1(
            entry,
            identity_seed,
            plan,
            begin_certificate,
            release_certificate,
            old_share_grant,
            wall_now,
            monotonic_now,
            boot_id,
        ),
        GuardianRotationRequestV3::RefreshRound2 { plan, incoming } => {
            refresh_round2(entry, identity_seed, plan, incoming)
        }
        GuardianRotationRequestV3::RefreshFinalize {
            plan,
            incoming,
            old_public_package,
        } => refresh_finalize(entry, identity_seed, plan, incoming, old_public_package),
        GuardianRotationRequestV3::StageMaterial {
            plan,
            wrap_grant,
            fragment_index,
            ciphertext_fragment,
            ciphertext_fragment_proof,
            policy,
            opaque_slot_id,
        } => stage_material(
            entry,
            identity_seed,
            plan,
            wrap_grant,
            fragment_index,
            ciphertext_fragment,
            ciphertext_fragment_proof,
            policy,
            opaque_slot_id,
        ),
        GuardianRotationRequestV3::PrepareCommit {
            plan,
            guardian_material_root,
            merkle_path_proof,
            dpss_result_commitment,
        } => prepare_commit(
            entry,
            identity_seed,
            plan,
            guardian_material_root,
            merkle_path_proof,
            dpss_result_commitment,
        ),
        GuardianRotationRequestV3::HandoffComplete {
            plan,
            dpss_result_commitment,
        } => handoff_complete(entry, plan, dpss_result_commitment),
        GuardianRotationRequestV3::Activate {
            plan,
            activated_capsule,
            drain_deadline,
        } => activate(entry, plan, activated_capsule, drain_deadline),
        GuardianRotationRequestV3::Abort { plan, certificate } => {
            validate_abort_rotation_certificate_v3(
                &certificate,
                &plan,
                &entry.provision.predecessor_capsule,
                wall_now,
            )?;
            let plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
            session_mut(entry, &plan)?
                .rotation_machine
                .apply(RotationEvent::AbortObserved {
                    certificate_valid: true,
                })?;
            entry
                .provision
                .epoch_store
                .abort_prepared(plan.context.rotation_id, plan_hash)?;
            entry
                .sessions
                .remove(&hex::encode(plan.context.rotation_id));
            Ok(GuardianRotationResponseV3::Aborted)
        }
        GuardianRotationRequestV3::Retire {
            notice,
            monotonic_now,
        } => retire(entry, notice, monotonic_now),
    }
}

#[allow(clippy::too_many_arguments)]
fn repair_round1(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    begin_certificate: gp_types::BeginRotationCertificate,
    release_certificate: gp_types::RotationReleaseCertificate,
    unlock_grant: gp_types::OldShareUnlockGrant,
    helper_ids: Vec<u16>,
    replacement_id: u16,
    wall_now: u64,
    monotonic_now: u64,
    boot_id: &str,
) -> Result<GuardianRotationResponseV3> {
    let release_hash = validate_rotation_release_certificate_v3(
        &release_certificate,
        &begin_certificate,
        &plan,
        &entry.provision.predecessor_capsule,
        wall_now,
    )?;
    let old_route = guardian_route(entry, &plan, false)?.clone();
    let signing_seed = entry.provision.signing_seed;
    let (old_share, fragment) =
        open_old_material(entry, identity_seed, &plan, &unlock_grant, release_hash)?;
    let (fragment_index, prepared_record_leaf, merkle_path_proof) = {
        let record = entry
            .provision
            .epoch_store
            .active
            .as_ref()
            .context("old guardian has no active record")?;
        (
            record.fragment_index,
            PreparedRecordLeaf {
                guardian_index: record.guardian_index,
                fragment_index: record.fragment_index,
                opaque_slot_id: record.opaque_slot_id,
                encrypted_share_hash: hash_aead(&record.encrypted_dek_share),
                fragment_hash: hash_aead(&record.encrypted_ciphertext_fragment),
                policy_hash: sha256(&gp_wire::guardian_policy_body_v3(&record.policy)?),
            },
            record.merkle_path_proof.clone(),
        )
    };
    let session = session_mut(entry, &plan)?;
    if session.begin_certificate_hash
        != sha256(&gp_wire::begin_rotation_certificate(&begin_certificate)?)
        || session.boot_id != boot_id
        || monotonic_now < session.not_before_monotonic
    {
        bail!("guardian delay is incomplete or reboot-ambiguous");
    }
    advance_to_preparing(session, monotonic_now)?;
    let deltas = gp_crypto::begin_old_share(&old_share, &helper_ids, replacement_id, random_id())?;
    let self_delta = deltas
        .iter()
        .find(|(recipient, _)| *recipient == old_route.guardian_index)
        .context("RTS provider omitted the helper's own delta")?
        .1
        .clone();
    save_local_state(
        session,
        identity_seed,
        &plan,
        old_route.guardian_index,
        &LocalDpssState::RepairDealer {
            old_share: old_share.clone(),
            self_delta,
        },
    )?;
    let mut deliveries = Vec::new();
    for (target_id, delta) in deltas {
        if target_id == old_route.guardian_index {
            continue;
        }
        let target = plan
            .old_roster
            .iter()
            .find(|route| route.guardian_index == target_id)
            .context("RTS helper is not in the old roster")?;
        deliveries.push(make_delivery(
            session,
            signing_seed,
            &plan,
            old_route.guardian_index,
            target,
            DpssPhase::RepairRound1,
            &delta,
        )?);
    }
    let mut contribution = gp_types::CiphertextFragmentContribution {
        context: plan.context.clone(),
        plan_hash: session.plan_hash,
        release_certificate_hash: release_hash,
        old_guardian_index: old_route.guardian_index,
        fragment_index,
        ciphertext_fragment: fragment.to_vec(),
        fragment_commitment: sha256(&fragment),
        prepared_record_leaf,
        merkle_path_proof,
        guardian_signature: vec![],
    };
    contribution.guardian_signature = sign(
        &signing_key(signing_seed),
        &gp_wire::ciphertext_fragment_contribution(&contribution)?,
    );
    Ok(GuardianRotationResponseV3::DpssDeliveries {
        deliveries,
        fragment: Some(contribution),
    })
}

fn repair_round2(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    incoming: Vec<gp_types::SealedMessage>,
    replacement_id: u16,
) -> Result<GuardianRotationResponseV3> {
    let old_route = guardian_route(entry, &plan, false)?.clone();
    let replacement = plan
        .new_roster
        .iter()
        .find(|route| route.guardian_index == replacement_id)
        .context("replacement is not in the successor roster")?
        .clone();
    let signing_seed = entry.provision.signing_seed;
    let old_roster = plan.old_roster.clone();
    let session = session_mut(entry, &plan)?;
    let opened = open_deliveries(
        session,
        identity_seed,
        &plan,
        &old_route,
        &old_roster,
        DpssPhase::RepairRound1,
        &incoming,
    )?;
    let LocalDpssState::RepairDealer {
        old_share,
        self_delta,
    } = open_local_state(session, identity_seed, &plan, old_route.guardian_index)?
    else {
        bail!("guardian is not in RTS repair-dealer state");
    };
    let mut deltas = opened
        .into_iter()
        .map(|(_, payload)| payload)
        .collect::<Vec<_>>();
    deltas.push(self_delta.to_vec());
    let sigma = frost_repair_part2(&deltas.iter().map(Vec::as_slice).collect::<Vec<_>>())?;
    save_local_state(
        session,
        identity_seed,
        &plan,
        old_route.guardian_index,
        &LocalDpssState::OldShare { share: old_share },
    )?;
    let delivery = make_delivery(
        session,
        signing_seed,
        &plan,
        old_route.guardian_index,
        &replacement,
        DpssPhase::RepairRound2,
        &sigma,
    )?;
    Ok(GuardianRotationResponseV3::DpssDeliveries {
        deliveries: vec![delivery],
        fragment: None,
    })
}

fn repair_finalize(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    incoming: Vec<gp_types::SealedMessage>,
    old_public_package: Vec<u8>,
) -> Result<GuardianRotationResponseV3> {
    let new_route = guardian_route(entry, &plan, true)?.clone();
    let old_roster = plan.old_roster.clone();
    let session = session_mut(entry, &plan)?;
    let opened = open_deliveries(
        session,
        identity_seed,
        &plan,
        &new_route,
        &old_roster,
        DpssPhase::RepairRound2,
        &incoming,
    )?;
    if opened.len() < usize::from(plan.old_guardian_threshold) {
        bail!("RTS finalization lacks an old-guardian threshold");
    }
    let inferred_release_time = session.not_before_monotonic;
    advance_to_preparing(session, inferred_release_time)?;
    let sigmas = opened
        .iter()
        .map(|(_, payload)| payload.as_slice())
        .collect::<Vec<_>>();
    let share = finalize_new_share(&sigmas, new_route.guardian_index, &old_public_package)?;
    let expanded_public_package = frost_public_add_repaired_share(&old_public_package, &share)?;
    if frost_verify_share(&share, &expanded_public_package)? != new_route.guardian_index {
        bail!("RTS replacement share has the wrong participant id");
    }
    save_local_state(
        session,
        identity_seed,
        &plan,
        new_route.guardian_index,
        &LocalDpssState::Repaired {
            share: share.clone(),
        },
    )?;
    Ok(GuardianRotationResponseV3::RepairStored {
        guardian_index: new_route.guardian_index,
        expanded_public_package,
    })
}

#[allow(clippy::too_many_arguments)]
fn refresh_round1(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    begin_certificate: Option<gp_types::BeginRotationCertificate>,
    release_certificate: Option<gp_types::RotationReleaseCertificate>,
    old_share_grant: Option<gp_types::OldShareUnlockGrant>,
    wall_now: u64,
    monotonic_now: u64,
    boot_id: &str,
) -> Result<GuardianRotationResponseV3> {
    let new_route = guardian_route(entry, &plan, true)?.clone();
    let signing_seed = entry.provision.signing_seed;
    let share = if let Some(grant) = old_share_grant {
        let begin = begin_certificate
            .as_ref()
            .context("unchanged guardian refresh lacks Begin certificate")?;
        let release = release_certificate
            .as_ref()
            .context("unchanged guardian refresh lacks Release certificate")?;
        let release_hash = validate_rotation_release_certificate_v3(
            release,
            begin,
            &plan,
            &entry.provision.predecessor_capsule,
            wall_now,
        )?;
        open_old_material(entry, identity_seed, &plan, &grant, release_hash)?.0
    } else {
        let session = session_mut(entry, &plan)?;
        match open_local_state(session, identity_seed, &plan, new_route.guardian_index)? {
            LocalDpssState::Repaired { share } => share,
            _ => bail!("candidate has no locally finalized RTS share"),
        }
    };
    let session = session_mut(entry, &plan)?;
    if session.boot_id != boot_id || monotonic_now < session.not_before_monotonic {
        bail!("guardian refresh delay is incomplete or reboot-ambiguous");
    }
    advance_to_preparing(session, monotonic_now)?;
    let refresh = frost_refresh_part1(
        new_route.guardian_index,
        plan.new_guardian_threshold,
        u16::try_from(plan.new_roster.len())?,
        random_id(),
    )?;
    save_local_state(
        session,
        identity_seed,
        &plan,
        new_route.guardian_index,
        &LocalDpssState::RefreshRound1 {
            old_share: share,
            secret_state: refresh.secret_state,
        },
    )?;
    let mut deliveries = Vec::with_capacity(plan.new_roster.len().saturating_sub(1));
    for target in plan
        .new_roster
        .iter()
        .filter(|route| route.guardian_index != new_route.guardian_index)
    {
        deliveries.push(make_delivery(
            session,
            signing_seed,
            &plan,
            new_route.guardian_index,
            target,
            DpssPhase::RefreshRound1,
            &refresh.broadcast,
        )?);
    }
    Ok(GuardianRotationResponseV3::DpssDeliveries {
        deliveries,
        fragment: None,
    })
}

fn refresh_round2(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    incoming: Vec<gp_types::SealedMessage>,
) -> Result<GuardianRotationResponseV3> {
    let new_route = guardian_route(entry, &plan, true)?.clone();
    let signing_seed = entry.provision.signing_seed;
    let new_roster = plan.new_roster.clone();
    let session = session_mut(entry, &plan)?;
    let round1 = open_deliveries(
        session,
        identity_seed,
        &plan,
        &new_route,
        &new_roster,
        DpssPhase::RefreshRound1,
        &incoming,
    )?;
    if round1.len().saturating_add(1) != plan.new_roster.len() {
        bail!("refresh round 1 is incomplete");
    }
    let LocalDpssState::RefreshRound1 {
        old_share,
        secret_state,
    } = open_local_state(session, identity_seed, &plan, new_route.guardian_index)?
    else {
        bail!("guardian is not in refresh round-1 state");
    };
    let refresh = frost_refresh_part2(&secret_state, &round1)?;
    save_local_state(
        session,
        identity_seed,
        &plan,
        new_route.guardian_index,
        &LocalDpssState::RefreshRound2 {
            old_share,
            secret_state: refresh.secret_state,
            round1_messages: round1,
        },
    )?;
    let mut deliveries = Vec::with_capacity(refresh.direct_messages.len());
    for (recipient, payload) in refresh.direct_messages {
        let target = new_roster
            .iter()
            .find(|route| route.guardian_index == recipient)
            .context("refresh provider emitted an unknown recipient")?;
        deliveries.push(make_delivery(
            session,
            signing_seed,
            &plan,
            new_route.guardian_index,
            target,
            DpssPhase::RefreshRound2,
            &payload,
        )?);
    }
    Ok(GuardianRotationResponseV3::DpssDeliveries {
        deliveries,
        fragment: None,
    })
}

fn refresh_finalize(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    incoming: Vec<gp_types::SealedMessage>,
    old_public_package: Vec<u8>,
) -> Result<GuardianRotationResponseV3> {
    let new_route = guardian_route(entry, &plan, true)?.clone();
    let new_roster = plan.new_roster.clone();
    let session = session_mut(entry, &plan)?;
    let round2 = open_deliveries(
        session,
        identity_seed,
        &plan,
        &new_route,
        &new_roster,
        DpssPhase::RefreshRound2,
        &incoming,
    )?;
    if round2.len().saturating_add(1) != plan.new_roster.len() {
        bail!("refresh round 2 is incomplete");
    }
    let LocalDpssState::RefreshRound2 {
        old_share,
        secret_state,
        round1_messages,
    } = open_local_state(session, identity_seed, &plan, new_route.guardian_index)?
    else {
        bail!("guardian is not in refresh round-2 state");
    };
    let output = frost_refresh_part3(
        &secret_state,
        &round1_messages,
        &round2,
        &old_public_package,
        &old_share,
    )?;
    if frost_verify_share(&output.share, &output.public_package)? != new_route.guardian_index {
        bail!("refreshed share has the wrong participant id");
    }
    let dpss_result_commitment = frost_public_package_digest(&output.public_package)?;
    save_local_state(
        session,
        identity_seed,
        &plan,
        new_route.guardian_index,
        &LocalDpssState::Refreshed {
            share: output.share,
            public_package: output.public_package.clone(),
        },
    )?;
    Ok(GuardianRotationResponseV3::RefreshFinalized {
        guardian_index: new_route.guardian_index,
        public_package: output.public_package,
        dpss_result_commitment,
    })
}

#[allow(clippy::too_many_arguments)]
fn stage_material(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    wrap_grant: gp_types::NewShareWrapGrant,
    fragment_index: u16,
    ciphertext_fragment: Vec<u8>,
    ciphertext_fragment_proof: Vec<u8>,
    policy: gp_types::GuardianPolicyV3,
    opaque_slot_id: Id32,
) -> Result<GuardianRotationResponseV3> {
    let new_route = guardian_route(entry, &plan, true)?.clone();
    let predecessor_capsule_hash = entry.provision.predecessor_capsule.capsule_hash;
    let ciphertext_fragment_root = entry.provision.predecessor_capsule.ciphertext_fragment_root;
    let signer_set_commitment = entry.provision.predecessor_capsule.signer_set_commitment;
    let session = session_mut(entry, &plan)?;
    let LocalDpssState::Refreshed {
        share,
        public_package,
    } = open_local_state(session, identity_seed, &plan, new_route.guardian_index)?
    else {
        bail!("guardian has not finalized its refresh share");
    };
    let dpss_result_commitment = frost_public_package_digest(&public_package)?;
    let fragment_position = plan
        .new_roster
        .iter()
        .position(|candidate| candidate.guardian_index == new_route.guardian_index)
        .context("successor route is absent")?;
    let expected_fragment_index = u16::try_from(fragment_position + 1)?;
    if policy.config_ref != plan.successor
        || policy.epoch_state != GuardianEpochState::Prepared
        || policy.predecessor_capsule_hash != predecessor_capsule_hash
        || policy.dpss_suite != plan.dpss_suite
        || policy.dpss_public_commitment != dpss_result_commitment
        || policy.signer_set_commitment != signer_set_commitment
        || opaque_slot_id != new_route.opaque_slot_id
        || fragment_index != expected_fragment_index
    {
        bail!("successor policy or opaque slot does not bind the exact DPSS result");
    }
    verify_ciphertext_fragment(
        ciphertext_fragment_root,
        &plan.successor.config_id,
        plan.successor.payload_generation,
        fragment_index,
        plan.total_shards,
        &ciphertext_fragment,
        &ciphertext_fragment_proof,
    )
    .context("successor ciphertext fragment is not committed by the predecessor payload")?;
    let (mut share_key, mut fragment_key) =
        open_new_keys(identity_seed, &plan, new_route.guardian_index, &wrap_grant)?;
    let encrypted_dek_share = aead_encrypt(
        share_key.as_slice().try_into()?,
        random_nonce(),
        &share,
        &gp_wire::guardian_share_context_v3(&plan.successor, new_route.guardian_index)?,
    )?;
    let encrypted_ciphertext_fragment = aead_encrypt(
        fragment_key.as_slice().try_into()?,
        random_nonce(),
        &ciphertext_fragment,
        &gp_wire::guardian_fragment_context_v3(
            &plan.successor,
            new_route.guardian_index,
            fragment_index,
        )?,
    )?;
    share_key.zeroize();
    fragment_key.zeroize();
    let leaf = PreparedRecordLeaf {
        guardian_index: new_route.guardian_index,
        fragment_index,
        opaque_slot_id,
        encrypted_share_hash: hash_aead(&encrypted_dek_share),
        fragment_hash: hash_aead(&encrypted_ciphertext_fragment),
        policy_hash: sha256(&gp_wire::guardian_policy_body_v3(&policy)?),
    };
    let mut custody_bytes = encrypted_dek_share.nonce.to_vec();
    custody_bytes.extend_from_slice(&encrypted_dek_share.ciphertext);
    custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.nonce);
    custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.ciphertext);
    let record_draft = gp_types::GuardianRecordV3 {
        opaque_slot_id,
        guardian_index: new_route.guardian_index,
        fragment_index,
        encrypted_ciphertext_fragment: encrypted_ciphertext_fragment.clone(),
        encrypted_dek_share: encrypted_dek_share.clone(),
        merkle_path_proof: vec![],
        custody_root: custody_commit(&custody_bytes)?.root,
        policy,
    };
    session.encrypted_local_state = None;
    session.staged_material = Some(StagedGuardianMaterialV3 {
        record_draft: Box::new(record_draft),
        leaf: leaf.clone(),
        dpss_result_commitment,
    });
    Ok(GuardianRotationResponseV3::RefreshMaterialStaged {
        leaf,
        public_package,
        dpss_result_commitment,
    })
}

fn prepare_commit(
    entry: &mut GuardianRotationEntryV3,
    identity_seed: &Id32,
    plan: RotationPlan,
    guardian_material_root: Id32,
    merkle_path_proof: Vec<u8>,
    dpss_result_commitment: Id32,
) -> Result<GuardianRotationResponseV3> {
    let route = guardian_route(entry, &plan, true)?.clone();
    let signing_seed = entry.provision.signing_seed;
    let (session_plan_hash, staged) = {
        let session = session_mut(entry, &plan)?;
        (
            session.plan_hash,
            session
                .staged_material
                .clone()
                .context("guardian has no staged successor material")?,
        )
    };
    let leaf_hash = sha256(&gp_wire::prepared_record_leaf_v3(&staged.leaf)?);
    let position = plan
        .new_roster
        .iter()
        .position(|candidate| candidate.guardian_index == route.guardian_index)
        .context("successor route is absent")?;
    if staged.dpss_result_commitment != dpss_result_commitment || guardian_material_root == [0; 32]
    {
        bail!("durable successor record differs from locally staged material");
    }
    merkle_verify(
        guardian_material_root,
        leaf_hash,
        position,
        plan.new_roster.len(),
        &merkle_path_proof,
    )?;
    let mut record = *staged.record_draft;
    if record.guardian_index != route.guardian_index
        || record.fragment_index != staged.leaf.fragment_index
        || record.opaque_slot_id != route.opaque_slot_id
        || record.policy.config_ref != plan.successor
        || record.policy.dpss_public_commitment != dpss_result_commitment
    {
        bail!("locally staged successor record is inconsistent");
    }
    record.policy.guardian_material_root = guardian_material_root;
    record.merkle_path_proof = merkle_path_proof;
    let mut custody_bytes = record.encrypted_dek_share.nonce.to_vec();
    custody_bytes.extend_from_slice(&record.encrypted_dek_share.ciphertext);
    custody_bytes.extend_from_slice(&record.encrypted_ciphertext_fragment.nonce);
    custody_bytes.extend_from_slice(&record.encrypted_ciphertext_fragment.ciphertext);
    if custody_commit(&custody_bytes)?.root != record.custody_root {
        bail!("successor custody commitment is invalid");
    }
    let journal = gp_storage::DpssSessionJournal {
        rotation_id: plan.context.rotation_id,
        plan_hash: session_plan_hash,
        session_id: plan.dpss_session_id,
        qualified_set_digest: plan.dpss_qualified_set_commitment,
        phase: 6,
        next_sequence: 1,
        provider_public_journal: dpss_result_commitment.to_vec(),
        encrypted_provider_secret_journal: seal_local_rotation_journal(
            identity_seed,
            random_nonce(),
            b"dpss-complete",
            &local_journal_context(&plan, route.guardian_index)?,
        )?,
    };
    let generation = entry.provision.epoch_store.prepare_successor(
        plan.context.rotation_id,
        session_plan_hash,
        record,
        journal,
    )?;
    let mut ack = NewGuardianPreparedAck {
        context: plan.context.clone(),
        plan_hash: session_plan_hash,
        dpss_result_commitment,
        guardian_material_root,
        new_guardian_index: route.guardian_index,
        prepared_record_leaf: staged.leaf.clone(),
        durable_write_generation: generation,
        guardian_signature: vec![],
    };
    ack.guardian_signature = sign(
        &signing_key(signing_seed),
        &gp_wire::new_guardian_prepared_ack(&ack)?,
    );
    entry
        .sessions
        .get_mut(&hex::encode(plan.context.rotation_id))
        .context("rotation session disappeared during prepare")?
        .staged_material = None;
    Ok(GuardianRotationResponseV3::Prepared(ack))
}

fn handoff_complete(
    entry: &mut GuardianRotationEntryV3,
    plan: RotationPlan,
    dpss_result_commitment: Id32,
) -> Result<GuardianRotationResponseV3> {
    let route = guardian_route(entry, &plan, false)?.clone();
    let signing_seed = entry.provision.signing_seed;
    let session = session_mut(entry, &plan)?;
    session.encrypted_local_state = None;
    let mut ack = OldGuardianHandoffAck {
        context: plan.context,
        plan_hash: session.plan_hash,
        dpss_result_commitment,
        qualified_set_commitment: plan.dpss_qualified_set_commitment,
        old_guardian_index: route.guardian_index,
        guardian_signature: vec![],
    };
    ack.guardian_signature = sign(
        &signing_key(signing_seed),
        &gp_wire::old_guardian_handoff_ack(&ack)?,
    );
    Ok(GuardianRotationResponseV3::Handoff(ack))
}

fn activate(
    entry: &mut GuardianRotationEntryV3,
    plan: RotationPlan,
    activated_capsule: gp_types::ConfigCapsuleV3,
    drain_deadline: u64,
) -> Result<GuardianRotationResponseV3> {
    let locally_pending = crate::recovery_runtime::pending_old_recovery_ids(entry);
    validate_activated_capsule_v3(&entry.provision.recovery_card, &activated_capsule)?;
    let qc = activated_capsule
        .activation_qc
        .clone()
        .context("activated successor capsule has no QC")?;
    let qc_hash = sha256(&gp_wire::epoch_activation_qc(&qc)?);
    let plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
    if activated_capsule.config_ref != plan.successor
        || activated_capsule.predecessor_capsule_hash
            != entry.provision.predecessor_capsule.capsule_hash
        || activated_capsule.ciphertext_fragment_root
            != entry.provision.predecessor_capsule.ciphertext_fragment_root
        || activated_capsule.guardian_count != u16::try_from(plan.new_roster.len())?
        || activated_capsule.guardian_threshold != plan.new_guardian_threshold
        || activated_capsule.dpss_suite != plan.dpss_suite
        || qc.rotation_id != plan.context.rotation_id
    {
        bail!("activation QC/capsule does not bind the exact plan");
    }
    if guardian_route(entry, &plan, true).is_ok() {
        let prepared = entry
            .provision
            .epoch_store
            .prepared
            .as_ref()
            .context("successor guardian has no locally prepared record")?;
        if prepared.record.policy.config_ref != activated_capsule.config_ref
            || prepared.record.policy.guardian_material_root
                != activated_capsule.guardian_material_root
            || prepared.record.policy.dpss_public_commitment
                != activated_capsule.dpss_public_commitment
        {
            bail!("activated capsule differs from the guardian's prepared record");
        }
    }
    {
        let session = session_mut(entry, &plan)?;
        let inferred_release_time = session.not_before_monotonic;
        advance_to_preparing(session, inferred_release_time)?;
        session
            .rotation_machine
            .apply(RotationEvent::PreparationComplete {
                prepared_count: u16::try_from(plan.new_roster.len())?,
                expected_count: u16::try_from(plan.new_roster.len())?,
                dpss_result_valid: true,
                fragments_valid: true,
            })?;
        session
            .rotation_machine
            .apply(RotationEvent::ActivationAuthorized {
                certificate_valid: true,
                exact_capsule: true,
            })?;
        session
            .rotation_machine
            .apply(RotationEvent::WitnessQcObserved {
                qc_valid: true,
                exact_successor: true,
                drain_deadline,
            })?;
    }
    if guardian_route(entry, &plan, true).is_ok() {
        entry.provision.epoch_store.activate_successor(
            plan.context.rotation_id,
            plan_hash,
            qc,
            qc_hash,
            drain_deadline,
            locally_pending,
        )?;
    } else {
        entry.provision.epoch_store.observe_replacement_activation(
            plan.context.rotation_id,
            plan_hash,
            qc,
            qc_hash,
            drain_deadline,
            locally_pending,
        )?;
    }
    entry.provision.predecessor_capsule = activated_capsule;
    entry
        .sessions
        .remove(&hex::encode(plan.context.rotation_id));
    Ok(GuardianRotationResponseV3::Activated {
        guardian_epoch: plan.successor.guardian_epoch,
    })
}

fn retire(
    entry: &mut GuardianRotationEntryV3,
    notice: gp_types::RetirementNotice,
    monotonic_now: u64,
) -> Result<GuardianRotationResponseV3> {
    let qc = entry
        .provision
        .epoch_store
        .activation_qc
        .as_ref()
        .context("guardian has not observed an activation QC")?;
    let qc_hash = sha256(&gp_wire::epoch_activation_qc(qc)?);
    if notice.activation_qc_hash != qc_hash
        || notice.retired_epoch != qc.predecessor_epoch
        || notice.drain_deadline > monotonic_now
    {
        bail!("retirement notice is early or QC-mismatched");
    }
    let guardian_index = entry
        .provision
        .epoch_store
        .draining
        .get(&notice.retired_epoch)
        .map(|draining| draining.record.guardian_index)
        .context("retired epoch is not draining")?;
    let tombstone_hash = entry
        .provision
        .epoch_store
        .retire_epoch(notice.retired_epoch, monotonic_now)?;
    let mut ack = RetirementAck {
        context: notice.context,
        plan_hash: notice.plan_hash,
        activation_qc_hash: qc_hash,
        guardian_index,
        retired_epoch: notice.retired_epoch,
        tombstone_hash,
        guardian_signature: vec![],
    };
    ack.guardian_signature = sign(
        &signing_key(entry.provision.signing_seed),
        &gp_wire::retirement_ack(&ack)?,
    );
    Ok(GuardianRotationResponseV3::Retired(ack))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_crypto::{
        EpochFrostShare, RecipientKeyPair, commit_ciphertext_fragments, erasure_encode,
        erasure_reconstruct, frost_dealer_split, frost_recover_dek_for_epoch,
        guardian_fragment_key_v3, guardian_share_key_v3, merkle_commit, verifying_key_bytes,
    };
    use gp_types::{
        AeadCiphertext, BeginRecoveryCertificateV3, BeginRotationCertificate, ConfigCapsuleV3,
        ConfigRef, DpssSuiteId, EpochActivationQc, GuardianPolicyV3, GuardianRecordV3,
        GuardianRouteV3, OwnerRecoveryCancelCertificateV3, RecoveryCardV3,
        RecoveryReleaseCertificateV3, RecoveryRequestV3, RotationActivateCertificate,
        RotationContext, RotationReleaseCertificate, SignerRecoveryContributionV3,
        SignerRecoveryReleaseVoteV3, SignerRotationActivateVote, SignerRotationBeginVote,
        SignerRotationReleaseVote, WitnessActivationAck, WitnessPin,
    };

    fn mailbox(epoch: u64, id: u16) -> String {
        format!("opaque-e{epoch}-g{id}-0123456789abcdef0123456789abcdef")
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

    fn call(
        entry: &mut GuardianRotationEntryV3,
        identity_seed: Id32,
        request: GuardianRotationRequestV3,
        monotonic: u64,
    ) -> GuardianRotationResponseV3 {
        handle_guardian_rotation_v3(
            entry,
            &identity_seed,
            request,
            10,
            monotonic,
            "test-boot",
            true,
        )
        .unwrap()
    }

    #[test]
    fn real_guardian_actors_run_rts_refresh_prepare_and_atomic_activation() {
        let authorization_key = [7; 32];
        let owner_cancel_seed = [14; 32];
        let owner_cancel_public_key = verifying_key_bytes(&signing_key(owner_cancel_seed));
        let initial = frost_dealer_split(3, 4, [8; 32]).unwrap();
        let old_ref = ConfigRef {
            config_id: [1; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: 1,
            epoch_binding: [2; 32],
        };
        let successor_ref = ConfigRef {
            guardian_epoch: 2,
            epoch_binding: [3; 32],
            ..old_ref
        };

        let signer_seeds = [[11; 32], [12; 32], [13; 32]];
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

        let guardian_signing_seeds = (1..=5_u16)
            .map(|id| (id, [u8::try_from(40 + id).unwrap(); 32]))
            .collect::<BTreeMap<_, _>>();
        let guardian_identity_seeds = (1..=5_u16)
            .map(|id| (id, [u8::try_from(70 + id).unwrap(); 32]))
            .collect::<BTreeMap<_, _>>();
        let old_routes = (1..=4_u16)
            .map(|id| GuardianRouteV3 {
                guardian_index: id,
                opaque_slot_id: [u8::try_from(90 + id).unwrap(); 32],
                mailbox: mailbox(1, id),
                guardian_public_key: verifying_key_bytes(&signing_key(guardian_signing_seeds[&id])),
                session_recipient_key: RecipientKeyPair::from_seed(guardian_identity_seeds[&id])
                    .public_key()
                    .to_vec(),
                operator_domain_commitment: [u8::try_from(100 + id).unwrap(); 32],
            })
            .collect::<Vec<_>>();
        let successor_ids = [1_u16, 2, 3, 5];
        let new_routes = successor_ids
            .iter()
            .map(|id| GuardianRouteV3 {
                guardian_index: *id,
                opaque_slot_id: [u8::try_from(110 + id).unwrap(); 32],
                mailbox: mailbox(2, *id),
                guardian_public_key: verifying_key_bytes(&signing_key(guardian_signing_seeds[id])),
                session_recipient_key: RecipientKeyPair::from_seed(guardian_identity_seeds[id])
                    .public_key()
                    .to_vec(),
                operator_domain_commitment: [u8::try_from(120 + id).unwrap(); 32],
            })
            .collect::<Vec<_>>();

        let ciphertext = b"already encrypted payload bytes; never decrypted during rotation";
        let fragments = erasure_encode(ciphertext, 3, 4).unwrap();
        let fragment_commitment =
            commit_ciphertext_fragments(&old_ref.config_id, old_ref.payload_generation, &fragments)
                .unwrap();
        let old_public_commitment = frost_public_package_digest(&initial.public_package).unwrap();
        let mut records = Vec::new();
        let mut leaves = Vec::new();
        for offset in 0..4 {
            let id = u16::try_from(offset + 1).unwrap();
            let policy = GuardianPolicyV3 {
                config_ref: old_ref,
                epoch_state: GuardianEpochState::Active,
                signer_set_commitment: signer_root,
                signer_count: 3,
                signer_threshold: 2,
                owner_cancel_public_key,
                minimum_recovery_delay: 1,
                guardian_material_root: [0; 32],
                dpss_suite: DpssSuiteId::default(),
                dpss_public_commitment: old_public_commitment,
                predecessor_capsule_hash: [0; 32],
                activation_qc_hash: None,
                drain_deadline: None,
            };
            let encrypted_dek_share = aead_encrypt(
                &guardian_share_key_v3(&authorization_key, &old_ref, id).unwrap(),
                [u8::try_from(10 + id).unwrap(); 24],
                &initial.shares[offset],
                &gp_wire::guardian_share_context_v3(&old_ref, id).unwrap(),
            )
            .unwrap();
            let encrypted_ciphertext_fragment = aead_encrypt(
                &guardian_fragment_key_v3(&authorization_key, &old_ref, id).unwrap(),
                [u8::try_from(20 + id).unwrap(); 24],
                &fragments[offset],
                &gp_wire::guardian_fragment_context_v3(&old_ref, id, id).unwrap(),
            )
            .unwrap();
            let mut custody_bytes = encrypted_dek_share.nonce.to_vec();
            custody_bytes.extend_from_slice(&encrypted_dek_share.ciphertext);
            custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.nonce);
            custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.ciphertext);
            let record = GuardianRecordV3 {
                opaque_slot_id: old_routes[offset].opaque_slot_id,
                guardian_index: id,
                fragment_index: id,
                encrypted_ciphertext_fragment,
                encrypted_dek_share,
                merkle_path_proof: vec![],
                custody_root: custody_commit(&custody_bytes).unwrap().root,
                policy,
            };
            let leaf = PreparedRecordLeaf {
                guardian_index: id,
                fragment_index: id,
                opaque_slot_id: record.opaque_slot_id,
                encrypted_share_hash: hash_aead(&record.encrypted_dek_share),
                fragment_hash: hash_aead(&record.encrypted_ciphertext_fragment),
                policy_hash: sha256(&gp_wire::guardian_policy_body_v3(&record.policy).unwrap()),
            };
            leaves.push(sha256(&gp_wire::prepared_record_leaf_v3(&leaf).unwrap()));
            records.push(record);
        }
        let (old_material_root, old_proofs) = merkle_commit(&leaves).unwrap();
        for (record, proof) in records.iter_mut().zip(old_proofs) {
            record.policy.guardian_material_root = old_material_root;
            record.merkle_path_proof = proof;
        }
        let mut old_capsule = ConfigCapsuleV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: old_ref,
            capsule_hash: [0; 32],
            predecessor_capsule_hash: [0; 32],
            signer_count: 3,
            signer_threshold: 2,
            guardian_count: 4,
            guardian_threshold: 3,
            minimum_recovery_delay: 1,
            max_request_lifetime: 100,
            signer_set_commitment: signer_root,
            owner_cancel_public_key,
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: old_public_commitment,
            ciphertext_fragment_root: fragment_commitment.root,
            guardian_material_root: old_material_root,
            encrypted_recovery_descriptor: AeadCiphertext {
                nonce: [15; 24],
                ciphertext: vec![16; 80],
            },
            activation_certificate: None,
            activation_qc: None,
        };
        old_capsule.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&old_capsule).unwrap());

        let witness_seeds = [[21; 32], [22; 32], [23; 32], [24; 32]];
        let witnesses = witness_seeds
            .iter()
            .enumerate()
            .map(|(offset, seed)| WitnessPin {
                witness_id: u16::try_from(offset + 1).unwrap(),
                mailbox: format!("https://w{offset}.invalid"),
                public_key: verifying_key_bytes(&signing_key(*seed)),
            })
            .collect::<Vec<_>>();
        let card = RecoveryCardV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: old_ref.config_id,
            signer_mailboxes: vec!["opaque-signer".into()],
            signer_set_commitment: signer_root,
            owner_cancel_public_key: old_capsule.owner_cancel_public_key,
            witness_fault_bound: 1,
            witnesses,
            relay_bases: vec!["https://relay.invalid".into()],
        };
        let mut entries = BTreeMap::new();
        for (offset, record) in records.into_iter().enumerate() {
            let id = u16::try_from(offset + 1).unwrap();
            entries.insert(
                id,
                GuardianRotationEntryV3 {
                    provision: crate::types::GuardianRotationProvisionV3 {
                        mailbox: old_routes[offset].mailbox.clone(),
                        signing_seed: guardian_signing_seeds[&id],
                        signing_public_key: old_routes[offset].guardian_public_key,
                        recovery_card: card.clone(),
                        predecessor_capsule: old_capsule.clone(),
                        signer_public_keys: signer_public_keys.clone(),
                        epoch_store: gp_storage::GuardianEpochStore::new(
                            record,
                            old_capsule.capsule_hash,
                        ),
                    },
                    sessions: BTreeMap::new(),
                    recoveries: BTreeMap::new(),
                },
            );
        }
        entries.insert(
            5,
            GuardianRotationEntryV3 {
                provision: crate::types::GuardianRotationProvisionV3 {
                    mailbox: new_routes[3].mailbox.clone(),
                    signing_seed: guardian_signing_seeds[&5],
                    signing_public_key: new_routes[3].guardian_public_key,
                    recovery_card: card.clone(),
                    predecessor_capsule: old_capsule.clone(),
                    signer_public_keys: signer_public_keys.clone(),
                    epoch_store: gp_storage::GuardianEpochStore::new_candidate(
                        old_ref,
                        old_capsule.capsule_hash,
                    ),
                },
                sessions: BTreeMap::new(),
                recoveries: BTreeMap::new(),
            },
        );

        let coordinator = RecipientKeyPair::from_seed([30; 32]);
        let context = RotationContext {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: old_ref,
            rotation_id: [31; 32],
            predecessor_capsule_hash: old_capsule.capsule_hash,
            recipient_key: coordinator.public_key().to_vec(),
            nonce: [32; 32],
            issued_at: 1,
            expiry: 1_000,
        };
        let mut plan = RotationPlan {
            context: context.clone(),
            intent_hash: [33; 32],
            predecessor: old_ref,
            successor: successor_ref,
            old_roster: old_routes.clone(),
            new_roster: new_routes.clone(),
            old_roster_commitment: [0; 32],
            new_roster_commitment: [0; 32],
            old_guardian_threshold: 3,
            new_guardian_threshold: 3,
            data_shards: 3,
            total_shards: 4,
            dpss_suite: DpssSuiteId::default(),
            dpss_session_id: [34; 32],
            dpss_qualified_set_commitment: [35; 32],
            minimum_delay_secs: 1,
            preparation_deadline: 900,
            drain_deadline: 950,
        };
        plan.old_roster_commitment =
            sha256(&gp_wire::guardian_roster_v3(&plan.old_roster).unwrap());
        plan.new_roster_commitment =
            sha256(&gp_wire::guardian_roster_v3(&plan.new_roster).unwrap());
        let plan_hash = sha256(&gp_wire::rotation_plan(&plan).unwrap());

        let mut begin_votes = Vec::new();
        for offset in 0..2 {
            let key = signing_key(signer_seeds[offset]);
            let mut vote = SignerRotationBeginVote {
                context: context.clone(),
                intent_hash: plan.intent_hash,
                plan_hash,
                old_roster_commitment: plan.old_roster_commitment,
                new_roster_commitment: plan.new_roster_commitment,
                signer_id: u16::try_from(offset + 1).unwrap(),
                signer_public_key: verifying_key_bytes(&key),
                signer_membership_proof: signer_proofs[offset].clone(),
                signer_signature: vec![],
            };
            vote.signer_signature =
                sign(&key, &gp_wire::signer_rotation_begin_vote(&vote).unwrap());
            begin_votes.push(vote);
        }
        let begin = BeginRotationCertificate {
            context: context.clone(),
            intent_hash: plan.intent_hash,
            plan_hash,
            old_roster_commitment: plan.old_roster_commitment,
            new_roster_commitment: plan.new_roster_commitment,
            not_before_wall: 2,
            votes: begin_votes,
        };
        let begin_hash = sha256(&gp_wire::begin_rotation_certificate(&begin).unwrap());
        let mut release_votes = Vec::new();
        for offset in 0..2 {
            let key = signing_key(signer_seeds[offset]);
            let mut vote = SignerRotationReleaseVote {
                context: context.clone(),
                plan_hash,
                begin_certificate_hash: begin_hash,
                signer_id: u16::try_from(offset + 1).unwrap(),
                signer_public_key: verifying_key_bytes(&key),
                signer_membership_proof: signer_proofs[offset].clone(),
                signer_signature: vec![],
            };
            vote.signer_signature =
                sign(&key, &gp_wire::signer_rotation_release_vote(&vote).unwrap());
            release_votes.push(vote);
        }
        let release = RotationReleaseCertificate {
            context: context.clone(),
            plan_hash,
            begin_certificate_hash: begin_hash,
            votes: release_votes,
        };
        let release_hash = sha256(&gp_wire::rotation_release_certificate(&release).unwrap());

        for id in 1..=5_u16 {
            let response = call(
                entries.get_mut(&id).unwrap(),
                guardian_identity_seeds[&id],
                GuardianRotationRequestV3::Begin {
                    plan: plan.clone(),
                    certificate: begin.clone(),
                },
                100,
            );
            assert!(matches!(
                response,
                GuardianRotationResponseV3::BeginAccepted { .. }
            ));
        }

        let mut old_grants = BTreeMap::new();
        for id in 1..=4_u16 {
            let mut grant = gp_types::OldShareUnlockGrant {
                context: context.clone(),
                plan_hash,
                release_certificate_hash: release_hash,
                old_guardian_index: id,
                encrypted_unwrap_key: empty_sealed(),
                encrypted_fragment_key: empty_sealed(),
            };
            let recipient = RecipientKeyPair::from_seed(guardian_identity_seeds[&id]);
            grant.encrypted_unwrap_key = seal_to_recipient(
                recipient.public_key(),
                [u8::try_from(130 + id).unwrap(); 32],
                [u8::try_from(140 + id).unwrap(); 24],
                &guardian_share_key_v3(&authorization_key, &old_ref, id).unwrap(),
                &gp_wire::old_share_unlock_grant_payload_context(&grant, false).unwrap(),
            )
            .unwrap();
            grant.encrypted_fragment_key = seal_to_recipient(
                recipient.public_key(),
                [u8::try_from(150 + id).unwrap(); 32],
                [u8::try_from(160 + id).unwrap(); 24],
                &guardian_fragment_key_v3(&authorization_key, &old_ref, id).unwrap(),
                &gp_wire::old_share_unlock_grant_payload_context(&grant, true).unwrap(),
            )
            .unwrap();
            old_grants.insert(id, grant);
        }

        let helpers = vec![1_u16, 2, 3];
        let mut repair1_by_recipient: BTreeMap<u16, Vec<gp_types::SealedMessage>> = BTreeMap::new();
        let mut fragment_contributions = Vec::new();
        for id in &helpers {
            let response = call(
                entries.get_mut(id).unwrap(),
                guardian_identity_seeds[id],
                GuardianRotationRequestV3::RepairRound1 {
                    plan: plan.clone(),
                    begin_certificate: begin.clone(),
                    release_certificate: release.clone(),
                    unlock_grant: old_grants[id].clone(),
                    helper_ids: helpers.clone(),
                    replacement_id: 5,
                },
                101,
            );
            let GuardianRotationResponseV3::DpssDeliveries {
                deliveries,
                fragment,
            } = response
            else {
                panic!("expected repair round-1 deliveries")
            };
            fragment_contributions.push(fragment.unwrap());
            for delivery in deliveries {
                let recipient = old_routes
                    .iter()
                    .find(|route| route.mailbox == delivery.target_mailbox)
                    .unwrap()
                    .guardian_index;
                repair1_by_recipient
                    .entry(recipient)
                    .or_default()
                    .push(delivery.sealed_message);
            }
        }
        // Crash/restart after secret-bearing RTS round 1 preserves only an
        // encrypted node-local journal and resumes with the same identity key.
        for id in &helpers {
            let encoded = serde_json::to_vec(&entries[id]).unwrap();
            let share_encoding =
                serde_json::to_string(&initial.shares[usize::from(*id - 1)]).unwrap();
            assert!(!String::from_utf8_lossy(&encoded).contains(&share_encoding));
            let rebooted = serde_json::from_slice(&encoded).unwrap();
            entries.insert(*id, rebooted);
        }
        let mut sigmas = Vec::new();
        for id in &helpers {
            let response = call(
                entries.get_mut(id).unwrap(),
                guardian_identity_seeds[id],
                GuardianRotationRequestV3::RepairRound2 {
                    plan: plan.clone(),
                    incoming: repair1_by_recipient.remove(id).unwrap(),
                    replacement_id: 5,
                },
                101,
            );
            let GuardianRotationResponseV3::DpssDeliveries { deliveries, .. } = response else {
                panic!("expected repair round-2 delivery")
            };
            sigmas.push(deliveries.into_iter().next().unwrap().sealed_message);
        }
        let response = call(
            entries.get_mut(&5).unwrap(),
            guardian_identity_seeds[&5],
            GuardianRotationRequestV3::RepairFinalize {
                plan: plan.clone(),
                incoming: sigmas,
                old_public_package: initial.public_package.clone(),
            },
            101,
        );
        let GuardianRotationResponseV3::RepairStored {
            expanded_public_package,
            ..
        } = response
        else {
            panic!("expected repaired share")
        };

        let mut refresh1_by_recipient: BTreeMap<u16, Vec<gp_types::SealedMessage>> =
            BTreeMap::new();
        for id in successor_ids {
            let response = call(
                entries.get_mut(&id).unwrap(),
                guardian_identity_seeds[&id],
                GuardianRotationRequestV3::RefreshRound1 {
                    plan: plan.clone(),
                    begin_certificate: (id != 5).then_some(begin.clone()),
                    release_certificate: (id != 5).then_some(release.clone()),
                    old_share_grant: (id != 5).then(|| old_grants[&id].clone()),
                },
                101,
            );
            let GuardianRotationResponseV3::DpssDeliveries { deliveries, .. } = response else {
                panic!("expected refresh round-1 deliveries")
            };
            for delivery in deliveries {
                let recipient = new_routes
                    .iter()
                    .find(|route| route.mailbox == delivery.target_mailbox)
                    .unwrap()
                    .guardian_index;
                refresh1_by_recipient
                    .entry(recipient)
                    .or_default()
                    .push(delivery.sealed_message);
            }
        }
        let mut refresh2_by_recipient: BTreeMap<u16, Vec<gp_types::SealedMessage>> =
            BTreeMap::new();
        for id in successor_ids {
            let response = call(
                entries.get_mut(&id).unwrap(),
                guardian_identity_seeds[&id],
                GuardianRotationRequestV3::RefreshRound2 {
                    plan: plan.clone(),
                    incoming: refresh1_by_recipient.remove(&id).unwrap(),
                },
                101,
            );
            let GuardianRotationResponseV3::DpssDeliveries { deliveries, .. } = response else {
                panic!("expected refresh round-2 deliveries")
            };
            for delivery in deliveries {
                let recipient = new_routes
                    .iter()
                    .find(|route| route.mailbox == delivery.target_mailbox)
                    .unwrap()
                    .guardian_index;
                refresh2_by_recipient
                    .entry(recipient)
                    .or_default()
                    .push(delivery.sealed_message);
            }
        }
        let mut refreshed_public = None;
        let mut dpss_result_commitment = None;
        for id in successor_ids {
            let response = call(
                entries.get_mut(&id).unwrap(),
                guardian_identity_seeds[&id],
                GuardianRotationRequestV3::RefreshFinalize {
                    plan: plan.clone(),
                    incoming: refresh2_by_recipient.remove(&id).unwrap(),
                    old_public_package: expanded_public_package.clone(),
                },
                101,
            );
            let GuardianRotationResponseV3::RefreshFinalized {
                public_package,
                dpss_result_commitment: commitment,
                ..
            } = response
            else {
                panic!("expected refresh finalization")
            };
            if let Some(expected) = &refreshed_public {
                assert_eq!(expected, &public_package);
            }
            if let Some(expected) = dpss_result_commitment {
                assert_eq!(expected, commitment);
            }
            refreshed_public = Some(public_package);
            dpss_result_commitment = Some(commitment);
        }
        let refreshed_public = refreshed_public.unwrap();
        let dpss_result_commitment = dpss_result_commitment.unwrap();

        let recovered_ciphertext = erasure_reconstruct(
            &fragment_contributions
                .iter()
                .map(|fragment| {
                    (
                        fragment.fragment_index,
                        fragment.ciphertext_fragment.clone(),
                    )
                })
                .collect::<Vec<_>>(),
            3,
            4,
            ciphertext.len(),
        )
        .unwrap();
        assert_eq!(recovered_ciphertext, ciphertext);
        let successor_fragments = erasure_encode(&recovered_ciphertext, 3, 4).unwrap();

        let mut successor_leaves = Vec::new();
        for (offset, id) in successor_ids.iter().enumerate() {
            let mut grant = gp_types::NewShareWrapGrant {
                context: context.clone(),
                plan_hash,
                release_certificate_hash: release_hash,
                new_guardian_index: *id,
                encrypted_wrap_key: empty_sealed(),
                encrypted_fragment_key: empty_sealed(),
            };
            let recipient = RecipientKeyPair::from_seed(guardian_identity_seeds[id]);
            grant.encrypted_wrap_key = seal_to_recipient(
                recipient.public_key(),
                [u8::try_from(170 + id).unwrap(); 32],
                [u8::try_from(180 + id).unwrap(); 24],
                &guardian_share_key_v3(&authorization_key, &successor_ref, *id).unwrap(),
                &gp_wire::new_share_wrap_grant_payload_context(&grant, false).unwrap(),
            )
            .unwrap();
            grant.encrypted_fragment_key = seal_to_recipient(
                recipient.public_key(),
                [u8::try_from(190 + id).unwrap(); 32],
                [u8::try_from(200 + id).unwrap(); 24],
                &guardian_fragment_key_v3(&authorization_key, &successor_ref, *id).unwrap(),
                &gp_wire::new_share_wrap_grant_payload_context(&grant, true).unwrap(),
            )
            .unwrap();
            let policy = GuardianPolicyV3 {
                config_ref: successor_ref,
                epoch_state: GuardianEpochState::Prepared,
                signer_set_commitment: signer_root,
                signer_count: 3,
                signer_threshold: 2,
                owner_cancel_public_key: old_capsule.owner_cancel_public_key,
                minimum_recovery_delay: 1,
                guardian_material_root: [0; 32],
                dpss_suite: DpssSuiteId::default(),
                dpss_public_commitment: dpss_result_commitment,
                predecessor_capsule_hash: old_capsule.capsule_hash,
                activation_qc_hash: None,
                drain_deadline: None,
            };
            if offset == 0 {
                let mut invalid_proof = fragment_commitment.proofs[offset].clone();
                invalid_proof[0] ^= 1;
                let error = handle_guardian_rotation_v3(
                    entries.get_mut(id).unwrap(),
                    &guardian_identity_seeds[id],
                    GuardianRotationRequestV3::StageMaterial {
                        plan: plan.clone(),
                        wrap_grant: grant.clone(),
                        fragment_index: u16::try_from(offset + 1).unwrap(),
                        ciphertext_fragment: successor_fragments[offset].clone(),
                        ciphertext_fragment_proof: invalid_proof,
                        policy: policy.clone(),
                        opaque_slot_id: new_routes[offset].opaque_slot_id,
                    },
                    10,
                    101,
                    "test-boot",
                    true,
                )
                .unwrap_err();
                assert!(error.to_string().contains("not committed"));
            }
            let response = call(
                entries.get_mut(id).unwrap(),
                guardian_identity_seeds[id],
                GuardianRotationRequestV3::StageMaterial {
                    plan: plan.clone(),
                    wrap_grant: grant,
                    fragment_index: u16::try_from(offset + 1).unwrap(),
                    ciphertext_fragment: successor_fragments[offset].clone(),
                    ciphertext_fragment_proof: fragment_commitment.proofs[offset].clone(),
                    policy,
                    opaque_slot_id: new_routes[offset].opaque_slot_id,
                },
                101,
            );
            let coordinator_view = serde_json::to_string(&response).unwrap();
            assert!(!coordinator_view.contains("encrypted_dek_share"));
            assert!(!coordinator_view.contains("record_draft"));
            let GuardianRotationResponseV3::RefreshMaterialStaged {
                leaf,
                public_package,
                ..
            } = response
            else {
                panic!("expected staged successor material")
            };
            assert_eq!(public_package, refreshed_public);
            successor_leaves.push(sha256(&gp_wire::prepared_record_leaf_v3(&leaf).unwrap()));
        }
        let (successor_root, successor_proofs) = merkle_commit(&successor_leaves).unwrap();
        let mut prepared_acks = Vec::new();
        for (offset, id) in successor_ids.iter().enumerate() {
            let response = call(
                entries.get_mut(id).unwrap(),
                guardian_identity_seeds[id],
                GuardianRotationRequestV3::PrepareCommit {
                    plan: plan.clone(),
                    guardian_material_root: successor_root,
                    merkle_path_proof: successor_proofs[offset].clone(),
                    dpss_result_commitment,
                },
                101,
            );
            let GuardianRotationResponseV3::Prepared(ack) = response else {
                panic!("expected durable Prepared ack")
            };
            prepared_acks.push(ack);
        }
        // A crash after all PREPARED writes but before activation cannot make
        // those records ACTIVE or remove any predecessor ACTIVE record.
        for id in successor_ids {
            let encoded = serde_json::to_vec(&entries[&id]).unwrap();
            let rebooted: GuardianRotationEntryV3 = serde_json::from_slice(&encoded).unwrap();
            assert!(rebooted.provision.epoch_store.prepared.is_some());
            if id != 5 {
                assert!(rebooted.provision.epoch_store.active.is_some());
            } else {
                assert!(rebooted.provision.epoch_store.active.is_none());
            }
            entries.insert(id, rebooted);
        }
        let mut handoff_acks = Vec::new();
        for id in &helpers {
            let response = call(
                entries.get_mut(id).unwrap(),
                guardian_identity_seeds[id],
                GuardianRotationRequestV3::HandoffComplete {
                    plan: plan.clone(),
                    dpss_result_commitment,
                },
                101,
            );
            let GuardianRotationResponseV3::Handoff(ack) = response else {
                panic!("expected handoff ack")
            };
            handoff_acks.push(ack);
        }

        let successor_descriptor = AeadCiphertext {
            nonce: [210; 24],
            ciphertext: vec![211; 96],
        };
        let ready = gp_types::RotationReadyCertificate {
            context: context.clone(),
            plan_hash,
            successor: successor_ref,
            dpss_result_commitment,
            guardian_material_root: successor_root,
            encrypted_descriptor_hash: hash_aead(&successor_descriptor),
            prepared_acks,
            old_handoff_acks: handoff_acks,
        };
        let mut mismatched_root = ready.clone();
        mismatched_root.prepared_acks[0].guardian_material_root[0] ^= 1;
        assert!(gp_wire::rotation_ready_certificate(&mismatched_root).is_err());
        let ready_hash = sha256(&gp_wire::rotation_ready_certificate(&ready).unwrap());
        let mut successor_capsule = ConfigCapsuleV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: successor_ref,
            capsule_hash: [0; 32],
            predecessor_capsule_hash: old_capsule.capsule_hash,
            signer_count: 3,
            signer_threshold: 2,
            guardian_count: 4,
            guardian_threshold: 3,
            minimum_recovery_delay: 1,
            max_request_lifetime: 100,
            signer_set_commitment: signer_root,
            owner_cancel_public_key: old_capsule.owner_cancel_public_key,
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: dpss_result_commitment,
            ciphertext_fragment_root: old_capsule.ciphertext_fragment_root,
            guardian_material_root: successor_root,
            encrypted_recovery_descriptor: successor_descriptor,
            activation_certificate: None,
            activation_qc: None,
        };
        successor_capsule.capsule_hash =
            sha256(&gp_wire::config_capsule_body_v3(&successor_capsule).unwrap());
        let mut activate_votes = Vec::new();
        for offset in 0..2 {
            let key = signing_key(signer_seeds[offset]);
            let mut vote = SignerRotationActivateVote {
                context: context.clone(),
                plan_hash,
                ready_certificate_hash: ready_hash,
                successor_capsule_hash: successor_capsule.capsule_hash,
                signer_id: u16::try_from(offset + 1).unwrap(),
                signer_public_key: verifying_key_bytes(&key),
                signer_membership_proof: signer_proofs[offset].clone(),
                signer_signature: vec![],
            };
            vote.signer_signature = sign(
                &key,
                &gp_wire::signer_rotation_activate_vote(&vote).unwrap(),
            );
            activate_votes.push(vote);
        }
        let activation = RotationActivateCertificate {
            context: context.clone(),
            plan_hash,
            ready_certificate_hash: ready_hash,
            successor: successor_ref,
            successor_capsule_hash: successor_capsule.capsule_hash,
            votes: activate_votes,
        };
        let activation_hash = sha256(&gp_wire::rotation_activate_certificate(&activation).unwrap());
        let mut witness_acks = Vec::new();
        for (offset, witness_seed) in witness_seeds.iter().enumerate().take(3) {
            let key = signing_key(*witness_seed);
            let mut ack = WitnessActivationAck {
                context: context.clone(),
                plan_hash,
                activation_certificate_hash: activation_hash,
                witness_id: u16::try_from(offset + 1).unwrap(),
                predecessor_epoch: 1,
                predecessor_capsule_hash: old_capsule.capsule_hash,
                successor_epoch: 2,
                successor_capsule_hash: successor_capsule.capsule_hash,
                witness_public_key: verifying_key_bytes(&key),
                witness_signature: vec![],
            };
            ack.witness_signature = sign(&key, &gp_wire::witness_activation_ack(&ack).unwrap());
            witness_acks.push(ack);
        }
        successor_capsule.activation_certificate = Some(activation);
        successor_capsule.activation_qc = Some(EpochActivationQc {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: old_ref.config_id,
            rotation_id: context.rotation_id,
            predecessor_epoch: 1,
            predecessor_capsule_hash: old_capsule.capsule_hash,
            successor_epoch: 2,
            successor_capsule_hash: successor_capsule.capsule_hash,
            activation_certificate_hash: activation_hash,
            witness_fault_bound: 1,
            witness_acks,
        });

        for id in 1..=5_u16 {
            let response = call(
                entries.get_mut(&id).unwrap(),
                guardian_identity_seeds[&id],
                GuardianRotationRequestV3::Activate {
                    plan: plan.clone(),
                    activated_capsule: successor_capsule.clone(),
                    drain_deadline: 1_000,
                },
                101,
            );
            assert!(matches!(
                response,
                GuardianRotationResponseV3::Activated { guardian_epoch: 2 }
            ));
        }
        assert!(entries[&4].provision.epoch_store.active.is_none());
        assert!(entries[&4].provision.epoch_store.draining.contains_key(&1));
        assert!(entries[&5].provision.epoch_store.active.is_some());

        let mut recovered_shares = Vec::new();
        for id in [1_u16, 2, 5] {
            let record = entries[&id].provision.epoch_store.active.as_ref().unwrap();
            let share = aead_decrypt(
                &guardian_share_key_v3(&authorization_key, &successor_ref, id).unwrap(),
                &record.encrypted_dek_share,
                &gp_wire::guardian_share_context_v3(&successor_ref, id).unwrap(),
            )
            .unwrap();
            recovered_shares.push(EpochFrostShare {
                config_ref: successor_ref,
                encoded_share: share,
            });
        }
        let recovered = frost_recover_dek_for_epoch(&recovered_shares, &successor_ref, 3).unwrap();
        assert_eq!(recovered, initial.dek);

        // The activated successor is not merely decryptable by test code: its
        // real guardian recovery actors enforce Begin -> local delay -> signer
        // Release and return only request/recipient-bound encrypted records.
        let recovery_recipient = RecipientKeyPair::from_seed([222; 32]);
        let recovery_request = RecoveryRequestV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: successor_ref,
            request_id: [223; 32],
            recovery_recipient_key: recovery_recipient.public_key().to_vec(),
            requested_at: 10,
            nonce: [224; 32],
            expiry: 100,
        };
        let recovery_digest =
            sha256(&gp_wire::recovery_request_digest_v3(&recovery_request).unwrap());
        let recovery_contributions = (0..2)
            .map(|offset| {
                let key = signing_key(signer_seeds[offset]);
                let mut contribution = SignerRecoveryContributionV3 {
                    request: recovery_request.clone(),
                    signer_id: u16::try_from(offset + 1).unwrap(),
                    signer_public_key: verifying_key_bytes(&key),
                    signer_membership_proof: signer_proofs[offset].clone(),
                    encrypted_authorization_share: empty_sealed(),
                    signer_signature: vec![],
                };
                contribution.signer_signature = sign(
                    &key,
                    &gp_wire::signer_recovery_contribution_v3(&contribution).unwrap(),
                );
                contribution
            })
            .collect::<Vec<_>>();
        let recovery_begin = BeginRecoveryCertificateV3 {
            request: recovery_request.clone(),
            request_digest: recovery_digest,
            signer_contributions: recovery_contributions,
        };
        for id in successor_ids {
            let response = crate::recovery_runtime::handle_guardian_recovery_v3(
                entries.get_mut(&id).unwrap(),
                crate::types::GuardianRecoveryRequestV3::Begin {
                    certificate: recovery_begin.clone(),
                },
                10,
                200,
                "recovery-boot",
                true,
            )
            .unwrap();
            assert!(matches!(
                response,
                crate::types::GuardianRecoveryResponseV3::BeginAccepted {
                    not_before_monotonic: 201
                }
            ));
        }
        let recovery_votes = (0..2)
            .map(|offset| {
                let key = signing_key(signer_seeds[offset]);
                let mut vote = SignerRecoveryReleaseVoteV3 {
                    request: recovery_request.clone(),
                    request_digest: recovery_digest,
                    signer_id: u16::try_from(offset + 1).unwrap(),
                    signer_public_key: verifying_key_bytes(&key),
                    signer_membership_proof: signer_proofs[offset].clone(),
                    signer_signature: vec![],
                };
                vote.signer_signature = sign(
                    &key,
                    &gp_wire::signer_recovery_release_vote_v3(&vote).unwrap(),
                );
                vote
            })
            .collect();
        let recovery_release = RecoveryReleaseCertificateV3 {
            request: recovery_request.clone(),
            request_digest: recovery_digest,
            votes: recovery_votes,
        };
        let cancel_recipient = RecipientKeyPair::from_seed([225; 32]);
        let mut cancellation = OwnerRecoveryCancelCertificateV3 {
            request: recovery_request.clone(),
            request_digest: recovery_digest,
            reason_code: 1,
            cancel_response_recipient_key: cancel_recipient.public_key().to_vec(),
            owner_cancel_public_key,
            owner_signature: vec![],
        };
        cancellation.owner_signature = sign(
            &signing_key(owner_cancel_seed),
            &gp_wire::owner_recovery_cancel_certificate_v3(&cancellation).unwrap(),
        );
        assert!(matches!(
            crate::recovery_runtime::handle_guardian_recovery_v3(
                entries.get_mut(&3).unwrap(),
                crate::types::GuardianRecoveryRequestV3::Cancel {
                    request: recovery_request.clone(),
                    certificate: cancellation,
                },
                11,
                201,
                "recovery-boot",
                true,
            )
            .unwrap(),
            crate::types::GuardianRecoveryResponseV3::Cancelled(_)
        ));
        assert!(
            crate::recovery_runtime::handle_guardian_recovery_v3(
                entries.get_mut(&3).unwrap(),
                crate::types::GuardianRecoveryRequestV3::Release {
                    request: recovery_request.clone(),
                    certificate: recovery_release.clone(),
                },
                12,
                202,
                "recovery-boot",
                true,
            )
            .is_err()
        );
        // A reboot changes the monotonic-time trust domain and fails closed;
        // retrying on the original boot in this deterministic actor test works.
        assert!(
            crate::recovery_runtime::handle_guardian_recovery_v3(
                entries.get_mut(&1).unwrap(),
                crate::types::GuardianRecoveryRequestV3::Release {
                    request: recovery_request.clone(),
                    certificate: recovery_release.clone(),
                },
                12,
                202,
                "different-boot",
                true,
            )
            .is_err()
        );
        let mut recovered_via_actors = Vec::new();
        let mut fragments_via_actors = Vec::new();
        for id in [1_u16, 2, 5] {
            let response = crate::recovery_runtime::handle_guardian_recovery_v3(
                entries.get_mut(&id).unwrap(),
                crate::types::GuardianRecoveryRequestV3::Release {
                    request: recovery_request.clone(),
                    certificate: recovery_release.clone(),
                },
                12,
                202,
                "recovery-boot",
                true,
            )
            .unwrap();
            let crate::types::GuardianRecoveryResponseV3::Contribution(contribution) = response
            else {
                panic!("expected guardian recovery contribution")
            };
            verify(
                &entries[&id].provision.signing_public_key,
                &gp_wire::guardian_recovery_contribution_v3(&contribution).unwrap(),
                &contribution.guardian_signature,
            )
            .unwrap();
            recovered_via_actors.push(EpochFrostShare {
                config_ref: contribution.config_ref,
                encoded_share: aead_decrypt(
                    &guardian_share_key_v3(
                        &authorization_key,
                        &successor_ref,
                        contribution.guardian_index,
                    )
                    .unwrap(),
                    &contribution.encrypted_dek_share,
                    &gp_wire::guardian_share_context_v3(
                        &successor_ref,
                        contribution.guardian_index,
                    )
                    .unwrap(),
                )
                .unwrap(),
            });
            fragments_via_actors.push((
                contribution.fragment_index,
                aead_decrypt(
                    &guardian_fragment_key_v3(
                        &authorization_key,
                        &successor_ref,
                        contribution.guardian_index,
                    )
                    .unwrap(),
                    &contribution.encrypted_ciphertext_fragment,
                    &gp_wire::guardian_fragment_context_v3(
                        &successor_ref,
                        contribution.guardian_index,
                        contribution.fragment_index,
                    )
                    .unwrap(),
                )
                .unwrap()
                .to_vec(),
            ));
        }
        assert_eq!(
            frost_recover_dek_for_epoch(&recovered_via_actors, &successor_ref, 3).unwrap(),
            initial.dek
        );
        assert_eq!(
            erasure_reconstruct(&fragments_via_actors, 3, 4, ciphertext.len()).unwrap(),
            ciphertext
        );
    }
}
