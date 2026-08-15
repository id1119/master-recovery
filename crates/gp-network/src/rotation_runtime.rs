//! Stateful protocol-v3 signer and guardian actor logic.
//!
//! HTTP handlers persist the mutated entry before returning a response. This
//! module contains no sockets or filesystem access and is reused by direct
//! integration tests.

use anyhow::{Result, bail};
use gp_crypto::{XWING_PUBLIC_KEY_LEN, hash_aead, seal_to_recipient, sha256, sign, signing_key};
use gp_types::{
    PROTOCOL_VERSION_V3, SignerRotationAbortVote, SignerRotationActivateVote,
    SignerRotationBeginVote, SignerRotationIntentContribution, SignerRotationReleaseVote,
};

use crate::{
    protocol::{random_id, random_nonce},
    rotation_protocol::{
        select_latest_epoch_v3, validate_abort_rotation_certificate_v3,
        validate_owner_rotation_cancel_witness_quorum_v3, validate_rotation_plan_against_intent_v3,
        validate_rotation_plan_v3, validate_rotation_ready_certificate_v3,
        witness_read_quorum_hash_v3,
    },
    types::{SignerRotationEntryV3, SignerRotationRequestV3, SignerRotationResponseV3},
};

pub fn handle_signer_rotation_v3(
    entry: &mut SignerRotationEntryV3,
    request: SignerRotationRequestV3,
    now: u64,
) -> Result<SignerRotationResponseV3> {
    let context = request.context();
    if context.protocol_version != PROTOCOL_VERSION_V3
        || context.config_ref.config_id != entry.provision.recovery_card.config_id
        || context.issued_at > now
        || context.expiry <= now
        || context.recipient_key.len() != XWING_PUBLIC_KEY_LEN
    {
        bail!("signer rejected malformed, stale, or recipient-mismatched rotation context");
    }

    match request {
        SignerRotationRequestV3::Intent {
            intent,
            witness_challenge,
            witness_reads,
        } => {
            let active = select_latest_epoch_v3(
                &entry.provision.recovery_card,
                &witness_challenge,
                &witness_reads,
            )?;
            if active.config_ref != intent.context.config_ref
                || active.capsule_hash != intent.context.predecessor_capsule_hash
                || intent.old_guardian_count != active.guardian_count
                || intent.old_guardian_threshold != active.guardian_threshold
                || intent.allowed_new_guardian_count.is_empty()
                || intent.allowed_new_guardian_threshold.is_empty()
                || intent.allowed_dpss_suites.is_empty()
                || intent.witness_read_qc_hash
                    != witness_read_quorum_hash_v3(&witness_challenge, &witness_reads)?
            {
                bail!("rotation intent does not bind the fresh active witness view");
            }
            let intent_transcript = gp_wire::rotation_intent(&intent)?;
            let intent_hash = sha256(&intent_transcript);
            gp_storage::SignerRotationStore::record_vote(
                &mut entry.security_state.intent_votes,
                intent.context.rotation_id,
                intent_hash,
            )?;
            let intent_key = hex::encode(intent.context.rotation_id);
            match entry.security_state.intents.get(&intent_key) {
                Some(existing) if existing != &intent => {
                    bail!("signer already approved a conflicting rotation Intent")
                }
                Some(_) => {}
                None => {
                    entry
                        .security_state
                        .intents
                        .insert(intent_key, intent.clone());
                }
            }
            entry.provision.active_capsule = active;
            entry.security_state.highest_observed_epoch.insert(
                hex::encode(intent.context.config_ref.config_id),
                intent.context.config_ref.guardian_epoch,
            );
            let encrypted_authorization_share = seal_to_recipient(
                &intent.context.recipient_key,
                random_id(),
                random_nonce(),
                &entry.provision.authorization_share,
                &gp_wire::rotation_intent_share_context_v3(
                    &intent.context,
                    &intent_hash,
                    entry.provision.signer_id,
                )?,
            )?;
            let mut contribution = SignerRotationIntentContribution {
                context: intent.context,
                intent_hash,
                signer_id: entry.provision.signer_id,
                signer_public_key: entry.provision.signing_public_key,
                signer_membership_proof: entry.provision.membership_proof.clone(),
                encrypted_authorization_share,
                signer_signature: vec![],
            };
            contribution.signer_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::signer_rotation_intent_contribution(&contribution)?,
            );
            Ok(SignerRotationResponseV3::IntentContribution(contribution))
        }
        SignerRotationRequestV3::Begin { intent_hash, plan } => {
            let rotation_key = hex::encode(plan.context.rotation_id);
            if entry
                .security_state
                .cancelled_rotations
                .contains_key(&rotation_key)
            {
                bail!("signer permanently rejected this cancelled rotation id");
            }
            let approved_intent =
                entry
                    .security_state
                    .intents
                    .get(&rotation_key)
                    .ok_or_else(|| {
                        anyhow::anyhow!("signer has no approved Intent for this rotation")
                    })?;
            let plan_hash = validate_rotation_plan_against_intent_v3(
                &plan,
                approved_intent,
                &entry.provision.active_capsule,
                now,
            )?;
            if plan.intent_hash != intent_hash
                || entry.security_state.intent_votes.get(&rotation_key) != Some(&intent_hash)
            {
                bail!("signer did not authorize this exact descriptor-open intent");
            }
            entry
                .security_state
                .lock_plan(plan.context.predecessor_capsule_hash, plan_hash)?;
            gp_storage::SignerRotationStore::record_vote(
                &mut entry.security_state.begin_votes,
                plan.context.rotation_id,
                plan_hash,
            )?;
            let mut vote = SignerRotationBeginVote {
                context: plan.context.clone(),
                intent_hash,
                plan_hash,
                old_roster_commitment: plan.old_roster_commitment,
                new_roster_commitment: plan.new_roster_commitment,
                signer_id: entry.provision.signer_id,
                signer_public_key: entry.provision.signing_public_key,
                signer_membership_proof: entry.provision.membership_proof.clone(),
                signer_signature: vec![],
            };
            vote.signer_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::signer_rotation_begin_vote(&vote)?,
            );
            Ok(SignerRotationResponseV3::BeginVote(vote))
        }
        SignerRotationRequestV3::Release {
            plan,
            begin_certificate,
        } => {
            let rotation_key = hex::encode(plan.context.rotation_id);
            if entry
                .security_state
                .cancelled_rotations
                .contains_key(&rotation_key)
            {
                bail!("signer refuses Release for a cancelled rotation");
            }
            let release_plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
            if entry.security_state.begin_votes.get(&rotation_key) != Some(&release_plan_hash) {
                bail!("signer never approved this exact Begin plan");
            }
            let begin_hash = crate::rotation_protocol::validate_begin_rotation_certificate_v3(
                &begin_certificate,
                &plan,
                &entry.provision.active_capsule,
                now,
            )?;
            if now < begin_certificate.not_before_wall {
                bail!("rotation delay has not elapsed");
            }
            let mut vote = SignerRotationReleaseVote {
                context: plan.context.clone(),
                plan_hash: release_plan_hash,
                begin_certificate_hash: begin_hash,
                signer_id: entry.provision.signer_id,
                signer_public_key: entry.provision.signing_public_key,
                signer_membership_proof: entry.provision.membership_proof.clone(),
                signer_signature: vec![],
            };
            let transcript = gp_wire::signer_rotation_release_vote(&vote)?;
            let vote_hash = sha256(&transcript);
            gp_storage::SignerRotationStore::record_vote(
                &mut entry.security_state.release_votes,
                plan.context.rotation_id,
                vote_hash,
            )?;
            vote.signer_signature = sign(&signing_key(entry.provision.signing_seed), &transcript);
            Ok(SignerRotationResponseV3::ReleaseVote(vote))
        }
        SignerRotationRequestV3::Activate {
            plan,
            ready_certificate,
            successor_capsule,
        } => {
            let rotation_key = hex::encode(plan.context.rotation_id);
            if entry
                .security_state
                .cancelled_rotations
                .contains_key(&rotation_key)
                || entry.security_state.begin_votes.get(&rotation_key)
                    != Some(&sha256(&gp_wire::rotation_plan(&plan)?))
                || !entry
                    .security_state
                    .release_votes
                    .contains_key(&rotation_key)
            {
                bail!("signer did not participate in this rotation's Begin and Release");
            }
            let ready_hash = validate_rotation_ready_certificate_v3(
                &ready_certificate,
                &plan,
                &entry.provision.active_capsule,
                now,
            )?;
            let capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&successor_capsule)?);
            if successor_capsule.config_ref != plan.successor
                || successor_capsule.predecessor_capsule_hash
                    != entry.provision.active_capsule.capsule_hash
                || successor_capsule.capsule_hash != capsule_hash
                || successor_capsule.signer_count != entry.provision.active_capsule.signer_count
                || successor_capsule.signer_threshold
                    != entry.provision.active_capsule.signer_threshold
                || successor_capsule.signer_set_commitment
                    != entry.provision.active_capsule.signer_set_commitment
                || successor_capsule.owner_cancel_public_key
                    != entry.provision.active_capsule.owner_cancel_public_key
                || successor_capsule.guardian_count != u16::try_from(plan.new_roster.len())?
                || successor_capsule.guardian_threshold != plan.new_guardian_threshold
                || successor_capsule.dpss_public_commitment
                    != ready_certificate.dpss_result_commitment
                || successor_capsule.guardian_material_root
                    != ready_certificate.guardian_material_root
                || hash_aead(&successor_capsule.encrypted_recovery_descriptor)
                    != ready_certificate.encrypted_descriptor_hash
                || successor_capsule.activation_certificate.is_some()
                || successor_capsule.activation_qc.is_some()
            {
                bail!("successor capsule does not match Ready and immutable signer policy");
            }
            let mut vote = SignerRotationActivateVote {
                context: plan.context.clone(),
                plan_hash: ready_certificate.plan_hash,
                ready_certificate_hash: ready_hash,
                successor_capsule_hash: capsule_hash,
                signer_id: entry.provision.signer_id,
                signer_public_key: entry.provision.signing_public_key,
                signer_membership_proof: entry.provision.membership_proof.clone(),
                signer_signature: vec![],
            };
            let transcript = gp_wire::signer_rotation_activate_vote(&vote)?;
            let vote_hash = sha256(&transcript);
            gp_storage::SignerRotationStore::record_vote(
                &mut entry.security_state.activate_votes,
                plan.context.rotation_id,
                vote_hash,
            )?;
            vote.signer_signature = sign(&signing_key(entry.provision.signing_seed), &transcript);
            Ok(SignerRotationResponseV3::ActivateVote(vote))
        }
        SignerRotationRequestV3::Abort {
            plan,
            state_at_abort,
            reason_code,
            response_recipient_key,
        } => {
            if response_recipient_key.len() != XWING_PUBLIC_KEY_LEN {
                bail!("signer Abort response recipient is malformed");
            }
            let rotation_key = hex::encode(plan.context.rotation_id);
            let plan_hash = validate_rotation_plan_v3(&plan, &entry.provision.active_capsule, now)?;
            if entry
                .security_state
                .cancelled_rotations
                .contains_key(&rotation_key)
                || entry.security_state.begin_votes.get(&rotation_key) != Some(&plan_hash)
                || entry
                    .security_state
                    .activate_votes
                    .contains_key(&rotation_key)
                || !matches!(
                    state_at_abort,
                    gp_types::RotationState::DelayPending
                        | gp_types::RotationState::Preparing
                        | gp_types::RotationState::Ready
                        | gp_types::RotationState::Activating
                )
            {
                bail!("signer refuses an unbegun, post-activation, or invalid-state abort");
            }
            let mut vote = SignerRotationAbortVote {
                context: plan.context,
                plan_hash,
                state_at_abort,
                reason_code,
                signer_id: entry.provision.signer_id,
                signer_public_key: entry.provision.signing_public_key,
                signer_membership_proof: entry.provision.membership_proof.clone(),
                signer_signature: vec![],
            };
            vote.signer_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::signer_rotation_abort_vote(&vote)?,
            );
            Ok(SignerRotationResponseV3::AbortVote(vote))
        }
        SignerRotationRequestV3::FinalizeAbort {
            plan,
            certificate,
            response_recipient_key,
        } => {
            if response_recipient_key.len() != XWING_PUBLIC_KEY_LEN {
                bail!("signer abort-finalization recipient is malformed");
            }
            let rotation_key = hex::encode(plan.context.rotation_id);
            validate_abort_rotation_certificate_v3(
                &certificate,
                &plan,
                &entry.provision.active_capsule,
                now,
            )?;
            let plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
            if entry.security_state.begin_votes.get(&rotation_key) != Some(&plan_hash)
                || entry
                    .security_state
                    .activate_votes
                    .contains_key(&rotation_key)
            {
                bail!("signer refuses to finalize an unbegun or post-Activate abort");
            }
            let predecessor_key = hex::encode(plan.context.predecessor_capsule_hash);
            if entry
                .security_state
                .predecessor_plan_locks
                .get(&predecessor_key)
                != Some(&plan_hash)
            {
                bail!("signer predecessor lock does not match the aborted plan");
            }
            entry.security_state.cancelled_rotations.insert(
                rotation_key,
                sha256(&gp_wire::abort_rotation_certificate(&certificate)?),
            );
            entry
                .security_state
                .predecessor_plan_locks
                .remove(&predecessor_key);
            Ok(SignerRotationResponseV3::AbortFinalized)
        }
        SignerRotationRequestV3::FinalizeOwnerCancel {
            plan,
            certificate,
            witness_acks,
            response_recipient_key,
        } => {
            if response_recipient_key.len() != XWING_PUBLIC_KEY_LEN {
                bail!("signer owner-cancel finalization recipient is malformed");
            }
            let cancel_hash = validate_owner_rotation_cancel_witness_quorum_v3(
                &certificate,
                &witness_acks,
                &entry.provision.recovery_card,
                &plan,
                &entry.provision.active_capsule,
                now,
            )?;
            let rotation_key = hex::encode(plan.context.rotation_id);
            if entry.security_state.cancelled_rotations.get(&rotation_key) == Some(&cancel_hash) {
                return Ok(SignerRotationResponseV3::OwnerCancelFinalized);
            }
            let plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
            if entry.security_state.begin_votes.get(&rotation_key) != Some(&plan_hash) {
                bail!("signer refuses to finalize owner cancellation for an unbegun plan");
            }
            let predecessor_key = hex::encode(plan.context.predecessor_capsule_hash);
            if entry
                .security_state
                .predecessor_plan_locks
                .get(&predecessor_key)
                != Some(&plan_hash)
            {
                bail!("signer predecessor lock does not match the owner-cancelled plan");
            }
            entry
                .security_state
                .cancelled_rotations
                .insert(rotation_key, cancel_hash);
            entry
                .security_state
                .predecessor_plan_locks
                .remove(&predecessor_key);
            Ok(SignerRotationResponseV3::OwnerCancelFinalized)
        }
    }
}
