//! Protocol-v3 certificate and config-witness quorum validation.
//!
//! This module is deliberately I/O-free. Network clients and servers feed it
//! already-decoded values; all security decisions are made over canonical
//! transcripts and card-pinned keys.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, bail};
use gp_crypto::{XWING_PUBLIC_KEY_LEN, merkle_verify, sha256, verify};
use gp_types::{
    AbortRotationCertificate, BeginRecoveryCertificateV3, BeginRotationCertificate,
    ConfigCapsuleV3, EpochReadChallenge, Id32, OwnerRecoveryCancelCertificateV3,
    PROTOCOL_VERSION_V3, RecoveryCardV3, RecoveryReleaseCertificateV3, RecoveryRequestV3,
    RotationActivateCertificate, RotationIntent, RotationPlan, RotationReadyCertificate,
    RotationReleaseCertificate, WitnessPin,
};

use crate::types::WitnessReadEnvelope;

fn required_witness_quorum(fault_bound: u16) -> Result<usize> {
    usize::from(fault_bound)
        .checked_mul(2)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("witness quorum size overflow"))
}

pub fn validate_recovery_card_v3(card: &RecoveryCardV3) -> Result<()> {
    if card.protocol_version != PROTOCOL_VERSION_V3 || card.witness_fault_bound == 0 {
        bail!("invalid protocol-v3 Recovery Card");
    }
    let required_roster = usize::from(card.witness_fault_bound)
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| anyhow::anyhow!("witness roster size overflow"))?;
    if card.witnesses.len() < required_roster {
        bail!("Recovery Card does not pin at least 3f+1 witnesses");
    }
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut mailboxes = BTreeSet::new();
    for pin in &card.witnesses {
        if pin.witness_id == 0
            || pin.mailbox.is_empty()
            || !ids.insert(pin.witness_id)
            || !keys.insert(pin.public_key)
            || !mailboxes.insert(pin.mailbox.as_str())
        {
            bail!("Recovery Card contains an invalid or duplicate witness pin");
        }
    }
    Ok(())
}

fn witness_pins(card: &RecoveryCardV3) -> BTreeMap<u16, &WitnessPin> {
    card.witnesses
        .iter()
        .map(|pin| (pin.witness_id, pin))
        .collect()
}

fn validate_signer_membership(
    signer_id: u16,
    signer_public_key: &[u8; 32],
    membership_proof: &[u8],
    capsule: &ConfigCapsuleV3,
) -> Result<()> {
    if signer_id == 0 || signer_id > capsule.signer_count {
        bail!("invalid signer id");
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

pub fn recovery_request_digest_v3(request: &RecoveryRequestV3) -> Result<Id32> {
    Ok(sha256(&gp_wire::recovery_request_digest_v3(request)?))
}

pub fn validate_recovery_request_for_ref_v3(
    request: &RecoveryRequestV3,
    capsule: &ConfigCapsuleV3,
    expected_config_ref: &gp_types::ConfigRef,
    now: u64,
) -> Result<Id32> {
    if request.protocol_version != PROTOCOL_VERSION_V3
        || &request.config_ref != expected_config_ref
        || request.config_ref.config_id != capsule.config_ref.config_id
        || request.config_ref.payload_generation != capsule.config_ref.payload_generation
        || request.config_ref.authorization_epoch != capsule.config_ref.authorization_epoch
        || request.recovery_recipient_key.len() != gp_crypto::XWING_PUBLIC_KEY_LEN
        || request.requested_at > now
        || request.expiry <= now
        || request.expiry
            > request
                .requested_at
                .saturating_add(capsule.max_request_lifetime)
    {
        bail!("invalid, stale, expired, or recipient-mismatched v3 recovery request");
    }
    recovery_request_digest_v3(request)
}

pub fn validate_recovery_request_v3(
    request: &RecoveryRequestV3,
    capsule: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    validate_recovery_request_for_ref_v3(request, capsule, &capsule.config_ref, now)
}

pub fn validate_begin_recovery_certificate_v3(
    certificate: &BeginRecoveryCertificateV3,
    capsule: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    let digest = validate_recovery_request_v3(&certificate.request, capsule, now)?;
    gp_wire::begin_recovery_certificate_v3(certificate)?;
    if certificate.request_digest != digest {
        bail!("v3 Begin certificate has the wrong request digest");
    }
    let mut ids = BTreeSet::new();
    for contribution in &certificate.signer_contributions {
        if contribution.request != certificate.request || !ids.insert(contribution.signer_id) {
            bail!("duplicate or request-mismatched signer recovery contribution");
        }
        validate_signer_membership(
            contribution.signer_id,
            &contribution.signer_public_key,
            &contribution.signer_membership_proof,
            capsule,
        )?;
        verify(
            &contribution.signer_public_key,
            &gp_wire::signer_recovery_contribution_v3(contribution)?,
            &contribution.signer_signature,
        )?;
    }
    if ids.len() < usize::from(capsule.signer_threshold) {
        bail!("v3 Begin certificate has no signer threshold");
    }
    Ok(digest)
}

pub fn validate_recovery_release_certificate_for_ref_v3(
    certificate: &RecoveryReleaseCertificateV3,
    capsule: &ConfigCapsuleV3,
    expected_config_ref: &gp_types::ConfigRef,
    now: u64,
) -> Result<Id32> {
    let digest = validate_recovery_request_for_ref_v3(
        &certificate.request,
        capsule,
        expected_config_ref,
        now,
    )?;
    gp_wire::recovery_release_certificate_v3(certificate)?;
    if certificate.request_digest != digest {
        bail!("v3 Release certificate has the wrong request digest");
    }
    let mut ids = BTreeSet::new();
    for vote in &certificate.votes {
        if vote.request != certificate.request || !ids.insert(vote.signer_id) {
            bail!("duplicate or request-mismatched v3 Release vote");
        }
        validate_signer_membership(
            vote.signer_id,
            &vote.signer_public_key,
            &vote.signer_membership_proof,
            capsule,
        )?;
        verify(
            &vote.signer_public_key,
            &gp_wire::signer_recovery_release_vote_v3(vote)?,
            &vote.signer_signature,
        )?;
    }
    if ids.len() < usize::from(capsule.signer_threshold) {
        bail!("v3 Release certificate has no signer threshold");
    }
    Ok(digest)
}

pub fn validate_owner_recovery_cancel_for_ref_v3(
    certificate: &OwnerRecoveryCancelCertificateV3,
    request: &RecoveryRequestV3,
    capsule: &ConfigCapsuleV3,
    expected_config_ref: &gp_types::ConfigRef,
    now: u64,
) -> Result<Id32> {
    let digest = validate_recovery_request_for_ref_v3(request, capsule, expected_config_ref, now)?;
    if &certificate.request != request
        || certificate.request_digest != digest
        || certificate.owner_cancel_public_key != capsule.owner_cancel_public_key
    {
        bail!("owner cancellation does not bind the exact v3 recovery request");
    }
    verify(
        &certificate.owner_cancel_public_key,
        &gp_wire::owner_recovery_cancel_certificate_v3(certificate)?,
        &certificate.owner_signature,
    )?;
    Ok(digest)
}

pub fn validate_rotation_plan_v3(
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    let transcript = gp_wire::rotation_plan(plan)?;
    if plan.context.protocol_version != PROTOCOL_VERSION_V3
        || plan.context.config_ref != predecessor.config_ref
        || plan.context.predecessor_capsule_hash != predecessor.capsule_hash
        || plan.predecessor != predecessor.config_ref
        || !plan.successor.is_direct_successor_of(&plan.predecessor)
        || plan.context.issued_at > now
        || plan.context.expiry <= now
        || plan.preparation_deadline <= plan.context.issued_at
        || plan.drain_deadline <= plan.preparation_deadline
        || plan.minimum_delay_secs < predecessor.minimum_recovery_delay
        || plan.old_guardian_threshold != predecessor.guardian_threshold
        || plan.data_shards != predecessor.guardian_threshold
        || plan.total_shards != predecessor.guardian_count
        || plan.old_roster.len() != usize::from(predecessor.guardian_count)
        || plan.new_roster.len() != usize::from(plan.total_shards)
        || plan.new_guardian_threshold < 2
        || plan.new_guardian_threshold > u16::try_from(plan.new_roster.len())?
    {
        bail!("rotation plan is stale, malformed, or weakens immutable policy");
    }
    let old_commitment = sha256(&gp_wire::guardian_roster_v3(&plan.old_roster)?);
    let new_commitment = sha256(&gp_wire::guardian_roster_v3(&plan.new_roster)?);
    if old_commitment != plan.old_roster_commitment || new_commitment != plan.new_roster_commitment
    {
        bail!("rotation roster commitment mismatch");
    }
    Ok(sha256(&transcript))
}

/// Enforces the constraints approved before signer A shares were released.
/// The current routine-rotation profile is one-for-one replacement; the
/// removed participant id is committed in the Intent without publishing the
/// private roster.
pub fn validate_rotation_plan_against_intent_v3(
    plan: &RotationPlan,
    intent: &RotationIntent,
    predecessor: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    let plan_hash = validate_rotation_plan_v3(plan, predecessor, now)?;
    let intent_hash = sha256(&gp_wire::rotation_intent(intent)?);
    if plan.context != intent.context
        || plan.intent_hash != intent_hash
        || intent.old_guardian_count != predecessor.guardian_count
        || intent.old_guardian_threshold != predecessor.guardian_threshold
        || !intent
            .allowed_new_guardian_count
            .contains(&u16::try_from(plan.new_roster.len())?)
        || !intent
            .allowed_new_guardian_threshold
            .contains(&plan.new_guardian_threshold)
        || !intent.allowed_dpss_suites.contains(&plan.dpss_suite)
        || plan.dpss_qualified_set_commitment != plan.new_roster_commitment
        || plan.preparation_deadline <= now
    {
        bail!("rotation plan violates the signer-approved Intent constraints");
    }

    let old = plan
        .old_roster
        .iter()
        .map(|route| (route.guardian_index, route))
        .collect::<BTreeMap<_, _>>();
    let new = plan
        .new_roster
        .iter()
        .map(|route| (route.guardian_index, route))
        .collect::<BTreeMap<_, _>>();
    let removed = old
        .keys()
        .filter(|id| !new.contains_key(id))
        .copied()
        .collect::<Vec<_>>();
    let added = new
        .keys()
        .filter(|id| !old.contains_key(id))
        .copied()
        .collect::<Vec<_>>();
    if removed.len() != 1
        || added.len() != 1
        || sha256(&removed[0].to_be_bytes()) != intent.selection_constraints_commitment
    {
        bail!("routine rotation must replace the exact one guardian authorized by Intent");
    }

    for (id, old_route) in &old {
        if let Some(new_route) = new.get(id)
            && (new_route.guardian_public_key != old_route.guardian_public_key
                || new_route.session_recipient_key != old_route.session_recipient_key
                || new_route.operator_domain_commitment != old_route.operator_domain_commitment
                || new_route.opaque_slot_id == old_route.opaque_slot_id
                || new_route.mailbox == old_route.mailbox)
        {
            bail!("unchanged guardian identity changed or did not receive a fresh route");
        }
    }
    let old_keys = old
        .values()
        .map(|route| route.guardian_public_key)
        .collect::<BTreeSet<_>>();
    let new_keys = new
        .values()
        .map(|route| route.guardian_public_key)
        .collect::<BTreeSet<_>>();
    let new_mailboxes = new
        .values()
        .map(|route| route.mailbox.as_str())
        .collect::<BTreeSet<_>>();
    let new_slots = new
        .values()
        .map(|route| route.opaque_slot_id)
        .collect::<BTreeSet<_>>();
    let new_domains = new
        .values()
        .map(|route| route.operator_domain_commitment)
        .collect::<BTreeSet<_>>();
    if new_keys.len() != new.len()
        || new_mailboxes.len() != new.len()
        || new_slots.len() != new.len()
        || new_domains.len() != new.len()
        || old_keys.contains(&new[&added[0]].guardian_public_key)
    {
        bail!("successor roster contains a reused or duplicate guardian identity/route");
    }
    Ok(plan_hash)
}

pub fn validate_begin_rotation_certificate_v3(
    certificate: &BeginRotationCertificate,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    let plan_hash = validate_rotation_plan_v3(plan, predecessor, now)?;
    let transcript = gp_wire::begin_rotation_certificate(certificate)?;
    if certificate.context != plan.context
        || certificate.intent_hash != plan.intent_hash
        || certificate.plan_hash != plan_hash
        || certificate.old_roster_commitment != plan.old_roster_commitment
        || certificate.new_roster_commitment != plan.new_roster_commitment
        || plan.preparation_deadline <= now
        || certificate.not_before_wall
            < certificate
                .context
                .issued_at
                .saturating_add(plan.minimum_delay_secs)
    {
        bail!("Begin certificate does not bind the exact plan and delay");
    }
    let mut ids = BTreeSet::new();
    for vote in &certificate.votes {
        if !ids.insert(vote.signer_id) {
            bail!("duplicate signer Begin vote");
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
    }
    if ids.len() < usize::from(predecessor.signer_threshold) {
        bail!("Begin certificate has no signer threshold");
    }
    Ok(sha256(&transcript))
}

pub fn validate_rotation_release_certificate_v3(
    release: &RotationReleaseCertificate,
    begin: &BeginRotationCertificate,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    let begin_hash = validate_begin_rotation_certificate_v3(begin, plan, predecessor, now)?;
    let transcript = gp_wire::rotation_release_certificate(release)?;
    if release.context != plan.context
        || release.plan_hash != sha256(&gp_wire::rotation_plan(plan)?)
        || release.begin_certificate_hash != begin_hash
        || now < begin.not_before_wall
        || now >= plan.preparation_deadline
    {
        bail!("Release certificate is early or does not bind the exact Begin");
    }
    let mut ids = BTreeSet::new();
    for vote in &release.votes {
        if !ids.insert(vote.signer_id) {
            bail!("duplicate signer Release vote");
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
    }
    if ids.len() < usize::from(predecessor.signer_threshold) {
        bail!("Release certificate has no signer threshold");
    }
    Ok(sha256(&transcript))
}

pub fn validate_abort_rotation_certificate_v3(
    certificate: &AbortRotationCertificate,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    let plan_hash = validate_rotation_plan_v3(plan, predecessor, now)?;
    let transcript = gp_wire::abort_rotation_certificate(certificate)?;
    if certificate.context != plan.context
        || certificate.plan_hash != plan_hash
        || !matches!(
            certificate.state_at_abort,
            gp_types::RotationState::Proposed
                | gp_types::RotationState::DelayPending
                | gp_types::RotationState::Preparing
                | gp_types::RotationState::Ready
                | gp_types::RotationState::Activating
        )
    {
        bail!("Abort certificate is post-activation or plan-mismatched");
    }
    let mut signer_ids = BTreeSet::new();
    for vote in &certificate.votes {
        if vote.context != certificate.context
            || vote.plan_hash != certificate.plan_hash
            || vote.state_at_abort != certificate.state_at_abort
            || vote.reason_code != certificate.reason_code
            || !signer_ids.insert(vote.signer_id)
        {
            bail!("Abort certificate contains a duplicate or mismatched vote");
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
    }
    if signer_ids.len() < usize::from(predecessor.signer_threshold) {
        bail!("Abort certificate lacks a signer threshold");
    }
    Ok(sha256(&transcript))
}

pub fn validate_owner_rotation_cancel_witness_quorum_v3(
    certificate: &gp_types::OwnerRotationCancelCertificate,
    witness_acks: &[gp_types::WitnessRotationCancelAck],
    card: &RecoveryCardV3,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    validate_recovery_card_v3(card)?;
    let plan_hash = validate_rotation_plan_v3(plan, predecessor, now)?;
    if card.config_id != predecessor.config_ref.config_id
        || card.owner_cancel_public_key != predecessor.owner_cancel_public_key
        || certificate.context != plan.context
        || certificate.plan_hash != plan_hash
        || certificate.owner_cancel_public_key != predecessor.owner_cancel_public_key
        || certificate.cancel_response_recipient_key.len() != XWING_PUBLIC_KEY_LEN
    {
        bail!("owner rotation cancellation does not bind the active plan and card");
    }
    let cancel_transcript = gp_wire::owner_rotation_cancel_certificate(certificate)?;
    verify(
        &certificate.owner_cancel_public_key,
        &cancel_transcript,
        &certificate.owner_signature,
    )?;
    let cancel_hash = sha256(&cancel_transcript);
    let pins = witness_pins(card);
    let mut witness_ids = BTreeSet::new();
    for ack in witness_acks {
        let pin = pins
            .get(&ack.witness_id)
            .ok_or_else(|| anyhow::anyhow!("owner cancellation uses an unpinned witness"))?;
        if ack.protocol_version != PROTOCOL_VERSION_V3
            || ack.config_id != card.config_id
            || ack.rotation_id != plan.context.rotation_id
            || ack.plan_hash != plan_hash
            || ack.cancel_certificate_hash != cancel_hash
            || ack.witness_public_key != pin.public_key
            || !witness_ids.insert(ack.witness_id)
        {
            bail!("owner cancellation contains a duplicate or mismatched witness veto");
        }
        verify(
            &pin.public_key,
            &gp_wire::witness_rotation_cancel_ack(ack)?,
            &ack.witness_signature,
        )?;
    }
    if witness_ids.len() < required_witness_quorum(card.witness_fault_bound)? {
        bail!("owner cancellation lacks a 2f+1 witness veto quorum");
    }
    Ok(cancel_hash)
}

pub fn validate_rotation_ready_certificate_v3(
    ready: &RotationReadyCertificate,
    plan: &RotationPlan,
    predecessor: &ConfigCapsuleV3,
    now: u64,
) -> Result<Id32> {
    let plan_hash = validate_rotation_plan_v3(plan, predecessor, now)?;
    let transcript = gp_wire::rotation_ready_certificate(ready)?;
    if ready.context != plan.context
        || ready.plan_hash != plan_hash
        || ready.successor != plan.successor
        || now >= plan.preparation_deadline
        || ready.prepared_acks.len() != plan.new_roster.len()
        || ready.old_handoff_acks.len() < usize::from(plan.old_guardian_threshold)
    {
        bail!("Ready certificate is incomplete or plan-mismatched");
    }
    let new_keys = plan
        .new_roster
        .iter()
        .map(|route| (route.guardian_index, route.guardian_public_key))
        .collect::<BTreeMap<_, _>>();
    for ack in &ready.prepared_acks {
        let key = new_keys
            .get(&ack.new_guardian_index)
            .ok_or_else(|| anyhow::anyhow!("Prepared ack is from a non-successor guardian"))?;
        verify(
            key,
            &gp_wire::new_guardian_prepared_ack(ack)?,
            &ack.guardian_signature,
        )?;
    }
    let old_keys = plan
        .old_roster
        .iter()
        .map(|route| (route.guardian_index, route.guardian_public_key))
        .collect::<BTreeMap<_, _>>();
    for ack in &ready.old_handoff_acks {
        let key = old_keys
            .get(&ack.old_guardian_index)
            .ok_or_else(|| anyhow::anyhow!("handoff ack is from a non-predecessor guardian"))?;
        verify(
            key,
            &gp_wire::old_guardian_handoff_ack(ack)?,
            &ack.guardian_signature,
        )?;
    }
    Ok(sha256(&transcript))
}

pub fn witness_read_quorum_hash_v3(
    challenge: &EpochReadChallenge,
    reads: &[WitnessReadEnvelope],
) -> Result<Id32> {
    let mut ordered = reads.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|read| read.response.witness_id);
    let mut material = gp_wire::epoch_read_challenge(challenge)?;
    let mut ids = BTreeSet::new();
    for read in ordered {
        if !ids.insert(read.response.witness_id) {
            bail!("duplicate witness in read transcript");
        }
        material.extend_from_slice(&gp_wire::witness_epoch_read_response(&read.response)?);
        material.extend_from_slice(&read.capsule.capsule_hash);
    }
    Ok(sha256(&material))
}

fn validate_activate_certificate(
    capsule: &ConfigCapsuleV3,
    certificate: &RotationActivateCertificate,
) -> Result<Id32> {
    if certificate.successor != capsule.config_ref
        || certificate.successor_capsule_hash != capsule.capsule_hash
        || certificate.context.config_ref.config_id != capsule.config_ref.config_id
        || certificate.context.config_ref.payload_generation
            != capsule.config_ref.payload_generation
        || certificate.context.config_ref.authorization_epoch
            != capsule.config_ref.authorization_epoch
        || certificate
            .context
            .config_ref
            .guardian_epoch
            .saturating_add(1)
            != capsule.config_ref.guardian_epoch
        || certificate.context.predecessor_capsule_hash != capsule.predecessor_capsule_hash
    {
        bail!("Activate certificate does not bind the exact direct successor");
    }
    let transcript = gp_wire::rotation_activate_certificate(certificate)?;
    let mut signer_ids = BTreeSet::new();
    for vote in &certificate.votes {
        if !signer_ids.insert(vote.signer_id)
            || vote.signer_id == 0
            || vote.signer_id > capsule.signer_count
        {
            bail!("Activate certificate contains an invalid signer id");
        }
        let leaf = sha256(&gp_wire::signer_leaf(
            vote.signer_id,
            &vote.signer_public_key,
        )?);
        merkle_verify(
            capsule.signer_set_commitment,
            leaf,
            usize::from(vote.signer_id - 1),
            usize::from(capsule.signer_count),
            &vote.signer_membership_proof,
        )?;
        verify(
            &vote.signer_public_key,
            &gp_wire::signer_rotation_activate_vote(vote)?,
            &vote.signer_signature,
        )?;
    }
    if signer_ids.len() < usize::from(capsule.signer_threshold) {
        bail!("Activate certificate has no signer threshold");
    }
    Ok(sha256(&transcript))
}

pub fn validate_activated_capsule_v3(
    card: &RecoveryCardV3,
    capsule: &ConfigCapsuleV3,
) -> Result<()> {
    validate_recovery_card_v3(card)?;
    let body_hash = sha256(&gp_wire::config_capsule_body_v3(capsule)?);
    if capsule.protocol_version != PROTOCOL_VERSION_V3
        || capsule.config_ref.config_id != card.config_id
        || capsule.signer_set_commitment != card.signer_set_commitment
        || capsule.owner_cancel_public_key != card.owner_cancel_public_key
        || capsule.capsule_hash != body_hash
    {
        bail!("capsule does not match the Recovery Card or its canonical body");
    }

    if capsule.config_ref.guardian_epoch == 1 {
        if capsule.predecessor_capsule_hash != [0; 32]
            || capsule.activation_certificate.is_some()
            || capsule.activation_qc.is_some()
        {
            bail!("invalid genesis capsule");
        }
        return Ok(());
    }

    let certificate = capsule
        .activation_certificate
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("successor capsule has no Activate certificate"))?;
    let activation_certificate_hash = validate_activate_certificate(capsule, certificate)?;
    let qc = capsule
        .activation_qc
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("successor capsule has no activation QC"))?;
    gp_wire::epoch_activation_qc(qc)?;
    if qc.protocol_version != PROTOCOL_VERSION_V3
        || qc.config_id != card.config_id
        || qc.rotation_id != certificate.context.rotation_id
        || qc.predecessor_epoch != certificate.context.config_ref.guardian_epoch
        || qc.predecessor_capsule_hash != capsule.predecessor_capsule_hash
        || qc.successor_epoch != capsule.config_ref.guardian_epoch
        || qc.successor_capsule_hash != capsule.capsule_hash
        || qc.activation_certificate_hash != activation_certificate_hash
        || qc.witness_fault_bound != card.witness_fault_bound
    {
        bail!("activation QC does not bind the exact capsule and certificate");
    }
    let pins = witness_pins(card);
    let mut witness_ids = BTreeSet::new();
    for ack in &qc.witness_acks {
        let pin = pins
            .get(&ack.witness_id)
            .ok_or_else(|| anyhow::anyhow!("activation QC uses an unpinned witness"))?;
        if !witness_ids.insert(ack.witness_id)
            || ack.witness_public_key != pin.public_key
            || ack.activation_certificate_hash != activation_certificate_hash
        {
            bail!("activation QC contains a duplicate or mismatched witness ack");
        }
        verify(
            &pin.public_key,
            &gp_wire::witness_activation_ack(ack)?,
            &ack.witness_signature,
        )?;
    }
    if witness_ids.len() < required_witness_quorum(card.witness_fault_bound)? {
        bail!("activation QC has no 2f+1 pinned witness quorum");
    }
    Ok(())
}

/// Selects the highest authenticated activated epoch from a fresh `2f+1`
/// witness read. A stale response is harmless, an invented high epoch lacks a
/// valid signer/witness QC, and two valid same-height forks fail closed.
pub fn select_latest_epoch_v3(
    card: &RecoveryCardV3,
    challenge: &EpochReadChallenge,
    envelopes: &[WitnessReadEnvelope],
) -> Result<ConfigCapsuleV3> {
    validate_recovery_card_v3(card)?;
    gp_wire::epoch_read_challenge(challenge)?;
    if challenge.config_id != card.config_id {
        bail!("witness challenge is for another configuration");
    }
    let pins = witness_pins(card);
    let mut seen_witnesses = BTreeSet::new();
    let mut valid_witnesses = BTreeSet::new();
    let mut valid = Vec::new();
    for envelope in envelopes {
        let response = &envelope.response;
        let Some(pin) = pins.get(&response.witness_id) else {
            continue;
        };
        if response.protocol_version != PROTOCOL_VERSION_V3
            || response.config_id != challenge.config_id
            || response.client_nonce != challenge.client_nonce
            || response.witness_public_key != pin.public_key
            || response.highest_guardian_epoch != envelope.capsule.config_ref.guardian_epoch
            || response.capsule_hash != envelope.capsule.capsule_hash
            || !seen_witnesses.insert(response.witness_id)
            || verify(
                &pin.public_key,
                &gp_wire::witness_epoch_read_response(response)?,
                &response.witness_signature,
            )
            .is_err()
            || validate_activated_capsule_v3(card, &envelope.capsule).is_err()
        {
            continue;
        }
        valid_witnesses.insert(response.witness_id);
        valid.push(&envelope.capsule);
    }
    if seen_witnesses.len() < required_witness_quorum(card.witness_fault_bound)?
        || valid.len() < required_witness_quorum(card.witness_fault_bound)?
    {
        bail!("fresh 2f+1 authenticated witness read quorum was not reached");
    }
    let highest_epoch = valid
        .iter()
        .map(|capsule| capsule.config_ref.guardian_epoch)
        .max()
        .ok_or_else(|| anyhow::anyhow!("witness quorum returned no capsule"))?;
    let highest = valid
        .into_iter()
        .filter(|capsule| capsule.config_ref.guardian_epoch == highest_epoch)
        .collect::<Vec<_>>();
    let hashes = highest
        .iter()
        .map(|capsule| capsule.capsule_hash)
        .collect::<BTreeSet<_>>();
    if hashes.len() != 1 {
        bail!("conflicting valid capsules exist at the same guardian epoch");
    }
    let selected = (*highest[0]).clone();
    if highest_epoch == 1 {
        let agreement = valid_genesis_agreement(envelopes, &valid_witnesses, selected.capsule_hash);
        if agreement < required_witness_quorum(card.witness_fault_bound)? {
            bail!("genesis capsule lacks 2f+1 read agreement");
        }
    }
    Ok(selected)
}

fn valid_genesis_agreement(
    envelopes: &[WitnessReadEnvelope],
    valid_witnesses: &BTreeSet<u16>,
    capsule_hash: Id32,
) -> usize {
    envelopes
        .iter()
        .filter(|envelope| {
            valid_witnesses.contains(&envelope.response.witness_id)
                && envelope.response.highest_guardian_epoch == 1
                && envelope.response.capsule_hash == capsule_hash
        })
        .map(|envelope| envelope.response.witness_id)
        .collect::<BTreeSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_crypto::{merkle_commit, sign, signing_key, verifying_key_bytes};
    use gp_types::{
        AbortRotationCertificate, AeadCiphertext, ConfigRef, DpssSuiteId, EpochActivationQc,
        GuardianRouteV3, RotationContext, RotationIntent, RotationPlan, RotationReason,
        RotationState, SignerRotationAbortVote, SignerRotationActivateVote, WitnessActivationAck,
        WitnessEpochReadResponse,
    };

    struct Fixture {
        card: RecoveryCardV3,
        challenge: EpochReadChallenge,
        witness_seeds: Vec<Id32>,
        signer_seeds: Vec<Id32>,
        signer_proofs: Vec<Vec<u8>>,
        genesis: ConfigCapsuleV3,
    }

    fn capsule(config_ref: ConfigRef, predecessor: Id32, marker: u8) -> ConfigCapsuleV3 {
        ConfigCapsuleV3 {
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
            signer_set_commitment: [0; 32],
            owner_cancel_public_key: [4; 32],
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: [marker; 32],
            ciphertext_fragment_root: [marker.wrapping_add(2); 32],
            guardian_material_root: [marker.wrapping_add(1); 32],
            encrypted_recovery_descriptor: AeadCiphertext {
                nonce: [marker; 24],
                ciphertext: vec![marker; 64],
            },
            activation_certificate: None,
            activation_qc: None,
        }
    }

    fn fixture() -> Fixture {
        let signer_seeds = vec![[11; 32], [12; 32], [13; 32]];
        let signer_keys = signer_seeds
            .iter()
            .enumerate()
            .map(|(offset, seed)| {
                (
                    u16::try_from(offset + 1).unwrap(),
                    verifying_key_bytes(&signing_key(*seed)),
                )
            })
            .collect::<Vec<_>>();
        let leaves = signer_keys
            .iter()
            .map(|(id, key)| sha256(&gp_wire::signer_leaf(*id, key).unwrap()))
            .collect::<Vec<_>>();
        let (signer_root, signer_proofs) = merkle_commit(&leaves).unwrap();
        let config_ref = ConfigRef {
            config_id: [1; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: 1,
            epoch_binding: [2; 32],
        };
        let mut genesis = capsule(config_ref, [0; 32], 5);
        genesis.signer_set_commitment = signer_root;
        genesis.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&genesis).unwrap());
        let witness_seeds = vec![[21; 32], [22; 32], [23; 32], [24; 32]];
        let witnesses = witness_seeds
            .iter()
            .enumerate()
            .map(|(offset, seed)| WitnessPin {
                witness_id: u16::try_from(offset + 1).unwrap(),
                mailbox: format!("https://witness-{offset}.invalid"),
                public_key: verifying_key_bytes(&signing_key(*seed)),
            })
            .collect();
        let card = RecoveryCardV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: config_ref.config_id,
            signer_mailboxes: vec!["opaque-signer".into()],
            signer_set_commitment: signer_root,
            owner_cancel_public_key: genesis.owner_cancel_public_key,
            witness_fault_bound: 1,
            witnesses,
            relay_bases: vec!["https://relay.invalid".into()],
        };
        let challenge = EpochReadChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: config_ref.config_id,
            client_nonce: [31; 32],
            response_recipient_key: vec![32; 1216],
            issued_at: 1,
            expiry: 100,
        };
        Fixture {
            card,
            challenge,
            witness_seeds,
            signer_seeds,
            signer_proofs,
            genesis,
        }
    }

    fn successor(fixture: &Fixture, marker: u8) -> ConfigCapsuleV3 {
        let mut successor_ref = fixture.genesis.config_ref;
        successor_ref.guardian_epoch = 2;
        successor_ref.epoch_binding = [marker; 32];
        let mut successor = capsule(
            successor_ref,
            fixture.genesis.capsule_hash,
            marker.wrapping_add(20),
        );
        successor.signer_set_commitment = fixture.card.signer_set_commitment;
        successor.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&successor).unwrap());
        let context = RotationContext {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: fixture.genesis.config_ref,
            rotation_id: [marker.wrapping_add(40); 32],
            predecessor_capsule_hash: fixture.genesis.capsule_hash,
            recipient_key: vec![marker; 1216],
            nonce: [marker.wrapping_add(1); 32],
            issued_at: 1,
            expiry: 100,
        };
        let mut votes = Vec::new();
        for offset in 0..2 {
            let key = signing_key(fixture.signer_seeds[offset]);
            let mut vote = SignerRotationActivateVote {
                context: context.clone(),
                plan_hash: [marker.wrapping_add(2); 32],
                ready_certificate_hash: [marker.wrapping_add(3); 32],
                successor_capsule_hash: successor.capsule_hash,
                signer_id: u16::try_from(offset + 1).unwrap(),
                signer_public_key: verifying_key_bytes(&key),
                signer_membership_proof: fixture.signer_proofs[offset].clone(),
                signer_signature: vec![],
            };
            vote.signer_signature = sign(
                &key,
                &gp_wire::signer_rotation_activate_vote(&vote).unwrap(),
            );
            votes.push(vote);
        }
        let certificate = RotationActivateCertificate {
            context: context.clone(),
            plan_hash: [marker.wrapping_add(2); 32],
            ready_certificate_hash: [marker.wrapping_add(3); 32],
            successor: successor.config_ref,
            successor_capsule_hash: successor.capsule_hash,
            votes,
        };
        let certificate_hash =
            sha256(&gp_wire::rotation_activate_certificate(&certificate).unwrap());
        let mut acks = Vec::new();
        for offset in 0..3 {
            let key = signing_key(fixture.witness_seeds[offset]);
            let mut ack = WitnessActivationAck {
                context: context.clone(),
                plan_hash: certificate.plan_hash,
                activation_certificate_hash: certificate_hash,
                witness_id: u16::try_from(offset + 1).unwrap(),
                predecessor_epoch: 1,
                predecessor_capsule_hash: fixture.genesis.capsule_hash,
                successor_epoch: 2,
                successor_capsule_hash: successor.capsule_hash,
                witness_public_key: verifying_key_bytes(&key),
                witness_signature: vec![],
            };
            ack.witness_signature = sign(&key, &gp_wire::witness_activation_ack(&ack).unwrap());
            acks.push(ack);
        }
        successor.activation_certificate = Some(certificate);
        successor.activation_qc = Some(EpochActivationQc {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: fixture.card.config_id,
            rotation_id: context.rotation_id,
            predecessor_epoch: 1,
            predecessor_capsule_hash: fixture.genesis.capsule_hash,
            successor_epoch: 2,
            successor_capsule_hash: successor.capsule_hash,
            activation_certificate_hash: certificate_hash,
            witness_fault_bound: 1,
            witness_acks: acks,
        });
        successor
    }

    fn read(
        fixture: &Fixture,
        witness_offset: usize,
        capsule: ConfigCapsuleV3,
    ) -> WitnessReadEnvelope {
        let key = signing_key(fixture.witness_seeds[witness_offset]);
        let mut response = WitnessEpochReadResponse {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: fixture.card.config_id,
            client_nonce: fixture.challenge.client_nonce,
            witness_id: u16::try_from(witness_offset + 1).unwrap(),
            highest_guardian_epoch: capsule.config_ref.guardian_epoch,
            capsule_hash: capsule.capsule_hash,
            witness_public_key: verifying_key_bytes(&key),
            witness_signature: vec![],
        };
        response.witness_signature = sign(
            &key,
            &gp_wire::witness_epoch_read_response(&response).unwrap(),
        );
        WitnessReadEnvelope { response, capsule }
    }

    fn rotation_plan_and_intent(fixture: &Fixture) -> (RotationPlan, RotationIntent) {
        let context = RotationContext {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: fixture.genesis.config_ref,
            rotation_id: [91; 32],
            predecessor_capsule_hash: fixture.genesis.capsule_hash,
            recipient_key: vec![92; 1216],
            nonce: [93; 32],
            issued_at: 1,
            expiry: 100,
        };
        let old_roster = (1_u16..=8)
            .map(|id| GuardianRouteV3 {
                guardian_index: id,
                opaque_slot_id: [u8::try_from(id).unwrap(); 32],
                mailbox: format!("https://relay.invalid/v3/mailboxes/old-{id}"),
                guardian_public_key: [u8::try_from(id + 10).unwrap(); 32],
                session_recipient_key: vec![u8::try_from(id + 20).unwrap(); 1216],
                operator_domain_commitment: [u8::try_from(id + 30).unwrap(); 32],
            })
            .collect::<Vec<_>>();
        let mut new_roster = old_roster
            .iter()
            .filter(|route| route.guardian_index != 4)
            .map(|route| GuardianRouteV3 {
                opaque_slot_id: [u8::try_from(route.guardian_index + 40).unwrap(); 32],
                mailbox: format!(
                    "https://relay.invalid/v3/mailboxes/new-{}",
                    route.guardian_index
                ),
                ..route.clone()
            })
            .collect::<Vec<_>>();
        new_roster.push(GuardianRouteV3 {
            guardian_index: 9,
            opaque_slot_id: [99; 32],
            mailbox: "https://relay.invalid/v3/mailboxes/new-9".into(),
            guardian_public_key: [109; 32],
            session_recipient_key: vec![119; 1216],
            operator_domain_commitment: [129; 32],
        });
        let intent = RotationIntent {
            context: context.clone(),
            reason: RotationReason::Unavailable,
            old_guardian_count: 8,
            old_guardian_threshold: 5,
            allowed_new_guardian_count: vec![8],
            allowed_new_guardian_threshold: vec![5],
            allowed_dpss_suites: vec![DpssSuiteId::default()],
            selection_constraints_commitment: sha256(&4_u16.to_be_bytes()),
            witness_read_qc_hash: [94; 32],
        };
        let old_roster_commitment = sha256(&gp_wire::guardian_roster_v3(&old_roster).unwrap());
        let new_roster_commitment = sha256(&gp_wire::guardian_roster_v3(&new_roster).unwrap());
        let plan = RotationPlan {
            context,
            intent_hash: sha256(&gp_wire::rotation_intent(&intent).unwrap()),
            predecessor: fixture.genesis.config_ref,
            successor: ConfigRef {
                guardian_epoch: 2,
                epoch_binding: [95; 32],
                ..fixture.genesis.config_ref
            },
            old_roster,
            new_roster,
            old_roster_commitment,
            new_roster_commitment,
            old_guardian_threshold: 5,
            new_guardian_threshold: 5,
            data_shards: 5,
            total_shards: 8,
            dpss_suite: DpssSuiteId::default(),
            dpss_session_id: [96; 32],
            dpss_qualified_set_commitment: new_roster_commitment,
            minimum_delay_secs: 10,
            preparation_deadline: 80,
            drain_deadline: 90,
        };
        (plan, intent)
    }

    #[test]
    fn signer_intent_constraints_bind_exact_replacement_and_successor_policy() {
        let fixture = fixture();
        let (plan, intent) = rotation_plan_and_intent(&fixture);
        assert!(
            validate_rotation_plan_against_intent_v3(&plan, &intent, &fixture.genesis, 10).is_ok()
        );

        let mut weakened = plan.clone();
        weakened.new_guardian_threshold = 2;
        assert!(
            validate_rotation_plan_against_intent_v3(&weakened, &intent, &fixture.genesis, 10)
                .is_err()
        );

        let mut substituted = plan;
        substituted.new_roster[0].guardian_public_key = [222; 32];
        substituted.new_roster_commitment =
            sha256(&gp_wire::guardian_roster_v3(&substituted.new_roster).unwrap());
        substituted.dpss_qualified_set_commitment = substituted.new_roster_commitment;
        assert!(
            validate_rotation_plan_against_intent_v3(&substituted, &intent, &fixture.genesis, 10)
                .is_err()
        );
    }

    #[test]
    fn threshold_abort_remains_valid_after_preparation_deadline() {
        let fixture = fixture();
        let (plan, _) = rotation_plan_and_intent(&fixture);
        let plan_hash = sha256(&gp_wire::rotation_plan(&plan).unwrap());
        let mut votes = Vec::new();
        for offset in 0..2 {
            let key = signing_key(fixture.signer_seeds[offset]);
            let mut vote = SignerRotationAbortVote {
                context: plan.context.clone(),
                plan_hash,
                state_at_abort: RotationState::Preparing,
                reason_code: 7,
                signer_id: u16::try_from(offset + 1).unwrap(),
                signer_public_key: verifying_key_bytes(&key),
                signer_membership_proof: fixture.signer_proofs[offset].clone(),
                signer_signature: vec![],
            };
            vote.signer_signature =
                sign(&key, &gp_wire::signer_rotation_abort_vote(&vote).unwrap());
            votes.push(vote);
        }
        let certificate = AbortRotationCertificate {
            context: plan.context.clone(),
            plan_hash,
            state_at_abort: RotationState::Preparing,
            reason_code: 7,
            votes,
        };
        assert!(
            validate_abort_rotation_certificate_v3(&certificate, &plan, &fixture.genesis, 85)
                .is_ok()
        );
    }

    #[test]
    fn fresh_quorum_selects_qc_proven_highest_despite_stale_and_invented_responses() {
        let fixture = fixture();
        let active = successor(&fixture, 50);
        let mut invented = active.clone();
        invented.config_ref.guardian_epoch = 99;
        invented.config_ref.epoch_binding = [99; 32];
        invented.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&invented).unwrap());
        // Its old activation QC no longer binds the mutated body, so it is rejected.
        let reads = vec![
            read(&fixture, 0, active.clone()),
            read(&fixture, 1, fixture.genesis.clone()),
            read(&fixture, 2, fixture.genesis.clone()),
            read(&fixture, 3, invented),
        ];
        let selected = select_latest_epoch_v3(&fixture.card, &fixture.challenge, &reads).unwrap();
        assert_eq!(selected.capsule_hash, active.capsule_hash);
    }

    #[test]
    fn same_epoch_valid_fork_fails_closed() {
        let fixture = fixture();
        let first = successor(&fixture, 60);
        let second = successor(&fixture, 61);
        let reads = vec![
            read(&fixture, 0, first),
            read(&fixture, 1, second),
            read(&fixture, 2, fixture.genesis.clone()),
        ];
        assert!(select_latest_epoch_v3(&fixture.card, &fixture.challenge, &reads).is_err());
    }

    #[test]
    fn duplicate_or_insufficient_witnesses_do_not_form_a_read_quorum() {
        let fixture = fixture();
        let reads = vec![
            read(&fixture, 0, fixture.genesis.clone()),
            read(&fixture, 0, fixture.genesis.clone()),
            read(&fixture, 1, fixture.genesis.clone()),
        ];
        assert!(select_latest_epoch_v3(&fixture.card, &fixture.challenge, &reads).is_err());
    }
}
