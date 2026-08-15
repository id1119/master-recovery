//! Canonical protocol-v3 guardian-rotation transcripts.
//!
//! No Rust/Serde serialization is signed. Each function below constructs an
//! explicit, length-prefixed, domain-separated transcript and omits only the
//! signature field belonging to the object being signed.

use std::collections::BTreeSet;

use gp_types::*;

use crate::{Transcript, WireError};

fn config_ref_into(out: &mut Transcript, value: &ConfigRef) -> Result<(), WireError> {
    out.bytes(&value.config_id)?;
    out.u64(value.payload_generation);
    out.u64(value.authorization_epoch);
    out.u64(value.guardian_epoch);
    out.bytes(&value.epoch_binding)?;
    Ok(())
}

fn context_into(out: &mut Transcript, value: &RotationContext) -> Result<(), WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3 || value.issued_at >= value.expiry {
        return Err(WireError::InvalidValue);
    }
    out.u16(value.protocol_version);
    config_ref_into(out, &value.config_ref)?;
    out.bytes(&value.rotation_id)?;
    out.bytes(&value.predecessor_capsule_hash)?;
    out.bytes(&value.recipient_key)?;
    out.bytes(&value.nonce)?;
    out.u64(value.issued_at);
    out.u64(value.expiry);
    Ok(())
}

fn same_rotation(left: &RotationContext, right: &RotationContext) -> bool {
    left.protocol_version == right.protocol_version
        && left.config_ref == right.config_ref
        && left.rotation_id == right.rotation_id
        && left.predecessor_capsule_hash == right.predecessor_capsule_hash
}

fn bounded_count(out: &mut Transcript, len: usize, max: u16) -> Result<(), WireError> {
    let len = u16::try_from(len).map_err(|_| WireError::InvalidValue)?;
    if len > max {
        return Err(WireError::InvalidValue);
    }
    out.u16(len);
    Ok(())
}

fn unique_ids<I>(ids: I) -> Result<(), WireError>
where
    I: IntoIterator<Item = u16>,
{
    let mut unique = BTreeSet::new();
    for id in ids {
        if id == 0 || id > MAX_ROTATION_ACTORS || !unique.insert(id) {
            return Err(if unique.contains(&id) {
                WireError::DuplicateActor
            } else {
                WireError::InvalidValue
            });
        }
    }
    Ok(())
}

fn dpss_suite_id(value: DpssSuiteId) -> u16 {
    match value {
        DpssSuiteId::ZfFrostRistretto255RtsRefreshV1 => 1,
    }
}

fn dpss_phase_id(value: DpssPhase) -> u16 {
    match value {
        DpssPhase::RepairRound1 => 1,
        DpssPhase::RepairRound2 => 2,
        DpssPhase::RepairRound3 => 3,
        DpssPhase::RefreshRound1 => 4,
        DpssPhase::RefreshRound2 => 5,
        DpssPhase::Finalize => 6,
    }
}

fn reason_id(value: RotationReason) -> u16 {
    match value {
        RotationReason::PlannedExit => 1,
        RotationReason::CustodyFailure => 2,
        RotationReason::Unavailable => 3,
        RotationReason::SuspectedCompromise => 4,
        RotationReason::DiversityPolicy => 5,
        RotationReason::ProactiveRefresh => 6,
        RotationReason::SecurityUpgrade => 7,
        RotationReason::OwnerAssistedMigration => 8,
    }
}

fn state_id(value: RotationState) -> u16 {
    match value {
        RotationState::Proposed => 1,
        RotationState::DelayPending => 2,
        RotationState::Preparing => 3,
        RotationState::Ready => 4,
        RotationState::Activating => 5,
        RotationState::Active => 6,
        RotationState::Draining => 7,
        RotationState::Retired => 8,
        RotationState::Aborted => 9,
    }
}

fn route_into(out: &mut Transcript, route: &GuardianRouteV3) -> Result<(), WireError> {
    if route.guardian_index == 0 || route.guardian_index > MAX_ROTATION_ACTORS {
        return Err(WireError::InvalidValue);
    }
    out.u16(route.guardian_index);
    out.bytes(&route.opaque_slot_id)?;
    out.bytes(route.mailbox.as_bytes())?;
    out.bytes(&route.guardian_public_key)?;
    out.bytes(&route.session_recipient_key)?;
    out.bytes(&route.operator_domain_commitment)?;
    Ok(())
}

pub fn guardian_roster_v3(routes: &[GuardianRouteV3]) -> Result<Vec<u8>, WireError> {
    unique_ids(routes.iter().map(|route| route.guardian_index))?;
    let mut out = Transcript::default();
    out.domain(b"gp/private-guardian-roster/v3")?;
    bounded_count(&mut out, routes.len(), MAX_ROTATION_ACTORS)?;
    for route in routes {
        route_into(&mut out, route)?;
    }
    Ok(out.finish())
}

fn sealed_into(out: &mut Transcript, sealed: &SealedMessage) -> Result<(), WireError> {
    out.bytes(&sealed.kem_ciphertext)?;
    out.bytes(&sealed.payload.nonce)?;
    out.bytes(&sealed.payload.ciphertext)?;
    Ok(())
}

fn begin_vote_into(
    out: &mut Transcript,
    vote: &SignerRotationBeginVote,
    include_signature: bool,
) -> Result<(), WireError> {
    context_into(out, &vote.context)?;
    out.bytes(&vote.intent_hash)?;
    out.bytes(&vote.plan_hash)?;
    out.bytes(&vote.old_roster_commitment)?;
    out.bytes(&vote.new_roster_commitment)?;
    out.u16(vote.signer_id);
    out.bytes(&vote.signer_public_key)?;
    out.bytes(&vote.signer_membership_proof)?;
    if include_signature {
        out.bytes(&vote.signer_signature)?;
    }
    Ok(())
}

fn release_vote_into(
    out: &mut Transcript,
    vote: &SignerRotationReleaseVote,
    include_signature: bool,
) -> Result<(), WireError> {
    context_into(out, &vote.context)?;
    out.bytes(&vote.plan_hash)?;
    out.bytes(&vote.begin_certificate_hash)?;
    out.u16(vote.signer_id);
    out.bytes(&vote.signer_public_key)?;
    out.bytes(&vote.signer_membership_proof)?;
    if include_signature {
        out.bytes(&vote.signer_signature)?;
    }
    Ok(())
}

fn prepared_leaf_into(out: &mut Transcript, leaf: &PreparedRecordLeaf) -> Result<(), WireError> {
    out.u16(leaf.guardian_index);
    out.u16(leaf.fragment_index);
    out.bytes(&leaf.opaque_slot_id)?;
    out.bytes(&leaf.encrypted_share_hash)?;
    out.bytes(&leaf.fragment_hash)?;
    out.bytes(&leaf.policy_hash)?;
    Ok(())
}

pub fn prepared_record_leaf_v3(value: &PreparedRecordLeaf) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/prepared-record-leaf/v3")?;
    prepared_leaf_into(&mut out, value)?;
    Ok(out.finish())
}

fn prepared_ack_into(
    out: &mut Transcript,
    ack: &NewGuardianPreparedAck,
    include_signature: bool,
) -> Result<(), WireError> {
    context_into(out, &ack.context)?;
    out.bytes(&ack.plan_hash)?;
    out.bytes(&ack.dpss_result_commitment)?;
    out.bytes(&ack.guardian_material_root)?;
    out.u16(ack.new_guardian_index);
    prepared_leaf_into(out, &ack.prepared_record_leaf)?;
    out.u64(ack.durable_write_generation);
    if include_signature {
        out.bytes(&ack.guardian_signature)?;
    }
    Ok(())
}

fn handoff_ack_into(
    out: &mut Transcript,
    ack: &OldGuardianHandoffAck,
    include_signature: bool,
) -> Result<(), WireError> {
    context_into(out, &ack.context)?;
    out.bytes(&ack.plan_hash)?;
    out.bytes(&ack.dpss_result_commitment)?;
    out.bytes(&ack.qualified_set_commitment)?;
    out.u16(ack.old_guardian_index);
    if include_signature {
        out.bytes(&ack.guardian_signature)?;
    }
    Ok(())
}

fn activate_vote_into(
    out: &mut Transcript,
    vote: &SignerRotationActivateVote,
    include_signature: bool,
) -> Result<(), WireError> {
    context_into(out, &vote.context)?;
    out.bytes(&vote.plan_hash)?;
    out.bytes(&vote.ready_certificate_hash)?;
    out.bytes(&vote.successor_capsule_hash)?;
    out.u16(vote.signer_id);
    out.bytes(&vote.signer_public_key)?;
    out.bytes(&vote.signer_membership_proof)?;
    if include_signature {
        out.bytes(&vote.signer_signature)?;
    }
    Ok(())
}

fn witness_ack_into(
    out: &mut Transcript,
    ack: &WitnessActivationAck,
    include_signature: bool,
) -> Result<(), WireError> {
    context_into(out, &ack.context)?;
    out.bytes(&ack.plan_hash)?;
    out.bytes(&ack.activation_certificate_hash)?;
    out.u16(ack.witness_id);
    out.u64(ack.predecessor_epoch);
    out.bytes(&ack.predecessor_capsule_hash)?;
    out.u64(ack.successor_epoch);
    out.bytes(&ack.successor_capsule_hash)?;
    out.bytes(&ack.witness_public_key)?;
    if include_signature {
        out.bytes(&ack.witness_signature)?;
    }
    Ok(())
}

pub fn rotation_intent(value: &RotationIntent) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/rotation-intent/v3")?;
    context_into(&mut out, &value.context)?;
    out.u16(reason_id(value.reason));
    out.u16(value.old_guardian_count);
    out.u16(value.old_guardian_threshold);
    bounded_count(
        &mut out,
        value.allowed_new_guardian_count.len(),
        MAX_ROTATION_ACTORS,
    )?;
    for count in &value.allowed_new_guardian_count {
        out.u16(*count);
    }
    bounded_count(
        &mut out,
        value.allowed_new_guardian_threshold.len(),
        MAX_ROTATION_ACTORS,
    )?;
    for threshold in &value.allowed_new_guardian_threshold {
        out.u16(*threshold);
    }
    bounded_count(&mut out, value.allowed_dpss_suites.len(), 32)?;
    for suite in &value.allowed_dpss_suites {
        out.u16(dpss_suite_id(*suite));
    }
    out.bytes(&value.selection_constraints_commitment)?;
    out.bytes(&value.witness_read_qc_hash)?;
    Ok(out.finish())
}

pub fn signer_rotation_intent_contribution(
    value: &SignerRotationIntentContribution,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-rotation-intent-contribution/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.intent_hash)?;
    out.u16(value.signer_id);
    out.bytes(&value.signer_public_key)?;
    out.bytes(&value.signer_membership_proof)?;
    sealed_into(&mut out, &value.encrypted_authorization_share)?;
    Ok(out.finish())
}

pub fn rotation_intent_share_context_v3(
    context: &RotationContext,
    intent_hash: &Id32,
    signer_id: u16,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/rotation-intent-a-share-context/v3")?;
    context_into(&mut out, context)?;
    out.bytes(intent_hash)?;
    out.u16(signer_id);
    Ok(out.finish())
}

pub fn rotation_plan(value: &RotationPlan) -> Result<Vec<u8>, WireError> {
    if !value.successor.is_direct_successor_of(&value.predecessor)
        || value.context.config_ref != value.predecessor
        || value.old_guardian_threshold == 0
        || value.new_guardian_threshold == 0
        || value.old_guardian_threshold as usize > value.old_roster.len()
        || value.new_guardian_threshold as usize > value.new_roster.len()
        || value.data_shards == 0
        || value.data_shards > value.total_shards
    {
        return Err(WireError::InvalidValue);
    }
    unique_ids(value.old_roster.iter().map(|route| route.guardian_index))?;
    unique_ids(value.new_roster.iter().map(|route| route.guardian_index))?;
    let mut out = Transcript::default();
    out.domain(b"gp/rotation-plan/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.intent_hash)?;
    config_ref_into(&mut out, &value.predecessor)?;
    config_ref_into(&mut out, &value.successor)?;
    bounded_count(&mut out, value.old_roster.len(), MAX_ROTATION_ACTORS)?;
    for route in &value.old_roster {
        route_into(&mut out, route)?;
    }
    bounded_count(&mut out, value.new_roster.len(), MAX_ROTATION_ACTORS)?;
    for route in &value.new_roster {
        route_into(&mut out, route)?;
    }
    out.bytes(&value.old_roster_commitment)?;
    out.bytes(&value.new_roster_commitment)?;
    out.u16(value.old_guardian_threshold);
    out.u16(value.new_guardian_threshold);
    out.u16(value.data_shards);
    out.u16(value.total_shards);
    out.u16(dpss_suite_id(value.dpss_suite));
    out.bytes(&value.dpss_session_id)?;
    out.bytes(&value.dpss_qualified_set_commitment)?;
    out.u64(value.minimum_delay_secs);
    out.u64(value.preparation_deadline);
    out.u64(value.drain_deadline);
    Ok(out.finish())
}

pub fn signer_rotation_begin_vote(value: &SignerRotationBeginVote) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-rotation-begin-vote/v3")?;
    begin_vote_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn begin_rotation_certificate(value: &BeginRotationCertificate) -> Result<Vec<u8>, WireError> {
    unique_ids(value.votes.iter().map(|vote| vote.signer_id))?;
    if value.votes.iter().any(|vote| {
        !same_rotation(&value.context, &vote.context)
            || vote.intent_hash != value.intent_hash
            || vote.plan_hash != value.plan_hash
            || vote.old_roster_commitment != value.old_roster_commitment
            || vote.new_roster_commitment != value.new_roster_commitment
    }) {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/begin-rotation-certificate/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.intent_hash)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.old_roster_commitment)?;
    out.bytes(&value.new_roster_commitment)?;
    out.u64(value.not_before_wall);
    bounded_count(&mut out, value.votes.len(), MAX_ROTATION_ACTORS)?;
    for vote in &value.votes {
        begin_vote_into(&mut out, vote, true)?;
    }
    Ok(out.finish())
}

pub fn owner_rotation_cancel_certificate(
    value: &OwnerRotationCancelCertificate,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/owner-rotation-cancel/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.u16(value.reason_code);
    out.bytes(&value.cancel_response_recipient_key)?;
    out.bytes(&value.owner_cancel_public_key)?;
    Ok(out.finish())
}

pub fn owner_rotation_cancel_ack(value: &OwnerRotationCancelAck) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/owner-rotation-cancel-ack/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.cancel_certificate_hash)?;
    out.u16(value.guardian_index);
    Ok(out.finish())
}

pub fn signer_rotation_release_vote(
    value: &SignerRotationReleaseVote,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-rotation-release-vote/v3")?;
    release_vote_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn rotation_release_certificate(
    value: &RotationReleaseCertificate,
) -> Result<Vec<u8>, WireError> {
    unique_ids(value.votes.iter().map(|vote| vote.signer_id))?;
    if value.votes.iter().any(|vote| {
        !same_rotation(&value.context, &vote.context)
            || vote.plan_hash != value.plan_hash
            || vote.begin_certificate_hash != value.begin_certificate_hash
    }) {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/rotation-release-certificate/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.begin_certificate_hash)?;
    bounded_count(&mut out, value.votes.len(), MAX_ROTATION_ACTORS)?;
    for vote in &value.votes {
        release_vote_into(&mut out, vote, true)?;
    }
    Ok(out.finish())
}

pub fn old_share_unlock_grant(value: &OldShareUnlockGrant) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/old-share-unlock-grant/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.release_certificate_hash)?;
    out.u16(value.old_guardian_index);
    sealed_into(&mut out, &value.encrypted_unwrap_key)?;
    sealed_into(&mut out, &value.encrypted_fragment_key)?;
    Ok(out.finish())
}

/// KEM associated data for the two key payloads in an old-share grant. It
/// excludes the ciphertexts themselves and adds an explicit key purpose.
pub fn old_share_unlock_grant_payload_context(
    value: &OldShareUnlockGrant,
    fragment_key: bool,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/old-share-unlock-grant-payload/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.release_certificate_hash)?;
    out.u16(value.old_guardian_index);
    out.u16(u16::from(fragment_key));
    Ok(out.finish())
}

pub fn new_share_wrap_grant(value: &NewShareWrapGrant) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/new-share-wrap-grant/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.release_certificate_hash)?;
    out.u16(value.new_guardian_index);
    sealed_into(&mut out, &value.encrypted_wrap_key)?;
    sealed_into(&mut out, &value.encrypted_fragment_key)?;
    Ok(out.finish())
}

pub fn new_share_wrap_grant_payload_context(
    value: &NewShareWrapGrant,
    fragment_key: bool,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/new-share-wrap-grant-payload/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.release_certificate_hash)?;
    out.u16(value.new_guardian_index);
    out.u16(u16::from(fragment_key));
    Ok(out.finish())
}

pub fn dpss_protocol_message(value: &DpssProtocolMessage) -> Result<Vec<u8>, WireError> {
    if value.sender_index == value.recipient_index || value.sequence == 0 {
        return Err(WireError::InvalidValue);
    }
    unique_ids([value.sender_index, value.recipient_index])?;
    let mut out = Transcript::default();
    out.domain(b"gp/dpss-protocol-message/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.u16(dpss_suite_id(value.dpss_suite));
    out.bytes(&value.dpss_session_id)?;
    out.bytes(&value.qualified_set_commitment)?;
    out.u16(dpss_phase_id(value.phase));
    out.u16(value.sender_index);
    out.u16(value.recipient_index);
    out.u64(value.sequence);
    out.bytes(&value.provider_payload)?;
    Ok(out.finish())
}

pub fn ciphertext_fragment_contribution(
    value: &CiphertextFragmentContribution,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/ciphertext-fragment-contribution/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.release_certificate_hash)?;
    out.u16(value.old_guardian_index);
    out.u16(value.fragment_index);
    out.bytes(&value.ciphertext_fragment)?;
    out.bytes(&value.fragment_commitment)?;
    prepared_leaf_into(&mut out, &value.prepared_record_leaf)?;
    out.bytes(&value.merkle_path_proof)?;
    Ok(out.finish())
}

pub fn new_guardian_prepared_ack(value: &NewGuardianPreparedAck) -> Result<Vec<u8>, WireError> {
    if value.new_guardian_index != value.prepared_record_leaf.guardian_index
        || value.durable_write_generation == 0
    {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/new-guardian-prepared-ack/v3")?;
    prepared_ack_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn old_guardian_handoff_ack(value: &OldGuardianHandoffAck) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/old-guardian-handoff-ack/v3")?;
    handoff_ack_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn rotation_ready_certificate(value: &RotationReadyCertificate) -> Result<Vec<u8>, WireError> {
    unique_ids(value.prepared_acks.iter().map(|ack| ack.new_guardian_index))?;
    unique_ids(
        value
            .old_handoff_acks
            .iter()
            .map(|ack| ack.old_guardian_index),
    )?;
    if value.prepared_acks.iter().any(|ack| {
        !same_rotation(&value.context, &ack.context)
            || ack.plan_hash != value.plan_hash
            || ack.dpss_result_commitment != value.dpss_result_commitment
            || ack.guardian_material_root != value.guardian_material_root
            || ack.new_guardian_index != ack.prepared_record_leaf.guardian_index
            || ack.durable_write_generation == 0
    }) || value.old_handoff_acks.iter().any(|ack| {
        !same_rotation(&value.context, &ack.context)
            || ack.plan_hash != value.plan_hash
            || ack.dpss_result_commitment != value.dpss_result_commitment
    }) {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/rotation-ready-certificate/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    config_ref_into(&mut out, &value.successor)?;
    out.bytes(&value.dpss_result_commitment)?;
    out.bytes(&value.guardian_material_root)?;
    out.bytes(&value.encrypted_descriptor_hash)?;
    bounded_count(&mut out, value.prepared_acks.len(), MAX_ROTATION_ACTORS)?;
    for ack in &value.prepared_acks {
        prepared_ack_into(&mut out, ack, true)?;
    }
    bounded_count(&mut out, value.old_handoff_acks.len(), MAX_ROTATION_ACTORS)?;
    for ack in &value.old_handoff_acks {
        handoff_ack_into(&mut out, ack, true)?;
    }
    Ok(out.finish())
}

pub fn signer_rotation_activate_vote(
    value: &SignerRotationActivateVote,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-rotation-activate-vote/v3")?;
    activate_vote_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn rotation_activate_certificate(
    value: &RotationActivateCertificate,
) -> Result<Vec<u8>, WireError> {
    unique_ids(value.votes.iter().map(|vote| vote.signer_id))?;
    if value.votes.iter().any(|vote| {
        !same_rotation(&value.context, &vote.context)
            || vote.plan_hash != value.plan_hash
            || vote.ready_certificate_hash != value.ready_certificate_hash
            || vote.successor_capsule_hash != value.successor_capsule_hash
    }) {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/rotation-activate-certificate/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.ready_certificate_hash)?;
    config_ref_into(&mut out, &value.successor)?;
    out.bytes(&value.successor_capsule_hash)?;
    bounded_count(&mut out, value.votes.len(), MAX_ROTATION_ACTORS)?;
    for vote in &value.votes {
        activate_vote_into(&mut out, vote, true)?;
    }
    Ok(out.finish())
}

pub fn witness_activation_ack(value: &WitnessActivationAck) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/witness-activation-ack/v3")?;
    witness_ack_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn witness_rotation_cancel_ack(value: &WitnessRotationCancelAck) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3 || value.witness_id == 0 {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/witness-rotation-cancel-ack/v3")?;
    out.u16(value.protocol_version);
    out.bytes(&value.config_id)?;
    out.bytes(&value.rotation_id)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.cancel_certificate_hash)?;
    out.u16(value.witness_id);
    out.bytes(&value.witness_public_key)?;
    Ok(out.finish())
}

pub fn epoch_activation_qc(value: &EpochActivationQc) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3
        || value.successor_epoch != value.predecessor_epoch.saturating_add(1)
        || value.witness_fault_bound > MAX_CONFIG_WITNESSES
    {
        return Err(WireError::InvalidValue);
    }
    unique_ids(value.witness_acks.iter().map(|ack| ack.witness_id))?;
    let required = usize::from(value.witness_fault_bound)
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .ok_or(WireError::InvalidValue)?;
    if value.witness_acks.len() < required {
        return Err(WireError::InvalidValue);
    }
    if value.witness_acks.iter().any(|ack| {
        ack.context.protocol_version != value.protocol_version
            || ack.context.config_ref.config_id != value.config_id
            || ack.context.rotation_id != value.rotation_id
            || ack.predecessor_epoch != value.predecessor_epoch
            || ack.predecessor_capsule_hash != value.predecessor_capsule_hash
            || ack.successor_epoch != value.successor_epoch
            || ack.successor_capsule_hash != value.successor_capsule_hash
            || ack.activation_certificate_hash != value.activation_certificate_hash
    }) {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/epoch-activation-qc/v3")?;
    out.u16(value.protocol_version);
    out.bytes(&value.config_id)?;
    out.bytes(&value.rotation_id)?;
    out.u64(value.predecessor_epoch);
    out.bytes(&value.predecessor_capsule_hash)?;
    out.u64(value.successor_epoch);
    out.bytes(&value.successor_capsule_hash)?;
    out.bytes(&value.activation_certificate_hash)?;
    out.u16(value.witness_fault_bound);
    bounded_count(&mut out, value.witness_acks.len(), MAX_CONFIG_WITNESSES)?;
    for ack in &value.witness_acks {
        witness_ack_into(&mut out, ack, true)?;
    }
    Ok(out.finish())
}

pub fn epoch_read_challenge(value: &EpochReadChallenge) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3 || value.issued_at >= value.expiry {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/epoch-read-challenge/v3")?;
    out.u16(value.protocol_version);
    out.bytes(&value.config_id)?;
    out.bytes(&value.client_nonce)?;
    out.bytes(&value.response_recipient_key)?;
    out.u64(value.issued_at);
    out.u64(value.expiry);
    Ok(out.finish())
}

pub fn witness_epoch_read_response(value: &WitnessEpochReadResponse) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3 {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/witness-epoch-read-response/v3")?;
    out.u16(value.protocol_version);
    out.bytes(&value.config_id)?;
    out.bytes(&value.client_nonce)?;
    out.u16(value.witness_id);
    out.u64(value.highest_guardian_epoch);
    out.bytes(&value.capsule_hash)?;
    out.bytes(&value.witness_public_key)?;
    Ok(out.finish())
}

pub fn retirement_notice(value: &RetirementNotice) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/retirement-notice/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.activation_qc_hash)?;
    out.u64(value.retired_epoch);
    out.u64(value.drain_deadline);
    Ok(out.finish())
}

pub fn retirement_ack(value: &RetirementAck) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/retirement-ack/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.bytes(&value.activation_qc_hash)?;
    out.u16(value.guardian_index);
    out.u64(value.retired_epoch);
    out.bytes(&value.tombstone_hash)?;
    Ok(out.finish())
}

pub fn abort_rotation_certificate(value: &AbortRotationCertificate) -> Result<Vec<u8>, WireError> {
    unique_ids(value.votes.iter().map(|vote| vote.signer_id))?;
    let mut out = Transcript::default();
    out.domain(b"gp/abort-rotation-certificate/v3")?;
    context_into(&mut out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.u16(state_id(value.state_at_abort));
    out.u16(value.reason_code);
    bounded_count(&mut out, value.votes.len(), MAX_ROTATION_ACTORS)?;
    for vote in &value.votes {
        signer_rotation_abort_vote_into(&mut out, vote, true)?;
    }
    Ok(out.finish())
}

fn signer_rotation_abort_vote_into(
    out: &mut Transcript,
    value: &SignerRotationAbortVote,
    include_signature: bool,
) -> Result<(), WireError> {
    context_into(out, &value.context)?;
    out.bytes(&value.plan_hash)?;
    out.u16(state_id(value.state_at_abort));
    out.u16(value.reason_code);
    out.u16(value.signer_id);
    out.bytes(&value.signer_public_key)?;
    out.bytes(&value.signer_membership_proof)?;
    if include_signature {
        out.bytes(&value.signer_signature)?;
    }
    Ok(())
}

pub fn signer_rotation_abort_vote(value: &SignerRotationAbortVote) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-rotation-abort-vote/v3")?;
    signer_rotation_abort_vote_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn recovery_request_v3(value: &RecoveryRequestV3) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3 || value.requested_at >= value.expiry {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-request/v3")?;
    out.u16(value.protocol_version);
    config_ref_into(&mut out, &value.config_ref)?;
    out.bytes(&value.request_id)?;
    out.bytes(&value.recovery_recipient_key)?;
    out.u64(value.requested_at);
    out.bytes(&value.nonce)?;
    out.u64(value.expiry);
    Ok(out.finish())
}

pub fn recovery_request_digest_v3(value: &RecoveryRequestV3) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-request-digest/v3")?;
    out.bytes(&recovery_request_v3(value)?)?;
    Ok(out.finish())
}

pub fn recovery_authorization_share_context_v3(
    request: &RecoveryRequestV3,
    signer_id: u16,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-a-share-context/v3")?;
    out.bytes(&recovery_request_v3(request)?)?;
    out.u16(signer_id);
    Ok(out.finish())
}

fn signer_recovery_contribution_into(
    out: &mut Transcript,
    value: &SignerRecoveryContributionV3,
    include_signature: bool,
) -> Result<(), WireError> {
    out.bytes(&recovery_request_v3(&value.request)?)?;
    out.u16(value.signer_id);
    out.bytes(&value.signer_public_key)?;
    out.bytes(&value.signer_membership_proof)?;
    sealed_into(out, &value.encrypted_authorization_share)?;
    if include_signature {
        out.bytes(&value.signer_signature)?;
    }
    Ok(())
}

pub fn signer_recovery_contribution_v3(
    value: &SignerRecoveryContributionV3,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-recovery-contribution/v3")?;
    signer_recovery_contribution_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn begin_recovery_certificate_v3(
    value: &BeginRecoveryCertificateV3,
) -> Result<Vec<u8>, WireError> {
    unique_ids(value.signer_contributions.iter().map(|item| item.signer_id))?;
    if value
        .signer_contributions
        .iter()
        .any(|item| item.request != value.request)
    {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/begin-recovery-certificate/v3")?;
    out.bytes(&recovery_request_v3(&value.request)?)?;
    out.bytes(&value.request_digest)?;
    bounded_count(
        &mut out,
        value.signer_contributions.len(),
        MAX_ROTATION_ACTORS,
    )?;
    for contribution in &value.signer_contributions {
        signer_recovery_contribution_into(&mut out, contribution, true)?;
    }
    Ok(out.finish())
}

fn signer_recovery_release_vote_into(
    out: &mut Transcript,
    value: &SignerRecoveryReleaseVoteV3,
    include_signature: bool,
) -> Result<(), WireError> {
    out.bytes(&recovery_request_v3(&value.request)?)?;
    out.bytes(&value.request_digest)?;
    out.u16(value.signer_id);
    out.bytes(&value.signer_public_key)?;
    out.bytes(&value.signer_membership_proof)?;
    if include_signature {
        out.bytes(&value.signer_signature)?;
    }
    Ok(())
}

pub fn signer_recovery_release_vote_v3(
    value: &SignerRecoveryReleaseVoteV3,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-recovery-release-vote/v3")?;
    signer_recovery_release_vote_into(&mut out, value, false)?;
    Ok(out.finish())
}

pub fn recovery_release_certificate_v3(
    value: &RecoveryReleaseCertificateV3,
) -> Result<Vec<u8>, WireError> {
    unique_ids(value.votes.iter().map(|vote| vote.signer_id))?;
    if value
        .votes
        .iter()
        .any(|vote| vote.request != value.request || vote.request_digest != value.request_digest)
    {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-release-certificate/v3")?;
    out.bytes(&recovery_request_v3(&value.request)?)?;
    out.bytes(&value.request_digest)?;
    bounded_count(&mut out, value.votes.len(), MAX_ROTATION_ACTORS)?;
    for vote in &value.votes {
        signer_recovery_release_vote_into(&mut out, vote, true)?;
    }
    Ok(out.finish())
}

pub fn owner_recovery_cancel_certificate_v3(
    value: &OwnerRecoveryCancelCertificateV3,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/owner-recovery-cancel/v3")?;
    out.bytes(&recovery_request_v3(&value.request)?)?;
    out.bytes(&value.request_digest)?;
    out.u16(value.reason_code);
    out.bytes(&value.cancel_response_recipient_key)?;
    out.bytes(&value.owner_cancel_public_key)?;
    Ok(out.finish())
}

pub fn owner_recovery_cancel_ack_v3(
    value: &OwnerRecoveryCancelAckV3,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/owner-recovery-cancel-ack/v3")?;
    config_ref_into(&mut out, &value.config_ref)?;
    out.bytes(&value.request_id)?;
    out.bytes(&value.request_digest)?;
    out.bytes(&value.cancel_certificate_hash)?;
    out.u16(value.guardian_index);
    Ok(out.finish())
}

pub fn guardian_recovery_contribution_v3(
    value: &GuardianRecoveryContributionV3,
) -> Result<Vec<u8>, WireError> {
    if value.guardian_index == 0 || value.fragment_index == 0 {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/guardian-recovery-contribution/v3")?;
    config_ref_into(&mut out, &value.config_ref)?;
    out.bytes(&value.request_id)?;
    out.bytes(&value.request_digest)?;
    out.bytes(&value.recovery_recipient_key)?;
    out.bytes(&value.nonce)?;
    out.u16(value.guardian_index);
    out.u16(value.fragment_index);
    out.bytes(&value.encrypted_ciphertext_fragment.nonce)?;
    out.bytes(&value.encrypted_ciphertext_fragment.ciphertext)?;
    out.bytes(&value.encrypted_dek_share.nonce)?;
    out.bytes(&value.encrypted_dek_share.ciphertext)?;
    out.bytes(&value.merkle_path_proof)?;
    Ok(out.finish())
}

pub fn guardian_share_context_v3(
    config_ref: &ConfigRef,
    guardian_index: u16,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/guardian-dek-share-context/v3")?;
    config_ref_into(&mut out, config_ref)?;
    out.u16(guardian_index);
    Ok(out.finish())
}

pub fn guardian_fragment_context_v3(
    config_ref: &ConfigRef,
    guardian_index: u16,
    fragment_index: u16,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/guardian-ciphertext-fragment-context/v3")?;
    config_ref_into(&mut out, config_ref)?;
    out.u16(guardian_index);
    out.u16(fragment_index);
    Ok(out.finish())
}

pub fn descriptor_context_v3(config_ref: &ConfigRef) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-descriptor-context/v3")?;
    config_ref_into(&mut out, config_ref)?;
    Ok(out.finish())
}

/// Canonical body whose SHA-256 is `ConfigCapsuleV3.capsule_hash`. The hash
/// field itself and its authenticating Activate certificate/QC are excluded,
/// avoiding self-reference while binding every immutable public field.
pub fn config_capsule_body_v3(value: &ConfigCapsuleV3) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3
        || value.signer_threshold == 0
        || value.signer_threshold > value.signer_count
        || value.guardian_threshold < 2
        || value.guardian_threshold > value.guardian_count
    {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/config-capsule-body/v3")?;
    out.u16(value.protocol_version);
    config_ref_into(&mut out, &value.config_ref)?;
    out.bytes(&value.predecessor_capsule_hash)?;
    out.u16(value.signer_count);
    out.u16(value.signer_threshold);
    out.u16(value.guardian_count);
    out.u16(value.guardian_threshold);
    out.u64(value.minimum_recovery_delay);
    out.u64(value.max_request_lifetime);
    out.bytes(&value.signer_set_commitment)?;
    out.bytes(&value.owner_cancel_public_key)?;
    out.u16(dpss_suite_id(value.dpss_suite));
    out.bytes(&value.dpss_public_commitment)?;
    out.bytes(&value.ciphertext_fragment_root)?;
    out.bytes(&value.guardian_material_root)?;
    out.bytes(&value.encrypted_recovery_descriptor.nonce)?;
    out.bytes(&value.encrypted_recovery_descriptor.ciphertext)?;
    Ok(out.finish())
}

/// Immutable guardian-policy commitment used by prepared-record leaves. The
/// mutable lifecycle/QC/drain fields and the material root containing this
/// leaf are deliberately outside the preimage.
pub fn guardian_policy_body_v3(value: &GuardianPolicyV3) -> Result<Vec<u8>, WireError> {
    if value.signer_threshold == 0
        || value.signer_threshold > value.signer_count
        || value.minimum_recovery_delay == 0
    {
        return Err(WireError::InvalidValue);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/guardian-policy-body/v3")?;
    config_ref_into(&mut out, &value.config_ref)?;
    out.bytes(&value.signer_set_commitment)?;
    out.u16(value.signer_count);
    out.u16(value.signer_threshold);
    out.bytes(&value.owner_cancel_public_key)?;
    out.u64(value.minimum_recovery_delay);
    out.u16(dpss_suite_id(value.dpss_suite));
    out.bytes(&value.dpss_public_commitment)?;
    out.bytes(&value.predecessor_capsule_hash)?;
    Ok(out.finish())
}

pub fn payload_context_v3(config_id: &Id32, payload_generation: u64) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/payload-context/v3")?;
    out.bytes(config_id)?;
    out.u64(payload_generation);
    Ok(out.finish())
}

pub fn custody_challenge(value: &CustodyChallenge) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3 || value.block_indices.is_empty() {
        return Err(WireError::InvalidValue);
    }
    let mut seen = BTreeSet::new();
    if value.block_indices.iter().any(|index| !seen.insert(*index)) {
        return Err(WireError::DuplicateActor);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/custody-challenge/v3")?;
    out.u16(value.protocol_version);
    config_ref_into(&mut out, &value.config_ref)?;
    out.bytes(&value.opaque_slot_id)?;
    out.bytes(&value.challenge_id)?;
    bounded_count(&mut out, value.block_indices.len(), 4096)?;
    for index in &value.block_indices {
        out.u32(*index);
    }
    out.bytes(&value.nonce)?;
    out.bytes(&value.response_recipient_key)?;
    out.u64(value.expiry);
    Ok(out.finish())
}

pub fn custody_response(value: &CustodyResponse) -> Result<Vec<u8>, WireError> {
    if value.protocol_version != PROTOCOL_VERSION_V3 || value.proofs.is_empty() {
        return Err(WireError::InvalidValue);
    }
    let mut seen = BTreeSet::new();
    if value
        .proofs
        .iter()
        .any(|proof| !seen.insert(proof.block_index))
    {
        return Err(WireError::DuplicateActor);
    }
    let mut out = Transcript::default();
    out.domain(b"gp/custody-response/v3")?;
    out.u16(value.protocol_version);
    config_ref_into(&mut out, &value.config_ref)?;
    out.bytes(&value.opaque_slot_id)?;
    out.bytes(&value.challenge_id)?;
    out.bytes(&value.nonce)?;
    out.u16(value.guardian_index);
    bounded_count(&mut out, value.proofs.len(), 4096)?;
    for proof in &value.proofs {
        out.u32(proof.block_index);
        out.bytes(&proof.block)?;
        out.bytes(&proof.merkle_path)?;
    }
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(epoch: u64, hash: u8) -> ConfigRef {
        ConfigRef {
            config_id: [1; 32],
            payload_generation: 2,
            authorization_epoch: 3,
            guardian_epoch: epoch,
            epoch_binding: [hash; 32],
        }
    }

    fn context() -> RotationContext {
        RotationContext {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config(4, 4),
            rotation_id: [5; 32],
            predecessor_capsule_hash: [4; 32],
            recipient_key: vec![6; 32],
            nonce: [7; 32],
            issued_at: 10,
            expiry: 100,
        }
    }

    fn route(index: u16, marker: u8) -> GuardianRouteV3 {
        GuardianRouteV3 {
            guardian_index: index,
            opaque_slot_id: [marker; 32],
            mailbox: format!("opaque-{marker}"),
            guardian_public_key: [marker; 32],
            session_recipient_key: vec![marker; 32],
            operator_domain_commitment: [marker; 32],
        }
    }

    fn plan() -> RotationPlan {
        RotationPlan {
            context: context(),
            intent_hash: [8; 32],
            predecessor: config(4, 4),
            successor: config(5, 9),
            old_roster: vec![route(1, 1), route(2, 2)],
            new_roster: vec![route(1, 3), route(2, 4)],
            old_roster_commitment: [10; 32],
            new_roster_commitment: [11; 32],
            old_guardian_threshold: 2,
            new_guardian_threshold: 2,
            data_shards: 1,
            total_shards: 2,
            dpss_suite: DpssSuiteId::default(),
            dpss_session_id: [12; 32],
            dpss_qualified_set_commitment: [13; 32],
            minimum_delay_secs: 20,
            preparation_deadline: 200,
            drain_deadline: 300,
        }
    }

    #[test]
    fn every_critical_plan_field_is_bound() {
        let original = plan();
        let canonical = rotation_plan(&original).unwrap();

        let mut mutations = Vec::new();
        let mut changed = original.clone();
        changed.successor.guardian_epoch += 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.new_roster[0].session_recipient_key[0] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.new_roster_commitment[0] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.new_guardian_threshold = 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.dpss_session_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.context.recipient_key[0] ^= 1;
        mutations.push(changed);
        let mut changed = original.clone();
        changed.context.nonce[0] ^= 1;
        mutations.push(changed);

        for changed in mutations {
            match rotation_plan(&changed) {
                Ok(transcript) => assert_ne!(canonical, transcript),
                Err(WireError::InvalidValue) => {}
                other => panic!("unexpected result: {other:?}"),
            }
        }
    }

    #[test]
    fn duplicate_actor_ids_cannot_inflate_a_quorum() {
        let vote = SignerRotationBeginVote {
            context: context(),
            intent_hash: [1; 32],
            plan_hash: [2; 32],
            old_roster_commitment: [3; 32],
            new_roster_commitment: [4; 32],
            signer_id: 1,
            signer_public_key: [5; 32],
            signer_membership_proof: vec![],
            signer_signature: vec![6],
        };
        let certificate = BeginRotationCertificate {
            context: context(),
            intent_hash: [1; 32],
            plan_hash: [2; 32],
            old_roster_commitment: [3; 32],
            new_roster_commitment: [4; 32],
            not_before_wall: 20,
            votes: vec![vote.clone(), vote],
        };
        assert!(matches!(
            begin_rotation_certificate(&certificate),
            Err(WireError::DuplicateActor)
        ));
    }

    #[test]
    fn duplicate_abort_votes_cannot_turn_one_signer_into_a_threshold() {
        let vote = SignerRotationAbortVote {
            context: context(),
            plan_hash: [2; 32],
            state_at_abort: RotationState::Preparing,
            reason_code: 9,
            signer_id: 1,
            signer_public_key: [5; 32],
            signer_membership_proof: vec![],
            signer_signature: vec![6],
        };
        let certificate = AbortRotationCertificate {
            context: context(),
            plan_hash: [2; 32],
            state_at_abort: RotationState::Preparing,
            reason_code: 9,
            votes: vec![vote.clone(), vote],
        };
        assert!(matches!(
            abort_rotation_certificate(&certificate),
            Err(WireError::DuplicateActor)
        ));
    }

    #[test]
    fn recovery_transcript_binds_epoch_recipient_nonce_and_actor() {
        let request = RecoveryRequestV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config(4, 4),
            request_id: [30; 32],
            recovery_recipient_key: vec![31; 1216],
            requested_at: 10,
            nonce: [32; 32],
            expiry: 100,
        };
        let original = recovery_authorization_share_context_v3(&request, 1).unwrap();
        let mut changed = request.clone();
        changed.config_ref.guardian_epoch += 1;
        assert_ne!(
            original,
            recovery_authorization_share_context_v3(&changed, 1).unwrap()
        );
        let mut changed = request.clone();
        changed.recovery_recipient_key[0] ^= 1;
        assert_ne!(
            original,
            recovery_authorization_share_context_v3(&changed, 1).unwrap()
        );
        let mut changed = request;
        changed.nonce[0] ^= 1;
        assert_ne!(
            original,
            recovery_authorization_share_context_v3(&changed, 1).unwrap()
        );
        assert_ne!(
            original,
            recovery_authorization_share_context_v3(&changed, 2).unwrap()
        );
    }

    #[test]
    fn payload_context_is_stable_across_guardian_epochs_but_share_context_is_not() {
        let old = config(4, 4);
        let new = config(5, 5);
        assert_eq!(
            payload_context_v3(&old.config_id, old.payload_generation).unwrap(),
            payload_context_v3(&new.config_id, new.payload_generation).unwrap()
        );
        assert_ne!(
            guardian_share_context_v3(&old, 1).unwrap(),
            guardian_share_context_v3(&new, 1).unwrap()
        );
    }

    #[test]
    fn witness_qc_requires_unique_two_f_plus_one_acks() {
        let base = WitnessActivationAck {
            context: context(),
            plan_hash: [1; 32],
            activation_certificate_hash: [2; 32],
            witness_id: 1,
            predecessor_epoch: 4,
            predecessor_capsule_hash: [4; 32],
            successor_epoch: 5,
            successor_capsule_hash: [5; 32],
            witness_public_key: [6; 32],
            witness_signature: vec![7],
        };
        let mut qc = EpochActivationQc {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: [1; 32],
            rotation_id: [5; 32],
            predecessor_epoch: 4,
            predecessor_capsule_hash: [4; 32],
            successor_epoch: 5,
            successor_capsule_hash: [5; 32],
            activation_certificate_hash: [2; 32],
            witness_fault_bound: 1,
            witness_acks: vec![base.clone(), base.clone(), base.clone()],
        };
        assert!(matches!(
            epoch_activation_qc(&qc),
            Err(WireError::DuplicateActor)
        ));
        for (offset, ack) in qc.witness_acks.iter_mut().enumerate() {
            ack.witness_id = u16::try_from(offset + 1).unwrap();
        }
        assert!(epoch_activation_qc(&qc).is_ok());
        qc.witness_acks.pop();
        assert!(matches!(
            epoch_activation_qc(&qc),
            Err(WireError::InvalidValue)
        ));
    }

    #[test]
    fn capsule_hash_body_binds_every_immutable_field_without_self_reference() {
        let capsule = ConfigCapsuleV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config(5, 9),
            capsule_hash: [99; 32],
            predecessor_capsule_hash: [4; 32],
            signer_count: 3,
            signer_threshold: 2,
            guardian_count: 8,
            guardian_threshold: 5,
            minimum_recovery_delay: 100,
            max_request_lifetime: 200,
            signer_set_commitment: [10; 32],
            owner_cancel_public_key: [11; 32],
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: [12; 32],
            ciphertext_fragment_root: [16; 32],
            guardian_material_root: [13; 32],
            encrypted_recovery_descriptor: AeadCiphertext {
                nonce: [14; 24],
                ciphertext: vec![15; 64],
            },
            activation_certificate: None,
            activation_qc: None,
        };
        let original = config_capsule_body_v3(&capsule).unwrap();
        let mut hash_only = capsule.clone();
        hash_only.capsule_hash[0] ^= 1;
        assert_eq!(original, config_capsule_body_v3(&hash_only).unwrap());

        let mut mutations = Vec::new();
        let mut changed = capsule.clone();
        changed.config_ref.epoch_binding[0] ^= 1;
        mutations.push(changed);
        let mut changed = capsule.clone();
        changed.predecessor_capsule_hash[0] ^= 1;
        mutations.push(changed);
        let mut changed = capsule.clone();
        changed.guardian_threshold = 6;
        mutations.push(changed);
        let mut changed = capsule.clone();
        changed.minimum_recovery_delay += 1;
        mutations.push(changed);
        let mut changed = capsule.clone();
        changed.signer_set_commitment[0] ^= 1;
        mutations.push(changed);
        let mut changed = capsule.clone();
        changed.dpss_public_commitment[0] ^= 1;
        mutations.push(changed);
        let mut changed = capsule.clone();
        changed.ciphertext_fragment_root[0] ^= 1;
        mutations.push(changed);
        let mut changed = capsule.clone();
        changed.guardian_material_root[0] ^= 1;
        mutations.push(changed);
        let mut changed = capsule;
        changed.encrypted_recovery_descriptor.ciphertext[0] ^= 1;
        mutations.push(changed);

        for changed in mutations {
            assert_ne!(original, config_capsule_body_v3(&changed).unwrap());
        }
    }
}
