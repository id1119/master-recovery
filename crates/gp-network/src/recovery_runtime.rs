//! Stateful protocol-v3 recovery actor logic.
//!
//! Recovery is pinned to the guardian epoch selected by a fresh witness read.
//! A guardian accepts new Begin requests only for its ACTIVE record. After an
//! activation it may finish only requests that were durably pending when the
//! predecessor entered DRAINING.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use gp_crypto::{XWING_PUBLIC_KEY_LEN, seal_to_recipient, sha256, sign, signing_key};
use gp_types::{
    GuardianRecordV3, GuardianRecoveryContributionV3, OwnerRecoveryCancelAckV3,
    PROTOCOL_VERSION_V3, SignerRecoveryContributionV3, SignerRecoveryReleaseVoteV3,
};

use crate::{
    protocol::{random_id, random_nonce},
    rotation_protocol::{
        select_latest_epoch_v3, validate_begin_recovery_certificate_v3,
        validate_owner_recovery_cancel_for_ref_v3,
        validate_recovery_release_certificate_for_ref_v3, validate_recovery_request_v3,
    },
    types::{
        GuardianRecoveryRequestV3, GuardianRecoveryResponseV3, GuardianRotationEntryV3,
        PendingNetworkRecoveryV3, SignerRecoveryRequestV3, SignerRecoveryResponseV3,
        SignerRotationEntryV3,
    },
};

pub fn handle_signer_recovery_v3(
    entry: &mut SignerRotationEntryV3,
    request: SignerRecoveryRequestV3,
    now: u64,
) -> Result<SignerRecoveryResponseV3> {
    match request {
        SignerRecoveryRequestV3::Approve {
            request,
            witness_challenge,
            witness_reads,
        } => {
            if witness_challenge.issued_at > now
                || witness_challenge.expiry <= now
                || witness_challenge.response_recipient_key != request.recovery_recipient_key
            {
                bail!("signer requires a fresh witness read bound to the recovery recipient");
            }
            let active = select_latest_epoch_v3(
                &entry.provision.recovery_card,
                &witness_challenge,
                &witness_reads,
            )?;
            let digest = validate_recovery_request_v3(&request, &active, now)?;
            let request_key = hex::encode(request.request_id);
            match entry.recovery_requests.get(&request_key) {
                Some(previous) if previous != &digest => {
                    bail!("signer request id is already bound to another transcript");
                }
                Some(_) => {}
                None => {
                    if !entry.recovery_nonces.insert(request.nonce) {
                        bail!("signer rejected a replayed recovery nonce");
                    }
                    entry.recovery_requests.insert(request_key, digest);
                }
            }
            entry.provision.active_capsule = active;
            let encrypted_authorization_share = seal_to_recipient(
                &request.recovery_recipient_key,
                random_id(),
                random_nonce(),
                &entry.provision.authorization_share,
                &gp_wire::recovery_authorization_share_context_v3(
                    &request,
                    entry.provision.signer_id,
                )?,
            )?;
            let mut contribution = SignerRecoveryContributionV3 {
                request,
                signer_id: entry.provision.signer_id,
                signer_public_key: entry.provision.signing_public_key,
                signer_membership_proof: entry.provision.membership_proof.clone(),
                encrypted_authorization_share,
                signer_signature: vec![],
            };
            contribution.signer_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::signer_recovery_contribution_v3(&contribution)?,
            );
            Ok(SignerRecoveryResponseV3::Contribution(contribution))
        }
        SignerRecoveryRequestV3::Release { request } => {
            let digest =
                validate_recovery_request_v3(&request, &entry.provision.active_capsule, now)?;
            if entry
                .recovery_requests
                .get(&hex::encode(request.request_id))
                != Some(&digest)
            {
                bail!("signer never approved this exact recovery request");
            }
            let mut vote = SignerRecoveryReleaseVoteV3 {
                request,
                request_digest: digest,
                signer_id: entry.provision.signer_id,
                signer_public_key: entry.provision.signing_public_key,
                signer_membership_proof: entry.provision.membership_proof.clone(),
                signer_signature: vec![],
            };
            vote.signer_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::signer_recovery_release_vote_v3(&vote)?,
            );
            Ok(SignerRecoveryResponseV3::ReleaseVote(vote))
        }
    }
}

fn record_for_request<'a>(
    entry: &'a GuardianRotationEntryV3,
    config_ref: &gp_types::ConfigRef,
    request_id: gp_types::Id32,
    require_pending_drain: bool,
) -> Result<&'a GuardianRecordV3> {
    if let Some(record) = entry.provision.epoch_store.active.as_ref()
        && &record.policy.config_ref == config_ref
    {
        return Ok(record);
    }
    let draining = entry
        .provision
        .epoch_store
        .draining
        .get(&config_ref.guardian_epoch)
        .filter(|epoch| epoch.record.policy.config_ref == *config_ref)
        .context("guardian has no record for the recovery request's exact epoch")?;
    if require_pending_drain && !draining.pending_request_ids.contains(&request_id) {
        bail!("draining guardian refuses a recovery that did not begin before activation");
    }
    Ok(&draining.record)
}

pub fn pending_old_recovery_ids(entry: &GuardianRotationEntryV3) -> BTreeSet<gp_types::Id32> {
    let predecessor = entry.provision.predecessor_capsule.config_ref;
    entry
        .recoveries
        .values()
        .filter(|pending| {
            pending.request.config_ref == predecessor && !pending.cancelled && !pending.released
        })
        .map(|pending| pending.request.request_id)
        .collect()
}

pub fn handle_guardian_recovery_v3(
    entry: &mut GuardianRotationEntryV3,
    request: GuardianRecoveryRequestV3,
    wall_now: u64,
    monotonic_now: u64,
    boot_id: &str,
    allow_insecure_demo_delay: bool,
) -> Result<GuardianRecoveryResponseV3> {
    let recovery = request.request().clone();
    if recovery.protocol_version != PROTOCOL_VERSION_V3
        || recovery.recovery_recipient_key.len() != XWING_PUBLIC_KEY_LEN
    {
        bail!("guardian rejected malformed protocol-v3 recovery request");
    }
    let key = hex::encode(recovery.request_id);
    match request {
        GuardianRecoveryRequestV3::Begin { certificate } => {
            let active = entry
                .provision
                .epoch_store
                .active
                .as_ref()
                .context("guardian has no ACTIVE recovery authority")?;
            if active.policy.config_ref != certificate.request.config_ref {
                bail!("new recovery Begin is not for this guardian's ACTIVE epoch");
            }
            let digest = validate_begin_recovery_certificate_v3(
                &certificate,
                &entry.provision.predecessor_capsule,
                wall_now,
            )?;
            if entry
                .provision
                .epoch_store
                .recovery_cancellation_tombstones
                .contains_key(&key)
            {
                bail!("recovery request was permanently cancelled");
            }
            if let Some(existing) = entry.recoveries.get(&key) {
                if existing.request_digest != digest || existing.request != certificate.request {
                    bail!("recovery request id is locked to another transcript");
                }
                return Ok(GuardianRecoveryResponseV3::BeginAccepted {
                    not_before_monotonic: existing.not_before_monotonic,
                });
            }
            if entry
                .recoveries
                .values()
                .any(|pending| pending.request.nonce == certificate.request.nonce)
            {
                bail!("guardian rejected a replayed recovery nonce");
            }
            let delay = if allow_insecure_demo_delay {
                active.policy.minimum_recovery_delay.min(2)
            } else {
                active.policy.minimum_recovery_delay
            };
            let not_before_monotonic = monotonic_now.saturating_add(delay);
            entry.recoveries.insert(
                key,
                PendingNetworkRecoveryV3 {
                    request: certificate.request,
                    request_digest: digest,
                    accepted_wall_time: wall_now,
                    started_monotonic: monotonic_now,
                    not_before_monotonic,
                    boot_id: boot_id.to_owned(),
                    cancelled: false,
                    released: false,
                },
            );
            Ok(GuardianRecoveryResponseV3::BeginAccepted {
                not_before_monotonic,
            })
        }
        GuardianRecoveryRequestV3::Cancel {
            request,
            certificate,
        } => {
            let expected_ref = request.config_ref;
            record_for_request(entry, &expected_ref, request.request_id, true)?;
            let digest = validate_owner_recovery_cancel_for_ref_v3(
                &certificate,
                &request,
                &entry.provision.predecessor_capsule,
                &expected_ref,
                wall_now,
            )?;
            if let Some(pending) = entry.recoveries.get(&key) {
                if pending.request_digest != digest {
                    bail!("cancellation conflicts with the accepted request transcript");
                }
                if pending.released {
                    bail!("owner cancellation is not retroactive after material release");
                }
            }
            entry
                .provision
                .epoch_store
                .recovery_cancellation_tombstones
                .insert(key.clone(), digest);
            if let Some(pending) = entry.recoveries.get_mut(&key) {
                pending.cancelled = true;
            }
            let guardian_index =
                record_for_request(entry, &expected_ref, request.request_id, true)?.guardian_index;
            let mut ack = OwnerRecoveryCancelAckV3 {
                config_ref: expected_ref,
                request_id: request.request_id,
                request_digest: digest,
                cancel_certificate_hash: sha256(&gp_wire::owner_recovery_cancel_certificate_v3(
                    &certificate,
                )?),
                guardian_index,
                guardian_signature: vec![],
            };
            ack.guardian_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::owner_recovery_cancel_ack_v3(&ack)?,
            );
            Ok(GuardianRecoveryResponseV3::Cancelled(ack))
        }
        GuardianRecoveryRequestV3::Release {
            request,
            certificate,
        } => {
            let expected_ref = request.config_ref;
            let digest = validate_recovery_release_certificate_for_ref_v3(
                &certificate,
                &entry.provision.predecessor_capsule,
                &expected_ref,
                wall_now,
            )?;
            let record =
                record_for_request(entry, &expected_ref, request.request_id, true)?.clone();
            let pending = entry
                .recoveries
                .get_mut(&key)
                .context("guardian never accepted Begin for this exact request")?;
            if pending.request != request || pending.request_digest != digest {
                bail!("guardian Release does not match the durably accepted Begin");
            }
            if pending.cancelled
                || pending.released
                || entry
                    .provision
                    .epoch_store
                    .recovery_cancellation_tombstones
                    .get(&key)
                    == Some(&digest)
            {
                bail!("guardian refuses cancelled or replayed recovery Release");
            }
            if pending.boot_id != boot_id
                || monotonic_now < pending.not_before_monotonic
                || wall_now >= pending.request.expiry
            {
                bail!("guardian recovery delay is incomplete, expired, or reboot-ambiguous");
            }
            let mut contribution = GuardianRecoveryContributionV3 {
                config_ref: request.config_ref,
                request_id: request.request_id,
                request_digest: digest,
                recovery_recipient_key: request.recovery_recipient_key,
                nonce: request.nonce,
                guardian_index: record.guardian_index,
                fragment_index: record.fragment_index,
                encrypted_ciphertext_fragment: record.encrypted_ciphertext_fragment,
                encrypted_dek_share: record.encrypted_dek_share,
                merkle_path_proof: record.merkle_path_proof,
                guardian_signature: vec![],
            };
            contribution.guardian_signature = sign(
                &signing_key(entry.provision.signing_seed),
                &gp_wire::guardian_recovery_contribution_v3(&contribution)?,
            );
            pending.released = true;
            if entry
                .provision
                .epoch_store
                .draining
                .contains_key(&expected_ref.guardian_epoch)
            {
                entry
                    .provision
                    .epoch_store
                    .finish_draining_request(expected_ref.guardian_epoch, request.request_id)?;
            }
            Ok(GuardianRecoveryResponseV3::Contribution(contribution))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use gp_crypto::{RecipientKeyPair, merkle_commit, verifying_key_bytes};
    use gp_storage::SignerRotationStore;
    use gp_types::{
        AeadCiphertext, ConfigCapsuleV3, ConfigRef, DpssSuiteId, EpochReadChallenge,
        RecoveryCardV3, RecoveryRequestV3, WitnessEpochReadResponse, WitnessPin,
    };
    use zeroize::Zeroizing;

    #[test]
    fn signer_uses_fresh_witness_epoch_and_binds_share_and_release_to_recipient() {
        let signer_seeds = [[1; 32], [2; 32], [3; 32]];
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
            config_id: [4; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: 1,
            epoch_binding: [5; 32],
        };
        let owner_key = verifying_key_bytes(&signing_key([6; 32]));
        let mut capsule = ConfigCapsuleV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref,
            capsule_hash: [0; 32],
            predecessor_capsule_hash: [0; 32],
            signer_count: 3,
            signer_threshold: 2,
            guardian_count: 3,
            guardian_threshold: 2,
            minimum_recovery_delay: 10,
            max_request_lifetime: 100,
            signer_set_commitment: signer_root,
            owner_cancel_public_key: owner_key,
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: [7; 32],
            ciphertext_fragment_root: [11; 32],
            guardian_material_root: [8; 32],
            encrypted_recovery_descriptor: AeadCiphertext {
                nonce: [9; 24],
                ciphertext: vec![10; 48],
            },
            activation_certificate: None,
            activation_qc: None,
        };
        capsule.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&capsule).unwrap());
        let witness_seeds = [[11; 32], [12; 32], [13; 32], [14; 32]];
        let witnesses = witness_seeds
            .iter()
            .enumerate()
            .map(|(offset, seed)| WitnessPin {
                witness_id: u16::try_from(offset + 1).unwrap(),
                mailbox: format!("https://witness-{offset}.invalid"),
                public_key: verifying_key_bytes(&signing_key(*seed)),
            })
            .collect::<Vec<_>>();
        let card = RecoveryCardV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: config_ref.config_id,
            signer_mailboxes: vec!["opaque-signer-mailbox-0123456789abcdef".into()],
            signer_set_commitment: signer_root,
            owner_cancel_public_key: owner_key,
            witness_fault_bound: 1,
            witnesses,
            relay_bases: vec!["https://relay.invalid".into()],
        };
        let recipient = RecipientKeyPair::from_seed([15; 32]);
        let challenge = EpochReadChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id: config_ref.config_id,
            client_nonce: [16; 32],
            response_recipient_key: recipient.public_key().to_vec(),
            issued_at: 20,
            expiry: 40,
        };
        let reads = witness_seeds
            .iter()
            .enumerate()
            .map(|(offset, seed)| {
                let mut response = WitnessEpochReadResponse {
                    protocol_version: PROTOCOL_VERSION_V3,
                    config_id: config_ref.config_id,
                    client_nonce: challenge.client_nonce,
                    witness_id: u16::try_from(offset + 1).unwrap(),
                    highest_guardian_epoch: 1,
                    capsule_hash: capsule.capsule_hash,
                    witness_public_key: verifying_key_bytes(&signing_key(*seed)),
                    witness_signature: vec![],
                };
                response.witness_signature = sign(
                    &signing_key(*seed),
                    &gp_wire::witness_epoch_read_response(&response).unwrap(),
                );
                crate::types::WitnessReadEnvelope {
                    response,
                    capsule: capsule.clone(),
                }
            })
            .collect::<Vec<_>>();
        let mut entry = SignerRotationEntryV3 {
            provision: crate::types::SignerRotationProvisionV3 {
                mailbox: card.signer_mailboxes[0].clone(),
                signer_id: 1,
                authorization_share: Zeroizing::new(vec![17; 33]),
                signing_seed: signer_seeds[0],
                signing_public_key: signer_keys[0].1,
                membership_proof: signer_proofs[0].clone(),
                recovery_card: card,
                active_capsule: capsule,
            },
            security_state: SignerRotationStore::new(),
            recovery_requests: BTreeMap::new(),
            recovery_nonces: BTreeSet::new(),
        };
        let request = RecoveryRequestV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref,
            request_id: [18; 32],
            recovery_recipient_key: recipient.public_key().to_vec(),
            requested_at: 20,
            nonce: [19; 32],
            expiry: 80,
        };
        let SignerRecoveryResponseV3::Contribution(contribution) = handle_signer_recovery_v3(
            &mut entry,
            SignerRecoveryRequestV3::Approve {
                request: request.clone(),
                witness_challenge: challenge.clone(),
                witness_reads: reads.clone(),
            },
            21,
        )
        .unwrap() else {
            panic!("expected contribution")
        };
        assert_eq!(
            recipient
                .open(
                    &contribution.encrypted_authorization_share,
                    &gp_wire::recovery_authorization_share_context_v3(&request, 1).unwrap(),
                )
                .unwrap()
                .as_slice(),
            &[17; 33]
        );
        let SignerRecoveryResponseV3::ReleaseVote(vote) = handle_signer_recovery_v3(
            &mut entry,
            SignerRecoveryRequestV3::Release {
                request: request.clone(),
            },
            22,
        )
        .unwrap() else {
            panic!("expected release vote")
        };
        gp_crypto::verify(
            &vote.signer_public_key,
            &gp_wire::signer_recovery_release_vote_v3(&vote).unwrap(),
            &vote.signer_signature,
        )
        .unwrap();
        let mut conflicting = request;
        conflicting.nonce = [20; 32];
        assert!(
            handle_signer_recovery_v3(
                &mut entry,
                SignerRecoveryRequestV3::Approve {
                    request: conflicting,
                    witness_challenge: challenge,
                    witness_reads: reads,
                },
                23,
            )
            .is_err()
        );
    }
}
