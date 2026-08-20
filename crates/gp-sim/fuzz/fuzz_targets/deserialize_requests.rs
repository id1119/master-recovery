#![no_main]

//! Fuzz the untrusted JSON boundary: every protocol message type that
//! gp-network deserializes from attacker-controlled bytes with
//! `serde_json::from_slice`. Successful parses are additionally driven through
//! the same transcript/KEM/Merkle/AEAD calls the gp-sim validators
//! (`validate_begin_certificate`, `validate_release_certificate`,
//! `validate_guardian_contribution`, `validate_approvals_and_reconstruct`, and
//! the DPSS handling in guardian_runtime.rs) perform on untrusted values, so a
//! panic anywhere in the parse -> validate chain surfaces as a crash.

use gp_crypto::{
    RecipientKeyPair, aead_decrypt, guardian_share_key, guardian_share_key_v3, hash_aead,
    merkle_verify, sha256, verify, zeroize_id,
};
use gp_types::{
    AbortRotationCertificate, AeadCiphertext, BeginRecoveryCertificate,
    BeginRecoveryCertificateV3, BeginRotationCertificate, ConfigCapsule, ConfigCapsuleV3,
    ConfigRef, CustodyBlockProof, CustodyChallenge, CustodyResponse, DpssProtocolMessage,
    EpochActivationQc, EpochReadChallenge, GuardianContribution, GuardianHealthRecord,
    GuardianPolicy, GuardianPolicyV3, GuardianRecord, GuardianRecordV3, GuardianRoute,
    GuardianRouteV3, GuardianRecoveryContributionV3, NewGuardianPreparedAck, NewShareWrapGrant,
    OldGuardianHandoffAck, OldShareUnlockGrant, OwnerCancelAck, OwnerCancelCertificate,
    OwnerRecoveryCancelAckV3, OwnerRecoveryCancelCertificateV3, OwnerRotationCancelAck,
    OwnerRotationCancelCertificate, PreparedRecordLeaf, RecoveryCard, RecoveryCardV3,
    RecoveryDescriptor, RecoveryDescriptorV3, RecoveryRequest, RecoveryRequestV3,
    RecoveryReleaseCertificateV3, ReleaseCertificate, ReleaseVote, RetirementAck, RetirementNotice,
    RotationActivateCertificate, RotationContext, RotationIntent, RotationPlan,
    RotationReadyCertificate, RotationReleaseCertificate, SealedMessage, SignerContribution,
    SignerPolicy, SignerRecoveryContributionV3, SignerRecoveryReleaseVoteV3, SignerRotationAbortVote,
    SignerRotationActivateVote, SignerRotationBeginVote, SignerRotationIntentContribution,
    SignerRotationReleaseVote, WitnessActivationAck, WitnessEpochReadResponse, WitnessPin,
    WitnessRotationCancelAck, CiphertextFragmentContribution,
};
use libfuzzer_sys::fuzz_target;

const FIXED_ID: [u8; 32] = [7; 32];
const FIXED_ROOT: [u8; 32] = [9; 32];
const FIXED_OWNER_KEY: [u8; 32] = [1; 32];
const FIXED_GUARDIAN_KEY: [u8; 32] = [2; 32];
const FIXED_DEK: [u8; 32] = [5; 32];
const FIXED_AUTHORIZATION_KEY: [u8; 32] = [6; 32];
const FIXED_AD: &[u8] = b"gp/fuzz-fixed-associated-data/v1";
const SIGNER_COUNT: u16 = 3;
const GUARDIAN_COUNT: u16 = 8;

fn drive_json<T>(data: &[u8], drive: impl Fn(&T))
where
    T: serde::de::DeserializeOwned,
{
    if let Ok(value) = serde_json::from_slice::<T>(data) {
        drive(&value);
    }
}

fn signature_probe(public_key: &[u8; 32], transcript: &[u8], signature: &[u8]) {
    let _ = verify(public_key, transcript, signature);
}

fn aead_probe(aead: &AeadCiphertext) {
    let _ = hash_aead(aead);
    let _ = aead_decrypt(&FIXED_DEK, aead, FIXED_AD);
}

fn open_probe(sealed: &SealedMessage) {
    let recipient = RecipientKeyPair::from_seed(FIXED_ID);
    let _ = recipient.open(sealed, FIXED_AD);
}

/// Mirrors `validate_signer_membership` in gp-sim: bounds check, leaf hash,
/// Merkle verification against the signer-set commitment.
fn signer_membership_probe(signer_id: u16, public_key: &[u8; 32], proof: &[u8]) {
    if signer_id == 0 || signer_id > SIGNER_COUNT {
        return;
    }
    let Ok(leaf) = gp_wire::signer_leaf(signer_id, public_key) else {
        return;
    };
    let _ = merkle_verify(
        FIXED_ROOT,
        sha256(&leaf),
        usize::from(signer_id - 1),
        usize::from(SIGNER_COUNT),
        proof,
    );
}

/// Mirrors the leaf/Merkle/decrypt steps of `validate_guardian_contribution`:
/// guardian leaf over the fragment and wrapped share, Merkle verification
/// against the guardian-material root, then AEAD open of the wrapped DEK share
/// under the A-derived key.
fn guardian_probe(contribution: &GuardianContribution) {
    if contribution.guardian_index == 0 || contribution.guardian_index > GUARDIAN_COUNT {
        return;
    }
    let fragment_hash = sha256(&contribution.ciphertext_fragment);
    let share_hash = hash_aead(&contribution.encrypted_dek_share);
    let Ok(leaf) = gp_wire::guardian_leaf(
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
        &fragment_hash,
        &share_hash,
    ) else {
        return;
    };
    let _ = merkle_verify(
        FIXED_ROOT,
        sha256(&leaf),
        usize::from(contribution.guardian_index - 1),
        usize::from(GUARDIAN_COUNT),
        &contribution.merkle_path_proof,
    );
    let Ok(context) =
        gp_wire::guardian_share_context(&contribution.config_id, contribution.config_version, contribution.guardian_index)
    else {
        return;
    };
    let Ok(mut key) = guardian_share_key(
        &FIXED_AUTHORIZATION_KEY,
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
    ) else {
        return;
    };
    let _ = aead_decrypt(&key, &contribution.encrypted_dek_share, &context);
    zeroize_id(&mut key);
}

fn drive_request(request: &RecoveryRequest) {
    let _ = gp_wire::recovery_request(request);
    let _ = gp_wire::request_digest_preimage(request);
    let _ = gp_wire::recipient_share_context(request, 1);
    let _ = gp_wire::guardian_release_context(request, 1);
}

fn drive_signer_contribution(contribution: &SignerContribution) {
    drive_request(&contribution.request);
    let Ok(transcript) = gp_wire::signer_approval(
        &contribution.request,
        contribution.signer_id,
        &contribution.encrypted_a_share,
    ) else {
        return;
    };
    signer_membership_probe(
        contribution.signer_id,
        &contribution.signer_public_key,
        &contribution.signer_membership_proof,
    );
    signature_probe(
        &contribution.signer_public_key,
        &transcript,
        &contribution.signer_signature,
    );
    open_probe(&contribution.encrypted_a_share);
}

fn drive_begin(certificate: &BeginRecoveryCertificate) {
    drive_request(&certificate.request);
    for contribution in certificate.signer_contributions.iter().take(16) {
        drive_signer_contribution(contribution);
    }
}

fn drive_owner_cancel(certificate: &OwnerCancelCertificate) {
    let Ok(transcript) = gp_wire::owner_cancel(certificate) else {
        return;
    };
    signature_probe(&FIXED_OWNER_KEY, &transcript, &certificate.owner_signature);
}

fn drive_release_vote(vote: &ReleaseVote) {
    let Ok(transcript) = gp_wire::release_vote(vote) else {
        return;
    };
    signer_membership_probe(
        vote.signer_id,
        &vote.signer_public_key,
        &vote.signer_membership_proof,
    );
    signature_probe(&vote.signer_public_key, &transcript, &vote.signer_signature);
}

fn drive_release(certificate: &ReleaseCertificate) {
    for vote in certificate.votes.iter().take(16) {
        drive_release_vote(vote);
    }
}

fn drive_guardian_contribution(contribution: &GuardianContribution) {
    let Ok(transcript) = gp_wire::guardian_contribution(contribution) else {
        return;
    };
    signature_probe(&FIXED_GUARDIAN_KEY, &transcript, &contribution.guardian_signature);
    guardian_probe(contribution);
}

/// Mirrors `open_deliveries` in guardian_runtime.rs: transcript binding and
/// sender-signature verification of a DPSS message.
fn drive_dpss(message: &DpssProtocolMessage) {
    let Ok(transcript) = gp_wire::dpss_protocol_message(message) else {
        return;
    };
    signature_probe(&FIXED_GUARDIAN_KEY, &transcript, &message.sender_signature);
}

fn drive_v3_signer_contribution(contribution: &SignerRecoveryContributionV3) {
    let _ = gp_wire::recovery_authorization_share_context_v3(&contribution.request, contribution.signer_id);
    let Ok(transcript) = gp_wire::signer_recovery_contribution_v3(contribution) else {
        return;
    };
    signer_membership_probe(
        contribution.signer_id,
        &contribution.signer_public_key,
        &contribution.signer_membership_proof,
    );
    signature_probe(
        &contribution.signer_public_key,
        &transcript,
        &contribution.signer_signature,
    );
    open_probe(&contribution.encrypted_authorization_share);
}

fn drive_v3_begin(certificate: &BeginRecoveryCertificateV3) {
    for contribution in certificate.signer_contributions.iter().take(16) {
        drive_v3_signer_contribution(contribution);
    }
    let _ = gp_wire::begin_recovery_certificate_v3(certificate);
}

fn drive_v3_release_vote(vote: &SignerRecoveryReleaseVoteV3) {
    let Ok(transcript) = gp_wire::signer_recovery_release_vote_v3(vote) else {
        return;
    };
    signer_membership_probe(
        vote.signer_id,
        &vote.signer_public_key,
        &vote.signer_membership_proof,
    );
    signature_probe(&vote.signer_public_key, &transcript, &vote.signer_signature);
}

fn drive_v3_release(certificate: &RecoveryReleaseCertificateV3) {
    for vote in certificate.votes.iter().take(16) {
        drive_v3_release_vote(vote);
    }
    let _ = gp_wire::recovery_release_certificate_v3(certificate);
}

fn drive_v3_owner_cancel(certificate: &OwnerRecoveryCancelCertificateV3) {
    let Ok(transcript) = gp_wire::owner_recovery_cancel_certificate_v3(certificate) else {
        return;
    };
    signature_probe(&FIXED_OWNER_KEY, &transcript, &certificate.owner_signature);
}

fn drive_v3_guardian_contribution(contribution: &GuardianRecoveryContributionV3) {
    let Ok(transcript) = gp_wire::guardian_recovery_contribution_v3(contribution) else {
        return;
    };
    signature_probe(&FIXED_GUARDIAN_KEY, &transcript, &contribution.guardian_signature);
    let _ = gp_wire::guardian_share_context_v3(&contribution.config_ref, contribution.guardian_index);
    let _ = gp_wire::guardian_fragment_context_v3(
        &contribution.config_ref,
        contribution.guardian_index,
        contribution.fragment_index,
    );
    let Ok(mut key) = guardian_share_key_v3(
        &FIXED_AUTHORIZATION_KEY,
        &contribution.config_ref,
        contribution.guardian_index,
    ) else {
        return;
    };
    let Ok(context) =
        gp_wire::guardian_share_context_v3(&contribution.config_ref, contribution.guardian_index)
    else {
        return;
    };
    let _ = aead_decrypt(&key, &contribution.encrypted_dek_share, &context);
    zeroize_id(&mut key);
    aead_probe(&contribution.encrypted_ciphertext_fragment);
}

fn drive_rotation_vote_with_signature<T>(
    transcript: impl Fn(&T) -> Result<Vec<u8>, gp_wire::WireError>,
    value: &T,
    signature: &[u8],
) {
    if let Ok(bytes) = transcript(value) {
        signature_probe(&FIXED_GUARDIAN_KEY, &bytes, signature);
    }
}

fn drive_v3_transcript<T>(transcript: impl Fn(&T) -> Result<Vec<u8>, gp_wire::WireError>, value: &T) {
    let _ = transcript(value);
}

fuzz_target!(|data: &[u8]| {
    // protocol-v2 request/certificate messages
    drive_json::<RecoveryRequest>(data, drive_request);
    drive_json::<SignerContribution>(data, drive_signer_contribution);
    drive_json::<BeginRecoveryCertificate>(data, drive_begin);
    drive_json::<OwnerCancelCertificate>(data, drive_owner_cancel);
    drive_json::<OwnerCancelAck>(data, |ack| {
        let _ = gp_wire::owner_cancel_ack(ack);
    });
    drive_json::<ReleaseVote>(data, drive_release_vote);
    drive_json::<ReleaseCertificate>(data, drive_release);
    drive_json::<GuardianContribution>(data, drive_guardian_contribution);
    drive_json::<SealedMessage>(data, open_probe);
    drive_json::<AeadCiphertext>(data, aead_probe);

    // protocol-v2 config/roster objects (no transcript; parse-only)
    drive_json::<RecoveryDescriptor>(data, |_| {});
    drive_json::<GuardianRoute>(data, |_| {});
    drive_json::<ConfigCapsule>(data, |_| {});
    drive_json::<RecoveryCard>(data, |_| {});
    drive_json::<SignerPolicy>(data, |_| {});
    drive_json::<GuardianPolicy>(data, |_| {});
    drive_json::<GuardianRecord>(data, |_| {});

    // protocol-v3 recovery messages
    drive_json::<RecoveryRequestV3>(data, |request| {
        let _ = gp_wire::recovery_authorization_share_context_v3(request, 1);
    });
    drive_json::<SignerRecoveryContributionV3>(data, drive_v3_signer_contribution);
    drive_json::<BeginRecoveryCertificateV3>(data, drive_v3_begin);
    drive_json::<SignerRecoveryReleaseVoteV3>(data, drive_v3_release_vote);
    drive_json::<RecoveryReleaseCertificateV3>(data, drive_v3_release);
    drive_json::<OwnerRecoveryCancelCertificateV3>(data, drive_v3_owner_cancel);
    drive_json::<OwnerRecoveryCancelAckV3>(data, |ack| {
        let _ = gp_wire::owner_recovery_cancel_ack_v3(ack);
    });
    drive_json::<GuardianRecoveryContributionV3>(data, drive_v3_guardian_contribution);
    drive_json::<RecoveryDescriptorV3>(data, |_| {});
    drive_json::<ConfigCapsuleV3>(data, |capsule| {
        let _ = gp_wire::config_capsule_body_v3(capsule);
    });
    drive_json::<RecoveryCardV3>(data, |_| {});
    drive_json::<GuardianPolicyV3>(data, |policy| {
        let _ = gp_wire::guardian_policy_body_v3(policy);
    });
    drive_json::<GuardianRecordV3>(data, |_| {});
    drive_json::<GuardianRouteV3>(data, |_| {});
    drive_json::<WitnessPin>(data, |_| {});

    // DPSS / rotation messages
    drive_json::<DpssProtocolMessage>(data, drive_dpss);
    drive_json::<ConfigRef>(data, |_| {});
    drive_json::<RotationContext>(data, |_| {});
    drive_json::<RotationPlan>(data, |plan| {
        let _ = gp_wire::rotation_plan(plan);
    });
    drive_json::<RotationIntent>(data, |intent| {
        let _ = gp_wire::rotation_intent(intent);
    });
    drive_json::<SignerRotationIntentContribution>(data, |contribution| {
        drive_rotation_vote_with_signature(
            gp_wire::signer_rotation_intent_contribution,
            contribution,
            &contribution.signer_signature,
        );
    });
    drive_json::<SignerRotationBeginVote>(data, |vote| {
        drive_rotation_vote_with_signature(
            gp_wire::signer_rotation_begin_vote,
            vote,
            &vote.signer_signature,
        );
    });
    drive_json::<BeginRotationCertificate>(data, |certificate| {
        for vote in certificate.votes.iter().take(16) {
            drive_rotation_vote_with_signature(
                gp_wire::signer_rotation_begin_vote,
                vote,
                &vote.signer_signature,
            );
        }
        let _ = gp_wire::begin_rotation_certificate(certificate);
    });
    drive_json::<OwnerRotationCancelCertificate>(data, |certificate| {
        let _ = gp_wire::owner_rotation_cancel_certificate(certificate);
    });
    drive_json::<OwnerRotationCancelAck>(data, |ack| {
        let _ = gp_wire::owner_rotation_cancel_ack(ack);
    });
    drive_json::<SignerRotationReleaseVote>(data, |vote| {
        let _ = gp_wire::signer_rotation_release_vote(vote);
    });
    drive_json::<RotationReleaseCertificate>(data, |certificate| {
        for vote in certificate.votes.iter().take(16) {
            let _ = gp_wire::signer_rotation_release_vote(vote);
        }
        let _ = gp_wire::rotation_release_certificate(certificate);
    });
    drive_json::<OldShareUnlockGrant>(data, |grant| {
        let _ = gp_wire::old_share_unlock_grant(grant);
    });
    drive_json::<NewShareWrapGrant>(data, |grant| {
        let _ = gp_wire::new_share_wrap_grant(grant);
    });
    drive_json::<CiphertextFragmentContribution>(data, |contribution| {
        drive_rotation_vote_with_signature(
            gp_wire::ciphertext_fragment_contribution,
            contribution,
            &contribution.guardian_signature,
        );
    });
    drive_json::<PreparedRecordLeaf>(data, |leaf| {
        let _ = gp_wire::prepared_record_leaf_v3(leaf);
    });
    drive_json::<NewGuardianPreparedAck>(data, |ack| {
        drive_rotation_vote_with_signature(
            gp_wire::new_guardian_prepared_ack,
            ack,
            &ack.guardian_signature,
        );
    });
    drive_json::<OldGuardianHandoffAck>(data, |ack| {
        drive_rotation_vote_with_signature(
            gp_wire::old_guardian_handoff_ack,
            ack,
            &ack.guardian_signature,
        );
    });
    drive_json::<RotationReadyCertificate>(data, |certificate| {
        let _ = gp_wire::rotation_ready_certificate(certificate);
    });
    drive_json::<SignerRotationActivateVote>(data, |vote| {
        drive_rotation_vote_with_signature(
            gp_wire::signer_rotation_activate_vote,
            vote,
            &vote.signer_signature,
        );
    });
    drive_json::<RotationActivateCertificate>(data, |certificate| {
        let _ = gp_wire::rotation_activate_certificate(certificate);
    });
    drive_json::<WitnessActivationAck>(data, |ack| {
        drive_rotation_vote_with_signature(
            gp_wire::witness_activation_ack,
            ack,
            &ack.witness_signature,
        );
    });
    drive_json::<WitnessRotationCancelAck>(data, |ack| {
        drive_rotation_vote_with_signature(
            gp_wire::witness_rotation_cancel_ack,
            ack,
            &ack.witness_signature,
        );
    });
    drive_json::<EpochActivationQc>(data, |qc| {
        let _ = gp_wire::epoch_activation_qc(qc);
    });
    drive_json::<EpochReadChallenge>(data, |challenge| {
        let _ = gp_wire::epoch_read_challenge(challenge);
    });
    drive_json::<WitnessEpochReadResponse>(data, |response| {
        drive_rotation_vote_with_signature(
            gp_wire::witness_epoch_read_response,
            response,
            &response.witness_signature,
        );
    });
    drive_json::<RetirementNotice>(data, |notice| {
        let _ = gp_wire::retirement_notice(notice);
    });
    drive_json::<RetirementAck>(data, |ack| {
        drive_rotation_vote_with_signature(
            gp_wire::retirement_ack,
            ack,
            &ack.guardian_signature,
        );
    });
    drive_json::<SignerRotationAbortVote>(data, |vote| {
        drive_rotation_vote_with_signature(
            gp_wire::signer_rotation_abort_vote,
            vote,
            &vote.signer_signature,
        );
    });
    drive_json::<AbortRotationCertificate>(data, |certificate| {
        let _ = gp_wire::abort_rotation_certificate(certificate);
    });
    drive_json::<CustodyChallenge>(data, |challenge| {
        let _ = gp_wire::custody_challenge(challenge);
    });
    drive_json::<CustodyBlockProof>(data, |_| {});
    drive_json::<CustodyResponse>(data, |response| {
        drive_rotation_vote_with_signature(
            gp_wire::custody_response,
            response,
            &response.guardian_signature,
        );
    });
    drive_json::<GuardianHealthRecord>(data, |_| {});
});