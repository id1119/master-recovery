#![no_main]

//! Fuzz the untrusted release-certificate boundary. Parses attacker bytes as a
//! protocol-v2 `ReleaseCertificate` and drives every vote through the same
//! probes `validate_release_certificate` in gp-sim performs on untrusted
//! values: request binding (digest, recipient, nonce), unique signer ids,
//! signer membership (leaf + Merkle), and Ed25519 verification of the
//! `release_vote` transcript. Any panic in the parse -> validate chain
//! surfaces as a crash.

use gp_crypto::{merkle_verify, sha256, verify};
use gp_types::{ConfigCapsule, RecoveryRequest, ReleaseCertificate, ReleaseVote};
use libfuzzer_sys::fuzz_target;

const FIXED_ROOT: [u8; 32] = [9; 32];
const SIGNER_COUNT: u16 = 3;
const THRESHOLD: u16 = 2;

fn membership_probe(signer_id: u16, public_key: &[u8; 32], proof: &[u8]) {
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

/// Mirrors `validate_release_certificate`: recompute the request digest,
/// field-bind every vote to the exact request, then membership + signature.
fn drive(certificate: &ReleaseCertificate, request: &RecoveryRequest) {
    let Ok(digest) = gp_wire::request_digest_preimage(request).map(|preimage| sha256(&preimage))
    else {
        return;
    };
    let mut ids = std::collections::BTreeSet::new();
    for vote in certificate.votes.iter().take(16) {
        if vote.protocol_version != request.protocol_version
            || vote.config_id != request.config_id
            || vote.config_version != request.config_version
            || vote.request_id != request.request_id
            || vote.request_digest != digest
            || vote.recovery_recipient_key != request.recovery_recipient_key
            || vote.nonce != request.nonce
            || !ids.insert(vote.signer_id)
        {
            continue;
        }
        membership_probe(
            vote.signer_id,
            &vote.signer_public_key,
            &vote.signer_membership_proof,
        );
        let Ok(transcript) = gp_wire::release_vote(vote) else {
            continue;
        };
        let _ = verify(&vote.signer_public_key, &transcript, &vote.signer_signature);
    }
    if ids.len() < usize::from(THRESHOLD) {
        return;
    }
    let _ = &certificate.votes;
}

fuzz_target!(|data: &[u8]| {
    if let Ok(certificate) = serde_json::from_slice::<ReleaseCertificate>(data) {
        if let Some(vote) = certificate.votes.first() {
            // The validator binds votes against the explicit request the
            // guardian has stored; reconstruct it from the attacker's own
            // vote fields so the digest/binding code runs.
            let request = RecoveryRequest {
                protocol_version: vote.protocol_version,
                crypto_suite: gp_types::CryptoSuite::XWingXChaCha20Poly1305Ed25519,
                config_id: vote.config_id,
                config_version: vote.config_version,
                request_id: vote.request_id,
                recovery_recipient_key: vote.recovery_recipient_key.clone(),
                requested_at: 0,
                nonce: vote.nonce,
                expiry: 100,
            };
            drive(&certificate, &request);
        } else {
            drive(&certificate, &DEFAULT_REQUEST);
        }
    }
    if let Ok(vote) = serde_json::from_slice::<ReleaseVote>(data) {
        membership_probe(
            vote.signer_id,
            &vote.signer_public_key,
            &vote.signer_membership_proof,
        );
        let _ = gp_wire::release_vote(&vote);
    }
    if let Ok(capsule) = serde_json::from_slice::<ConfigCapsule>(data) {
        let _ = capsule.signer_threshold;
    }
});

static DEFAULT_REQUEST: RecoveryRequest = RecoveryRequest {
    protocol_version: 2,
    crypto_suite: gp_types::CryptoSuite::XWingXChaCha20Poly1305Ed25519,
    config_id: [1; 32],
    config_version: 1,
    request_id: [2; 32],
    recovery_recipient_key: vec![],
    requested_at: 0,
    nonce: [3; 32],
    expiry: 100,
};