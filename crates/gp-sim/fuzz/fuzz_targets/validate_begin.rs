#![no_main]

//! Fuzz the untrusted begin-certificate boundary. Parses attacker bytes as a
//! protocol-v2 `BeginRecoveryCertificate` and drives every contribution through
//! the same probes `validate_begin_certificate` in gp-sim performs on
//! untrusted values: request equality, unique signer ids, signer membership
//! (leaf + Merkle), Ed25519 verification of the `signer_approval` transcript,
//! and the threshold count. Any panic in the parse -> validate chain surfaces
//! as a crash.

use gp_crypto::{merkle_verify, sha256, verify};
use gp_types::{BeginRecoveryCertificate, ConfigCapsule, SignerContribution};
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

fn signature_probe(public_key: &[u8; 32], transcript: &[u8], signature: &[u8]) {
    let _ = verify(public_key, transcript, signature);
}

/// Mirrors `validate_begin_certificate`: request equality, unique ids,
/// membership, transcript signature, threshold.
fn drive(certificate: &BeginRecoveryCertificate) {
    let mut ids = std::collections::BTreeSet::new();
    for contribution in certificate.signer_contributions.iter().take(16) {
        if contribution.request != certificate.request {
            continue;
        }
        if !ids.insert(contribution.signer_id) {
            continue;
        }
        membership_probe(
            contribution.signer_id,
            &contribution.signer_public_key,
            &contribution.signer_membership_proof,
        );
        let Ok(transcript) = gp_wire::signer_approval(
            &contribution.request,
            contribution.signer_id,
            &contribution.encrypted_a_share,
        ) else {
            continue;
        };
        signature_probe(
            &contribution.signer_public_key,
            &transcript,
            &contribution.signer_signature,
        );
    }
    if ids.len() < usize::from(THRESHOLD) {
        return;
    }
    // The threshold branch is the one the validator returns Ok on; keep the
    // parse -> probe chain exercised identically regardless.
    let _ = &certificate.request;
}

fuzz_target!(|data: &[u8]| {
    if let Ok(certificate) = serde_json::from_slice::<BeginRecoveryCertificate>(data) {
        drive(&certificate);
    }
    // Also drive bare contributions and the capsule shape the validator reads.
    if let Ok(contribution) = serde_json::from_slice::<SignerContribution>(data) {
        membership_probe(
            contribution.signer_id,
            &contribution.signer_public_key,
            &contribution.signer_membership_proof,
        );
        let _ = gp_wire::signer_approval(
            &contribution.request,
            contribution.signer_id,
            &contribution.encrypted_a_share,
        );
    }
    if let Ok(capsule) = serde_json::from_slice::<ConfigCapsule>(data) {
        let _ = capsule.signer_count;
    }
});