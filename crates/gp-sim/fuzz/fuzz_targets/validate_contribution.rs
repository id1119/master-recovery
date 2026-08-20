#![no_main]

//! Fuzz the untrusted guardian-contribution boundary. Parses attacker bytes as
//! a protocol-v2 `GuardianContribution` and drives it through the same probes
//! `validate_guardian_contribution` in gp-sim performs on untrusted values:
//! request binding, Ed25519 verification of the `guardian_contribution`
//! transcript, the fragment/share Merkle leaf against the guardian-material
//! root, the A-derived DEK-share key, and AEAD open of the wrapped share.
//! Any panic in the parse -> validate chain surfaces as a crash.

use gp_crypto::{
    aead_decrypt, guardian_share_key, hash_aead, merkle_verify, sha256, verify, zeroize_id,
};
use gp_types::{ConfigCapsule, GuardianContribution, RecoveryDescriptor};
use libfuzzer_sys::fuzz_target;

const FIXED_ROOT: [u8; 32] = [9; 32];
const FIXED_AUTHORIZATION_KEY: [u8; 32] = [6; 32];
const FIXED_GUARDIAN_KEY: [u8; 32] = [2; 32];
const GUARDIAN_COUNT: u16 = 8;
const TOTAL_SHARDS: u16 = 8;

/// Mirrors `validate_guardian_contribution`: binding, signature, leaf +
/// Merkle, then decrypt of the wrapped DEK share.
fn drive(contribution: &GuardianContribution) {
    if contribution.guardian_index == 0 || contribution.guardian_index > GUARDIAN_COUNT {
        return;
    }
    let Ok(transcript) = gp_wire::guardian_contribution(contribution) else {
        return;
    };
    let _ = verify(
        &FIXED_GUARDIAN_KEY,
        &transcript,
        &contribution.guardian_signature,
    );
    let Ok(leaf) = gp_wire::guardian_leaf(
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
        &sha256(&contribution.ciphertext_fragment),
        &hash_aead(&contribution.encrypted_dek_share),
    ) else {
        return;
    };
    let _ = merkle_verify(
        FIXED_ROOT,
        sha256(&leaf),
        usize::from(contribution.guardian_index - 1),
        usize::from(TOTAL_SHARDS),
        &contribution.merkle_path_proof,
    );
    let Ok(mut key) = guardian_share_key(
        &FIXED_AUTHORIZATION_KEY,
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
    ) else {
        return;
    };
    let Ok(context) = gp_wire::guardian_share_context(
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
    ) else {
        return;
    };
    let _ = aead_decrypt(&key, &contribution.encrypted_dek_share, &context);
    zeroize_id(&mut key);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(contribution) = serde_json::from_slice::<GuardianContribution>(data) {
        drive(&contribution);
    }
    if let Ok(capsule) = serde_json::from_slice::<ConfigCapsule>(data) {
        let _ = capsule.guardian_material_commitment;
    }
    if let Ok(descriptor) = serde_json::from_slice::<RecoveryDescriptor>(data) {
        let _ = descriptor.guardian_material_root;
    }
});