//! Differential oracle tests: independent implementations of the same
//! primitives checked against the gp-crypto wrappers on identical inputs.
//!
//! Ed25519 is exercised with three independent implementations
//! (ed25519-dalek, ed25519-compact, ring) that must agree on key derivation,
//! signing, and strict verification. HKDF-SHA256 is exercised with the
//! `hkdf` crate used in production, `ring`, and a reference RFC 5869
//! recomputation over the `hmac` crate; the protocol domain-separated KDF
//! paths are pinned to the independent outputs so any reordering of domain
//! bytes breaks the build.
//!
//! X-Wing is deliberately absent here: the hybrid combiner must not be
//! reimplemented (protocol rule), the official draft vectors are tested
//! inside the `x-wing` crate itself, and the recipient-binding round trip is
//! covered by the unit tests in lib.rs.

use ed25519_compact::{KeyPair as CompactKeyPair, Noise as CompactNoise, Seed as CompactSeed};
use gp_crypto::{
    aead_decrypt, aead_encrypt, descriptor_key, descriptor_key_v3, guardian_fragment_key_v3,
    guardian_share_key, guardian_share_key_v3, hkdf_sha256, recover_secret, sign, signing_key,
    split_secret, verify, verifying_key_bytes,
};
use gp_types::ConfigRef;
use hmac::{Hmac, Mac, digest::KeyInit};
use ring::hkdf::{HKDF_SHA256, Salt};
use ring::signature::{Ed25519KeyPair as RingKeyPair, UnparsedPublicKey, ED25519};
use ring::signature::KeyPair as RingKeyPairTrait;
use sha2::Sha256;

/// A representative signed transcript. Byte-level binding of real transcripts
/// is tested in gp-core and gp-wire; this only needs to be a fixed message.
fn transcript_bytes() -> Vec<u8> {
    let mut transcript = b"gp/sign/request/v1".to_vec();
    transcript.extend_from_slice(&[7; 32]);
    transcript.extend_from_slice(&[8; 32]);
    transcript.extend_from_slice(&[9; 32]);
    transcript
}

fn compact_public_key(seed: &[u8; 32]) -> Vec<u8> {
    let pair = CompactKeyPair::from_seed(CompactSeed::from_slice(seed).unwrap());
    Vec::from(&*pair.pk)
}

fn ring_public_key(seed: &[u8; 32]) -> Vec<u8> {
    let pair = RingKeyPair::from_seed_unchecked(seed).unwrap();
    Vec::from(RingKeyPairTrait::public_key(&pair).as_ref())
}

fn compact_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let pair = CompactKeyPair::from_seed(CompactSeed::from_slice(seed).unwrap());
    let signature = pair.sk.sign(message, None::<CompactNoise>);
    Vec::from(&*signature)
}

fn ring_sign(seed: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let pair = RingKeyPair::from_seed_unchecked(seed).unwrap();
    Vec::from(pair.sign(message).as_ref())
}

fn ring_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ring::error::Unspecified> {
    UnparsedPublicKey::new(&ED25519, public_key).verify(message, signature)
}

#[test]
fn ed25519_three_implementations_derive_identical_public_keys() {
    let seeds = [[0x42; 32], [0x13; 32], [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]];
    for seed in seeds {
        let dalek = verifying_key_bytes(&signing_key(seed));
        assert_eq!(compact_public_key(&seed), dalek, "ed25519-compact disagrees on key derivation");
        assert_eq!(ring_public_key(&seed), dalek, "ring disagrees on key derivation");
    }
}

#[test]
fn ed25519_signatures_verify_across_all_three_implementations() {
    let seed = [0x24; 32];
    let public_key = verifying_key_bytes(&signing_key(seed));
    let message = transcript_bytes();

    let dalek_signature = sign(&signing_key(seed), &message);
    let compact_signature = compact_sign(&seed, &message);
    let ring_signature = ring_sign(&seed, &message);

    assert!(verify(&public_key, &message, &dalek_signature).is_ok());
    assert!(ring_verify(&public_key, &message, &dalek_signature).is_ok());

    assert!(verify(&public_key, &message, &compact_signature).is_ok());
    assert!(ring_verify(&public_key, &message, &compact_signature).is_ok());

    assert!(verify(&public_key, &message, &ring_signature).is_ok());
    assert!(ring_verify(&public_key, &message, &ring_signature).is_ok());

    let compact_public = compact_public_key(&seed);
    UnparsedPublicKey::new(&ED25519, &compact_public)
        .verify(&message, &compact_signature)
        .unwrap();
}

#[test]
fn ed25519_all_three_implementations_reject_tampering() {
    let seed = [0x25; 32];
    let public_key = verifying_key_bytes(&signing_key(seed));
    let message = transcript_bytes();

    let dalek_signature = sign(&signing_key(seed), &message);
    let compact_signature = compact_sign(&seed, &message);
    let ring_signature = ring_sign(&seed, &message);

    let mut tampered_message = message.clone();
    tampered_message[0] ^= 1;
    assert!(verify(&public_key, &tampered_message, &dalek_signature).is_err());
    assert!(ring_verify(&public_key, &tampered_message, &dalek_signature).is_err());
    assert!(verify(&public_key, &tampered_message, &compact_signature).is_err());

    let mut tampered_signature = dalek_signature.clone();
    tampered_signature[10] ^= 1;
    assert!(verify(&public_key, &message, &tampered_signature).is_err());
    assert!(ring_verify(&public_key, &message, &tampered_signature).is_err());
    assert!(verify(&public_key, &message, &ring_signature).is_ok());

    let mut wrong_key = public_key;
    wrong_key[0] ^= 1;
    assert!(verify(&wrong_key, &message, &dalek_signature).is_err());
    assert!(ring_verify(&wrong_key, &message, &dalek_signature).is_err());
}

/// Reference RFC 5869 HKDF-SHA256 expand-only recomputation (the protocol
/// always expands exactly 32 bytes, so only the first block T(1) is needed).
fn hkdf_reference(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut extract = <Hmac<Sha256> as KeyInit>::new_from_slice(&[0_u8; 32]).unwrap();
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk).unwrap();
    mac.update(info);
    mac.update(&[1]);
    let mut out = [0_u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn hkdf_ring(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let prk = Salt::new(HKDF_SHA256, &[0_u8; 32]).extract(ikm);
    let mut out = [0_u8; 32];
    prk.expand(&[info], HKDF_SHA256).unwrap().fill(&mut out).unwrap();
    out
}

#[test]
fn hkdf_three_implementations_agree_on_extract_and_expand() {
    let cases: [(&[u8], &[u8]); 4] = [
        (b"authorization-key", b"gp/guardian-dek-share/v1"),
        (b"", b"gp/recovery-descriptor/v1"),
        (b"authorization-key", b""),
        (&[0xa5; 32], b"gp/guardian-dek-share/v3"),
    ];
    for (ikm, info) in cases {
        let expected = hkdf_reference(ikm, info);
        assert_eq!(hkdf_sha256(ikm, info).unwrap(), expected);
        assert_eq!(hkdf_ring(ikm, info), expected);
    }
}

#[test]
fn protocol_kdf_paths_pin_to_independent_reference() {
    let authorization_key = [0x5a; 32];
    let config_id = [0x6b; 32];
    let config_version: u64 = 7;
    let guardian_index = 3_u16;

    let mut info = b"gp/guardian-dek-share/v1".to_vec();
    info.extend_from_slice(&config_id);
    info.extend_from_slice(&config_version.to_be_bytes());
    info.extend_from_slice(&guardian_index.to_be_bytes());
    let expected = hkdf_reference(&authorization_key, &info);
    assert_eq!(
        guardian_share_key(&authorization_key, &config_id, config_version, guardian_index).unwrap(),
        expected
    );

    let mut info = b"gp/recovery-descriptor/v1".to_vec();
    info.extend_from_slice(&config_id);
    info.extend_from_slice(&config_version.to_be_bytes());
    let expected = hkdf_reference(&authorization_key, &info);
    assert_eq!(descriptor_key(&authorization_key, &config_id, config_version).unwrap(), expected);

    let config_ref = ConfigRef {
        config_id,
        payload_generation: 11,
        authorization_epoch: 13,
        guardian_epoch: 17,
        epoch_binding: [0x77; 32],
    };
    let wrapper_keys: [(&[u8], [u8; 32]); 3] = [
        (
            b"gp/guardian-dek-share/v3",
            guardian_share_key_v3(&authorization_key, &config_ref, guardian_index).unwrap(),
        ),
        (
            b"gp/guardian-ciphertext-fragment/v3",
            guardian_fragment_key_v3(&authorization_key, &config_ref, guardian_index).unwrap(),
        ),
        (
            b"gp/recovery-descriptor/v3",
            descriptor_key_v3(&authorization_key, &config_ref).unwrap(),
        ),
    ];
    for (domain, expected) in wrapper_keys {
        let mut info = domain.to_vec();
        info.extend_from_slice(&config_id);
        info.extend_from_slice(&config_ref.payload_generation.to_be_bytes());
        info.extend_from_slice(&config_ref.authorization_epoch.to_be_bytes());
        info.extend_from_slice(&config_ref.guardian_epoch.to_be_bytes());
        info.extend_from_slice(&config_ref.epoch_binding);
        if domain != &b"gp/recovery-descriptor/v3"[..] {
            info.extend_from_slice(&guardian_index.to_be_bytes());
        }
        assert_eq!(hkdf_reference(&authorization_key, &info), expected);
        assert_eq!(hkdf_ring(&authorization_key, &info), expected);
    }
}

#[test]
fn aead_round_trip_survives_an_independent_hkdf_key() {
    let key = hkdf_ring(b"authorization-key", b"gp/guardian-dek-share/v1");
    let sealed = aead_encrypt(&key, [3; 24], b"dek-share", b"share-context-v1").unwrap();
    assert_eq!(
        &*aead_decrypt(&key, &sealed, b"share-context-v1").unwrap(),
        b"dek-share"
    );
    assert!(aead_decrypt(&[0; 32], &sealed, b"share-context-v1").is_err());
}

#[test]
fn shamir_round_trip_with_seed_derived_keys() {
    let secret = [0x63; 32];
    let seed = hkdf_ring(b"shamir-seed", b"gp/shamir/v1");
    let shares = split_secret(&secret, 3, 5, seed).unwrap();
    let subset: Vec<_> = shares[..3].iter().collect();
    assert_eq!(&*recover_secret(&subset, 3).unwrap(), &secret);
}