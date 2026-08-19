//! Google Wycheproof test vectors for the wrapped primitives.
//!
//! Covers the two primitives the protocol relies on directly:
//! Ed25519 verification (signer approvals) and XChaCha20-Poly1305
//! (payload sealing). Every vector in the published test sets is run;
//! `valid` must pass, `invalid` must fail, and `acceptable` cases are
//! required to pass because the wrappers use standard, unconstrained
//! implementations.

use gp_crypto::{aead_decrypt, aead_encrypt, verify};
use gp_types::AeadCiphertext;
use wycheproof::TestResult;
use wycheproof::aead::{TestName as AeadTestName, TestSet as AeadTestSet};
use wycheproof::eddsa::{TestName as EddsaTestName, TestSet as EddsaTestSet};

fn key32(bytes: &[u8]) -> Option<[u8; 32]> {
    bytes.try_into().ok()
}

fn nonce24(bytes: &[u8]) -> Option<[u8; 24]> {
    bytes.try_into().ok()
}

#[test]
fn ed25519_verify_wycheproof() {
    let set = EddsaTestSet::load(EddsaTestName::Ed25519).expect("ed25519 test set loads");
    let mut ran = 0;
    for group in &set.test_groups {
        let pk = key32(&group.key.pk).expect("ed25519 pk is 32 bytes");
        for t in &group.tests {
            let outcome = verify(&pk, &t.msg, &t.sig);
            match (t.result, outcome) {
                (TestResult::Valid | TestResult::Acceptable, Ok(())) => {}
                (TestResult::Valid | TestResult::Acceptable, Err(e)) => {
                    panic!("tcId {} ({}) expected to verify: {e:?}", t.tc_id, t.comment)
                }
                (TestResult::Invalid, Err(_)) => {}
                (TestResult::Invalid, Ok(())) => {
                    panic!("tcId {} ({}) must fail but verified", t.tc_id, t.comment)
                }
            }
            ran += 1;
        }
    }
    assert!(ran > 100, "expected a substantial vector set, got {ran}");
}

#[test]
fn xchacha20poly1305_wycheproof() {
    let set = AeadTestSet::load(AeadTestName::XChaCha20Poly1305).expect("xchacha test set loads");
    let mut ran = 0;
    for group in &set.test_groups {
        for t in &group.tests {
            let mut sealed = Vec::with_capacity(t.ct.len() + t.tag.len());
            sealed.extend_from_slice(&t.ct);
            sealed.extend_from_slice(&t.tag);
            let Some(key) = key32(&t.key) else {
                assert!(
                    t.result.must_fail(),
                    "tcId {} ({}) has malformed key but is expected to pass",
                    t.tc_id,
                    t.comment
                );
                continue;
            };
            let Some(nonce) = nonce24(&t.nonce) else {
                assert!(
                    t.result.must_fail(),
                    "tcId {} ({}) has malformed nonce but is expected to pass",
                    t.tc_id,
                    t.comment
                );
                continue;
            };
            let value = AeadCiphertext {
                nonce,
                ciphertext: sealed,
            };
            match (t.result, aead_decrypt(&key, &value, &t.aad)) {
                (TestResult::Valid | TestResult::Acceptable, Ok(pt)) => {
                    assert_eq!(
                        pt.as_slice(),
                        t.pt.as_slice(),
                        "tcId {} ({}) plaintext mismatch",
                        t.tc_id,
                        t.comment
                    );
                    let reencrypted =
                        aead_encrypt(&key, nonce, &t.pt, &t.aad).expect("re-encrypt succeeds");
                    assert_eq!(
                        reencrypted.ciphertext, value.ciphertext,
                        "tcId {} ({}) ciphertext mismatch",
                        t.tc_id, t.comment
                    );
                }
                (TestResult::Valid | TestResult::Acceptable, Err(e)) => {
                    panic!(
                        "tcId {} ({}) expected to decrypt: {e:?}",
                        t.tc_id, t.comment
                    )
                }
                (TestResult::Invalid, Err(_)) => {}
                (TestResult::Invalid, Ok(pt)) => {
                    panic!(
                        "tcId {} ({}) must fail but decrypted {:?}",
                        t.tc_id,
                        t.comment,
                        String::from_utf8_lossy(&pt)
                    )
                }
            }
            ran += 1;
        }
    }
    assert!(ran > 100, "expected a substantial vector set, got {ran}");
}
