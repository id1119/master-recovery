#![no_main]

use gp_crypto::{merkle_commit, merkle_verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let leaf_count = data[0] as usize % 64 + 1;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(leaf_count);
    for i in 0..leaf_count {
        let start = 1 + i * 32;
        let Some(bytes) = data.get(start..start + 32) else {
            return;
        };
        leaves.push(bytes.try_into().unwrap());
    }
    let Ok((root, proofs)) = merkle_commit(&leaves) else {
        return;
    };
    assert_eq!(proofs.len(), leaves.len());
    for (i, proof) in proofs.iter().enumerate() {
        assert!(
            merkle_verify(root, leaves[i], i, leaves.len(), proof).is_ok(),
            "genuine proof must verify"
        );
        if let Some(wrong) = (1..leaves.len()).find_map(|k| {
            let other = leaves[(i + k) % leaves.len()];
            (other != leaves[i]).then_some(other)
        }) {
            assert!(
                merkle_verify(root, wrong, i, leaves.len(), proof).is_err(),
                "different leaf with genuine proof must fail"
            );
        }
        if !proof.is_empty() {
            let mut tampered = proof.clone();
            for byte in tampered.iter_mut() {
                *byte ^= 0xFF;
            }
            assert!(
                merkle_verify(root, leaves[i], i, leaves.len(), &tampered).is_err(),
                "tampered proof must fail"
            );
        }
    }
});
