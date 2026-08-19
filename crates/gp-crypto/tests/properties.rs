use gp_crypto::{
    erasure_encode, erasure_reconstruct, merkle_commit, merkle_verify, recover_secret, split_secret,
};
use proptest::prelude::*;

const MAX_SHARES: u16 = 20;

prop_compose! {
    fn threshold_pair()(n in 1_u16..=MAX_SHARES, k in 1_u16..=MAX_SHARES) -> (u16, u16) {
        (n.min(k), k.max(n.min(k)))
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn split_recover_roundtrip_first_k(
        secret in prop::array::uniform32(0_u8..),
        (k, n) in threshold_pair(),
        seed in prop::array::uniform32(0_u8..),
    ) {
        let shares = split_secret(&secret, k, n, seed).unwrap();
        prop_assert_eq!(shares.len(), n as usize);
        let subset: Vec<_> = shares[..k as usize].iter().collect();
        prop_assert_eq!(&*recover_secret(&subset, k).unwrap(), &secret);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn every_subset_reconstructs(
        secret in prop::array::uniform32(0_u8..),
        k in 1_u16..=4_u16,
        seed in prop::array::uniform32(0_u8..),
    ) {
        let n = k + 1;
        let shares = split_secret(&secret, k, n, seed).unwrap();
        let indices: Vec<usize> = (0..n as usize).collect();
        for combo in combinations(&indices, k as usize) {
            let subset: Vec<_> = combo.iter().map(|i| &shares[*i]).collect();
            prop_assert_eq!(&*recover_secret(&subset, k).unwrap(), &secret);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn insufficient_shares_rejected(
        secret in prop::array::uniform32(0_u8..),
        k in 2_u16..=5_u16,
        seed in prop::array::uniform32(0_u8..),
    ) {
        let n = k + 1;
        let shares = split_secret(&secret, k, n, seed).unwrap();
        let subset: Vec<_> = shares[..(k - 1) as usize].iter().collect();
        prop_assert!(recover_secret(&subset, k).is_err());
    }

    #[test]
    fn invalid_parameters_rejected(secret in prop::array::uniform32(0_u8..)) {
        prop_assert!(split_secret(&secret, 0, 3, [0; 32]).is_err());
        prop_assert!(split_secret(&secret, 4, 3, [0; 32]).is_err());
        prop_assert!(split_secret(&secret, 3, 256, [0; 32]).is_err());
        prop_assert!(split_secret(&secret[..16], 2, 3, [0; 32]).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn tampered_share_never_recovers_secret(
        secret in prop::array::uniform32(0_u8..),
        seed in prop::array::uniform32(0_u8..),
        byte in 0_usize..32,
        value in 0_u8..,
    ) {
        let shares = split_secret(&secret, 3, 5, seed).unwrap();
        let mut tampered = shares[0].to_vec();
        let flip_at = 1 + byte % (tampered.len() - 1);
        tampered[flip_at] ^= value.max(1);
        let recovered = recover_secret(&[&tampered, &shares[1], &shares[2]], 3);
        if let Ok(out) = recovered {
            prop_assert_ne!(&*out, &secret);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn erasure_roundtrip_tolerates_loss(
        data in prop::collection::vec(0_u8.., 1..512),
        data_shards in 2_u16..=8_u16,
        loss in 0_usize..=1_usize,
    ) {
        let total = data_shards + 2;
        let shards = erasure_encode(&data, data_shards, total).unwrap();
        let mut fragments: Vec<(u16, Vec<u8>)> =
            shards.iter().enumerate().map(|(i, s)| (i as u16 + 1, s.clone())).collect();
        if loss > 0 {
            fragments.remove(0);
        }
        let recovered = erasure_reconstruct(&fragments, data_shards, total, data.len()).unwrap();
        prop_assert_eq!(recovered, data);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn merkle_roundtrip_and_tamper(
        leaves in prop::collection::vec(prop::array::uniform32(0_u8..), 1..16),
    ) {
        let (root, proofs) = merkle_commit(&leaves).unwrap();
        for (index, proof) in proofs.iter().enumerate() {
            prop_assert!(merkle_verify(root, leaves[index], index, leaves.len(), proof).is_ok());
        }
        if leaves.len() > 1 {
            let mut wrong = leaves[0];
            wrong[0] ^= 0x01;
            prop_assert!(merkle_verify(root, wrong, 0, leaves.len(), &proofs[0]).is_err());
            prop_assert!(merkle_verify(root, leaves[0], leaves.len(), leaves.len(), &proofs[0]).is_err());
        }
    }
}

fn combinations<T: Clone>(items: &[T], k: usize) -> Vec<Vec<T>> {
    fn go<T: Clone>(items: &[T], k: usize, start: usize, acc: &mut Vec<T>, out: &mut Vec<Vec<T>>) {
        if acc.len() == k {
            out.push(acc.clone());
            return;
        }
        for i in start..items.len() {
            acc.push(items[i].clone());
            go(items, k, i + 1, acc, out);
            acc.pop();
        }
    }
    let mut out = Vec::new();
    go(items, k, 0, &mut Vec::new(), &mut out);
    out
}
