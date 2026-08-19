use gp_crypto::{
    erasure_encode, erasure_reconstruct, merkle_commit, merkle_verify, recover_secret, split_secret,
};

const SECRET: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];

const FROZEN_SHARES: [&str; 5] = [
    "0186e004800a94554cc729e56ecee2601bec1275c56c1d92e9b205b01e5b329e1c",
    "02bdb9c6b029cf74325d092c938dc2ef0ca546662bc56632637da87172b4a5c686",
    "032a48d321324a306f8b31d8ec52319e06584502ffb86ab19bdebcd07dfe86498b",
    "04121d710c59b348095a9c6ce5c80a800f35e639631c5eb7b315002d3e828bd52c",
    "0585ec649d42360c548ca4989a17f9f105c8e55db76152344bb6148c31c8a85a21",
];

const FROZEN_ERASURE_SHARDS: [&str; 5] = [
    "6b6e6f776e2d616e737765722d64",
    "6174612d666f722d657261737572",
    "652d303030303030303030300000",
    "6f373e6a38722373263534315816",
    "1f29c012f749029554d0a6eb3991",
];

const FROZEN_MERKLE_ROOT: &str = "d35f51699389da7eec7ce5eb02640c6d318cf51ae39eca890bbc7b84ecb5da68";

#[test]
fn split_secret_known_answer() {
    let shares = split_secret(&SECRET, 3, 5, SEED).unwrap();
    let encoded: Vec<String> = shares.iter().map(|s| hex::encode(&**s)).collect();
    assert_eq!(encoded, FROZEN_SHARES);
    let subset: Vec<_> = shares[..3].iter().collect();
    assert_eq!(&*recover_secret(&subset, 3).unwrap(), &SECRET);
}

#[test]
fn erasure_known_answer() {
    let data = b"known-answer-data-for-erasure-0000000000";
    let shards = erasure_encode(data, 3, 5).unwrap();
    let encoded: Vec<String> = shards.iter().map(hex::encode).collect();
    assert_eq!(encoded, FROZEN_ERASURE_SHARDS);
    let fragments: Vec<(u16, Vec<u8>)> = shards
        .iter()
        .enumerate()
        .map(|(i, s)| (i as u16 + 1, s.clone()))
        .collect();
    let recovered = erasure_reconstruct(&fragments, 3, 5, data.len()).unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn merkle_known_answer() {
    let leaves: Vec<[u8; 32]> = (0..4).map(|i| [i as u8; 32]).collect();
    let (root, proofs) = merkle_commit(&leaves).unwrap();
    assert_eq!(hex::encode(root), FROZEN_MERKLE_ROOT);
    for (index, proof) in proofs.iter().enumerate() {
        assert!(merkle_verify(root, leaves[index], index, leaves.len(), proof).is_ok());
    }
    let mut wrong = leaves[0];
    wrong[0] ^= 0x01;
    assert!(merkle_verify(root, wrong, 0, leaves.len(), &proofs[0]).is_err());
}
