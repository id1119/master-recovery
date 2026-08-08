//! Thin wrappers around maintained cryptographic libraries.
//!
//! No other workspace crate directly uses cryptographic primitive libraries.

use blahaj::{Share, Sharks};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gp_types::{AeadCiphertext, Id32, SealedMessage};
use hkdf::Hkdf;
use rand_chacha08::{ChaCha20Rng as ChaCha20Rng08, rand_core::SeedableRng as _};
use rand_chacha10::{ChaCha20Rng as ChaCha20Rng10, rand_core::SeedableRng as _};
use reed_solomon_erasure::galois_8::ReedSolomon;
use rs_merkle::{MerkleProof, MerkleTree, algorithms::Sha256 as MerkleSha256};
use sha2::{Digest, Sha256};
use x_wing::{
    Ciphertext as XWingCiphertext, DecapsulationKey, EncapsulationKey,
    kem::{Decapsulate, Decapsulator, Encapsulate, KeyExport},
};
use zeroize::{Zeroize, Zeroizing};

pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
pub const XWING_CIPHERTEXT_LEN: usize = 1120;
pub type SecretVec = Zeroizing<Vec<u8>>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("AEAD authentication failed")]
    Authentication,
    #[error("invalid threshold parameters")]
    InvalidThreshold,
    #[error("not enough valid shares")]
    InsufficientShares,
    #[error("invalid share encoding")]
    InvalidShare,
    #[error("invalid erasure fragment set")]
    InvalidFragments,
    #[error("invalid signature or public key")]
    InvalidSignature,
    #[error("invalid X-Wing key or ciphertext")]
    InvalidKemData,
    #[error("invalid Merkle proof")]
    InvalidMerkleProof,
    #[error("KDF expansion failed")]
    Kdf,
}

#[must_use]
pub fn sha256(data: &[u8]) -> Id32 {
    Sha256::digest(data).into()
}

pub fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> Result<Id32, CryptoError> {
    let mut output = [0_u8; 32];
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, &mut output)
        .map_err(|_| CryptoError::Kdf)?;
    Ok(output)
}

pub fn guardian_share_key(
    authorization_key: &[u8; 32],
    config_id: &Id32,
    config_version: u64,
    guardian_index: u16,
) -> Result<Id32, CryptoError> {
    let mut info = b"gp/guardian-dek-share/v1".to_vec();
    info.extend_from_slice(config_id);
    info.extend_from_slice(&config_version.to_be_bytes());
    info.extend_from_slice(&guardian_index.to_be_bytes());
    hkdf_sha256(authorization_key, &info)
}

pub fn descriptor_key(
    authorization_key: &[u8; 32],
    config_id: &Id32,
    config_version: u64,
) -> Result<Id32, CryptoError> {
    let mut info = b"gp/recovery-descriptor/v1".to_vec();
    info.extend_from_slice(config_id);
    info.extend_from_slice(&config_version.to_be_bytes());
    hkdf_sha256(authorization_key, &info)
}

pub fn aead_encrypt(
    key: &[u8; 32],
    nonce: [u8; 24],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<AeadCiphertext, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| CryptoError::Authentication)?;
    Ok(AeadCiphertext { nonce, ciphertext })
}

pub fn aead_decrypt(
    key: &[u8; 32],
    value: &AeadCiphertext,
    associated_data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&value.nonce),
            Payload {
                msg: &value.ciphertext,
                aad: associated_data,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Authentication)
}

pub fn split_secret(
    secret: &[u8],
    threshold: u16,
    total: u16,
    seed: Id32,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    if threshold == 0 || threshold > total || total > 255 {
        return Err(CryptoError::InvalidThreshold);
    }
    let sharks = Sharks(threshold as u8);
    let mut rng = ChaCha20Rng08::from_seed(seed);
    Ok(sharks
        .dealer_rng(secret, &mut rng)
        .take(total as usize)
        .map(|share| Vec::from(&share))
        .collect())
}

pub fn recover_secret(
    shares: &[Vec<u8>],
    threshold: u16,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if shares.len() < threshold as usize {
        return Err(CryptoError::InsufficientShares);
    }
    let decoded: Vec<Share> = shares
        .iter()
        .map(|share| Share::try_from(share.as_slice()).map_err(|_| CryptoError::InvalidShare))
        .collect::<Result<_, _>>()?;
    Sharks(threshold as u8)
        .recover(&decoded)
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::InsufficientShares)
}

pub fn erasure_encode(
    data: &[u8],
    data_shards: u16,
    total_shards: u16,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    if data_shards == 0 || data_shards > total_shards {
        return Err(CryptoError::InvalidThreshold);
    }
    let parity = (total_shards - data_shards) as usize;
    let coder = ReedSolomon::new(data_shards as usize, parity)
        .map_err(|_| CryptoError::InvalidThreshold)?;
    let shard_len = data.len().div_ceil(data_shards as usize).max(1);
    let mut shards = vec![vec![0_u8; shard_len]; total_shards as usize];
    for (offset, byte) in data.iter().copied().enumerate() {
        shards[offset / shard_len][offset % shard_len] = byte;
    }
    coder
        .encode(&mut shards)
        .map_err(|_| CryptoError::InvalidFragments)?;
    Ok(shards)
}

pub fn erasure_reconstruct(
    fragments: &[(u16, Vec<u8>)],
    data_shards: u16,
    total_shards: u16,
    original_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    if fragments.len() < data_shards as usize || data_shards > total_shards {
        return Err(CryptoError::InsufficientShares);
    }
    let parity = (total_shards - data_shards) as usize;
    let coder = ReedSolomon::new(data_shards as usize, parity)
        .map_err(|_| CryptoError::InvalidThreshold)?;
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total_shards as usize];
    for (index, fragment) in fragments {
        let position = usize::from(*index)
            .checked_sub(1)
            .filter(|position| *position < shards.len())
            .ok_or(CryptoError::InvalidFragments)?;
        shards[position] = Some(fragment.clone());
    }
    coder
        .reconstruct(&mut shards)
        .map_err(|_| CryptoError::InvalidFragments)?;
    let mut output = Vec::new();
    for shard in shards.into_iter().take(data_shards as usize) {
        output.extend_from_slice(&shard.ok_or(CryptoError::InvalidFragments)?);
    }
    output.truncate(original_len);
    Ok(output)
}

pub fn merkle_commit(leaves: &[[u8; 32]]) -> Result<(Id32, Vec<Vec<u8>>), CryptoError> {
    if leaves.is_empty() {
        return Err(CryptoError::InvalidMerkleProof);
    }
    let tree = MerkleTree::<MerkleSha256>::from_leaves(leaves);
    let root = tree.root().ok_or(CryptoError::InvalidMerkleProof)?;
    let proofs = (0..leaves.len())
        .map(|index| tree.proof(&[index]).to_bytes())
        .collect();
    Ok((root, proofs))
}

pub fn merkle_verify(
    root: Id32,
    leaf: Id32,
    index: usize,
    leaf_count: usize,
    proof: &[u8],
) -> Result<(), CryptoError> {
    let proof = MerkleProof::<MerkleSha256>::try_from(proof)
        .map_err(|_| CryptoError::InvalidMerkleProof)?;
    if proof.verify(root, &[index], &[leaf], leaf_count) {
        Ok(())
    } else {
        Err(CryptoError::InvalidMerkleProof)
    }
}

#[must_use]
pub fn signing_key(seed: Id32) -> SigningKey {
    SigningKey::from_bytes(&seed)
}

#[must_use]
pub fn verifying_key_bytes(key: &SigningKey) -> [u8; 32] {
    key.verifying_key().to_bytes()
}

#[must_use]
pub fn sign(key: &SigningKey, transcript: &[u8]) -> Vec<u8> {
    key.sign(transcript).to_bytes().to_vec()
}

pub fn verify(
    public_key: &[u8; 32],
    transcript: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidSignature)?;
    let signature = Signature::try_from(signature).map_err(|_| CryptoError::InvalidSignature)?;
    key.verify(transcript, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub struct RecipientKeyPair {
    secret: DecapsulationKey,
    public: Vec<u8>,
}

impl RecipientKeyPair {
    #[must_use]
    pub fn from_seed(seed: Id32) -> Self {
        let secret = DecapsulationKey::from(seed);
        let public = secret.encapsulation_key().to_bytes().to_vec();
        Self { secret, public }
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    pub fn open(
        &self,
        sealed: &SealedMessage,
        associated_data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let ciphertext = XWingCiphertext::try_from(sealed.kem_ciphertext.as_slice())
            .map_err(|_| CryptoError::InvalidKemData)?;
        let mut shared_key = self.secret.decapsulate(&ciphertext);
        let mut key: [u8; 32] = shared_key
            .as_slice()
            .try_into()
            .expect("X-Wing shared key is 32 bytes");
        let result = aead_decrypt(&key, &sealed.payload, associated_data);
        key.zeroize();
        shared_key.zeroize();
        result
    }
}

pub fn seal_to_recipient(
    recipient_public_key: &[u8],
    kem_seed: Id32,
    nonce: [u8; 24],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<SealedMessage, CryptoError> {
    let recipient = EncapsulationKey::try_from(recipient_public_key)
        .map_err(|_| CryptoError::InvalidKemData)?;
    let mut rng = ChaCha20Rng10::from_seed(kem_seed);
    let (ciphertext, mut shared_key) = recipient.encapsulate_with_rng(&mut rng);
    let mut key: [u8; 32] = shared_key
        .as_slice()
        .try_into()
        .expect("X-Wing shared key is 32 bytes");
    let payload = aead_encrypt(&key, nonce, plaintext, associated_data);
    key.zeroize();
    shared_key.zeroize();
    let payload = payload?;
    Ok(SealedMessage {
        kem_ciphertext: ciphertext.to_vec(),
        payload,
    })
}

#[must_use]
pub fn hash_aead(value: &AeadCiphertext) -> Id32 {
    let mut bytes = value.nonce.to_vec();
    bytes.extend_from_slice(&value.ciphertext);
    sha256(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shamir_threshold_round_trip_and_insufficient_failure() {
        let secret = [7_u8; 32];
        let shares = split_secret(&secret, 3, 5, [8; 32]).unwrap();
        assert_eq!(&*recover_secret(&shares[..3], 3).unwrap(), &secret);
        assert!(matches!(
            recover_secret(&shares[..2], 3),
            Err(CryptoError::InsufficientShares)
        ));
    }

    #[test]
    fn every_three_of_five_subset_reconstructs() {
        let secret = [42_u8; 32];
        let shares = split_secret(&secret, 3, 5, [17; 32]).unwrap();
        for first in 0..3 {
            for second in (first + 1)..4 {
                for third in (second + 1)..5 {
                    let subset = vec![
                        shares[first].clone(),
                        shares[second].clone(),
                        shares[third].clone(),
                    ];
                    assert_eq!(&*recover_secret(&subset, 3).unwrap(), &secret);
                }
            }
        }
    }

    #[test]
    fn erasure_threshold_round_trip() {
        let data = b"metadata resistant recovery payload";
        let shards = erasure_encode(data, 3, 5).unwrap();
        let selected = vec![
            (1, shards[0].clone()),
            (3, shards[2].clone()),
            (5, shards[4].clone()),
        ];
        assert_eq!(
            erasure_reconstruct(&selected, 3, 5, data.len()).unwrap(),
            data
        );
    }

    #[test]
    fn wrong_a_fails_to_open_share() {
        let context = b"context";
        let sealed = aead_encrypt(&[1; 32], [2; 24], b"share", context).unwrap();
        assert!(aead_decrypt(&[3; 32], &sealed, context).is_err());
    }

    #[test]
    fn share_wrap_is_bound_to_config_version_and_index() {
        let authorization_key = [1; 32];
        let config_id = [2; 32];
        let key = guardian_share_key(&authorization_key, &config_id, 1, 4).unwrap();
        let sealed = aead_encrypt(&key, [3; 24], b"dek-share", b"share-context-v1").unwrap();

        let wrong_version = guardian_share_key(&authorization_key, &config_id, 2, 4).unwrap();
        let wrong_index = guardian_share_key(&authorization_key, &config_id, 1, 5).unwrap();
        let wrong_config = guardian_share_key(&authorization_key, &[9; 32], 1, 4).unwrap();
        assert!(aead_decrypt(&wrong_version, &sealed, b"share-context-v1").is_err());
        assert!(aead_decrypt(&wrong_index, &sealed, b"share-context-v1").is_err());
        assert!(aead_decrypt(&wrong_config, &sealed, b"share-context-v1").is_err());
    }

    #[test]
    fn merkle_proof_rejects_tampered_leaf() {
        let leaves = [sha256(b"one"), sha256(b"two"), sha256(b"three")];
        let (root, proofs) = merkle_commit(&leaves).unwrap();
        assert!(merkle_verify(root, leaves[1], 1, leaves.len(), &proofs[1]).is_ok());
        assert!(merkle_verify(root, sha256(b"tampered"), 1, leaves.len(), &proofs[1]).is_err());
    }

    #[test]
    fn xwing_recipient_binding_round_trip() {
        let recipient = RecipientKeyPair::from_seed([9; 32]);
        let other = RecipientKeyPair::from_seed([8; 32]);
        let sealed = seal_to_recipient(
            recipient.public_key(),
            [7; 32],
            [6; 24],
            b"authorization share",
            b"exact request",
        )
        .unwrap();
        assert_eq!(
            &*recipient.open(&sealed, b"exact request").unwrap(),
            b"authorization share"
        );
        assert!(other.open(&sealed, b"exact request").is_err());
        assert!(recipient.open(&sealed, b"other request").is_err());
    }
}
