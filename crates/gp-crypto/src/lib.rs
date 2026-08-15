//! Thin wrappers around maintained cryptographic libraries.
//!
//! No other workspace crate directly uses cryptographic primitive libraries.

use std::collections::BTreeSet;

mod rotation;

pub use rotation::*;

use blahaj::{Share, Sharks};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use gp_types::{AeadCiphertext, ConfigRef, Id32, SealedMessage};
use hkdf::Hkdf;
use rand_chacha08::{ChaCha20Rng as ChaCha20Rng08, rand_core::SeedableRng as _};
use rand_chacha10::{ChaCha20Rng as ChaCha20Rng10, rand_core::SeedableRng as _};
use reed_solomon_turbo::ReedSolomon;
use rs_merkle::{MerkleProof, MerkleTree, algorithms::Sha256 as MerkleSha256};
use sha2::{Digest, Sha256};
use x_wing::{
    Ciphertext as XWingCiphertext, DecapsulationKey, EncapsulationKey,
    kem::{Decapsulate, Decapsulator, Encapsulate, KeyExport},
};
use zeroize::{Zeroize, Zeroizing};

pub const XWING_PUBLIC_KEY_LEN: usize = 1216;
pub const XWING_CIPHERTEXT_LEN: usize = 1120;
/// The authoritative protocol shares only 256-bit `A` and `DEK` values.
pub const SHAMIR_SECRET_LEN: usize = 32;
/// `blahaj` encodes a share as one nonzero GF(256) index plus the secret-length payload.
pub const SHAMIR_SHARE_LEN: usize = SHAMIR_SECRET_LEN + 1;
/// GF(256) provides 255 nonzero evaluation points.
pub const SHAMIR_MAX_SHARES: u16 = 255;
const SHAMIR_INDEX_WORDS: usize = 4;
const SHAMIR_INDEX_BITS_PER_WORD: usize = 64;
pub type SecretVec = Zeroizing<Vec<u8>>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("AEAD authentication failed")]
    Authentication,
    #[error("invalid threshold parameters")]
    InvalidThreshold,
    #[error("Shamir secrets must be exactly 32 bytes")]
    InvalidSecretLength,
    #[error("not enough valid shares")]
    InsufficientShares,
    #[error("invalid share encoding")]
    InvalidShare,
    #[error("duplicate Shamir share index")]
    DuplicateShare,
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
    #[error("invalid FROST share, public package, or protocol message")]
    InvalidFrost,
    #[error("FROST participant identifier is duplicated or out of range")]
    InvalidFrostParticipant,
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

fn config_ref_kdf_info(domain: &[u8], config_ref: &ConfigRef, actor_index: Option<u16>) -> Vec<u8> {
    let mut info = Vec::with_capacity(domain.len() + 32 + 8 * 3 + 32 + 2);
    info.extend_from_slice(domain);
    info.extend_from_slice(&config_ref.config_id);
    info.extend_from_slice(&config_ref.payload_generation.to_be_bytes());
    info.extend_from_slice(&config_ref.authorization_epoch.to_be_bytes());
    info.extend_from_slice(&config_ref.guardian_epoch.to_be_bytes());
    info.extend_from_slice(&config_ref.epoch_binding);
    if let Some(index) = actor_index {
        info.extend_from_slice(&index.to_be_bytes());
    }
    info
}

/// Epoch-specific DEK-share wrapper key. The full `ConfigRef` and exact slot
/// index prevent wrapper reuse across guardian epochs.
pub fn guardian_share_key_v3(
    authorization_key: &[u8; 32],
    config_ref: &ConfigRef,
    guardian_index: u16,
) -> Result<Id32, CryptoError> {
    if guardian_index == 0 || guardian_index > crate::rotation::FROST_MAX_PARTICIPANTS {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    hkdf_sha256(
        authorization_key,
        &config_ref_kdf_info(
            b"gp/guardian-dek-share/v3",
            config_ref,
            Some(guardian_index),
        ),
    )
}

/// Independent epoch storage-envelope key for a ciphertext fragment. This
/// re-randomizes at-rest fragment bytes without decrypting the payload C.
pub fn guardian_fragment_key_v3(
    authorization_key: &[u8; 32],
    config_ref: &ConfigRef,
    guardian_index: u16,
) -> Result<Id32, CryptoError> {
    if guardian_index == 0 || guardian_index > crate::rotation::FROST_MAX_PARTICIPANTS {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    hkdf_sha256(
        authorization_key,
        &config_ref_kdf_info(
            b"gp/guardian-ciphertext-fragment/v3",
            config_ref,
            Some(guardian_index),
        ),
    )
}

pub fn descriptor_key_v3(
    authorization_key: &[u8; 32],
    config_ref: &ConfigRef,
) -> Result<Id32, CryptoError> {
    hkdf_sha256(
        authorization_key,
        &config_ref_kdf_info(b"gp/recovery-descriptor/v3", config_ref, None),
    )
}

/// Encrypts crash-recovery state for one node under a key derived from its
/// persistent identity seed and the exact canonical rotation/session context.
/// Callers persist only the returned ciphertext and erase the plaintext.
pub fn seal_local_rotation_journal(
    node_identity_seed: &Id32,
    nonce: [u8; 24],
    plaintext: &[u8],
    canonical_context: &[u8],
) -> Result<AeadCiphertext, CryptoError> {
    let mut info = b"gp/local-rotation-journal/v3".to_vec();
    info.extend_from_slice(&sha256(canonical_context));
    let mut key = hkdf_sha256(node_identity_seed, &info)?;
    let result = aead_encrypt(&key, nonce, plaintext, canonical_context);
    key.zeroize();
    result
}

pub fn open_local_rotation_journal(
    node_identity_seed: &Id32,
    encrypted: &AeadCiphertext,
    canonical_context: &[u8],
) -> Result<SecretVec, CryptoError> {
    let mut info = b"gp/local-rotation-journal/v3".to_vec();
    info.extend_from_slice(&sha256(canonical_context));
    let mut key = hkdf_sha256(node_identity_seed, &info)?;
    let result = aead_decrypt(&key, encrypted, canonical_context);
    key.zeroize();
    result
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
) -> Result<Vec<SecretVec>, CryptoError> {
    if secret.len() != SHAMIR_SECRET_LEN {
        return Err(CryptoError::InvalidSecretLength);
    }
    if threshold == 0 || threshold > total || total > SHAMIR_MAX_SHARES {
        return Err(CryptoError::InvalidThreshold);
    }
    let scheme = Sharks(threshold as u8);
    let mut rng = ChaCha20Rng08::from_seed(seed);
    Ok(scheme
        .dealer_rng(secret, &mut rng)
        .take(total as usize)
        .map(|share| Zeroizing::new(Vec::from(&share)))
        .collect())
}

pub fn recover_secret<T: AsRef<[u8]>>(
    shares: &[T],
    threshold: u16,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if threshold == 0 || threshold > SHAMIR_MAX_SHARES {
        return Err(CryptoError::InvalidThreshold);
    }
    if shares.len() < threshold as usize {
        return Err(CryptoError::InsufficientShares);
    }
    if shares.len() > usize::from(SHAMIR_MAX_SHARES) {
        return Err(CryptoError::InvalidShare);
    }

    let mut seen_indices = [0_u64; SHAMIR_INDEX_WORDS];
    let mut decoded = Vec::with_capacity(shares.len());
    for share in shares {
        let encoded = share.as_ref();
        if encoded.len() != SHAMIR_SHARE_LEN || encoded[0] == 0 {
            return Err(CryptoError::InvalidShare);
        }
        let index = usize::from(encoded[0]);
        let word = index / SHAMIR_INDEX_BITS_PER_WORD;
        let mask = 1_u64 << (index % SHAMIR_INDEX_BITS_PER_WORD);
        if seen_indices[word] & mask != 0 {
            return Err(CryptoError::DuplicateShare);
        }
        seen_indices[word] |= mask;
        decoded.push(Share::try_from(encoded).map_err(|_| CryptoError::InvalidShare)?);
    }

    let recovered = Sharks(threshold as u8)
        .recover(decoded.iter())
        .map_err(|_| CryptoError::InvalidShare)?;
    if recovered.len() != SHAMIR_SECRET_LEN {
        return Err(CryptoError::InvalidShare);
    }
    Ok(Zeroizing::new(recovered))
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
    let shard_len = fragments
        .first()
        .map(|(_, fragment)| fragment.len())
        .filter(|length| *length > 0)
        .ok_or(CryptoError::InvalidFragments)?;
    let mut shards = vec![(vec![0_u8; shard_len], false); total_shards as usize];
    for (index, fragment) in fragments {
        let position = usize::from(*index)
            .checked_sub(1)
            .filter(|position| *position < shards.len())
            .ok_or(CryptoError::InvalidFragments)?;
        if fragment.len() != shard_len || shards[position].1 {
            return Err(CryptoError::InvalidFragments);
        }
        shards[position] = (fragment.clone(), true);
    }
    coder
        .reconstruct(&mut shards)
        .map_err(|_| CryptoError::InvalidFragments)?;
    let mut output = Vec::new();
    for (shard, present) in shards.into_iter().take(data_shards as usize) {
        if !present {
            return Err(CryptoError::InvalidFragments);
        }
        output.extend_from_slice(&shard);
    }
    output.truncate(original_len);
    Ok(output)
}

/// Reconstruct authenticated ciphertext bytes from an old erasure quorum and
/// encode a complete successor fragment set. This function never performs
/// payload AEAD decryption.
pub fn rotate_ciphertext_fragments(
    old_fragments: &[(u16, Vec<u8>)],
    old_data_shards: u16,
    old_total_shards: u16,
    ciphertext_len: usize,
    new_data_shards: u16,
    new_total_shards: u16,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    let mut seen = BTreeSet::new();
    if old_fragments.iter().any(|(index, _)| !seen.insert(*index)) {
        return Err(CryptoError::InvalidFragments);
    }
    let ciphertext = erasure_reconstruct(
        old_fragments,
        old_data_shards,
        old_total_shards,
        ciphertext_len,
    )?;
    erasure_encode(&ciphertext, new_data_shards, new_total_shards)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CiphertextFragmentCommitment {
    pub root: Id32,
    pub proofs: Vec<Vec<u8>>,
}

fn ciphertext_fragment_leaf(
    config_id: &Id32,
    payload_generation: u64,
    fragment_index: u16,
    fragment: &[u8],
) -> Result<Id32, CryptoError> {
    if fragment_index == 0 || fragment.is_empty() {
        return Err(CryptoError::InvalidFragments);
    }
    let fragment_len = u64::try_from(fragment.len()).map_err(|_| CryptoError::InvalidFragments)?;
    let mut value = Vec::with_capacity(32 + 32 + 8 + 2 + 8 + 32);
    value.extend_from_slice(b"gp/ciphertext-fragment-leaf/v3");
    value.extend_from_slice(config_id);
    value.extend_from_slice(&payload_generation.to_be_bytes());
    value.extend_from_slice(&fragment_index.to_be_bytes());
    value.extend_from_slice(&fragment_len.to_be_bytes());
    value.extend_from_slice(&sha256(fragment));
    Ok(sha256(&value))
}

/// Commits to the complete deterministic Reed-Solomon fragment set for one
/// immutable payload generation. The root is retained across guardian epochs,
/// allowing every successor to reject a coordinator-supplied fragment that is
/// corrupt, duplicated at another index, or derived from another payload.
pub fn commit_ciphertext_fragments(
    config_id: &Id32,
    payload_generation: u64,
    fragments: &[Vec<u8>],
) -> Result<CiphertextFragmentCommitment, CryptoError> {
    if fragments.is_empty() || fragments.len() > usize::from(u16::MAX) {
        return Err(CryptoError::InvalidFragments);
    }
    let leaves = fragments
        .iter()
        .enumerate()
        .map(|(offset, fragment)| {
            ciphertext_fragment_leaf(
                config_id,
                payload_generation,
                u16::try_from(offset + 1).map_err(|_| CryptoError::InvalidFragments)?,
                fragment,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (root, proofs) = merkle_commit(&leaves)?;
    Ok(CiphertextFragmentCommitment { root, proofs })
}

pub fn verify_ciphertext_fragment(
    root: Id32,
    config_id: &Id32,
    payload_generation: u64,
    fragment_index: u16,
    total_fragments: u16,
    fragment: &[u8],
    proof: &[u8],
) -> Result<(), CryptoError> {
    let position = usize::from(fragment_index)
        .checked_sub(1)
        .filter(|position| *position < usize::from(total_fragments))
        .ok_or(CryptoError::InvalidFragments)?;
    merkle_verify(
        root,
        ciphertext_fragment_leaf(config_id, payload_generation, fragment_index, fragment)?,
        position,
        usize::from(total_fragments),
        proof,
    )
}

pub const CUSTODY_BLOCK_SIZE: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CustodyCommitment {
    pub root: Id32,
    pub block_count: u32,
    pub proofs: Vec<Vec<u8>>,
}

fn custody_leaf(index: u32, block: &[u8]) -> Id32 {
    let mut value = b"gp/custody-block/v3".to_vec();
    value.extend_from_slice(&index.to_be_bytes());
    value.extend_from_slice(&(block.len() as u32).to_be_bytes());
    value.extend_from_slice(block);
    sha256(&value)
}

/// Builds a sampled-retrieval Merkle commitment. It is intentionally not
/// described as a proof of retrievability.
pub fn custody_commit(bytes: &[u8]) -> Result<CustodyCommitment, CryptoError> {
    if bytes.is_empty() {
        return Err(CryptoError::InvalidMerkleProof);
    }
    let leaves = bytes
        .chunks(CUSTODY_BLOCK_SIZE)
        .enumerate()
        .map(|(index, block)| custody_leaf(index as u32, block))
        .collect::<Vec<_>>();
    let block_count = u32::try_from(leaves.len()).map_err(|_| CryptoError::InvalidMerkleProof)?;
    let (root, proofs) = merkle_commit(&leaves)?;
    Ok(CustodyCommitment {
        root,
        block_count,
        proofs,
    })
}

pub fn custody_verify_block(
    root: Id32,
    block_count: u32,
    block_index: u32,
    block: &[u8],
    proof: &[u8],
) -> Result<(), CryptoError> {
    if block_count == 0 || block_index >= block_count || block.len() > CUSTODY_BLOCK_SIZE {
        return Err(CryptoError::InvalidMerkleProof);
    }
    merkle_verify(
        root,
        custody_leaf(block_index, block),
        block_index as usize,
        block_count as usize,
        proof,
    )
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

pub fn zeroize_id(value: &mut Id32) {
    value.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(counter: u16) -> Id32 {
        let mut value = [0_u8; 32];
        value[..2].copy_from_slice(&counter.to_be_bytes());
        value
    }

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
    fn every_default_signer_subset_reconstructs() {
        let secret = [0x21; SHAMIR_SECRET_LEN];
        let shares = split_secret(&secret, 2, 3, [0x31; 32]).unwrap();
        for first in 0..2 {
            for second in (first + 1)..3 {
                assert_eq!(
                    &*recover_secret(&[&shares[first], &shares[second]], 2).unwrap(),
                    &secret
                );
            }
        }
    }

    #[test]
    fn every_default_guardian_subset_reconstructs() {
        let secret = [0x41; SHAMIR_SECRET_LEN];
        let shares = split_secret(&secret, 5, 8, [0x51; 32]).unwrap();
        for first in 0..4 {
            for second in (first + 1)..5 {
                for third in (second + 1)..6 {
                    for fourth in (third + 1)..7 {
                        for fifth in (fourth + 1)..8 {
                            let subset = [
                                &shares[first],
                                &shares[second],
                                &shares[third],
                                &shares[fourth],
                                &shares[fifth],
                            ];
                            assert_eq!(&*recover_secret(&subset, 5).unwrap(), &secret);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn seeded_threshold_properties_hold_across_parameter_range() {
        for total in 1..=12 {
            for threshold in 1..=total {
                let secret = [total as u8 ^ threshold as u8; SHAMIR_SECRET_LEN];
                let shares =
                    split_secret(&secret, threshold, total, seed(total * 16 + threshold)).unwrap();
                assert_eq!(shares.len(), usize::from(total));
                assert!(shares.iter().all(|share| share.len() == SHAMIR_SHARE_LEN));
                assert_eq!(
                    &*recover_secret(&shares[..usize::from(threshold)], threshold).unwrap(),
                    &secret
                );
                if threshold > 1 {
                    assert!(matches!(
                        recover_secret(&shares[..usize::from(threshold - 1)], threshold),
                        Err(CryptoError::InsufficientShares)
                    ));
                }
            }
        }
    }

    #[test]
    fn seeded_generation_is_deterministic_and_seed_separated() {
        let secret = [0x61; SHAMIR_SECRET_LEN];
        let first = split_secret(&secret, 3, 5, [0x71; 32]).unwrap();
        let replay = split_secret(&secret, 3, 5, [0x71; 32]).unwrap();
        let independent = split_secret(&secret, 3, 5, [0x72; 32]).unwrap();
        assert_eq!(first, replay);
        assert_ne!(first, independent);
        assert_eq!(&*recover_secret(&independent[..3], 3).unwrap(), &secret);
    }

    #[test]
    fn unbiased_coefficient_regression_allows_zero_coefficients() {
        let secret = [0xa5; SHAMIR_SECRET_LEN];
        let found_zero_slope = (0..1024).any(|counter| {
            let shares = split_secret(&secret, 2, 2, seed(counter)).unwrap();
            shares[0][1..]
                .iter()
                .zip(&shares[1][1..])
                .any(|(first, second)| first == second)
        });
        assert!(
            found_zero_slope,
            "a 2-of-n polynomial must permit a uniformly sampled zero slope"
        );
    }

    #[test]
    fn shamir_rejects_invalid_parameters_and_encodings() {
        let secret = [0x81; SHAMIR_SECRET_LEN];
        let shares = split_secret(&secret, 2, 3, [0x91; 32]).unwrap();
        let no_shares: Vec<Vec<u8>> = Vec::new();

        assert!(matches!(
            split_secret(&secret, 0, 3, [0; 32]),
            Err(CryptoError::InvalidThreshold)
        ));
        assert!(matches!(
            split_secret(&secret, 2, 256, [0; 32]),
            Err(CryptoError::InvalidThreshold)
        ));
        assert!(matches!(
            split_secret(&secret[..31], 2, 3, [0; 32]),
            Err(CryptoError::InvalidSecretLength)
        ));
        assert!(matches!(
            recover_secret(&no_shares, 0),
            Err(CryptoError::InvalidThreshold)
        ));
        assert!(matches!(
            recover_secret(&no_shares, 1),
            Err(CryptoError::InsufficientShares)
        ));
        assert!(matches!(
            recover_secret(&no_shares, 256),
            Err(CryptoError::InvalidThreshold)
        ));

        let duplicate = [&shares[0], &shares[0]];
        assert!(matches!(
            recover_secret(&duplicate, 2),
            Err(CryptoError::DuplicateShare)
        ));

        let mut zero_index = shares[0].to_vec();
        zero_index[0] = 0;
        assert!(matches!(
            recover_secret(&[zero_index, shares[1].to_vec()], 2),
            Err(CryptoError::InvalidShare)
        ));
        assert!(matches!(
            recover_secret(
                &[
                    shares[0][..SHAMIR_SHARE_LEN - 1].to_vec(),
                    shares[1].to_vec()
                ],
                2
            ),
            Err(CryptoError::InvalidShare)
        ));

        let too_many = vec![shares[0].to_vec(); usize::from(SHAMIR_MAX_SHARES) + 1];
        assert!(matches!(
            recover_secret(&too_many, 2),
            Err(CryptoError::InvalidShare)
        ));
    }

    #[test]
    fn shamir_supports_the_maximum_distinct_share_count() {
        let secret = [0xb1; SHAMIR_SECRET_LEN];
        let shares = split_secret(&secret, 2, SHAMIR_MAX_SHARES, [0xc1; 32]).unwrap();
        assert_eq!(shares.len(), usize::from(SHAMIR_MAX_SHARES));
        assert_eq!(shares.first().unwrap()[0], 1);
        assert_eq!(shares.last().unwrap()[0], u8::MAX);
        assert_eq!(&*recover_secret(&shares[..2], 2).unwrap(), &secret);
        assert_eq!(
            &*recover_secret(&[&shares[1], &shares[0]], 2).unwrap(),
            &secret
        );

        let all_required =
            split_secret(&secret, SHAMIR_MAX_SHARES, SHAMIR_MAX_SHARES, [0xd1; 32]).unwrap();
        assert_eq!(
            &*recover_secret(&all_required, SHAMIR_MAX_SHARES).unwrap(),
            &secret
        );
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
    fn v3_epoch_keys_separate_share_fragment_epoch_and_actor_contexts() {
        let authorization_key = [1; 32];
        let old = ConfigRef {
            config_id: [2; 32],
            payload_generation: 3,
            authorization_epoch: 4,
            guardian_epoch: 5,
            epoch_binding: [6; 32],
        };
        let mut new = old;
        new.guardian_epoch += 1;
        new.epoch_binding = [7; 32];
        let old_share = guardian_share_key_v3(&authorization_key, &old, 1).unwrap();
        assert_ne!(
            old_share,
            guardian_share_key_v3(&authorization_key, &new, 1).unwrap()
        );
        assert_ne!(
            old_share,
            guardian_share_key_v3(&authorization_key, &old, 2).unwrap()
        );
        assert_ne!(
            old_share,
            guardian_fragment_key_v3(&authorization_key, &old, 1).unwrap()
        );
    }

    #[test]
    fn ciphertext_fragment_rotation_reencodes_without_payload_decryption() {
        let ciphertext = (0..173_u8).collect::<Vec<_>>();
        let old = erasure_encode(&ciphertext, 3, 5).unwrap();
        let selected = vec![
            (1, old[0].clone()),
            (3, old[2].clone()),
            (5, old[4].clone()),
        ];
        let new = rotate_ciphertext_fragments(&selected, 3, 5, ciphertext.len(), 4, 7).unwrap();
        let reconstructed = erasure_reconstruct(
            &[
                (2, new[1].clone()),
                (4, new[3].clone()),
                (5, new[4].clone()),
                (7, new[6].clone()),
            ],
            4,
            7,
            ciphertext.len(),
        )
        .unwrap();
        assert_eq!(reconstructed, ciphertext);
    }

    #[test]
    fn ciphertext_fragment_commitment_rejects_corruption_and_index_substitution() {
        let config_id = [0x44; 32];
        let ciphertext = (0..173_u8).collect::<Vec<_>>();
        let fragments = erasure_encode(&ciphertext, 3, 5).unwrap();
        let commitment = commit_ciphertext_fragments(&config_id, 7, &fragments).unwrap();
        verify_ciphertext_fragment(
            commitment.root,
            &config_id,
            7,
            3,
            5,
            &fragments[2],
            &commitment.proofs[2],
        )
        .unwrap();

        let mut corrupted = fragments[2].clone();
        corrupted[0] ^= 1;
        assert!(
            verify_ciphertext_fragment(
                commitment.root,
                &config_id,
                7,
                3,
                5,
                &corrupted,
                &commitment.proofs[2],
            )
            .is_err()
        );
        assert!(
            verify_ciphertext_fragment(
                commitment.root,
                &config_id,
                7,
                4,
                5,
                &fragments[2],
                &commitment.proofs[2],
            )
            .is_err()
        );
        assert!(
            verify_ciphertext_fragment(
                commitment.root,
                &config_id,
                8,
                3,
                5,
                &fragments[2],
                &commitment.proofs[2],
            )
            .is_err()
        );
    }

    #[test]
    fn custody_sample_rejects_block_and_proof_mutation() {
        let bytes = vec![9_u8; CUSTODY_BLOCK_SIZE * 2 + 17];
        let commitment = custody_commit(&bytes).unwrap();
        let block = &bytes[CUSTODY_BLOCK_SIZE..CUSTODY_BLOCK_SIZE * 2];
        custody_verify_block(
            commitment.root,
            commitment.block_count,
            1,
            block,
            &commitment.proofs[1],
        )
        .unwrap();
        let mut bad = block.to_vec();
        bad[0] ^= 1;
        assert!(
            custody_verify_block(
                commitment.root,
                commitment.block_count,
                1,
                &bad,
                &commitment.proofs[1]
            )
            .is_err()
        );
        let mut proof = commitment.proofs[1].clone();
        proof[0] ^= 1;
        assert!(
            custody_verify_block(commitment.root, commitment.block_count, 1, block, &proof)
                .is_err()
        );
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
