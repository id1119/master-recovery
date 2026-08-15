//! Guardian-rotation threshold wrappers.
//!
//! This module deliberately delegates all scalar, Shamir, RTS, VSS, and DKG
//! operations to Zcash Foundation FROST. Callers only handle opaque bounded
//! encodings and authenticated protocol routing.

use std::collections::{BTreeMap, BTreeSet};

use frost_ristretto255::{self as frost, Identifier};
use rand_chacha08::{ChaCha20Rng, rand_core::SeedableRng};
use zeroize::Zeroizing;

use gp_types::ConfigRef;

use crate::{CryptoError, Id32, SecretVec, sha256};

pub const FROST_SHARE_MAX_LEN: usize = 512;
pub const FROST_PUBLIC_PACKAGE_MAX_LEN: usize = 4 * 1024;
pub const FROST_ROUND_PACKAGE_MAX_LEN: usize = 4 * 1024;
pub const FROST_SCALAR_LEN: usize = 32;
/// Conservative application bound. The provider supports larger rosters, but
/// this protocol deliberately caps every serialized DKG package at 4 KiB and
/// uses all-participant refresh rounds, so advertising a larger limit would be
/// a false availability claim.
pub const FROST_MAX_PARTICIPANTS: u16 = 32;

#[derive(Clone)]
pub struct FrostDealerOutput {
    pub dek: SecretVec,
    pub shares: Vec<SecretVec>,
    pub public_package: Vec<u8>,
}

impl std::fmt::Debug for FrostDealerOutput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostDealerOutput")
            .field("dek", &"[REDACTED]")
            .field(
                "shares",
                &format_args!("{} redacted shares", self.shares.len()),
            )
            .field("public_package_len", &self.public_package.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrostRefreshRound1 {
    pub secret_state: SecretVec,
    pub broadcast: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrostRefreshRound2 {
    pub secret_state: SecretVec,
    pub direct_messages: Vec<(u16, Vec<u8>)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrostRefreshOutput {
    pub share: SecretVec,
    pub public_package: Vec<u8>,
}

fn identifier(value: u16) -> Result<Identifier, CryptoError> {
    if value == 0 || value > FROST_MAX_PARTICIPANTS {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    Identifier::try_from(value).map_err(|_| CryptoError::InvalidFrostParticipant)
}

fn validate_threshold(threshold: u16, total: u16) -> Result<(), CryptoError> {
    if threshold < 2 || threshold > total || !(2..=FROST_MAX_PARTICIPANTS).contains(&total) {
        return Err(CryptoError::InvalidThreshold);
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DpssMessageTracker {
    next_sequences: BTreeMap<(u16, u16), u64>,
    seen_payloads: BTreeSet<Id32>,
}

/// Validates bounded, ordered provider-owned messages before they enter a
/// FROST RTS/refresh round. Message contents remain opaque until passed to the
/// corresponding maintained-library deserializer.
pub fn accept_dpss_message(
    tracker: &mut DpssMessageTracker,
    sender: u16,
    recipient: u16,
    sequence: u64,
    provider_payload: &[u8],
) -> Result<(), CryptoError> {
    identifier(sender)?;
    identifier(recipient)?;
    if sender == recipient {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    bounded(provider_payload, FROST_ROUND_PACKAGE_MAX_LEN)?;
    let expected = tracker
        .next_sequences
        .entry((sender, recipient))
        .or_insert(1);
    if sequence != *expected || !tracker.seen_payloads.insert(sha256(provider_payload)) {
        return Err(CryptoError::InvalidFrost);
    }
    *expected = expected.saturating_add(1);
    Ok(())
}

/// Begins one old helper's repairable-threshold-sharing contribution. This is
/// a named adapter boundary over the ZF FROST RTS implementation.
pub fn begin_old_share(
    helper_share: &[u8],
    helper_ids: &[u16],
    replacement_id: u16,
    seed: Id32,
) -> Result<Vec<(u16, SecretVec)>, CryptoError> {
    frost_repair_part1(helper_share, helper_ids, replacement_id, seed)
}

/// Finalizes the replacement participant's RTS share from the helper sigmas.
pub fn finalize_new_share(
    sigmas: &[&[u8]],
    replacement_id: u16,
    encoded_public: &[u8],
) -> Result<SecretVec, CryptoError> {
    frost_repair_part3(sigmas, replacement_id, encoded_public)
}

/// Checks that all successor outputs agree on one canonical public package,
/// contain exactly the expected participants, and preserve the old DEK's
/// FROST verifying key. Returns the successor commitment.
pub fn verify_dpss_result<T: AsRef<[u8]>>(
    old_public: &[u8],
    successor_public_packages: &[T],
    successor_shares: &[T],
    expected_participants: &[u16],
) -> Result<Id32, CryptoError> {
    if successor_public_packages.len() != expected_participants.len()
        || successor_shares.len() != expected_participants.len()
        || expected_participants.is_empty()
    {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    let expected = expected_participants
        .iter()
        .copied()
        .map(identifier)
        .collect::<Result<BTreeSet<_>, _>>()?;
    if expected.len() != expected_participants.len() {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    let old = decode_public(old_public)?;
    let canonical = decode_public(successor_public_packages[0].as_ref())?;
    if old.verifying_key() != canonical.verifying_key()
        || canonical
            .verifying_shares()
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
            != expected
    {
        return Err(CryptoError::InvalidFrost);
    }
    let encoded_canonical = encode_public(&canonical)?;
    let mut actual = BTreeSet::new();
    for (public, share) in successor_public_packages
        .iter()
        .zip(successor_shares.iter())
    {
        if public.as_ref() != encoded_canonical {
            return Err(CryptoError::InvalidFrost);
        }
        actual.insert(frost_verify_share(share.as_ref(), &encoded_canonical)?);
    }
    if actual != expected_participants.iter().copied().collect() {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    Ok(sha256(&encoded_canonical))
}

/// Explicit erasure boundary for any serialized provider session state.
pub fn zeroize_session(session_state: &mut SecretVec) {
    use zeroize::Zeroize;
    session_state.zeroize();
}

fn bounded(value: &[u8], maximum: usize) -> Result<(), CryptoError> {
    if value.is_empty() || value.len() > maximum {
        return Err(CryptoError::InvalidFrost);
    }
    Ok(())
}

fn decode_share(value: &[u8]) -> Result<frost::keys::KeyPackage, CryptoError> {
    bounded(value, FROST_SHARE_MAX_LEN)?;
    let share =
        frost::keys::KeyPackage::deserialize(value).map_err(|_| CryptoError::InvalidFrost)?;
    let derived: frost::keys::VerifyingShare = (*share.signing_share()).into();
    if &derived != share.verifying_share() {
        return Err(CryptoError::InvalidFrost);
    }
    Ok(share)
}

fn decode_public(value: &[u8]) -> Result<frost::keys::PublicKeyPackage, CryptoError> {
    bounded(value, FROST_PUBLIC_PACKAGE_MAX_LEN)?;
    frost::keys::PublicKeyPackage::deserialize(value).map_err(|_| CryptoError::InvalidFrost)
}

fn encode_share(value: &frost::keys::KeyPackage) -> Result<SecretVec, CryptoError> {
    let encoded = value.serialize().map_err(|_| CryptoError::InvalidFrost)?;
    bounded(&encoded, FROST_SHARE_MAX_LEN)?;
    Ok(Zeroizing::new(encoded))
}

fn encode_public(value: &frost::keys::PublicKeyPackage) -> Result<Vec<u8>, CryptoError> {
    let encoded = value.serialize().map_err(|_| CryptoError::InvalidFrost)?;
    bounded(&encoded, FROST_PUBLIC_PACKAGE_MAX_LEN)?;
    Ok(encoded)
}

pub fn frost_dealer_split(
    threshold: u16,
    total: u16,
    seed: Id32,
) -> Result<FrostDealerOutput, CryptoError> {
    validate_threshold(threshold, total)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (secret_shares, public_package) = frost::keys::generate_with_dealer(
        total,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
    .map_err(|_| CryptoError::InvalidFrost)?;
    if secret_shares.len() != usize::from(total) {
        return Err(CryptoError::InvalidFrost);
    }

    let mut shares = Vec::with_capacity(secret_shares.len());
    let mut reconstruction = Vec::with_capacity(usize::from(threshold));
    for secret_share in secret_shares.into_values() {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)
            .map_err(|_| CryptoError::InvalidFrost)?;
        if reconstruction.len() < usize::from(threshold) {
            reconstruction.push(key_package.clone());
        }
        shares.push(encode_share(&key_package)?);
    }
    let signing_key =
        frost::keys::reconstruct(&reconstruction).map_err(|_| CryptoError::InvalidFrost)?;
    let dek = Zeroizing::new(signing_key.serialize().to_vec());
    if dek.len() != FROST_SCALAR_LEN {
        return Err(CryptoError::InvalidFrost);
    }
    Ok(FrostDealerOutput {
        dek,
        shares,
        public_package: encode_public(&public_package)?,
    })
}

pub fn frost_recover_dek<T: AsRef<[u8]>>(
    shares: &[T],
    threshold: u16,
) -> Result<SecretVec, CryptoError> {
    if threshold < 2 || shares.len() < usize::from(threshold) {
        return Err(CryptoError::InsufficientShares);
    }
    let mut identifiers = BTreeSet::new();
    let mut packages = Vec::with_capacity(shares.len());
    let mut verifying_key = None;
    for encoded in shares {
        let package = decode_share(encoded.as_ref())?;
        if *package.min_signers() != threshold
            || !identifiers.insert(package.identifier().serialize())
            || verifying_key.is_some_and(|key| key != *package.verifying_key())
        {
            return Err(CryptoError::InvalidFrostParticipant);
        }
        verifying_key = Some(*package.verifying_key());
        packages.push(package);
    }
    let secret = frost::keys::reconstruct(&packages).map_err(|_| CryptoError::InvalidFrost)?;
    let output = Zeroizing::new(secret.serialize().to_vec());
    if output.len() != FROST_SCALAR_LEN {
        return Err(CryptoError::InvalidFrost);
    }
    Ok(output)
}

#[derive(Clone, Debug)]
pub struct EpochFrostShare<T> {
    pub config_ref: ConfigRef,
    pub encoded_share: T,
}

/// Recovery entry point for protocol v3. Epoch labels are authenticated by
/// the enclosing guardian contribution and share AEAD context; this adapter
/// refuses mixed labels before passing any bytes to FROST interpolation.
pub fn frost_recover_dek_for_epoch<T: AsRef<[u8]>>(
    shares: &[EpochFrostShare<T>],
    expected: &ConfigRef,
    threshold: u16,
) -> Result<SecretVec, CryptoError> {
    if shares.iter().any(|share| &share.config_ref != expected) {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    frost_recover_dek(
        &shares
            .iter()
            .map(|share| share.encoded_share.as_ref())
            .collect::<Vec<_>>(),
        threshold,
    )
}

pub fn frost_verify_share(encoded_share: &[u8], encoded_public: &[u8]) -> Result<u16, CryptoError> {
    let share = decode_share(encoded_share)?;
    let public = decode_public(encoded_public)?;
    if share.verifying_key() != public.verifying_key()
        || public.min_signers() != Some(*share.min_signers())
        || public.verifying_shares().get(share.identifier()) != Some(share.verifying_share())
    {
        return Err(CryptoError::InvalidFrost);
    }
    numeric_identifier(*share.identifier())
}

pub fn frost_public_package_digest(encoded_public: &[u8]) -> Result<Id32, CryptoError> {
    let public = decode_public(encoded_public)?;
    Ok(sha256(&encode_public(&public)?))
}

pub fn frost_repair_part1(
    helper_share: &[u8],
    helper_ids: &[u16],
    replacement_id: u16,
    seed: Id32,
) -> Result<Vec<(u16, SecretVec)>, CryptoError> {
    let helper = decode_share(helper_share)?;
    let helper_identifiers = helper_ids
        .iter()
        .copied()
        .map(identifier)
        .collect::<Result<Vec<_>, _>>()?;
    let unique = helper_identifiers.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() != helper_identifiers.len()
        || !unique.contains(helper.identifier())
        || helper_ids.len() < usize::from(*helper.min_signers())
    {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    let mut rng = ChaCha20Rng::from_seed(seed);
    let values = frost::keys::repairable::repair_share_part1::<frost::Ristretto255Sha512, _>(
        &helper_identifiers,
        &helper,
        &mut rng,
        identifier(replacement_id)?,
    )
    .map_err(|_| CryptoError::InvalidFrost)?;
    helper_ids
        .iter()
        .copied()
        .zip(helper_identifiers)
        .map(|(numeric, id)| {
            let encoded = values
                .get(&id)
                .ok_or(CryptoError::InvalidFrost)?
                .serialize();
            bounded(&encoded, FROST_ROUND_PACKAGE_MAX_LEN)?;
            Ok((numeric, Zeroizing::new(encoded)))
        })
        .collect()
}

pub fn frost_repair_part2(deltas: &[&[u8]]) -> Result<SecretVec, CryptoError> {
    if deltas.len() < 2 {
        return Err(CryptoError::InsufficientShares);
    }
    let decoded = deltas
        .iter()
        .map(|value| {
            bounded(value, FROST_ROUND_PACKAGE_MAX_LEN)?;
            frost::keys::repairable::Delta::deserialize(value)
                .map_err(|_| CryptoError::InvalidFrost)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Zeroizing::new(
        frost::keys::repairable::repair_share_part2(&decoded).serialize(),
    ))
}

pub fn frost_repair_part3(
    sigmas: &[&[u8]],
    replacement_id: u16,
    encoded_public: &[u8],
) -> Result<SecretVec, CryptoError> {
    let public = decode_public(encoded_public)?;
    let threshold = public.min_signers().ok_or(CryptoError::InvalidFrost)?;
    if sigmas.len() < usize::from(threshold) {
        return Err(CryptoError::InsufficientShares);
    }
    let decoded = sigmas
        .iter()
        .map(|value| {
            bounded(value, FROST_ROUND_PACKAGE_MAX_LEN)?;
            frost::keys::repairable::Sigma::deserialize(value)
                .map_err(|_| CryptoError::InvalidFrost)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let share =
        frost::keys::repairable::repair_share_part3(&decoded, identifier(replacement_id)?, &public)
            .map_err(|_| CryptoError::InvalidFrost)?;
    encode_share(&share)
}

pub fn frost_public_add_repaired_share(
    encoded_public: &[u8],
    repaired_share: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let public = decode_public(encoded_public)?;
    let share = decode_share(repaired_share)?;
    if public.verifying_key() != share.verifying_key()
        || public.min_signers() != Some(*share.min_signers())
    {
        return Err(CryptoError::InvalidFrost);
    }
    let mut verifying_shares = public.verifying_shares().clone();
    if verifying_shares
        .insert(*share.identifier(), *share.verifying_share())
        .is_some()
    {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    encode_public(&frost::keys::PublicKeyPackage::new(
        verifying_shares,
        *public.verifying_key(),
        public.min_signers(),
    ))
}

pub fn frost_refresh_part1(
    participant_id: u16,
    threshold: u16,
    total: u16,
    seed: Id32,
) -> Result<FrostRefreshRound1, CryptoError> {
    validate_threshold(threshold, total)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (secret, public) = frost::keys::refresh::refresh_dkg_part1(
        identifier(participant_id)?,
        total,
        threshold,
        &mut rng,
    )
    .map_err(|_| CryptoError::InvalidFrost)?;
    let secret_state = Zeroizing::new(secret.serialize().map_err(|_| CryptoError::InvalidFrost)?);
    let broadcast = public.serialize().map_err(|_| CryptoError::InvalidFrost)?;
    bounded(&secret_state, FROST_ROUND_PACKAGE_MAX_LEN)?;
    bounded(&broadcast, FROST_ROUND_PACKAGE_MAX_LEN)?;
    Ok(FrostRefreshRound1 {
        secret_state,
        broadcast,
    })
}

pub fn frost_refresh_part2(
    secret_state: &[u8],
    round1_messages: &[(u16, Vec<u8>)],
) -> Result<FrostRefreshRound2, CryptoError> {
    bounded(secret_state, FROST_ROUND_PACKAGE_MAX_LEN)?;
    let secret = frost::keys::dkg::round1::SecretPackage::deserialize(secret_state)
        .map_err(|_| CryptoError::InvalidFrost)?;
    let self_id = *secret.identifier();
    let mut messages = BTreeMap::new();
    for (sender, encoded) in round1_messages {
        let sender = identifier(*sender)?;
        if sender == self_id || messages.contains_key(&sender) {
            return Err(CryptoError::InvalidFrostParticipant);
        }
        bounded(encoded, FROST_ROUND_PACKAGE_MAX_LEN)?;
        let package = frost::keys::dkg::round1::Package::deserialize(encoded)
            .map_err(|_| CryptoError::InvalidFrost)?;
        messages.insert(sender, package);
    }
    let (next_secret, outgoing) = frost::keys::refresh::refresh_dkg_part2(secret, &messages)
        .map_err(|_| CryptoError::InvalidFrost)?;
    let secret_state = Zeroizing::new(
        next_secret
            .serialize()
            .map_err(|_| CryptoError::InvalidFrost)?,
    );
    let mut direct_messages = Vec::with_capacity(outgoing.len());
    for (recipient, package) in outgoing {
        let numeric = numeric_identifier(recipient)?;
        let encoded = package.serialize().map_err(|_| CryptoError::InvalidFrost)?;
        bounded(&encoded, FROST_ROUND_PACKAGE_MAX_LEN)?;
        direct_messages.push((numeric, encoded));
    }
    Ok(FrostRefreshRound2 {
        secret_state,
        direct_messages,
    })
}

pub fn frost_refresh_part3(
    secret_state: &[u8],
    round1_messages: &[(u16, Vec<u8>)],
    round2_messages: &[(u16, Vec<u8>)],
    old_public: &[u8],
    old_share: &[u8],
) -> Result<FrostRefreshOutput, CryptoError> {
    bounded(secret_state, FROST_ROUND_PACKAGE_MAX_LEN)?;
    let secret = frost::keys::dkg::round2::SecretPackage::deserialize(secret_state)
        .map_err(|_| CryptoError::InvalidFrost)?;
    let self_id = *secret.identifier();
    let mut round1 = BTreeMap::new();
    for (sender, encoded) in round1_messages {
        let sender = identifier(*sender)?;
        if sender == self_id || round1.contains_key(&sender) {
            return Err(CryptoError::InvalidFrostParticipant);
        }
        bounded(encoded, FROST_ROUND_PACKAGE_MAX_LEN)?;
        round1.insert(
            sender,
            frost::keys::dkg::round1::Package::deserialize(encoded)
                .map_err(|_| CryptoError::InvalidFrost)?,
        );
    }
    let mut round2 = BTreeMap::new();
    for (sender, encoded) in round2_messages {
        let sender = identifier(*sender)?;
        if sender == self_id || round2.contains_key(&sender) {
            return Err(CryptoError::InvalidFrostParticipant);
        }
        bounded(encoded, FROST_ROUND_PACKAGE_MAX_LEN)?;
        round2.insert(
            sender,
            frost::keys::dkg::round2::Package::deserialize(encoded)
                .map_err(|_| CryptoError::InvalidFrost)?,
        );
    }
    if round1.keys().ne(round2.keys()) {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    let old_public = decode_public(old_public)?;
    let old_share = decode_share(old_share)?;
    if old_share.identifier() != &self_id {
        return Err(CryptoError::InvalidFrostParticipant);
    }
    let (share, public) =
        frost::keys::refresh::refresh_dkg_shares(&secret, &round1, &round2, old_public, old_share)
            .map_err(|_| CryptoError::InvalidFrost)?;
    Ok(FrostRefreshOutput {
        share: encode_share(&share)?,
        public_package: encode_public(&public)?,
    })
}

fn numeric_identifier(value: Identifier) -> Result<u16, CryptoError> {
    for candidate in 1..=u16::MAX {
        if identifier(candidate)? == value {
            return Ok(candidate);
        }
        if candidate >= FROST_MAX_PARTICIPANTS {
            break;
        }
    }
    Err(CryptoError::InvalidFrostParticipant)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(value: u8) -> Id32 {
        [value; 32]
    }

    #[test]
    fn frost_dealer_round_trip_and_validation() {
        let output = frost_dealer_split(5, 8, seed(1)).unwrap();
        assert_eq!(output.dek.len(), FROST_SCALAR_LEN);
        assert_eq!(output.shares.len(), 8);
        assert_eq!(
            frost_recover_dek(&output.shares[..5], 5).unwrap(),
            output.dek
        );
        for (offset, share) in output.shares.iter().enumerate() {
            assert_eq!(
                frost_verify_share(share, &output.public_package).unwrap(),
                u16::try_from(offset + 1).unwrap()
            );
        }
        assert!(matches!(
            frost_recover_dek(&output.shares[..4], 5),
            Err(CryptoError::InsufficientShares)
        ));
        let mut corrupted = output.shares[0].to_vec();
        let corrupted_offset = corrupted.len() / 2;
        corrupted[corrupted_offset] ^= 1;
        assert!(frost_verify_share(&corrupted, &output.public_package).is_err());
    }

    #[test]
    fn advertised_frost_roster_bound_fits_protocol_encodings() {
        let output = frost_dealer_split(16, FROST_MAX_PARTICIPANTS, seed(90)).unwrap();
        assert_eq!(output.shares.len(), usize::from(FROST_MAX_PARTICIPANTS));
        assert!(output.public_package.len() <= FROST_PUBLIC_PACKAGE_MAX_LEN);
        let refresh = frost_refresh_part1(1, 16, FROST_MAX_PARTICIPANTS, seed(91)).unwrap();
        assert!(refresh.secret_state.len() <= FROST_ROUND_PACKAGE_MAX_LEN);
        assert!(refresh.broadcast.len() <= FROST_ROUND_PACKAGE_MAX_LEN);
        assert!(frost_dealer_split(16, FROST_MAX_PARTICIPANTS + 1, seed(92)).is_err());
    }

    #[test]
    fn provider_message_tracker_rejects_replay_reordering_and_duplicate_payloads() {
        let mut tracker = DpssMessageTracker::default();
        accept_dpss_message(&mut tracker, 1, 2, 1, b"first").unwrap();
        assert!(accept_dpss_message(&mut tracker, 1, 2, 1, b"second").is_err());
        assert!(accept_dpss_message(&mut tracker, 1, 2, 3, b"third").is_err());
        accept_dpss_message(&mut tracker, 1, 2, 2, b"second").unwrap();
        assert!(accept_dpss_message(&mut tracker, 2, 1, 1, b"first").is_err());
    }

    #[test]
    fn mixed_epoch_shares_are_rejected_before_interpolation() {
        let output = frost_dealer_split(3, 5, seed(44)).unwrap();
        let epoch1 = ConfigRef {
            config_id: [1; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: 1,
            epoch_binding: [2; 32],
        };
        let mut epoch2 = epoch1;
        epoch2.guardian_epoch = 2;
        epoch2.epoch_binding = [3; 32];
        let shares = vec![
            EpochFrostShare {
                config_ref: epoch1,
                encoded_share: output.shares[0].to_vec(),
            },
            EpochFrostShare {
                config_ref: epoch2,
                encoded_share: output.shares[1].to_vec(),
            },
            EpochFrostShare {
                config_ref: epoch1,
                encoded_share: output.shares[2].to_vec(),
            },
        ];
        assert!(matches!(
            frost_recover_dek_for_epoch(&shares, &epoch1, 3),
            Err(CryptoError::InvalidFrostParticipant)
        ));
    }

    #[test]
    fn rts_replacement_and_full_roster_refresh_preserve_dek() {
        let output = frost_dealer_split(5, 8, seed(2)).unwrap();
        let helpers = [1, 2, 3, 5, 6];
        let replacement = 9;

        let dealer_deltas = helpers
            .iter()
            .enumerate()
            .map(|(offset, helper)| {
                frost_repair_part1(
                    &output.shares[usize::from(*helper - 1)],
                    &helpers,
                    replacement,
                    seed(10 + u8::try_from(offset).unwrap()),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let sigmas = helpers
            .iter()
            .map(|recipient| {
                let incoming = dealer_deltas
                    .iter()
                    .map(|dealer| {
                        dealer
                            .iter()
                            .find(|(target, _)| target == recipient)
                            .unwrap()
                            .1
                            .as_slice()
                    })
                    .collect::<Vec<_>>();
                frost_repair_part2(&incoming).unwrap()
            })
            .collect::<Vec<_>>();
        let repaired = frost_repair_part3(
            &sigmas.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
            replacement,
            &output.public_package,
        )
        .unwrap();
        let expanded_public =
            frost_public_add_repaired_share(&output.public_package, &repaired).unwrap();
        assert_eq!(
            frost_verify_share(&repaired, &expanded_public).unwrap(),
            replacement
        );

        let successor_ids = [1, 2, 3, 5, 6, 7, 8, 9];
        let mut old_shares = BTreeMap::new();
        for id in 1..=8_u16 {
            old_shares.insert(id, output.shares[usize::from(id - 1)].to_vec());
        }
        old_shares.insert(replacement, repaired.to_vec());

        let round1 = successor_ids
            .iter()
            .enumerate()
            .map(|(offset, id)| {
                (
                    *id,
                    frost_refresh_part1(*id, 5, 8, seed(30 + u8::try_from(offset).unwrap()))
                        .unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let round2 = successor_ids
            .iter()
            .map(|participant| {
                let incoming = round1
                    .iter()
                    .filter(|(sender, _)| sender != &participant)
                    .map(|(sender, package)| (*sender, package.broadcast.clone()))
                    .collect::<Vec<_>>();
                (
                    *participant,
                    frost_refresh_part2(&round1[participant].secret_state, &incoming).unwrap(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut refreshed = BTreeMap::new();
        let mut new_public = None;
        for participant in successor_ids {
            let incoming1 = round1
                .iter()
                .filter(|(sender, _)| **sender != participant)
                .map(|(sender, package)| (*sender, package.broadcast.clone()))
                .collect::<Vec<_>>();
            let incoming2 = round2
                .iter()
                .filter(|(sender, _)| **sender != participant)
                .map(|(sender, package)| {
                    let message = package
                        .direct_messages
                        .iter()
                        .find(|(recipient, _)| *recipient == participant)
                        .unwrap()
                        .1
                        .clone();
                    (*sender, message)
                })
                .collect::<Vec<_>>();
            let result = frost_refresh_part3(
                &round2[&participant].secret_state,
                &incoming1,
                &incoming2,
                &expanded_public,
                &old_shares[&participant],
            )
            .unwrap();
            if let Some(expected) = &new_public {
                assert_eq!(expected, &result.public_package);
            } else {
                new_public = Some(result.public_package.clone());
            }
            refreshed.insert(participant, result.share);
        }
        let new_public = new_public.unwrap();
        let current = [1, 2, 3, 5, 6]
            .iter()
            .map(|id| &refreshed[id])
            .collect::<Vec<_>>();
        assert_eq!(frost_recover_dek(&current, 5).unwrap(), output.dek);
        assert!(frost_verify_share(&output.shares[3], &new_public).is_err());

        let mixed = [
            output.shares[0].as_slice(),
            output.shares[1].as_slice(),
            refreshed[&3].as_slice(),
            refreshed[&5].as_slice(),
            refreshed[&6].as_slice(),
        ];
        assert_ne!(frost_recover_dek(&mixed, 5).unwrap(), output.dek);
        let epoch1 = ConfigRef {
            config_id: [41; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: 1,
            epoch_binding: [42; 32],
        };
        let epoch2 = ConfigRef {
            guardian_epoch: 2,
            epoch_binding: [43; 32],
            ..epoch1
        };
        let labelled_mixed = vec![
            EpochFrostShare {
                config_ref: epoch1,
                encoded_share: output.shares[0].as_slice(),
            },
            EpochFrostShare {
                config_ref: epoch1,
                encoded_share: output.shares[1].as_slice(),
            },
            EpochFrostShare {
                config_ref: epoch2,
                encoded_share: refreshed[&3].as_slice(),
            },
            EpochFrostShare {
                config_ref: epoch2,
                encoded_share: refreshed[&5].as_slice(),
            },
            EpochFrostShare {
                config_ref: epoch2,
                encoded_share: refreshed[&6].as_slice(),
            },
        ];
        assert!(matches!(
            frost_recover_dek_for_epoch(&labelled_mixed, &epoch2, 5),
            Err(CryptoError::InvalidFrostParticipant)
        ));

        let mut corrupted_round1 = round1[&2].broadcast.clone();
        let corrupted_offset = corrupted_round1.len() / 2;
        corrupted_round1[corrupted_offset] ^= 1;
        let invalid = successor_ids
            .iter()
            .filter(|id| **id != 1)
            .map(|id| {
                if *id == 2 {
                    (*id, corrupted_round1.clone())
                } else {
                    (*id, round1[id].broadcast.clone())
                }
            })
            .collect::<Vec<_>>();
        assert!(frost_refresh_part2(&round1[&1].secret_state, &invalid).is_err());
    }
}
