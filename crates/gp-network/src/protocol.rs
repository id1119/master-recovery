use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use gp_crypto::{
    RecipientKeyPair, SecretVec, aead_decrypt, aead_encrypt, descriptor_key, erasure_encode,
    erasure_reconstruct, guardian_share_key, hash_aead, merkle_commit, merkle_verify,
    recover_secret, sha256, sign, signing_key, split_secret, verify, verifying_key_bytes,
    zeroize_id,
};
use gp_storage::SignerState;
use gp_types::{
    AeadCiphertext, BeginRecoveryCertificate, ConfigCapsule, CryptoSuite, GuardianContribution,
    GuardianPolicy, GuardianRecord, GuardianRoute, Id32, OwnerCancelAck, OwnerCancelCertificate,
    PROTOCOL_VERSION, RecoveryCard, RecoveryDescriptor, RecoveryRequest, ReleaseCertificate,
    SetupPolicy, SignerPolicy,
};
use rand::Rng;

use crate::types::GuardianProvision;

pub struct SetupBundle {
    pub capsule: ConfigCapsule,
    pub card: RecoveryCard,
    pub signers: Vec<SignerState>,
    pub guardians: Vec<GuardianProvision>,
    pub owner_cancel_signing_seed: SecretVec,
    pub owner_guardian_routes: Vec<GuardianRoute>,
}

pub fn random_id() -> Id32 {
    let mut value = [0_u8; 32];
    rand::rng().fill(&mut value);
    value
}

pub fn random_nonce() -> [u8; 24] {
    let mut value = [0_u8; 24];
    rand::rng().fill(&mut value);
    value
}

pub fn wall_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

pub fn create_setup(
    secret: &[u8],
    policy: &SetupPolicy,
    signer_mailboxes: Vec<String>,
    guardian_mailboxes: Vec<String>,
    capsule_locator_base: &str,
) -> Result<SetupBundle> {
    if signer_mailboxes.len() != usize::from(policy.signer_count)
        || guardian_mailboxes.len() != usize::from(policy.guardian_count)
        || policy.signer_threshold == 0
        || policy.signer_threshold > policy.signer_count
        || policy.guardian_threshold == 0
        || policy.guardian_threshold > policy.guardian_count
    {
        bail!("invalid setup policy or node count");
    }

    let config_id = random_id();
    let config_version = 1;
    let owner_cancel_signing_seed = SecretVec::new(random_id().to_vec());
    let owner_cancel_public_key = verifying_key_bytes(&signing_key(
        owner_cancel_signing_seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid owner cancellation seed"))?,
    ));
    let authorization_key = SecretVec::new(random_id().to_vec());
    let dek = SecretVec::new(random_id().to_vec());
    let a_shares = split_secret(
        &authorization_key,
        policy.signer_threshold,
        policy.signer_count,
        random_id(),
    )?;

    let mut signers = Vec::new();
    let mut signer_leaves = Vec::new();
    for (offset, mailbox) in signer_mailboxes.iter().enumerate() {
        let signer_id = u16::try_from(offset + 1)?;
        let seed = random_id();
        let public = verifying_key_bytes(&signing_key(seed));
        signer_leaves.push(sha256(&gp_wire::signer_leaf(signer_id, &public)?));
        signers.push(SignerState {
            signer_id,
            mailbox: mailbox.clone(),
            authorization_share: a_shares[offset].to_vec(),
            signing_seed: seed,
            signing_public_key: public,
            membership_proof: vec![],
            policy: SignerPolicy {
                config_id,
                config_version,
                signer_set_commitment: [0; 32],
                signer_threshold: policy.signer_threshold,
            },
            seen_requests: Default::default(),
            seen_nonces: Default::default(),
        });
    }
    let (signer_root, signer_proofs) = merkle_commit(&signer_leaves)?;
    for (signer, proof) in signers.iter_mut().zip(signer_proofs) {
        signer.membership_proof = proof;
        signer.policy.signer_set_commitment = signer_root;
    }

    let payload_nonce = random_nonce();
    let payload = aead_encrypt(
        dek.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid DEK"))?,
        payload_nonce,
        secret,
        &gp_wire::payload_context(&config_id, config_version)?,
    )?;
    let fragments = erasure_encode(
        &payload.ciphertext,
        policy.guardian_threshold,
        policy.guardian_count,
    )?;
    let dek_shares = split_secret(
        &dek,
        policy.guardian_threshold,
        policy.guardian_count,
        random_id(),
    )?;

    let mut raw = Vec::new();
    let mut routes = Vec::new();
    let mut leaves = Vec::new();
    for (offset, mailbox) in guardian_mailboxes.iter().enumerate() {
        let index = u16::try_from(offset + 1)?;
        let mut key = guardian_share_key(
            authorization_key
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid authorization key"))?,
            &config_id,
            config_version,
            index,
        )?;
        let encrypted_share = aead_encrypt(
            &key,
            random_nonce(),
            &dek_shares[offset],
            &gp_wire::guardian_share_context(&config_id, config_version, index)?,
        );
        zeroize_id(&mut key);
        let encrypted_share = encrypted_share?;
        let fragment = fragments[offset].clone();
        leaves.push(sha256(&gp_wire::guardian_leaf(
            &config_id,
            config_version,
            index,
            &sha256(&fragment),
            &hash_aead(&encrypted_share),
        )?));
        let signing_seed = random_id();
        routes.push(GuardianRoute {
            mailbox: mailbox.clone(),
            opaque_slot_id: random_id(),
            guardian_index: index,
            guardian_public_key: verifying_key_bytes(&signing_key(signing_seed)),
        });
        raw.push((index, signing_seed, fragment, encrypted_share));
    }
    let (guardian_root, proofs) = merkle_commit(&leaves)?;
    let mut guardians = Vec::new();
    for (((index, signing_seed, fragment, encrypted_share), route), proof) in
        raw.into_iter().zip(routes.iter()).zip(proofs)
    {
        guardians.push(GuardianProvision {
            mailbox: route.mailbox.clone(),
            guardian_id: index,
            signing_seed,
            record: GuardianRecord {
                opaque_slot_id: route.opaque_slot_id,
                guardian_index: index,
                ciphertext_fragment: fragment,
                encrypted_dek_share: encrypted_share,
                merkle_path_proof: proof,
                policy: GuardianPolicy {
                    config_id,
                    config_version,
                    signer_set_commitment: signer_root,
                    signer_count: policy.signer_count,
                    signer_threshold: policy.signer_threshold,
                    owner_cancel_public_key,
                    minimum_recovery_delay: policy.minimum_recovery_delay,
                    guardian_material_root: guardian_root,
                },
            },
        });
    }

    let descriptor = RecoveryDescriptor {
        guardians: routes.clone(),
        guardian_material_root: guardian_root,
        data_shards: policy.guardian_threshold,
        total_shards: policy.guardian_count,
        ciphertext_len: payload.ciphertext.len() as u64,
        payload_nonce,
    };
    let descriptor_bytes = SecretVec::new(serde_json::to_vec(&descriptor)?);
    let mut descriptor_key_value = descriptor_key(
        &authorization_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid authorization key"))?,
        &config_id,
        config_version,
    )?;
    let encrypted_recovery_descriptor = aead_encrypt(
        &descriptor_key_value,
        random_nonce(),
        &descriptor_bytes,
        &gp_wire::descriptor_context(&config_id, config_version)?,
    );
    zeroize_id(&mut descriptor_key_value);
    let encrypted_recovery_descriptor = encrypted_recovery_descriptor?;
    let capsule = ConfigCapsule {
        protocol_version: PROTOCOL_VERSION,
        crypto_suite: CryptoSuite::default(),
        config_id,
        config_version,
        signer_count: policy.signer_count,
        signer_threshold: policy.signer_threshold,
        guardian_count: policy.guardian_count,
        guardian_threshold: policy.guardian_threshold,
        minimum_recovery_delay: policy.minimum_recovery_delay,
        signer_set_commitment: signer_root,
        owner_cancel_public_key,
        guardian_material_commitment: guardian_root,
        encrypted_recovery_descriptor,
        max_request_lifetime: 7 * 24 * 60 * 60,
    };
    let locator = format!(
        "{}/v1/configs/{}",
        capsule_locator_base.trim_end_matches('/'),
        hex::encode(config_id)
    );
    let card = RecoveryCard {
        config_id,
        capsule_locator: locator,
        signer_mailboxes,
        signer_set_commitment: signer_root,
        owner_cancel_public_key,
    };
    Ok(SetupBundle {
        capsule,
        card,
        signers,
        guardians,
        owner_cancel_signing_seed,
        owner_guardian_routes: routes,
    })
}

pub fn validate_capsule(card: &RecoveryCard, capsule: &ConfigCapsule) -> Result<()> {
    if capsule.protocol_version != PROTOCOL_VERSION
        || capsule.crypto_suite != CryptoSuite::default()
        || capsule.config_id != card.config_id
        || capsule.signer_set_commitment != card.signer_set_commitment
        || capsule.owner_cancel_public_key != card.owner_cancel_public_key
        || capsule.signer_count == 0
        || capsule.signer_threshold == 0
        || capsule.signer_threshold > capsule.signer_count
        || capsule.guardian_count == 0
        || capsule.guardian_threshold == 0
        || capsule.guardian_threshold > capsule.guardian_count
    {
        bail!("Config Capsule does not match the Recovery Card or has invalid thresholds");
    }
    Ok(())
}

pub fn validate_request(
    request: &RecoveryRequest,
    capsule: &ConfigCapsule,
    now: u64,
) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION
        || request.crypto_suite != capsule.crypto_suite
        || request.config_id != capsule.config_id
        || request.config_version != capsule.config_version
        || request.recovery_recipient_key.len() != gp_crypto::XWING_PUBLIC_KEY_LEN
        || request.requested_at > now
        || request.expiry <= now
        || request.expiry
            > request
                .requested_at
                .saturating_add(capsule.max_request_lifetime)
    {
        bail!("invalid, stale, expired, or recipient-mismatched RecoveryRequest");
    }
    Ok(())
}

fn validate_membership(
    signer_id: u16,
    public: &[u8; 32],
    proof: &[u8],
    root: Id32,
    signer_count: u16,
) -> Result<()> {
    if signer_id == 0 || signer_id > signer_count {
        bail!("invalid signer index");
    }
    let leaf = sha256(&gp_wire::signer_leaf(signer_id, public)?);
    merkle_verify(
        root,
        leaf,
        usize::from(signer_id - 1),
        usize::from(signer_count),
        proof,
    )?;
    Ok(())
}

pub fn validate_begin_for_policy(
    certificate: &BeginRecoveryCertificate,
    policy: &GuardianPolicy,
    now: u64,
) -> Result<()> {
    let request = &certificate.request;
    if request.protocol_version != PROTOCOL_VERSION
        || request.config_id != policy.config_id
        || request.config_version != policy.config_version
        || request.recovery_recipient_key.len() != gp_crypto::XWING_PUBLIC_KEY_LEN
        || request.requested_at > now
        || request.expiry <= now
    {
        bail!("guardian rejected RecoveryRequest fields");
    }
    let mut ids = BTreeSet::new();
    for contribution in &certificate.signer_contributions {
        if contribution.request != *request || !ids.insert(contribution.signer_id) {
            bail!("duplicate or request-mismatched signer contribution");
        }
        validate_membership(
            contribution.signer_id,
            &contribution.signer_public_key,
            &contribution.signer_membership_proof,
            policy.signer_set_commitment,
            policy.signer_count,
        )?;
        verify(
            &contribution.signer_public_key,
            &gp_wire::signer_approval(
                request,
                contribution.signer_id,
                &contribution.encrypted_a_share,
            )?,
            &contribution.signer_signature,
        )?;
    }
    if ids.len() < usize::from(policy.signer_threshold) {
        bail!("signer approval threshold not reached");
    }
    Ok(())
}

pub fn reconstruct_a(
    certificate: &BeginRecoveryCertificate,
    capsule: &ConfigCapsule,
    recipient: &RecipientKeyPair,
    now: u64,
) -> Result<SecretVec> {
    validate_request(&certificate.request, capsule, now)?;
    let mut ids = BTreeSet::new();
    let mut shares = Vec::new();
    for contribution in &certificate.signer_contributions {
        if contribution.request != certificate.request || !ids.insert(contribution.signer_id) {
            bail!("duplicate or mismatched signer contribution");
        }
        validate_membership(
            contribution.signer_id,
            &contribution.signer_public_key,
            &contribution.signer_membership_proof,
            capsule.signer_set_commitment,
            capsule.signer_count,
        )?;
        verify(
            &contribution.signer_public_key,
            &gp_wire::signer_approval(
                &certificate.request,
                contribution.signer_id,
                &contribution.encrypted_a_share,
            )?,
            &contribution.signer_signature,
        )?;
        shares.push(
            recipient
                .open(
                    &contribution.encrypted_a_share,
                    &gp_wire::recipient_share_context(
                        &certificate.request,
                        contribution.signer_id,
                    )?,
                )?
                .to_vec(),
        );
    }
    if shares.len() < usize::from(capsule.signer_threshold) {
        bail!("signer threshold not reached");
    }
    Ok(recover_secret(&shares, capsule.signer_threshold)?)
}

pub fn open_descriptor(
    capsule: &ConfigCapsule,
    authorization_key: &[u8],
) -> Result<RecoveryDescriptor> {
    let authorization_key: &[u8; 32] = authorization_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid authorization key"))?;
    let mut key = descriptor_key(
        authorization_key,
        &capsule.config_id,
        capsule.config_version,
    )?;
    let plaintext = aead_decrypt(
        &key,
        &capsule.encrypted_recovery_descriptor,
        &gp_wire::descriptor_context(&capsule.config_id, capsule.config_version)?,
    );
    zeroize_id(&mut key);
    let descriptor: RecoveryDescriptor = serde_json::from_slice(&plaintext?)?;
    if descriptor.guardians.len() != usize::from(capsule.guardian_count)
        || descriptor.guardian_material_root != capsule.guardian_material_commitment
        || descriptor.data_shards != capsule.guardian_threshold
        || descriptor.total_shards != capsule.guardian_count
    {
        bail!("Recovery Descriptor does not match Config Capsule");
    }
    Ok(descriptor)
}

pub fn validate_release_for_policy(
    certificate: &ReleaseCertificate,
    policy: &GuardianPolicy,
    request: &RecoveryRequest,
    now: u64,
) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION
        || request.crypto_suite != CryptoSuite::default()
        || request.config_id != policy.config_id
        || request.config_version != policy.config_version
        || request.recovery_recipient_key.len() != gp_crypto::XWING_PUBLIC_KEY_LEN
        || request.requested_at > now
        || request.expiry <= now
    {
        bail!("release request is stale or expired");
    }
    let digest = sha256(&gp_wire::request_digest_preimage(request)?);
    let mut ids = BTreeSet::new();
    for vote in &certificate.votes {
        if vote.protocol_version != PROTOCOL_VERSION
            || vote.config_id != request.config_id
            || vote.config_version != request.config_version
            || vote.request_id != request.request_id
            || vote.request_digest != digest
            || vote.recovery_recipient_key != request.recovery_recipient_key
            || vote.nonce != request.nonce
            || !ids.insert(vote.signer_id)
        {
            bail!("release vote is not bound to the exact request");
        }
        validate_membership(
            vote.signer_id,
            &vote.signer_public_key,
            &vote.signer_membership_proof,
            policy.signer_set_commitment,
            policy.signer_count,
        )?;
        verify(
            &vote.signer_public_key,
            &gp_wire::release_vote(vote)?,
            &vote.signer_signature,
        )?;
    }
    if ids.len() < usize::from(policy.signer_threshold) {
        bail!("release threshold not reached");
    }
    Ok(())
}

pub fn make_owner_cancel_certificate(
    request: &RecoveryRequest,
    owner_cancel_signing_seed: Id32,
    cancel_response_recipient_key: Vec<u8>,
    reason_code: u16,
    issued_at: u64,
) -> Result<OwnerCancelCertificate> {
    let owner_key = signing_key(owner_cancel_signing_seed);
    let mut certificate = OwnerCancelCertificate {
        protocol_version: PROTOCOL_VERSION,
        config_id: request.config_id,
        config_version: request.config_version,
        request_id: request.request_id,
        request_digest: request_digest(request)?,
        recovery_recipient_key: request.recovery_recipient_key.clone(),
        cancel_response_recipient_key,
        reason_code,
        nonce: request.nonce,
        issued_at,
        owner_cancel_public_key: verifying_key_bytes(&owner_key),
        owner_signature: vec![],
    };
    certificate.owner_signature = sign(&owner_key, &gp_wire::owner_cancel(&certificate)?);
    Ok(certificate)
}

pub fn validate_owner_cancel_for_policy(
    certificate: &OwnerCancelCertificate,
    policy: &GuardianPolicy,
    request: &RecoveryRequest,
    now: u64,
) -> Result<()> {
    if request.protocol_version != PROTOCOL_VERSION
        || request.crypto_suite != CryptoSuite::default()
        || request.config_id != policy.config_id
        || request.config_version != policy.config_version
        || request.recovery_recipient_key.len() != gp_crypto::XWING_PUBLIC_KEY_LEN
        || request.requested_at > now
        || request.expiry <= now
        || certificate.protocol_version != PROTOCOL_VERSION
        || certificate.config_id != request.config_id
        || certificate.config_version != request.config_version
        || certificate.request_id != request.request_id
        || certificate.request_digest != request_digest(request)?
        || certificate.recovery_recipient_key != request.recovery_recipient_key
        || certificate.cancel_response_recipient_key.len() != gp_crypto::XWING_PUBLIC_KEY_LEN
        || certificate.nonce != request.nonce
        || certificate.issued_at < request.requested_at
        || certificate.issued_at > now
        || certificate.issued_at >= request.expiry
        || certificate.owner_cancel_public_key != policy.owner_cancel_public_key
    {
        bail!("owner hard-cancel is stale, malformed, or not bound to the exact request");
    }
    verify(
        &policy.owner_cancel_public_key,
        &gp_wire::owner_cancel(certificate)?,
        &certificate.owner_signature,
    )?;
    Ok(())
}

pub fn validate_owner_cancel_ack(
    ack: &OwnerCancelAck,
    certificate: &OwnerCancelCertificate,
    request: &RecoveryRequest,
    route: &GuardianRoute,
) -> Result<()> {
    if ack.protocol_version != PROTOCOL_VERSION
        || ack.config_id != request.config_id
        || ack.config_version != request.config_version
        || ack.request_id != request.request_id
        || ack.request_digest != request_digest(request)?
        || ack.owner_cancel_transcript_digest != sha256(&gp_wire::owner_cancel(certificate)?)
        || ack.guardian_index != route.guardian_index
    {
        bail!("owner hard-cancel acknowledgement is not bound to the exact request");
    }
    verify(
        &route.guardian_public_key,
        &gp_wire::owner_cancel_ack(ack)?,
        &ack.guardian_signature,
    )?;
    Ok(())
}

pub fn validate_guardian_contribution(
    contribution: &GuardianContribution,
    route: &GuardianRoute,
    descriptor: &RecoveryDescriptor,
    request: &RecoveryRequest,
    authorization_key: &[u8],
) -> Result<Vec<u8>> {
    let digest = sha256(&gp_wire::request_digest_preimage(request)?);
    if contribution.protocol_version != PROTOCOL_VERSION
        || contribution.config_id != request.config_id
        || contribution.config_version != request.config_version
        || contribution.request_id != request.request_id
        || contribution.request_digest != digest
        || contribution.guardian_index != route.guardian_index
    {
        bail!("guardian contribution is not bound to the exact request");
    }
    verify(
        &route.guardian_public_key,
        &gp_wire::guardian_contribution(contribution)?,
        &contribution.guardian_signature,
    )?;
    let leaf = sha256(&gp_wire::guardian_leaf(
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
        &sha256(&contribution.ciphertext_fragment),
        &hash_aead(&contribution.encrypted_dek_share),
    )?);
    merkle_verify(
        descriptor.guardian_material_root,
        leaf,
        usize::from(contribution.guardian_index - 1),
        usize::from(descriptor.total_shards),
        &contribution.merkle_path_proof,
    )?;
    let authorization_key: &[u8; 32] = authorization_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid authorization key"))?;
    let mut key = guardian_share_key(
        authorization_key,
        &contribution.config_id,
        contribution.config_version,
        contribution.guardian_index,
    )?;
    let share = aead_decrypt(
        &key,
        &contribution.encrypted_dek_share,
        &gp_wire::guardian_share_context(
            &contribution.config_id,
            contribution.config_version,
            contribution.guardian_index,
        )?,
    );
    zeroize_id(&mut key);
    Ok(share?.to_vec())
}

pub fn reconstruct_payload(
    capsule: &ConfigCapsule,
    descriptor: &RecoveryDescriptor,
    fragments: &[(u16, Vec<u8>)],
    dek_shares: &[Vec<u8>],
) -> Result<SecretVec> {
    let dek = recover_secret(dek_shares, capsule.guardian_threshold)?;
    let ciphertext = erasure_reconstruct(
        fragments,
        descriptor.data_shards,
        descriptor.total_shards,
        usize::try_from(descriptor.ciphertext_len)?,
    )?;
    let plaintext = aead_decrypt(
        dek.as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid DEK"))?,
        &AeadCiphertext {
            nonce: descriptor.payload_nonce,
            ciphertext,
        },
        &gp_wire::payload_context(&capsule.config_id, capsule.config_version)?,
    )?;
    Ok(plaintext)
}

pub fn sign_guardian_contribution(
    mut contribution: GuardianContribution,
    signing_seed: Id32,
) -> Result<GuardianContribution> {
    contribution.guardian_signature = sign(
        &signing_key(signing_seed),
        &gp_wire::guardian_contribution(&contribution)?,
    );
    Ok(contribution)
}

pub fn request_digest(request: &RecoveryRequest) -> Result<Id32> {
    Ok(sha256(&gp_wire::request_digest_preimage(request)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> SetupBundle {
        create_setup(
            b"network-only plaintext marker",
            &SetupPolicy {
                signer_count: 3,
                signer_threshold: 2,
                guardian_count: 5,
                guardian_threshold: 3,
                minimum_recovery_delay: 5,
            },
            (1..=3)
                .map(|index| format!("http://relay/v1/mailboxes/signer-opaque-{index:032}"))
                .collect(),
            (1..=5)
                .map(|index| format!("http://relay/v1/mailboxes/guardian-opaque-{index:030}"))
                .collect(),
            "http://config-store",
        )
        .unwrap()
    }

    #[test]
    fn distributed_setup_keeps_guardian_roster_off_recovery_card() {
        let bundle = bundle();
        let card_json = serde_json::to_string(&bundle.card).unwrap();
        assert!(!card_json.contains("guardian"));
        assert!(!card_json.contains("signing_seed"));
        assert_eq!(bundle.card.signer_mailboxes.len(), 3);
        assert_eq!(bundle.guardians.len(), 5);
        assert!(
            bundle
                .guardians
                .iter()
                .all(|guardian| guardian.record.policy.signer_count == 3)
        );
        assert!(bundle.guardians.iter().all(|guardian| {
            guardian.record.policy.owner_cancel_public_key == bundle.capsule.owner_cancel_public_key
        }));
    }

    #[test]
    fn guardian_provisioning_does_not_contain_plaintext_secret() {
        let bundle = bundle();
        for guardian in bundle.guardians {
            let bytes = serde_json::to_vec(&guardian).unwrap();
            assert!(
                !bytes
                    .windows(b"network-only plaintext marker".len())
                    .any(|window| window == b"network-only plaintext marker")
            );
        }
    }

    #[test]
    fn only_pinned_owner_key_can_hard_cancel_exact_request() {
        let bundle = bundle();
        let recipient = RecipientKeyPair::from_seed([42; 32]);
        let request = RecoveryRequest {
            protocol_version: PROTOCOL_VERSION,
            crypto_suite: bundle.capsule.crypto_suite,
            config_id: bundle.capsule.config_id,
            config_version: bundle.capsule.config_version,
            request_id: [7; 32],
            recovery_recipient_key: recipient.public_key().to_vec(),
            requested_at: 10,
            nonce: [8; 32],
            expiry: 100,
        };
        let owner_seed: Id32 = bundle
            .owner_cancel_signing_seed
            .as_slice()
            .try_into()
            .unwrap();
        let certificate = make_owner_cancel_certificate(
            &request,
            owner_seed,
            RecipientKeyPair::from_seed([43; 32]).public_key().to_vec(),
            1,
            11,
        )
        .unwrap();
        let policy = &bundle.guardians[0].record.policy;
        validate_owner_cancel_for_policy(&certificate, policy, &request, 11).unwrap();

        let route = &bundle.owner_guardian_routes[0];
        let mut ack = OwnerCancelAck {
            protocol_version: PROTOCOL_VERSION,
            config_id: request.config_id,
            config_version: request.config_version,
            request_id: request.request_id,
            request_digest: request_digest(&request).unwrap(),
            owner_cancel_transcript_digest: sha256(&gp_wire::owner_cancel(&certificate).unwrap()),
            guardian_index: route.guardian_index,
            guardian_signature: vec![],
        };
        ack.guardian_signature = sign(
            &signing_key(bundle.guardians[0].signing_seed),
            &gp_wire::owner_cancel_ack(&ack).unwrap(),
        );
        validate_owner_cancel_ack(&ack, &certificate, &request, route).unwrap();
        ack.guardian_index += 1;
        assert!(validate_owner_cancel_ack(&ack, &certificate, &request, route).is_err());

        let wrong_key = make_owner_cancel_certificate(
            &request,
            [99; 32],
            RecipientKeyPair::from_seed([44; 32]).public_key().to_vec(),
            1,
            11,
        )
        .unwrap();
        assert!(validate_owner_cancel_for_policy(&wrong_key, policy, &request, 11).is_err());

        let mut changed_request = request;
        changed_request.recovery_recipient_key[0] ^= 1;
        assert!(
            validate_owner_cancel_for_policy(&certificate, policy, &changed_request, 11).is_err()
        );
    }
}
