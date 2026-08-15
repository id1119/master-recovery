//! Deterministic multi-epoch guardian-rotation simulator. Virtual actors hold
//! only their own private state and exchange provider-owned FROST messages;
//! the coordinator never receives a DEK share or the DEK.

use std::collections::{BTreeMap, BTreeSet};

use gp_core::{
    EpochRecoveryMachine, EpochReleaseAuthorization, EpochWitnessMachine, RotationAction,
    RotationEvent, RotationMachine,
};
use gp_crypto::{
    EpochFrostShare, RecipientKeyPair, SecretVec, aead_decrypt, aead_encrypt, begin_old_share,
    custody_commit, descriptor_key_v3, erasure_encode, finalize_new_share, frost_dealer_split,
    frost_public_add_repaired_share, frost_public_package_digest, frost_recover_dek_for_epoch,
    frost_refresh_part1, frost_refresh_part2, frost_refresh_part3, frost_repair_part2,
    frost_verify_share, guardian_fragment_key_v3, guardian_share_key_v3, hash_aead, merkle_commit,
    recover_secret, rotate_ciphertext_fragments, seal_to_recipient, sha256, sign, signing_key,
    split_secret, verify, verify_dpss_result, verifying_key_bytes,
};
use gp_storage::{DpssSessionJournal, GuardianEpochStore};
use gp_types::{
    AeadCiphertext, ConfigCapsuleV3, ConfigRef, DpssSuiteId, EpochActivationQc, GuardianEpochState,
    GuardianPolicyV3, GuardianRecordV3, GuardianRouteV3, Id32, NewGuardianPreparedAck,
    OldGuardianHandoffAck, PROTOCOL_VERSION_V3, PreparedRecordLeaf, RecoveryDescriptorV3,
    RecoveryRequestV3, RotationActivateCertificate, RotationContext, RotationIntent, RotationPlan,
    RotationReadyCertificate, RotationReason, SignerRotationActivateVote, SignerRotationBeginVote,
    SignerRotationIntentContribution, SignerRotationReleaseVote, WitnessActivationAck,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

use crate::SimError;

const SIGNER_COUNT: u16 = 3;
const SIGNER_THRESHOLD: u16 = 2;
const WITNESS_FAULT_BOUND: u16 = 1;
const WITNESS_COUNT: u16 = 4;
const GUARDIAN_COUNT: u16 = 8;
const GUARDIAN_THRESHOLD: u16 = 5;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationDemoOptions {
    pub seed: u64,
    pub secret: String,
    pub simulated_delay_secs: u64,
    /// Ordered `(retired operator id, replacement operator id)` transitions.
    pub replacements: Vec<(u16, u16)>,
    pub cancel_rotation_at: Option<usize>,
    pub fail_preparation_at: Option<usize>,
}

impl Default for RotationDemoOptions {
    fn default() -> Self {
        Self {
            seed: 424_242,
            secret: "correct horse battery staple".into(),
            simulated_delay_secs: 5,
            replacements: vec![(4, 9), (2, 10), (7, 11), (5, 12)],
            cancel_rotation_at: None,
            fail_preparation_at: None,
        }
    }
}

impl RotationDemoOptions {
    fn validate(&self) -> Result<(), SimError> {
        if self.secret.is_empty() || self.simulated_delay_secs == 0 {
            return Err(SimError::InvalidOptions(
                "rotation secret and delay must be non-empty/non-zero".into(),
            ));
        }
        let mut current = (1..=GUARDIAN_COUNT).collect::<BTreeSet<_>>();
        for (removed, added) in &self.replacements {
            if !current.remove(removed)
                || *added == 0
                || *added > gp_crypto::FROST_MAX_PARTICIPANTS
                || !current.insert(*added)
            {
                return Err(SimError::InvalidOptions(format!(
                    "invalid sequential replacement G{removed} -> G{added}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationSimEvent {
    pub guardian_epoch: u64,
    pub phase: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationDemoResult {
    pub seed: u64,
    pub success: bool,
    pub cancelled_safely: bool,
    pub preparation_failed_safely: bool,
    pub rotations_requested: usize,
    pub rotations_completed: usize,
    pub initial_guardian_epoch: u64,
    pub final_guardian_epoch: u64,
    pub active_guardians: Vec<u16>,
    pub retired_guardians: Vec<u16>,
    pub dek_commitment_before: String,
    pub dek_commitment_after: String,
    pub dek_preserved: bool,
    pub plaintext_decryptions_during_rotation: u64,
    pub final_recovery_plaintext_decryptions: u64,
    pub early_release_rejected: bool,
    pub owner_cancel_enforced: bool,
    pub final_recovered_secret: Option<String>,
    pub events: Vec<RotationSimEvent>,
    pub security_notice: String,
}

struct SimSigner {
    id: u16,
    signing_seed: Id32,
    public_key: [u8; 32],
    authorization_share: SecretVec,
}

struct RotationWorld {
    rng: ChaCha20Rng,
    authorization_key: Id32,
    signers: Vec<SimSigner>,
    witness_seeds: Vec<Id32>,
    witnesses: Vec<EpochWitnessMachine>,
    stores: BTreeMap<u16, GuardianEpochStore>,
    routes: Vec<GuardianRouteV3>,
    current_ref: ConfigRef,
    current_capsule_hash: Id32,
    current_capsule: ConfigCapsuleV3,
    public_package: Vec<u8>,
    active_ids: Vec<u16>,
    payload_ciphertext: AeadCiphertext,
    ciphertext_len: usize,
    dek_commitment: Id32,
    plaintext_decryptions_during_rotation: u64,
    final_recovery_plaintext_decryptions: u64,
}

type ShareMap = BTreeMap<u16, SecretVec>;

struct RecordBuildInput<'a> {
    authorization_key: &'a Id32,
    config_ref: ConfigRef,
    predecessor_capsule_hash: Id32,
    routes: &'a [GuardianRouteV3],
    shares: &'a ShareMap,
    fragments: &'a [Vec<u8>],
    public_package: &'a [u8],
}

struct BuiltRecords {
    records: BTreeMap<u16, GuardianRecordV3>,
    leaves: BTreeMap<u16, PreparedRecordLeaf>,
    material_root: Id32,
}

struct CapsuleBuildInput<'a> {
    authorization_key: &'a Id32,
    config_ref: ConfigRef,
    predecessor_capsule_hash: Id32,
    routes: &'a [GuardianRouteV3],
    guardian_material_root: Id32,
    ciphertext_len: usize,
    payload_nonce: [u8; 24],
    public_package: &'a [u8],
}

struct OldMaterial {
    shares: ShareMap,
    fragments: Vec<(u16, Vec<u8>)>,
}

struct DpssOutput {
    shares: ShareMap,
    public_package: Vec<u8>,
    result_commitment: Id32,
}

fn random_id(rng: &mut ChaCha20Rng) -> Id32 {
    let mut value = [0_u8; 32];
    rng.fill_bytes(&mut value);
    value
}

fn random_nonce(rng: &mut ChaCha20Rng) -> [u8; 24] {
    let mut value = [0_u8; 24];
    rng.fill_bytes(&mut value);
    value
}

fn array32(value: &[u8]) -> Result<Id32, SimError> {
    value.try_into().map_err(|_| SimError::InvalidCertificate)
}

fn signer_seed(seed: u64, id: u16) -> Id32 {
    let mut value = b"gp/rotation-sim/signer/v3".to_vec();
    value.extend_from_slice(&seed.to_be_bytes());
    value.extend_from_slice(&id.to_be_bytes());
    sha256(&value)
}

fn guardian_seed(id: u16) -> Id32 {
    let mut value = b"gp/rotation-sim/guardian/v3".to_vec();
    value.extend_from_slice(&id.to_be_bytes());
    sha256(&value)
}

fn witness_seed(seed: u64, id: u16) -> Id32 {
    let mut value = b"gp/rotation-sim/witness/v3".to_vec();
    value.extend_from_slice(&seed.to_be_bytes());
    value.extend_from_slice(&id.to_be_bytes());
    sha256(&value)
}

fn make_routes(ids: &[u16], epoch: u64, rng: &mut ChaCha20Rng) -> Vec<GuardianRouteV3> {
    ids.iter()
        .map(|id| {
            let session = RecipientKeyPair::from_seed(random_id(rng));
            GuardianRouteV3 {
                guardian_index: *id,
                opaque_slot_id: random_id(rng),
                mailbox: format!("opaque-e{epoch}-{}", hex::encode(&random_id(rng)[..8])),
                guardian_public_key: verifying_key_bytes(&signing_key(guardian_seed(*id))),
                session_recipient_key: session.public_key().to_vec(),
                operator_domain_commitment: sha256(&id.to_be_bytes()),
            }
        })
        .collect()
}

fn prepared_leaf(record: &GuardianRecordV3) -> Result<PreparedRecordLeaf, SimError> {
    Ok(PreparedRecordLeaf {
        guardian_index: record.guardian_index,
        fragment_index: record.fragment_index,
        opaque_slot_id: record.opaque_slot_id,
        encrypted_share_hash: hash_aead(&record.encrypted_dek_share),
        fragment_hash: hash_aead(&record.encrypted_ciphertext_fragment),
        policy_hash: sha256(&gp_wire::guardian_policy_body_v3(&record.policy)?),
    })
}

fn build_records(
    rng: &mut ChaCha20Rng,
    input: RecordBuildInput<'_>,
) -> Result<BuiltRecords, SimError> {
    let RecordBuildInput {
        authorization_key,
        config_ref,
        predecessor_capsule_hash,
        routes,
        shares,
        fragments,
        public_package,
    } = input;
    if routes.len() != fragments.len() || routes.len() != shares.len() {
        return Err(SimError::Threshold);
    }
    let public_commitment = frost_public_package_digest(public_package)?;
    let mut records = BTreeMap::new();
    for (offset, route) in routes.iter().enumerate() {
        let share = shares
            .get(&route.guardian_index)
            .ok_or(SimError::Threshold)?;
        frost_verify_share(share, public_package)?;
        let fragment_index = u16::try_from(offset + 1).map_err(|_| SimError::Threshold)?;
        let share_context = gp_wire::guardian_share_context_v3(&config_ref, route.guardian_index)?;
        let fragment_context = gp_wire::guardian_fragment_context_v3(
            &config_ref,
            route.guardian_index,
            fragment_index,
        )?;
        let encrypted_dek_share = aead_encrypt(
            &guardian_share_key_v3(authorization_key, &config_ref, route.guardian_index)?,
            random_nonce(rng),
            share,
            &share_context,
        )?;
        let encrypted_ciphertext_fragment = aead_encrypt(
            &guardian_fragment_key_v3(authorization_key, &config_ref, route.guardian_index)?,
            random_nonce(rng),
            &fragments[offset],
            &fragment_context,
        )?;
        let mut custody_bytes = encrypted_dek_share.nonce.to_vec();
        custody_bytes.extend_from_slice(&encrypted_dek_share.ciphertext);
        custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.nonce);
        custody_bytes.extend_from_slice(&encrypted_ciphertext_fragment.ciphertext);
        let custody_root = custody_commit(&custody_bytes)?.root;
        records.insert(
            route.guardian_index,
            GuardianRecordV3 {
                opaque_slot_id: route.opaque_slot_id,
                guardian_index: route.guardian_index,
                fragment_index,
                encrypted_ciphertext_fragment,
                encrypted_dek_share,
                merkle_path_proof: vec![],
                custody_root,
                policy: GuardianPolicyV3 {
                    config_ref,
                    epoch_state: GuardianEpochState::Prepared,
                    signer_set_commitment: [21; 32],
                    signer_count: SIGNER_COUNT,
                    signer_threshold: SIGNER_THRESHOLD,
                    owner_cancel_public_key: [22; 32],
                    minimum_recovery_delay: 24 * 60 * 60,
                    guardian_material_root: [0; 32],
                    dpss_suite: DpssSuiteId::default(),
                    dpss_public_commitment: public_commitment,
                    predecessor_capsule_hash,
                    activation_qc_hash: None,
                    drain_deadline: None,
                },
            },
        );
    }
    let leaves = records
        .values()
        .map(prepared_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let leaf_hashes = leaves
        .iter()
        .map(|leaf| Ok(sha256(&gp_wire::prepared_record_leaf_v3(leaf)?)))
        .collect::<Result<Vec<_>, SimError>>()?;
    let (root, proofs) = merkle_commit(&leaf_hashes)?;
    let mut leaf_map = BTreeMap::new();
    for ((record, leaf), proof) in records.values_mut().zip(leaves).zip(proofs) {
        record.policy.guardian_material_root = root;
        record.merkle_path_proof = proof;
        leaf_map.insert(record.guardian_index, leaf);
    }
    Ok(BuiltRecords {
        records,
        leaves: leaf_map,
        material_root: root,
    })
}

fn build_capsule(
    rng: &mut ChaCha20Rng,
    input: CapsuleBuildInput<'_>,
) -> Result<ConfigCapsuleV3, SimError> {
    let CapsuleBuildInput {
        authorization_key,
        config_ref,
        predecessor_capsule_hash,
        routes,
        guardian_material_root,
        ciphertext_len,
        payload_nonce,
        public_package,
    } = input;
    let descriptor = RecoveryDescriptorV3 {
        config_ref,
        guardians: routes.to_vec(),
        guardian_material_root,
        data_shards: GUARDIAN_THRESHOLD,
        total_shards: GUARDIAN_COUNT,
        ciphertext_len: ciphertext_len as u64,
        payload_nonce,
        dpss_suite: DpssSuiteId::default(),
        dpss_public_package: public_package.to_vec(),
        dpss_public_commitment: frost_public_package_digest(public_package)?,
    };
    let descriptor_plaintext = serde_json::to_vec(&descriptor)?;
    let descriptor_context = gp_wire::descriptor_context_v3(&config_ref)?;
    let encrypted_recovery_descriptor = aead_encrypt(
        &descriptor_key_v3(authorization_key, &config_ref)?,
        random_nonce(rng),
        &descriptor_plaintext,
        &descriptor_context,
    )?;
    let mut capsule = ConfigCapsuleV3 {
        protocol_version: PROTOCOL_VERSION_V3,
        config_ref,
        capsule_hash: [0; 32],
        predecessor_capsule_hash,
        signer_count: SIGNER_COUNT,
        signer_threshold: SIGNER_THRESHOLD,
        guardian_count: GUARDIAN_COUNT,
        guardian_threshold: GUARDIAN_THRESHOLD,
        minimum_recovery_delay: 24 * 60 * 60,
        max_request_lifetime: 7 * 24 * 60 * 60,
        signer_set_commitment: [21; 32],
        owner_cancel_public_key: [22; 32],
        dpss_suite: DpssSuiteId::default(),
        dpss_public_commitment: frost_public_package_digest(public_package)?,
        guardian_material_root,
        encrypted_recovery_descriptor,
        activation_certificate: None,
        activation_qc: None,
    };
    capsule.capsule_hash = sha256(&gp_wire::config_capsule_body_v3(&capsule)?);
    Ok(capsule)
}

fn setup_world(options: &RotationDemoOptions) -> Result<RotationWorld, SimError> {
    let mut rng = ChaCha20Rng::seed_from_u64(options.seed);
    let authorization_key = random_id(&mut rng);
    let authorization_shares = split_secret(
        &authorization_key,
        SIGNER_THRESHOLD,
        SIGNER_COUNT,
        random_id(&mut rng),
    )?;
    let signers = authorization_shares
        .into_iter()
        .enumerate()
        .map(|(offset, share)| {
            let id = u16::try_from(offset + 1).expect("three signers");
            let seed = signer_seed(options.seed, id);
            SimSigner {
                id,
                signing_seed: seed,
                public_key: verifying_key_bytes(&signing_key(seed)),
                authorization_share: share,
            }
        })
        .collect::<Vec<_>>();
    let dealer = frost_dealer_split(GUARDIAN_THRESHOLD, GUARDIAN_COUNT, random_id(&mut rng))?;
    let dek = array32(&dealer.dek)?;
    let config_ref = ConfigRef {
        config_id: random_id(&mut rng),
        payload_generation: 1,
        authorization_epoch: 1,
        guardian_epoch: 1,
        epoch_binding: random_id(&mut rng),
    };
    let payload_context =
        gp_wire::payload_context_v3(&config_ref.config_id, config_ref.payload_generation)?;
    let payload_ciphertext = aead_encrypt(
        &dek,
        random_nonce(&mut rng),
        options.secret.as_bytes(),
        &payload_context,
    )?;
    let ciphertext_len = payload_ciphertext.ciphertext.len();
    let fragments = erasure_encode(
        &payload_ciphertext.ciphertext,
        GUARDIAN_THRESHOLD,
        GUARDIAN_COUNT,
    )?;
    let active_ids = (1..=GUARDIAN_COUNT).collect::<Vec<_>>();
    let routes = make_routes(&active_ids, 1, &mut rng);
    let shares = active_ids
        .iter()
        .copied()
        .zip(dealer.shares)
        .collect::<BTreeMap<_, _>>();
    let BuiltRecords {
        records,
        material_root,
        ..
    } = build_records(
        &mut rng,
        RecordBuildInput {
            authorization_key: &authorization_key,
            config_ref,
            predecessor_capsule_hash: [0; 32],
            routes: &routes,
            shares: &shares,
            fragments: &fragments,
            public_package: &dealer.public_package,
        },
    )?;
    let capsule = build_capsule(
        &mut rng,
        CapsuleBuildInput {
            authorization_key: &authorization_key,
            config_ref,
            predecessor_capsule_hash: [0; 32],
            routes: &routes,
            guardian_material_root: material_root,
            ciphertext_len,
            payload_nonce: payload_ciphertext.nonce,
            public_package: &dealer.public_package,
        },
    )?;
    let stores = records
        .into_iter()
        .map(|(id, record)| (id, GuardianEpochStore::new(record, capsule.capsule_hash)))
        .collect();
    let witness_seeds = (1..=WITNESS_COUNT)
        .map(|id| witness_seed(options.seed, id))
        .collect::<Vec<_>>();
    let witnesses = (1..=WITNESS_COUNT)
        .map(|_| EpochWitnessMachine::new(config_ref.config_id, 1, capsule.capsule_hash))
        .collect();
    Ok(RotationWorld {
        rng,
        authorization_key,
        signers,
        witness_seeds,
        witnesses,
        stores,
        routes,
        current_ref: config_ref,
        current_capsule_hash: capsule.capsule_hash,
        current_capsule: capsule,
        public_package: dealer.public_package,
        active_ids,
        payload_ciphertext,
        ciphertext_len,
        dek_commitment: sha256(&dek),
        plaintext_decryptions_during_rotation: 0,
        final_recovery_plaintext_decryptions: 0,
    })
}

fn context(
    world: &mut RotationWorld,
    rotation_id: Id32,
    recipient_key: Vec<u8>,
) -> RotationContext {
    RotationContext {
        protocol_version: PROTOCOL_VERSION_V3,
        config_ref: world.current_ref,
        rotation_id,
        predecessor_capsule_hash: world.current_capsule_hash,
        recipient_key,
        nonce: random_id(&mut world.rng),
        issued_at: 10,
        expiry: 10_000,
    }
}

fn authorize_intent(
    world: &mut RotationWorld,
    context: &RotationContext,
    removed: u16,
) -> Result<(Id32, Id32), SimError> {
    let intent = RotationIntent {
        context: context.clone(),
        reason: RotationReason::PlannedExit,
        old_guardian_count: GUARDIAN_COUNT,
        old_guardian_threshold: GUARDIAN_THRESHOLD,
        allowed_new_guardian_count: vec![GUARDIAN_COUNT],
        allowed_new_guardian_threshold: vec![GUARDIAN_THRESHOLD],
        allowed_dpss_suites: vec![DpssSuiteId::default()],
        selection_constraints_commitment: sha256(&removed.to_be_bytes()),
        witness_read_qc_hash: sha256(b"fresh-witness-read-qc"),
    };
    let intent_hash = sha256(&gp_wire::rotation_intent(&intent)?);
    let recipient = RecipientKeyPair::from_seed(random_id(&mut world.rng));
    let mut opened = Vec::new();
    for signer in world.signers.iter().take(usize::from(SIGNER_THRESHOLD)) {
        let share_context =
            gp_wire::rotation_intent_share_context_v3(context, &intent_hash, signer.id)?;
        let sealed = seal_to_recipient(
            recipient.public_key(),
            random_id(&mut world.rng),
            random_nonce(&mut world.rng),
            &signer.authorization_share,
            &share_context,
        )?;
        let mut contribution = SignerRotationIntentContribution {
            context: context.clone(),
            intent_hash,
            signer_id: signer.id,
            signer_public_key: signer.public_key,
            signer_membership_proof: vec![],
            encrypted_authorization_share: sealed,
            signer_signature: vec![],
        };
        let transcript = gp_wire::signer_rotation_intent_contribution(&contribution)?;
        contribution.signer_signature = sign(&signing_key(signer.signing_seed), &transcript);
        verify(
            &contribution.signer_public_key,
            &transcript,
            &contribution.signer_signature,
        )?;
        opened.push(recipient.open(&contribution.encrypted_authorization_share, &share_context)?);
    }
    let reconstructed = recover_secret(&opened, SIGNER_THRESHOLD)?;
    let reconstructed = array32(&reconstructed)?;
    if reconstructed != world.authorization_key {
        return Err(SimError::RecoveryMismatch);
    }
    Ok((intent_hash, reconstructed))
}

fn sign_begin_votes(
    world: &RotationWorld,
    context: &RotationContext,
    intent_hash: Id32,
    plan_hash: Id32,
    old_roster_commitment: Id32,
    new_roster_commitment: Id32,
) -> Result<Vec<SignerRotationBeginVote>, SimError> {
    world
        .signers
        .iter()
        .take(usize::from(SIGNER_THRESHOLD))
        .map(|signer| {
            let mut vote = SignerRotationBeginVote {
                context: context.clone(),
                intent_hash,
                plan_hash,
                old_roster_commitment,
                new_roster_commitment,
                signer_id: signer.id,
                signer_public_key: signer.public_key,
                signer_membership_proof: vec![],
                signer_signature: vec![],
            };
            let transcript = gp_wire::signer_rotation_begin_vote(&vote)?;
            vote.signer_signature = sign(&signing_key(signer.signing_seed), &transcript);
            verify(&vote.signer_public_key, &transcript, &vote.signer_signature)?;
            Ok(vote)
        })
        .collect()
}

fn sign_release_votes(
    world: &RotationWorld,
    context: &RotationContext,
    plan_hash: Id32,
    begin_hash: Id32,
) -> Result<Vec<SignerRotationReleaseVote>, SimError> {
    world
        .signers
        .iter()
        .take(usize::from(SIGNER_THRESHOLD))
        .map(|signer| {
            let mut vote = SignerRotationReleaseVote {
                context: context.clone(),
                plan_hash,
                begin_certificate_hash: begin_hash,
                signer_id: signer.id,
                signer_public_key: signer.public_key,
                signer_membership_proof: vec![],
                signer_signature: vec![],
            };
            let transcript = gp_wire::signer_rotation_release_vote(&vote)?;
            vote.signer_signature = sign(&signing_key(signer.signing_seed), &transcript);
            verify(&vote.signer_public_key, &transcript, &vote.signer_signature)?;
            Ok(vote)
        })
        .collect()
}

fn decrypt_old_material(world: &RotationWorld) -> Result<OldMaterial, SimError> {
    let mut shares = BTreeMap::new();
    let mut fragments = Vec::new();
    for id in &world.active_ids {
        let record = world
            .stores
            .get(id)
            .and_then(|store| store.active.as_ref())
            .ok_or(SimError::Threshold)?;
        let share = aead_decrypt(
            &guardian_share_key_v3(&world.authorization_key, &world.current_ref, *id)?,
            &record.encrypted_dek_share,
            &gp_wire::guardian_share_context_v3(&world.current_ref, *id)?,
        )?;
        frost_verify_share(&share, &world.public_package)?;
        let fragment = aead_decrypt(
            &guardian_fragment_key_v3(&world.authorization_key, &world.current_ref, *id)?,
            &record.encrypted_ciphertext_fragment,
            &gp_wire::guardian_fragment_context_v3(&world.current_ref, *id, record.fragment_index)?,
        )?;
        shares.insert(*id, share);
        fragments.push((record.fragment_index, fragment.to_vec()));
    }
    Ok(OldMaterial { shares, fragments })
}

fn dpss_replace_and_refresh(
    world: &mut RotationWorld,
    mut old_shares: BTreeMap<u16, SecretVec>,
    removed: u16,
    added: u16,
    successor_ids: &[u16],
    malicious_helper: bool,
) -> Result<DpssOutput, SimError> {
    let helper_ids = world
        .active_ids
        .iter()
        .copied()
        .filter(|id| *id != removed)
        .take(usize::from(GUARDIAN_THRESHOLD))
        .collect::<Vec<_>>();
    let mut dealer_deltas = Vec::new();
    for helper in &helper_ids {
        dealer_deltas.push(begin_old_share(
            old_shares.get(helper).ok_or(SimError::Threshold)?,
            &helper_ids,
            added,
            random_id(&mut world.rng),
        )?);
    }
    if malicious_helper
        && let Some((_, payload)) = dealer_deltas
            .first_mut()
            .and_then(|messages| messages.first_mut())
    {
        // Empty provider bytes are deterministically rejected by the adapter;
        // no malformed value is allowed to enter interpolation/refresh.
        payload.clear();
    }
    let sigmas = helper_ids
        .iter()
        .map(|recipient| {
            let incoming = dealer_deltas
                .iter()
                .map(|dealer| {
                    dealer
                        .iter()
                        .find(|(target, _)| target == recipient)
                        .map(|(_, payload)| payload.as_slice())
                        .ok_or(SimError::Threshold)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(frost_repair_part2(&incoming)?)
        })
        .collect::<Result<Vec<_>, SimError>>()?;
    let repaired = finalize_new_share(
        &sigmas.iter().map(AsRef::as_ref).collect::<Vec<_>>(),
        added,
        &world.public_package,
    )?;
    old_shares.remove(&removed).ok_or(SimError::Threshold)?;
    old_shares.insert(added, repaired.clone());
    let expanded_public = frost_public_add_repaired_share(&world.public_package, &repaired)?;

    let mut round1 = BTreeMap::new();
    for id in successor_ids {
        round1.insert(
            *id,
            frost_refresh_part1(
                *id,
                GUARDIAN_THRESHOLD,
                GUARDIAN_COUNT,
                random_id(&mut world.rng),
            )?,
        );
    }
    let mut round2 = BTreeMap::new();
    for id in successor_ids {
        let incoming = round1
            .iter()
            .filter(|(sender, _)| *sender != id)
            .map(|(sender, message)| (*sender, message.broadcast.clone()))
            .collect::<Vec<_>>();
        round2.insert(
            *id,
            frost_refresh_part2(&round1[id].secret_state, &incoming)?,
        );
    }
    let mut refreshed = BTreeMap::new();
    let mut public_packages = Vec::new();
    for id in successor_ids {
        let incoming_round1 = round1
            .iter()
            .filter(|(sender, _)| *sender != id)
            .map(|(sender, message)| (*sender, message.broadcast.clone()))
            .collect::<Vec<_>>();
        let incoming_round2 = round2
            .iter()
            .filter(|(sender, _)| *sender != id)
            .map(|(sender, message)| {
                let payload = message
                    .direct_messages
                    .iter()
                    .find(|(recipient, _)| recipient == id)
                    .map(|(_, payload)| payload.clone())
                    .ok_or(SimError::Threshold)?;
                Ok((*sender, payload))
            })
            .collect::<Result<Vec<_>, SimError>>()?;
        let output = frost_refresh_part3(
            &round2[id].secret_state,
            &incoming_round1,
            &incoming_round2,
            &expanded_public,
            old_shares.get(id).ok_or(SimError::Threshold)?,
        )?;
        public_packages.push(output.public_package.clone());
        refreshed.insert(*id, output.share);
    }
    let public_package = public_packages
        .first()
        .cloned()
        .ok_or(SimError::Threshold)?;
    let share_bytes = refreshed
        .values()
        .map(|share| share.to_vec())
        .collect::<Vec<_>>();
    let result_commitment = verify_dpss_result(
        &world.public_package,
        &public_packages,
        &share_bytes,
        successor_ids,
    )?;
    Ok(DpssOutput {
        shares: refreshed,
        public_package,
        result_commitment,
    })
}

fn rotate_once(
    world: &mut RotationWorld,
    options: &RotationDemoOptions,
    ordinal: usize,
    removed: u16,
    added: u16,
    events: &mut Vec<RotationSimEvent>,
) -> Result<(bool, bool), SimError> {
    let rotation_id = random_id(&mut world.rng);
    let recipient = RecipientKeyPair::from_seed(random_id(&mut world.rng));
    let rotation_context = context(world, rotation_id, recipient.public_key().to_vec());
    let (intent_hash, reconstructed_a) = authorize_intent(world, &rotation_context, removed)?;
    if reconstructed_a != world.authorization_key {
        return Err(SimError::RecoveryMismatch);
    }
    events.push(RotationSimEvent {
        guardian_epoch: world.current_ref.guardian_epoch,
        phase: "INTENT".into(),
        message: format!(
            "{} of {} signers opened the private predecessor descriptor for G{removed} -> G{added}; coordinator obtained A but no DEK share.",
            SIGNER_THRESHOLD, SIGNER_COUNT
        ),
    });

    let mut successor_ids = world
        .active_ids
        .iter()
        .copied()
        .filter(|id| *id != removed)
        .collect::<Vec<_>>();
    successor_ids.push(added);
    successor_ids.sort_unstable();
    let successor_ref = ConfigRef {
        guardian_epoch: world.current_ref.guardian_epoch + 1,
        epoch_binding: random_id(&mut world.rng),
        ..world.current_ref
    };
    let successor_routes =
        make_routes(&successor_ids, successor_ref.guardian_epoch, &mut world.rng);
    let old_roster_commitment = sha256(&gp_wire::guardian_roster_v3(&world.routes)?);
    let new_roster_commitment = sha256(&gp_wire::guardian_roster_v3(&successor_routes)?);
    let plan = RotationPlan {
        context: rotation_context.clone(),
        intent_hash,
        predecessor: world.current_ref,
        successor: successor_ref,
        old_roster: world.routes.clone(),
        new_roster: successor_routes.clone(),
        old_roster_commitment,
        new_roster_commitment,
        old_guardian_threshold: GUARDIAN_THRESHOLD,
        new_guardian_threshold: GUARDIAN_THRESHOLD,
        data_shards: GUARDIAN_THRESHOLD,
        total_shards: GUARDIAN_COUNT,
        dpss_suite: DpssSuiteId::default(),
        dpss_session_id: random_id(&mut world.rng),
        dpss_qualified_set_commitment: sha256(b"qualified-successor-set"),
        minimum_delay_secs: options.simulated_delay_secs,
        preparation_deadline: 20_000,
        drain_deadline: 30_000,
    };
    let plan_hash = sha256(&gp_wire::rotation_plan(&plan)?);
    let mut machine =
        RotationMachine::new(rotation_id, plan_hash, world.current_ref, successor_ref)?;
    let begin_votes = sign_begin_votes(
        world,
        &rotation_context,
        intent_hash,
        plan_hash,
        old_roster_commitment,
        new_roster_commitment,
    )?;
    let begin_certificate = gp_types::BeginRotationCertificate {
        context: rotation_context.clone(),
        intent_hash,
        plan_hash,
        old_roster_commitment,
        new_roster_commitment,
        not_before_wall: 100 + options.simulated_delay_secs,
        votes: begin_votes,
    };
    let begin_hash = sha256(&gp_wire::begin_rotation_certificate(&begin_certificate)?);
    machine.apply(RotationEvent::BeginAccepted {
        monotonic_now: 100,
        delay_secs: options.simulated_delay_secs,
        certificate_valid: true,
    })?;

    if options.cancel_rotation_at == Some(ordinal) {
        let actions = machine.apply(RotationEvent::OwnerCancelObserved {
            certificate_valid: true,
        })?;
        if actions != vec![RotationAction::AbortAndErasePreparedState] {
            return Err(SimError::InvalidCertificate);
        }
        events.push(RotationSimEvent {
            guardian_epoch: world.current_ref.guardian_epoch,
            phase: "ABORTED".into(),
            message: "Owner hard-cancel tombstone persisted; predecessor remains ACTIVE.".into(),
        });
        return Ok((true, false));
    }

    let release_votes = sign_release_votes(world, &rotation_context, plan_hash, begin_hash)?;
    let release_certificate = gp_types::RotationReleaseCertificate {
        context: rotation_context.clone(),
        plan_hash,
        begin_certificate_hash: begin_hash,
        votes: release_votes,
    };
    let release_hash = sha256(&gp_wire::rotation_release_certificate(
        &release_certificate,
    )?);
    machine.apply(RotationEvent::ReleaseAccepted {
        monotonic_now: 100 + options.simulated_delay_secs,
        certificate_valid: true,
        state_unambiguous: true,
    })?;
    events.push(RotationSimEvent {
        guardian_epoch: world.current_ref.guardian_epoch,
        phase: "RELEASE".into(),
        message: format!(
            "Begin -> {}s delay -> Release completed; old epoch remains ACTIVE.",
            options.simulated_delay_secs
        ),
    });

    let OldMaterial {
        shares: old_shares,
        fragments: old_fragments,
    } = decrypt_old_material(world)?;
    let repaired_fragments = rotate_ciphertext_fragments(
        &old_fragments[..usize::from(GUARDIAN_THRESHOLD)],
        GUARDIAN_THRESHOLD,
        GUARDIAN_COUNT,
        world.ciphertext_len,
        GUARDIAN_THRESHOLD,
        GUARDIAN_COUNT,
    )?;
    let malicious = options.fail_preparation_at == Some(ordinal);
    let dpss =
        dpss_replace_and_refresh(world, old_shares, removed, added, &successor_ids, malicious);
    let DpssOutput {
        shares: new_shares,
        public_package: new_public,
        result_commitment: dpss_result_commitment,
    } = match dpss {
        Ok(output) => output,
        Err(_) if malicious => {
            machine.apply(RotationEvent::AbortObserved {
                certificate_valid: true,
            })?;
            events.push(RotationSimEvent {
                guardian_epoch: world.current_ref.guardian_epoch,
                phase: "ABORTED".into(),
                message: "Invalid FROST provider message rejected; no successor record activated."
                    .into(),
            });
            return Ok((false, true));
        }
        Err(error) => return Err(error),
    };
    let BuiltRecords {
        mut records,
        leaves: prepared_leaves,
        material_root,
    } = build_records(
        &mut world.rng,
        RecordBuildInput {
            authorization_key: &world.authorization_key,
            config_ref: successor_ref,
            predecessor_capsule_hash: world.current_capsule_hash,
            routes: &successor_routes,
            shares: &new_shares,
            fragments: &repaired_fragments,
            public_package: &new_public,
        },
    )?;
    let mut successor_capsule = build_capsule(
        &mut world.rng,
        CapsuleBuildInput {
            authorization_key: &world.authorization_key,
            config_ref: successor_ref,
            predecessor_capsule_hash: world.current_capsule_hash,
            routes: &successor_routes,
            guardian_material_root: material_root,
            ciphertext_len: world.ciphertext_len,
            payload_nonce: world.payload_ciphertext.nonce,
            public_package: &new_public,
        },
    )?;

    let mut prepared_acks = Vec::new();
    for id in &successor_ids {
        if !world.stores.contains_key(id) {
            world.stores.insert(
                *id,
                GuardianEpochStore::new_candidate(world.current_ref, world.current_capsule_hash),
            );
        }
        let record = records.remove(id).ok_or(SimError::Threshold)?;
        let journal = DpssSessionJournal {
            rotation_id,
            plan_hash,
            session_id: plan.dpss_session_id,
            qualified_set_digest: plan.dpss_qualified_set_commitment,
            phase: 6,
            next_sequence: 1,
            provider_public_journal: dpss_result_commitment.to_vec(),
            encrypted_provider_secret_journal: AeadCiphertext {
                nonce: [0_u8; 24],
                ciphertext: vec![0_u8; 48],
            },
        };
        let generation = world
            .stores
            .get_mut(id)
            .ok_or(SimError::Threshold)?
            .transaction(false, |store| {
                store.prepare_successor(rotation_id, plan_hash, record, journal)
            })?;
        let mut ack = NewGuardianPreparedAck {
            context: rotation_context.clone(),
            plan_hash,
            dpss_result_commitment,
            new_guardian_index: *id,
            prepared_record_leaf: prepared_leaves[id].clone(),
            durable_write_generation: generation,
            guardian_signature: vec![],
        };
        let transcript = gp_wire::new_guardian_prepared_ack(&ack)?;
        ack.guardian_signature = sign(&signing_key(guardian_seed(*id)), &transcript);
        verify(
            &successor_routes
                .iter()
                .find(|route| route.guardian_index == *id)
                .ok_or(SimError::Threshold)?
                .guardian_public_key,
            &transcript,
            &ack.guardian_signature,
        )?;
        prepared_acks.push(ack);
    }
    if !records.is_empty() || prepared_acks.len() != usize::from(GUARDIAN_COUNT) {
        return Err(SimError::Threshold);
    }
    machine.apply(RotationEvent::PreparationComplete {
        prepared_count: GUARDIAN_COUNT,
        expected_count: GUARDIAN_COUNT,
        dpss_result_valid: true,
        fragments_valid: true,
    })?;

    let mut handoff_acks = Vec::new();
    for id in &world.active_ids {
        let mut ack = OldGuardianHandoffAck {
            context: rotation_context.clone(),
            plan_hash,
            dpss_result_commitment,
            qualified_set_commitment: plan.dpss_qualified_set_commitment,
            old_guardian_index: *id,
            guardian_signature: vec![],
        };
        let transcript = gp_wire::old_guardian_handoff_ack(&ack)?;
        ack.guardian_signature = sign(&signing_key(guardian_seed(*id)), &transcript);
        verify(
            &world
                .routes
                .iter()
                .find(|route| route.guardian_index == *id)
                .ok_or(SimError::Threshold)?
                .guardian_public_key,
            &transcript,
            &ack.guardian_signature,
        )?;
        handoff_acks.push(ack);
    }
    let ready = RotationReadyCertificate {
        context: rotation_context.clone(),
        plan_hash,
        successor: successor_ref,
        dpss_result_commitment,
        guardian_material_root: material_root,
        encrypted_descriptor_hash: hash_aead(&successor_capsule.encrypted_recovery_descriptor),
        prepared_acks,
        old_handoff_acks: handoff_acks,
    };
    let ready_hash = sha256(&gp_wire::rotation_ready_certificate(&ready)?);
    let mut activate_votes = Vec::new();
    for signer in world.signers.iter().take(usize::from(SIGNER_THRESHOLD)) {
        let mut vote = SignerRotationActivateVote {
            context: rotation_context.clone(),
            plan_hash,
            ready_certificate_hash: ready_hash,
            successor_capsule_hash: successor_capsule.capsule_hash,
            signer_id: signer.id,
            signer_public_key: signer.public_key,
            signer_membership_proof: vec![],
            signer_signature: vec![],
        };
        let transcript = gp_wire::signer_rotation_activate_vote(&vote)?;
        vote.signer_signature = sign(&signing_key(signer.signing_seed), &transcript);
        verify(&vote.signer_public_key, &transcript, &vote.signer_signature)?;
        activate_votes.push(vote);
    }
    let activate = RotationActivateCertificate {
        context: rotation_context.clone(),
        plan_hash,
        ready_certificate_hash: ready_hash,
        successor: successor_ref,
        successor_capsule_hash: successor_capsule.capsule_hash,
        votes: activate_votes,
    };
    let activation_hash = sha256(&gp_wire::rotation_activate_certificate(&activate)?);
    machine.apply(RotationEvent::ActivationAuthorized {
        certificate_valid: true,
        exact_capsule: true,
    })?;

    let mut witness_acks = Vec::new();
    for (offset, witness) in world.witnesses.iter_mut().enumerate() {
        witness.accept_successor(
            world.current_ref,
            world.current_capsule_hash,
            successor_ref,
            successor_capsule.capsule_hash,
            true,
        )?;
        let witness_id = u16::try_from(offset + 1).expect("four witnesses");
        let witness_key = signing_key(world.witness_seeds[offset]);
        let mut ack = WitnessActivationAck {
            context: rotation_context.clone(),
            plan_hash,
            activation_certificate_hash: activation_hash,
            witness_id,
            predecessor_epoch: world.current_ref.guardian_epoch,
            predecessor_capsule_hash: world.current_capsule_hash,
            successor_epoch: successor_ref.guardian_epoch,
            successor_capsule_hash: successor_capsule.capsule_hash,
            witness_public_key: verifying_key_bytes(&witness_key),
            witness_signature: vec![],
        };
        let transcript = gp_wire::witness_activation_ack(&ack)?;
        ack.witness_signature = sign(&witness_key, &transcript);
        verify(&ack.witness_public_key, &transcript, &ack.witness_signature)?;
        witness_acks.push(ack);
    }
    witness_acks.truncate(usize::from(WITNESS_FAULT_BOUND * 2 + 1));
    let qc = EpochActivationQc {
        protocol_version: PROTOCOL_VERSION_V3,
        config_id: world.current_ref.config_id,
        rotation_id,
        predecessor_epoch: world.current_ref.guardian_epoch,
        predecessor_capsule_hash: world.current_capsule_hash,
        successor_epoch: successor_ref.guardian_epoch,
        successor_capsule_hash: successor_capsule.capsule_hash,
        activation_certificate_hash: activation_hash,
        witness_fault_bound: WITNESS_FAULT_BOUND,
        witness_acks,
    };
    let qc_hash = sha256(&gp_wire::epoch_activation_qc(&qc)?);
    let drain_deadline = 40_000 + ordinal as u64;
    machine.apply(RotationEvent::WitnessQcObserved {
        qc_valid: true,
        exact_successor: true,
        drain_deadline,
    })?;
    successor_capsule.activation_certificate = Some(activate);
    successor_capsule.activation_qc = Some(qc.clone());
    if successor_capsule.capsule_hash
        != sha256(&gp_wire::config_capsule_body_v3(&successor_capsule)?)
    {
        return Err(SimError::InvalidCertificate);
    }

    for id in &successor_ids {
        world
            .stores
            .get_mut(id)
            .ok_or(SimError::Threshold)?
            .transaction(false, |store| {
                store.activate_successor(
                    rotation_id,
                    plan_hash,
                    qc.clone(),
                    qc_hash,
                    drain_deadline,
                    BTreeSet::new(),
                )
            })?;
    }
    world
        .stores
        .get_mut(&removed)
        .ok_or(SimError::Threshold)?
        .transaction(false, |store| {
            store.observe_replacement_activation(
                rotation_id,
                plan_hash,
                qc.clone(),
                qc_hash,
                drain_deadline,
                BTreeSet::new(),
            )
        })?;
    machine.apply(RotationEvent::DrainStarted)?;
    for id in &world.active_ids {
        world
            .stores
            .get_mut(id)
            .ok_or(SimError::Threshold)?
            .transaction(false, |store| {
                store.retire_epoch(world.current_ref.guardian_epoch, drain_deadline)
            })?;
    }
    machine.apply(RotationEvent::DrainDeadlineReached {
        monotonic_now: drain_deadline,
    })?;
    events.push(RotationSimEvent {
        guardian_epoch: successor_ref.guardian_epoch,
        phase: "ACTIVE".into(),
        message: format!(
            "G{removed} retired; G{added} active after 8/8 durable records and a 3-of-4 witness QC."
        ),
    });
    world.current_ref = successor_ref;
    world.current_capsule_hash = successor_capsule.capsule_hash;
    world.current_capsule = successor_capsule;
    world.public_package = new_public;
    world.active_ids = successor_ids;
    world.routes = successor_routes;
    let _ = release_hash;
    Ok((false, false))
}

fn final_recovery(
    world: &mut RotationWorld,
    options: &RotationDemoOptions,
) -> Result<(String, bool, bool, Id32), SimError> {
    let cancelled_request = RecoveryRequestV3 {
        protocol_version: PROTOCOL_VERSION_V3,
        config_ref: world.current_ref,
        request_id: random_id(&mut world.rng),
        recovery_recipient_key: RecipientKeyPair::from_seed(random_id(&mut world.rng))
            .public_key()
            .to_vec(),
        requested_at: 100,
        nonce: random_id(&mut world.rng),
        expiry: 1_000,
    };
    let cancelled_digest = sha256(&gp_wire::recovery_request_v3(&cancelled_request)?);
    let mut recovery = EpochRecoveryMachine::new(world.current_ref);
    recovery.begin(
        &cancelled_request,
        cancelled_digest,
        100,
        100,
        options.simulated_delay_secs,
        true,
    )?;
    recovery.cancel(cancelled_request.request_id, cancelled_digest, true)?;
    let owner_cancel_enforced = recovery
        .authorize_release(EpochReleaseAuthorization {
            request_id: cancelled_request.request_id,
            request_digest: cancelled_digest,
            config_ref: world.current_ref,
            wall_now: 200,
            monotonic_now: 200,
            certificate_valid: true,
            state_unambiguous: true,
        })
        .is_err();

    let request = RecoveryRequestV3 {
        protocol_version: PROTOCOL_VERSION_V3,
        config_ref: world.current_ref,
        request_id: random_id(&mut world.rng),
        recovery_recipient_key: RecipientKeyPair::from_seed(random_id(&mut world.rng))
            .public_key()
            .to_vec(),
        requested_at: 300,
        nonce: random_id(&mut world.rng),
        expiry: 2_000,
    };
    let digest = sha256(&gp_wire::recovery_request_v3(&request)?);
    let not_before = recovery.begin(
        &request,
        digest,
        300,
        300,
        options.simulated_delay_secs,
        true,
    )?;
    let early_release_rejected = recovery
        .authorize_release(EpochReleaseAuthorization {
            request_id: request.request_id,
            request_digest: digest,
            config_ref: world.current_ref,
            wall_now: 301,
            monotonic_now: not_before - 1,
            certificate_valid: true,
            state_unambiguous: true,
        })
        .is_err();
    recovery.authorize_release(EpochReleaseAuthorization {
        request_id: request.request_id,
        request_digest: digest,
        config_ref: world.current_ref,
        wall_now: 400,
        monotonic_now: not_before,
        certificate_valid: true,
        state_unambiguous: true,
    })?;

    let mut shares = Vec::new();
    let mut fragments = Vec::new();
    for id in world
        .active_ids
        .iter()
        .take(usize::from(GUARDIAN_THRESHOLD))
    {
        let record = world
            .stores
            .get(id)
            .and_then(|store| store.active.as_ref())
            .ok_or(SimError::Threshold)?;
        shares.push(aead_decrypt(
            &guardian_share_key_v3(&world.authorization_key, &world.current_ref, *id)?,
            &record.encrypted_dek_share,
            &gp_wire::guardian_share_context_v3(&world.current_ref, *id)?,
        )?);
        fragments.push((
            record.fragment_index,
            aead_decrypt(
                &guardian_fragment_key_v3(&world.authorization_key, &world.current_ref, *id)?,
                &record.encrypted_ciphertext_fragment,
                &gp_wire::guardian_fragment_context_v3(
                    &world.current_ref,
                    *id,
                    record.fragment_index,
                )?,
            )?
            .to_vec(),
        ));
    }
    let epoch_shares = shares
        .into_iter()
        .map(|encoded_share| EpochFrostShare {
            config_ref: world.current_ref,
            encoded_share,
        })
        .collect::<Vec<_>>();
    let dek = frost_recover_dek_for_epoch(&epoch_shares, &world.current_ref, GUARDIAN_THRESHOLD)?;
    let dek_commitment = sha256(&dek);
    let ciphertext = gp_crypto::erasure_reconstruct(
        &fragments,
        GUARDIAN_THRESHOLD,
        GUARDIAN_COUNT,
        world.ciphertext_len,
    )?;
    if ciphertext != world.payload_ciphertext.ciphertext {
        return Err(SimError::RecoveryMismatch);
    }
    let payload = aead_decrypt(
        &array32(&dek)?,
        &world.payload_ciphertext,
        &gp_wire::payload_context_v3(
            &world.current_ref.config_id,
            world.current_ref.payload_generation,
        )?,
    )?;
    world.final_recovery_plaintext_decryptions += 1;
    let recovered = String::from_utf8(payload.to_vec()).map_err(|_| SimError::RecoveryMismatch)?;
    Ok((
        recovered,
        early_release_rejected,
        owner_cancel_enforced,
        dek_commitment,
    ))
}

pub fn run_rotation_demo(options: &RotationDemoOptions) -> Result<RotationDemoResult, SimError> {
    options.validate()?;
    let mut world = setup_world(options)?;
    let initial_dek_commitment = world.dek_commitment;
    let initial_epoch = world.current_ref.guardian_epoch;
    let mut events = vec![RotationSimEvent {
        guardian_epoch: initial_epoch,
        phase: "SETUP".into(),
        message: "Protocol-v3 5-of-8 FROST sharing and encrypted fragment epoch is ACTIVE.".into(),
    }];
    let mut completed = 0;
    let mut retired = Vec::new();
    let mut cancelled_safely = false;
    let mut preparation_failed_safely = false;
    for (ordinal, (removed, added)) in options.replacements.iter().copied().enumerate() {
        let predecessor_ref = world.current_ref;
        let predecessor_hash = world.current_capsule_hash;
        let (cancelled, failed) =
            rotate_once(&mut world, options, ordinal, removed, added, &mut events)?;
        if cancelled || failed {
            if world.current_ref != predecessor_ref
                || world.current_capsule_hash != predecessor_hash
            {
                return Err(SimError::RecoveryMismatch);
            }
            cancelled_safely |= cancelled;
            preparation_failed_safely |= failed;
            break;
        }
        completed += 1;
        retired.push(removed);
    }

    let (recovered, early_release_rejected, owner_cancel_enforced, final_dek_commitment) =
        final_recovery(&mut world, options)?;
    let dek_preserved = initial_dek_commitment == final_dek_commitment;
    let success = recovered == options.secret
        && dek_preserved
        && world.plaintext_decryptions_during_rotation == 0
        && early_release_rejected
        && owner_cancel_enforced;
    Ok(RotationDemoResult {
        seed: options.seed,
        success,
        cancelled_safely,
        preparation_failed_safely,
        rotations_requested: options.replacements.len(),
        rotations_completed: completed,
        initial_guardian_epoch: initial_epoch,
        final_guardian_epoch: world.current_ref.guardian_epoch,
        active_guardians: world.active_ids,
        retired_guardians: retired,
        dek_commitment_before: hex::encode(initial_dek_commitment),
        dek_commitment_after: hex::encode(final_dek_commitment),
        dek_preserved,
        plaintext_decryptions_during_rotation: world.plaintext_decryptions_during_rotation,
        final_recovery_plaintext_decryptions: world.final_recovery_plaintext_decryptions,
        early_release_rejected,
        owner_cancel_enforced,
        final_recovered_secret: Some(recovered),
        events,
        security_notice: "ZF FROST Ristretto255 RTS + full successor refresh is classical; its refresh integration requires an external audit. Rotation assumes secure erasure and no complete threshold compromise within any epoch.".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_g4_g2_g7_g5_replacements_preserve_recovery_without_rotation_plaintext() {
        let result = run_rotation_demo(&RotationDemoOptions::default()).unwrap();
        assert!(result.success);
        assert_eq!(result.rotations_completed, 4);
        assert_eq!(result.final_guardian_epoch, 5);
        assert_eq!(result.retired_guardians, [4, 2, 7, 5]);
        assert!(result.active_guardians.contains(&9));
        assert!(result.active_guardians.contains(&10));
        assert!(result.active_guardians.contains(&11));
        assert!(result.active_guardians.contains(&12));
        assert_eq!(result.plaintext_decryptions_during_rotation, 0);
        assert_eq!(
            result.final_recovered_secret.as_deref(),
            Some("correct horse battery staple")
        );
    }

    #[test]
    fn owner_cancel_before_release_keeps_predecessor_active_and_recoverable() {
        let options = RotationDemoOptions {
            cancel_rotation_at: Some(0),
            ..RotationDemoOptions::default()
        };
        let result = run_rotation_demo(&options).unwrap();
        assert!(result.success);
        assert!(result.cancelled_safely);
        assert_eq!(result.rotations_completed, 0);
        assert_eq!(result.final_guardian_epoch, 1);
    }

    #[test]
    fn malicious_rts_message_aborts_before_any_activation() {
        let options = RotationDemoOptions {
            fail_preparation_at: Some(0),
            ..RotationDemoOptions::default()
        };
        let result = run_rotation_demo(&options).unwrap();
        assert!(result.success);
        assert!(result.preparation_failed_safely);
        assert_eq!(result.rotations_completed, 0);
        assert_eq!(result.final_guardian_epoch, 1);
    }

    #[test]
    fn seeded_multi_epoch_trace_is_deterministic() {
        let first = run_rotation_demo(&RotationDemoOptions::default()).unwrap();
        let second = run_rotation_demo(&RotationDemoOptions::default()).unwrap();
        assert_eq!(first, second);
    }
}
