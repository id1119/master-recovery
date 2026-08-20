//! Field-omission property tests for every canonical transcript builder.
//!
//! For each builder we construct a structurally valid message from random
//! field values, compute the canonical transcript, then mutate exactly one
//! field at a time: the transcript must change whenever the builder still
//! accepts the mutated value. Fields that the builder deliberately excludes
//! from the domain-separated preimage (the signature being signed,
//! self-referential hashes, mutable lifecycle state) must leave the transcript
//! byte-identical.
//!
//! A mutation that trips a builder-side validity check (returning
//! `InvalidValue`/`DuplicateActor`) is accepted as evidence that the field is
//! meaningful, mirroring `every_critical_plan_field_is_bound` in rotation.rs.
//! Single-variant enums (`CryptoSuite`, `DpssSuiteId`) have no alternate value
//! to mutate and are skipped.

use gp_types::*;
use gp_wire::WireError;
use proptest::prelude::*;

fn id32() -> impl Strategy<Value = Id32> {
    prop::array::uniform32(any::<u8>())
}

fn nonce24() -> impl Strategy<Value = [u8; 24]> {
    prop::array::uniform24(any::<u8>())
}

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=128)
}

fn string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 1..=32)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// Asserts that every mutation block either changes the canonical transcript
/// or is rejected by the builder. Blocks run on a clone named `$mutant`;
/// `$base` must be a reference to the unmutated value.
macro_rules! assert_bound {
    ($mutant:ident, $build:expr, $base:expr, $( { $($mutate:tt)* } ),* $(,)?) => {
        let base_bytes = $build($base).unwrap();
        $(
            let mut $mutant = $base.clone();
            $($mutate)*
            assert_ne!($mutant, *$base, "mutation must change the value");
            match $build(&$mutant) {
                Ok(bytes) => assert_ne!(base_bytes, bytes, "field mutation must change the transcript"),
                Err(WireError::InvalidValue) | Err(WireError::DuplicateActor) => {}
                Err(other) => panic!("unexpected builder error after field mutation: {other:?}"),
            }
        )*
    };
}

/// Asserts that mutations of deliberately excluded fields leave the transcript
/// byte-identical and keep the builder accepting the value.
macro_rules! assert_excluded {
    ($mutant:ident, $build:expr, $base:expr, $( { $($mutate:tt)* } ),* $(,)?) => {
        let base_bytes = $build($base).unwrap();
        $(
            let mut $mutant = $base.clone();
            $($mutate)*
            assert_ne!($mutant, *$base, "mutation must change the value");
            let bytes = $build(&$mutant)
                .unwrap_or_else(|err| panic!("excluded-field mutation must keep the value valid: {err:?}"));
            assert_eq!(base_bytes, bytes, "excluded field must not be bound into the transcript");
        )*
    };
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn protocol_v2_request_transcripts_bind_every_field(
        config_id in id32(),
        request_id in id32(),
        nonce in id32(),
        digest in id32(),
        public_key in id32(),
        fragment_hash in id32(),
        share_hash in id32(),
        recipient in bytes(),
        cancel_recipient in bytes(),
        kem in bytes(),
        nonce24 in nonce24(),
        ciphertext in bytes(),
        fragment in bytes(),
        merkle_proof in bytes(),
        membership in bytes(),
        signature in bytes(),
        node_id in string(),
        role in string(),
        mailbox in string(),
        direction in string(),
        signer_id in 1_u16..=100,
        signer_index in 1_u16..=100,
        protocol_version in 1_u16..=10,
        config_version in 1_u64..=1000,
        requested_at in 0_u64..=1_000_000,
        expiry in 1_u64..=2_000_000,
        reason_code in 1_u16..=100,
        issued_at in 0_u64..=1_000_000,
    ) {
        let request = RecoveryRequest {
            protocol_version,
            crypto_suite: CryptoSuite::default(),
            config_id,
            config_version,
            request_id,
            recovery_recipient_key: recipient.clone(),
            requested_at,
            nonce,
            expiry,
        };
        assert_bound!(mutant, gp_wire::recovery_request, &request,
            { mutant.protocol_version += 1; },
            { mutant.config_id[0] ^= 1; },
            { mutant.config_version += 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.requested_at += 1; },
            { mutant.nonce[0] ^= 1; },
            { mutant.expiry += 1; },
        );
        assert_bound!(mutant, gp_wire::request_digest_preimage, &request,
            { mutant.nonce[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
        );
        assert_bound!(mutant,
            |request: &RecoveryRequest| gp_wire::recipient_share_context(request, signer_id),
            &request,
            { mutant.request_id[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
        );
        assert_bound!(mutant,
            |request: &RecoveryRequest| gp_wire::guardian_release_context(request, signer_index),
            &request,
            { mutant.request_id[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
        );

        let sealed = SealedMessage {
            kem_ciphertext: kem.clone(),
            payload: AeadCiphertext {
                nonce: nonce24,
                ciphertext: ciphertext.clone(),
            },
        };
        let sealed_base = sealed.clone();
        assert_bound!(mutant,
            |request: &RecoveryRequest| gp_wire::signer_approval(request, signer_id, &sealed_base),
            &request,
            { mutant.request_id[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
        );
        assert_bound!(mutant,
            |sealed: &SealedMessage| gp_wire::signer_approval(&request, signer_id, sealed),
            &sealed,
            { mutant.kem_ciphertext[0] ^= 1; },
            { mutant.payload.nonce[0] ^= 1; },
            { mutant.payload.ciphertext[0] ^= 1; },
        );

        assert_bound!(mutant,
            |(id, key): &(u16, [u8; 32])| gp_wire::signer_leaf(*id, key),
            &(signer_id, public_key),
            { mutant.0 += 1; },
            { mutant.1[0] ^= 1; },
        );

        assert_bound!(mutant,
            |(id, version): &([u8; 32], u64)| gp_wire::descriptor_context(id, *version),
            &(config_id, config_version),
            { mutant.0[0] ^= 1; },
            { mutant.1 += 1; },
        );

        assert_bound!(mutant,
            |(id, version, index, f_hash, s_hash): &([u8; 32], u64, u16, [u8; 32], [u8; 32])| {
                gp_wire::guardian_leaf(id, *version, *index, f_hash, s_hash)
            },
            &(config_id, config_version, signer_index, fragment_hash, share_hash),
            { mutant.0[0] ^= 1; },
            { mutant.1 += 1; },
            { mutant.2 += 1; },
            { mutant.3[0] ^= 1; },
            { mutant.4[0] ^= 1; },
        );

        assert_bound!(mutant,
            |(id, version, index): &([u8; 32], u64, u16)| {
                gp_wire::guardian_share_context(id, *version, *index)
            },
            &(config_id, config_version, signer_index),
            { mutant.0[0] ^= 1; },
            { mutant.1 += 1; },
            { mutant.2 += 1; },
        );

        assert_bound!(mutant,
            |(id, version): &([u8; 32], u64)| gp_wire::payload_context(id, *version),
            &(config_id, config_version),
            { mutant.0[0] ^= 1; },
            { mutant.1 += 1; },
        );

        assert_bound!(mutant,
            |(node, role): &(String, String)| {
                gp_wire::node_provision_context(node, role)
            },
            &(node_id.clone(), role.clone()),
            { mutant.0.push('x'); },
            { mutant.1.push('y'); },
        );

        assert_bound!(mutant,
            |(mailbox, direction): &(String, String)| {
                gp_wire::mailbox_transport_context(mailbox, direction)
            },
            &(mailbox.clone(), direction.clone()),
            { mutant.0.push('x'); },
            { mutant.1.push('y'); },
        );

        let cancel = OwnerCancelCertificate {
            protocol_version,
            config_id,
            config_version,
            request_id,
            request_digest: digest,
            recovery_recipient_key: recipient.clone(),
            cancel_response_recipient_key: cancel_recipient.clone(),
            reason_code,
            nonce,
            issued_at,
            owner_cancel_public_key: public_key,
            owner_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::owner_cancel, &cancel,
            { mutant.protocol_version += 1; },
            { mutant.config_id[0] ^= 1; },
            { mutant.config_version += 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.cancel_response_recipient_key[0] ^= 1; },
            { mutant.reason_code += 1; },
            { mutant.nonce[0] ^= 1; },
            { mutant.issued_at += 1; },
            { mutant.owner_cancel_public_key[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::owner_cancel, &cancel,
            { mutant.owner_signature.push(0); },
        );

        let ack = OwnerCancelAck {
            protocol_version,
            config_id,
            config_version,
            request_id,
            request_digest: digest,
            owner_cancel_transcript_digest: digest,
            guardian_index: signer_id,
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::owner_cancel_ack, &ack,
            { mutant.protocol_version += 1; },
            { mutant.config_id[0] ^= 1; },
            { mutant.config_version += 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.owner_cancel_transcript_digest[0] ^= 1; },
            { mutant.guardian_index += 1; },
        );
        assert_excluded!(mutant, gp_wire::owner_cancel_ack, &ack,
            { mutant.guardian_signature.push(0); },
        );

        let vote = ReleaseVote {
            protocol_version,
            config_id,
            config_version,
            request_id,
            request_digest: digest,
            recovery_recipient_key: recipient.clone(),
            nonce,
            signer_id,
            signer_public_key: public_key,
            signer_membership_proof: membership.clone(),
            signer_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::release_vote, &vote,
            { mutant.protocol_version += 1; },
            { mutant.config_id[0] ^= 1; },
            { mutant.config_version += 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
            { mutant.signer_id += 1; },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::release_vote, &vote,
            { mutant.signer_signature.push(0); },
        );

        let contribution = GuardianContribution {
            protocol_version,
            config_id,
            config_version,
            request_id,
            request_digest: digest,
            guardian_index: signer_id,
            ciphertext_fragment: fragment.clone(),
            encrypted_dek_share: AeadCiphertext {
                nonce: nonce24,
                ciphertext: ciphertext.clone(),
            },
            merkle_path_proof: merkle_proof.clone(),
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::guardian_contribution, &contribution,
            { mutant.protocol_version += 1; },
            { mutant.config_id[0] ^= 1; },
            { mutant.config_version += 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.guardian_index += 1; },
            { mutant.ciphertext_fragment[0] ^= 1; },
            { mutant.encrypted_dek_share.nonce[0] ^= 1; },
            { mutant.encrypted_dek_share.ciphertext[0] ^= 1; },
            { mutant.merkle_path_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::guardian_contribution, &contribution,
            { mutant.guardian_signature.push(0); },
        );
    }
}
fn config_ref(
    config_id: Id32,
    payload_generation: u64,
    authorization_epoch: u64,
    guardian_epoch: u64,
    epoch_binding: Id32,
) -> ConfigRef {
    ConfigRef {
        config_id,
        payload_generation,
        authorization_epoch,
        guardian_epoch,
        epoch_binding,
    }
}

fn rotation_context(
    config_ref: ConfigRef,
    rotation_id: Id32,
    predecessor_capsule_hash: Id32,
    recipient_key: Vec<u8>,
    nonce: Id32,
    issued_at: u64,
    expiry: u64,
) -> RotationContext {
    RotationContext {
        protocol_version: PROTOCOL_VERSION_V3,
        config_ref,
        rotation_id,
        predecessor_capsule_hash,
        recipient_key,
        nonce,
        issued_at,
        expiry,
    }
}

/// Structurally valid QC used only where a builder deliberately ignores the
/// field (config-capsule body), so shape is enough.
fn epoch_activation_qc_placeholder() -> EpochActivationQc {
    EpochActivationQc {
        protocol_version: PROTOCOL_VERSION_V3,
        config_id: [1; 32],
        rotation_id: [2; 32],
        predecessor_epoch: 1,
        predecessor_capsule_hash: [3; 32],
        successor_epoch: 2,
        successor_capsule_hash: [4; 32],
        activation_certificate_hash: [5; 32],
        witness_fault_bound: 0,
        witness_acks: vec![WitnessActivationAck {
            context: rotation_context(
                config_ref([1; 32], 1, 1, 1, [9; 32]),
                [2; 32],
                [3; 32],
                vec![6; 32],
                [7; 32],
                10,
                100,
            ),
            plan_hash: [8; 32],
            activation_certificate_hash: [5; 32],
            witness_id: 1,
            predecessor_epoch: 1,
            predecessor_capsule_hash: [3; 32],
            successor_epoch: 2,
            successor_capsule_hash: [4; 32],
            witness_public_key: [10; 32],
            witness_signature: vec![11],
        }],
    }
}

fn route(
    guardian_index: u16,
    opaque_slot_id: Id32,
    mailbox: String,
    guardian_public_key: Id32,
    session_recipient_key: Vec<u8>,
    operator_domain_commitment: Id32,
) -> GuardianRouteV3 {
    GuardianRouteV3 {
        guardian_index,
        opaque_slot_id,
        mailbox,
        guardian_public_key,
        session_recipient_key,
        operator_domain_commitment,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn rotation_context_and_roster_transcripts_bind_every_field(
        config_id in id32(),
        epoch_binding in id32(),
        rotation_id in id32(),
        predecessor_hash in id32(),
        recipient_key in bytes(),
        nonce in id32(),
        intent_hash in id32(),
        _plan_hash in id32(),
        commitment_a in id32(),
        commitment_b in id32(),
        slot_id in id32(),
        guardian_key in id32(),
        session_key in bytes(),
        operator_domain in id32(),
        mailbox in string(),
        payload_generation in 1_u64..=100,
        authorization_epoch in 1_u64..=100,
        guardian_epoch in 1_u64..=100,
        (issued_at, expiry) in (0_u64..=1_000_000, 1_u64..=2_000_000).prop_map(|(i, e)| (i, e.max(i + 1))),
        signer_id in 1_u16..=50,
        old_count in 1_u16..=100,
        old_threshold in 1_u16..=100,
        _delay_secs in 1_u64..=1_000_000,
        _preparation_deadline in 1_u64..=1_000_000,
        _drain_deadline in 1_u64..=1_000_000,
    ) {
        let ctx = rotation_context(
            config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch, epoch_binding),
            rotation_id,
            predecessor_hash,
            recipient_key.clone(),
            nonce,
            issued_at,
            expiry,
        );
        assert_bound!(mutant,
            |context: &RotationContext| gp_wire::rotation_intent_share_context_v3(context, &intent_hash, signer_id),
            &ctx,
            { mutant.recipient_key[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
            { mutant.rotation_id[0] ^= 1; },
            { mutant.predecessor_capsule_hash[0] ^= 1; },
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.payload_generation += 1; },
            { mutant.config_ref.authorization_epoch += 1; },
            { mutant.config_ref.guardian_epoch += 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.issued_at += 1; },
            { mutant.expiry += 1; },
        );
        assert_bound!(mutant,
            |(context, intent, id): &(RotationContext, Id32, u16)| {
                gp_wire::rotation_intent_share_context_v3(context, intent, *id)
            },
            &(ctx.clone(), intent_hash, signer_id),
            { mutant.0.nonce[0] ^= 1; },
            { mutant.1[0] ^= 1; },
            { mutant.2 += 1; },
        );
        assert_bound!(mutant,
            |(config, index): &(ConfigRef, u16)| gp_wire::guardian_share_context_v3(config, *index),
            &(ctx.config_ref, signer_id),
            { mutant.0.config_id[0] ^= 1; },
            { mutant.0.guardian_epoch += 1; },
            { mutant.0.epoch_binding[0] ^= 1; },
            { mutant.1 += 1; },
        );
        assert_bound!(mutant,
            |(config, index, fragment): &(ConfigRef, u16, u16)| {
                gp_wire::guardian_fragment_context_v3(config, *index, *fragment)
            },
            &(ctx.config_ref, signer_id, signer_id + 1),
            { mutant.0.config_id[0] ^= 1; },
            { mutant.1 += 1; },
            { mutant.2 += 1; },
        );
        assert_bound!(mutant,
            |config: &ConfigRef| gp_wire::descriptor_context_v3(config),
            &ctx.config_ref,
            { mutant.config_id[0] ^= 1; },
            { mutant.payload_generation += 1; },
            { mutant.authorization_epoch += 1; },
            { mutant.guardian_epoch += 1; },
            { mutant.epoch_binding[0] ^= 1; },
        );
        assert_bound!(mutant,
            |(config, generation): &(Id32, u64)| gp_wire::payload_context_v3(config, *generation),
            &(config_id, payload_generation),
            { mutant.0[0] ^= 1; },
            { mutant.1 += 1; },
        );

        let route_one = route(
            signer_id,
            slot_id,
            mailbox.clone(),
            guardian_key,
            session_key.clone(),
            operator_domain,
        );
        let route_two = route(
            signer_id + 1,
            rotation_id,
            mailbox.clone(),
            predecessor_hash,
            recipient_key.clone(),
            commitment_a,
        );
        let roster = vec![route_one.clone(), route_two.clone()];
        assert_bound!(mutant,
            |routes: &Vec<GuardianRouteV3>| gp_wire::guardian_roster_v3(routes),
            &roster,
            { mutant[0].guardian_index = mutant[0].guardian_index.wrapping_add(3).max(1); },
            { mutant[0].opaque_slot_id[0] ^= 1; },
            { mutant[0].mailbox.push('x'); },
            { mutant[0].guardian_public_key[0] ^= 1; },
            { mutant[0].session_recipient_key[0] ^= 1; },
            { mutant[0].operator_domain_commitment[0] ^= 1; },
            { let mut extra = mutant[0].clone(); extra.guardian_index = mutant[0].guardian_index.wrapping_add(5); mutant.push(extra); },
        );

        let intent = RotationIntent {
            context: ctx.clone(),
            reason: RotationReason::PlannedExit,
            old_guardian_count: old_count,
            old_guardian_threshold: old_threshold,
            allowed_new_guardian_count: vec![old_count, old_count + 1],
            allowed_new_guardian_threshold: vec![old_threshold],
            allowed_dpss_suites: vec![DpssSuiteId::default()],
            selection_constraints_commitment: commitment_a,
            witness_read_qc_hash: commitment_b,
        };
        assert_bound!(mutant, gp_wire::rotation_intent, &intent,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.recipient_key[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.context.predecessor_capsule_hash[0] ^= 1; },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.context.issued_at += 1; },
            { mutant.context.expiry += 1; },
            { mutant.reason = RotationReason::SecurityUpgrade; },
            { mutant.old_guardian_count += 1; },
            { mutant.old_guardian_threshold += 1; },
            { mutant.allowed_new_guardian_count[0] += 1; },
            { mutant.allowed_new_guardian_count.push(7); },
            { mutant.allowed_new_guardian_threshold[0] += 1; },
            { mutant.allowed_new_guardian_threshold.push(7); },
            { mutant.allowed_dpss_suites.push(DpssSuiteId::default()); },
            { mutant.selection_constraints_commitment[0] ^= 1; },
            { mutant.witness_read_qc_hash[0] ^= 1; },
        );

        let contribution = SignerRotationIntentContribution {
            context: ctx.clone(),
            intent_hash,
            signer_id,
            signer_public_key: guardian_key,
            signer_membership_proof: session_key.clone(),
            encrypted_authorization_share: SealedMessage {
                kem_ciphertext: recipient_key.clone(),
                payload: AeadCiphertext {
                    nonce: [7; 24],
                    ciphertext: commitment_a.to_vec(),
                },
            },
            signer_signature: commitment_b.to_vec(),
        };
        assert_bound!(mutant, gp_wire::signer_rotation_intent_contribution, &contribution,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.intent_hash[0] ^= 1; },
            { mutant.signer_id = mutant.signer_id.wrapping_add(3).max(1); },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
            { mutant.encrypted_authorization_share.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_authorization_share.payload.nonce[0] ^= 1; },
            { mutant.encrypted_authorization_share.payload.ciphertext[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::signer_rotation_intent_contribution, &contribution,
            { mutant.signer_signature.push(0); },
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn rotation_plan_and_vote_transcripts_bind_every_field(
        config_id in id32(),
        epoch_binding in id32(),
        successor_binding in id32(),
        rotation_id in id32(),
        predecessor_hash in id32(),
        recipient_key in bytes(),
        nonce in id32(),
        intent_hash in id32(),
        plan_hash in id32(),
        ready_hash in id32(),
        capsule_hash in id32(),
        commitment_a in id32(),
        commitment_b in id32(),
        commitment_c in id32(),
        slot_id in id32(),
        guardian_key in id32(),
        session_key in bytes(),
        operator_domain in id32(),
        mailbox in string(),
        membership in bytes(),
        signature in bytes(),
        payload_generation in 1_u64..=100,
        authorization_epoch in 1_u64..=100,
        guardian_epoch in 1_u64..=100,
        (issued_at, expiry) in (0_u64..=1_000_000, 1_u64..=2_000_000).prop_map(|(i, e)| (i, e.max(i + 1))),
        signer_id in 1_u16..=50,
        delay_secs in 1_u64..=1_000_000,
        preparation_deadline in 1_u64..=1_000_000,
        drain_deadline in 1_u64..=1_000_000,
        not_before in 1_u64..=1_000_000,
    ) {
        let predecessor = config_ref(
            config_id, payload_generation, authorization_epoch, guardian_epoch, epoch_binding,
        );
        let successor = config_ref(
            config_id, payload_generation, authorization_epoch, guardian_epoch + 1, successor_binding,
        );
        let ctx = rotation_context(
            predecessor,
            rotation_id,
            predecessor_hash,
            recipient_key.clone(),
            nonce,
            issued_at,
            expiry,
        );
        let plan = RotationPlan {
            context: ctx.clone(),
            intent_hash,
            predecessor,
            successor,
            old_roster: vec![route(signer_id, slot_id, mailbox.clone(), guardian_key, session_key.clone(), operator_domain)],
            new_roster: vec![route(signer_id, slot_id, mailbox.clone(), guardian_key, session_key.clone(), operator_domain)],
            old_roster_commitment: commitment_a,
            new_roster_commitment: commitment_b,
            old_guardian_threshold: 1,
            new_guardian_threshold: 1,
            data_shards: 1,
            total_shards: 2,
            dpss_suite: DpssSuiteId::default(),
            dpss_session_id: commitment_c,
            dpss_qualified_set_commitment: commitment_a,
            minimum_delay_secs: delay_secs,
            preparation_deadline,
            drain_deadline,
        };
        assert_bound!(mutant, gp_wire::rotation_plan, &plan,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.recipient_key[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.context.predecessor_capsule_hash[0] ^= 1; },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.context.issued_at += 1; },
            { mutant.context.expiry += 1; },
            { mutant.intent_hash[0] ^= 1; },
            { mutant.predecessor.epoch_binding[0] ^= 1; mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.predecessor.config_id[0] ^= 1; mutant.context.config_ref.config_id[0] ^= 1; },
            { mutant.successor.epoch_binding[0] ^= 1; },
            { mutant.successor.guardian_epoch += 1; },
            { mutant.old_roster[0].mailbox.push('x'); },
            { mutant.new_roster[0].session_recipient_key[0] ^= 1; },
            { mutant.old_roster_commitment[0] ^= 1; },
            { mutant.new_roster_commitment[0] ^= 1; },
            { mutant.old_guardian_threshold += 1; },
            { mutant.new_guardian_threshold += 1; },
            { mutant.data_shards = 2; },
            { mutant.total_shards += 1; },
            { mutant.dpss_session_id[0] ^= 1; },
            { mutant.dpss_qualified_set_commitment[0] ^= 1; },
            { mutant.minimum_delay_secs += 1; },
            { mutant.preparation_deadline += 1; },
            { mutant.drain_deadline += 1; },
        );

        let begin_vote = SignerRotationBeginVote {
            context: ctx.clone(),
            intent_hash,
            plan_hash,
            old_roster_commitment: commitment_a,
            new_roster_commitment: commitment_b,
            signer_id,
            signer_public_key: guardian_key,
            signer_membership_proof: membership.clone(),
            signer_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::signer_rotation_begin_vote, &begin_vote,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.intent_hash[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.old_roster_commitment[0] ^= 1; },
            { mutant.new_roster_commitment[0] ^= 1; },
            { mutant.signer_id = mutant.signer_id.wrapping_add(3).max(1); },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::signer_rotation_begin_vote, &begin_vote,
            { mutant.signer_signature.push(0); },
        );

        let second_vote = SignerRotationBeginVote {
            signer_id: signer_id + 1,
            ..begin_vote.clone()
        };
        let begin_certificate = BeginRotationCertificate {
            context: ctx.clone(),
            intent_hash,
            plan_hash,
            old_roster_commitment: commitment_a,
            new_roster_commitment: commitment_b,
            not_before_wall: not_before,
            votes: vec![begin_vote.clone(), second_vote],
        };
        assert_bound!(mutant, gp_wire::begin_rotation_certificate, &begin_certificate,
            { mutant.context.recipient_key[0] ^= 1; for vote in &mut mutant.votes { vote.context.recipient_key[0] ^= 1; } },
            { mutant.context.nonce[0] ^= 1; for vote in &mut mutant.votes { vote.context.nonce[0] ^= 1; } },
            { mutant.context.rotation_id[0] ^= 1; for vote in &mut mutant.votes { vote.context.rotation_id[0] ^= 1; } },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; for vote in &mut mutant.votes { vote.context.config_ref.epoch_binding[0] ^= 1; } },
            { mutant.context.issued_at += 1; for vote in &mut mutant.votes { vote.context.issued_at += 1; } },
            { mutant.context.expiry += 1; for vote in &mut mutant.votes { vote.context.expiry += 1; } },
            { mutant.intent_hash[0] ^= 1; for vote in &mut mutant.votes { vote.intent_hash[0] ^= 1; } },
            { mutant.plan_hash[0] ^= 1; for vote in &mut mutant.votes { vote.plan_hash[0] ^= 1; } },
            { mutant.old_roster_commitment[0] ^= 1; for vote in &mut mutant.votes { vote.old_roster_commitment[0] ^= 1; } },
            { mutant.new_roster_commitment[0] ^= 1; for vote in &mut mutant.votes { vote.new_roster_commitment[0] ^= 1; } },
            { mutant.not_before_wall += 1; },
            { mutant.votes[1].signer_id = mutant.votes[1].signer_id.wrapping_add(3).max(1); },
            { mutant.votes[0].signer_public_key[0] ^= 1; },
            { mutant.votes[0].signer_membership_proof[0] ^= 1; },
            { mutant.votes[0].signer_signature[0] ^= 1; },
        );

        let release_vote = SignerRotationReleaseVote {
            context: ctx.clone(),
            plan_hash,
            begin_certificate_hash: ready_hash,
            signer_id,
            signer_public_key: guardian_key,
            signer_membership_proof: membership.clone(),
            signer_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::signer_rotation_release_vote, &release_vote,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.begin_certificate_hash[0] ^= 1; },
            { mutant.signer_id = mutant.signer_id.wrapping_add(3).max(1); },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::signer_rotation_release_vote, &release_vote,
            { mutant.signer_signature.push(0); },
        );

        let second_release = SignerRotationReleaseVote {
            signer_id: signer_id + 1,
            ..release_vote.clone()
        };
        let release_certificate = RotationReleaseCertificate {
            context: ctx.clone(),
            plan_hash,
            begin_certificate_hash: ready_hash,
            votes: vec![release_vote.clone(), second_release],
        };
        assert_bound!(mutant, gp_wire::rotation_release_certificate, &release_certificate,
            { mutant.context.nonce[0] ^= 1; for vote in &mut mutant.votes { vote.context.nonce[0] ^= 1; } },
            { mutant.context.recipient_key[0] ^= 1; for vote in &mut mutant.votes { vote.context.recipient_key[0] ^= 1; } },
            { mutant.context.rotation_id[0] ^= 1; for vote in &mut mutant.votes { vote.context.rotation_id[0] ^= 1; } },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; for vote in &mut mutant.votes { vote.context.config_ref.epoch_binding[0] ^= 1; } },
            { mutant.plan_hash[0] ^= 1; for vote in &mut mutant.votes { vote.plan_hash[0] ^= 1; } },
            { mutant.begin_certificate_hash[0] ^= 1; for vote in &mut mutant.votes { vote.begin_certificate_hash[0] ^= 1; } },
            { mutant.votes[1].signer_id = mutant.votes[1].signer_id.wrapping_add(3).max(1); },
            { mutant.votes[0].signer_public_key[0] ^= 1; },
            { mutant.votes[0].signer_membership_proof[0] ^= 1; },
            { mutant.votes[0].signer_signature[0] ^= 1; },
        );

        let owner_cancel = OwnerRotationCancelCertificate {
            context: ctx.clone(),
            plan_hash,
            reason_code: 1,
            cancel_response_recipient_key: recipient_key.clone(),
            owner_cancel_public_key: guardian_key,
            owner_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::owner_rotation_cancel_certificate, &owner_cancel,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.recipient_key[0] ^= 1; },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.reason_code += 1; },
            { mutant.cancel_response_recipient_key[0] ^= 1; },
            { mutant.owner_cancel_public_key[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::owner_rotation_cancel_certificate, &owner_cancel,
            { mutant.owner_signature.push(0); },
        );

        let owner_ack = OwnerRotationCancelAck {
            context: ctx.clone(),
            plan_hash,
            cancel_certificate_hash: capsule_hash,
            guardian_index: signer_id,
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::owner_rotation_cancel_ack, &owner_ack,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.cancel_certificate_hash[0] ^= 1; },
            { mutant.guardian_index += 1; },
        );
        assert_excluded!(mutant, gp_wire::owner_rotation_cancel_ack, &owner_ack,
            { mutant.guardian_signature.push(0); },
        );

        let abort_vote = SignerRotationAbortVote {
            context: ctx.clone(),
            plan_hash,
            state_at_abort: RotationState::Preparing,
            reason_code: 1,
            signer_id,
            signer_public_key: guardian_key,
            signer_membership_proof: membership.clone(),
            signer_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::signer_rotation_abort_vote, &abort_vote,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.state_at_abort = RotationState::Ready; },
            { mutant.reason_code += 1; },
            { mutant.signer_id = mutant.signer_id.wrapping_add(3).max(1); },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::signer_rotation_abort_vote, &abort_vote,
            { mutant.signer_signature.push(0); },
        );

        let second_abort = SignerRotationAbortVote {
            signer_id: signer_id + 1,
            ..abort_vote.clone()
        };
        let abort_certificate = AbortRotationCertificate {
            context: ctx.clone(),
            plan_hash,
            state_at_abort: RotationState::Preparing,
            reason_code: 1,
            votes: vec![abort_vote.clone(), second_abort],
        };
        assert_bound!(mutant, gp_wire::abort_rotation_certificate, &abort_certificate,
            { mutant.context.nonce[0] ^= 1; for vote in &mut mutant.votes { vote.context.nonce[0] ^= 1; } },
            { mutant.context.recipient_key[0] ^= 1; for vote in &mut mutant.votes { vote.context.recipient_key[0] ^= 1; } },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; for vote in &mut mutant.votes { vote.context.config_ref.epoch_binding[0] ^= 1; } },
            { mutant.plan_hash[0] ^= 1; for vote in &mut mutant.votes { vote.plan_hash[0] ^= 1; } },
            { mutant.state_at_abort = RotationState::Ready; for vote in &mut mutant.votes { vote.state_at_abort = RotationState::Ready; } },
            { mutant.reason_code += 1; for vote in &mut mutant.votes { vote.reason_code += 1; } },
            { mutant.votes[1].signer_id = mutant.votes[1].signer_id.wrapping_add(3).max(1); },
            { mutant.votes[0].signer_public_key[0] ^= 1; },
            { mutant.votes[0].signer_membership_proof[0] ^= 1; },
            { mutant.votes[0].signer_signature[0] ^= 1; },
        );

        let activate_vote = SignerRotationActivateVote {
            context: ctx.clone(),
            plan_hash,
            ready_certificate_hash: ready_hash,
            successor_capsule_hash: capsule_hash,
            signer_id,
            signer_public_key: guardian_key,
            signer_membership_proof: membership.clone(),
            signer_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::signer_rotation_activate_vote, &activate_vote,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.ready_certificate_hash[0] ^= 1; },
            { mutant.successor_capsule_hash[0] ^= 1; },
            { mutant.signer_id = mutant.signer_id.wrapping_add(3).max(1); },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::signer_rotation_activate_vote, &activate_vote,
            { mutant.signer_signature.push(0); },
        );

        let second_activate = SignerRotationActivateVote {
            signer_id: signer_id + 1,
            ..activate_vote.clone()
        };
        let activate_certificate = RotationActivateCertificate {
            context: ctx.clone(),
            plan_hash,
            ready_certificate_hash: ready_hash,
            successor,
            successor_capsule_hash: capsule_hash,
            votes: vec![activate_vote.clone(), second_activate],
        };
        assert_bound!(mutant, gp_wire::rotation_activate_certificate, &activate_certificate,
            { mutant.context.nonce[0] ^= 1; for vote in &mut mutant.votes { vote.context.nonce[0] ^= 1; } },
            { mutant.context.recipient_key[0] ^= 1; for vote in &mut mutant.votes { vote.context.recipient_key[0] ^= 1; } },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; for vote in &mut mutant.votes { vote.context.config_ref.epoch_binding[0] ^= 1; } },
            { mutant.plan_hash[0] ^= 1; for vote in &mut mutant.votes { vote.plan_hash[0] ^= 1; } },
            { mutant.ready_certificate_hash[0] ^= 1; for vote in &mut mutant.votes { vote.ready_certificate_hash[0] ^= 1; } },
            { mutant.successor_capsule_hash[0] ^= 1; for vote in &mut mutant.votes { vote.successor_capsule_hash[0] ^= 1; } },
            { mutant.successor.epoch_binding[0] ^= 1; },
            { mutant.successor.guardian_epoch += 1; },
            { mutant.votes[1].signer_id = mutant.votes[1].signer_id.wrapping_add(3).max(1); },
            { mutant.votes[0].signer_public_key[0] ^= 1; },
            { mutant.votes[0].signer_membership_proof[0] ^= 1; },
            { mutant.votes[0].signer_signature[0] ^= 1; },
        );

        let retirement_notice = RetirementNotice {
            context: ctx.clone(),
            plan_hash,
            activation_qc_hash: capsule_hash,
            retired_epoch: guardian_epoch,
            drain_deadline,
        };
        assert_bound!(mutant, gp_wire::retirement_notice, &retirement_notice,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.activation_qc_hash[0] ^= 1; },
            { mutant.retired_epoch += 1; },
            { mutant.drain_deadline += 1; },
        );

        let retirement_ack = RetirementAck {
            context: ctx.clone(),
            plan_hash,
            activation_qc_hash: capsule_hash,
            guardian_index: signer_id,
            retired_epoch: guardian_epoch,
            tombstone_hash: commitment_c,
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::retirement_ack, &retirement_ack,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.activation_qc_hash[0] ^= 1; },
            { mutant.guardian_index += 1; },
            { mutant.retired_epoch += 1; },
            { mutant.tombstone_hash[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::retirement_ack, &retirement_ack,
            { mutant.guardian_signature.push(0); },
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn grant_dpss_and_witness_transcripts_bind_every_field(
        config_id in id32(),
        epoch_binding in id32(),
        rotation_id in id32(),
        predecessor_hash in id32(),
        recipient_key in bytes(),
        nonce in id32(),
        plan_hash in id32(),
        release_hash in id32(),
        activation_hash in id32(),
        commitment_a in id32(),
        commitment_b in id32(),
        commitment_c in id32(),
        slot_id in id32(),
        guardian_key in id32(),
        _session_key in bytes(),
        _operator_domain in id32(),
        _mailbox in string(),
        unwrap_key in bytes(),
        wrap_key in bytes(),
        fragment_key in bytes(),
        membership in bytes(),
        signature in bytes(),
        provider_payload in bytes(),
        payload_generation in 1_u64..=100,
        authorization_epoch in 1_u64..=100,
        guardian_epoch in 1_u64..=100,
        (issued_at, expiry) in (0_u64..=1_000_000, 1_u64..=2_000_000).prop_map(|(i, e)| (i, e.max(i + 1))),
        signer_id in 1_u16..=50,
        sequence in 1_u64..=1_000_000,
        write_generation in 1_u64..=1_000_000,
        retired_epoch in 1_u64..=100,
    ) {
        let ctx = rotation_context(
            config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch, epoch_binding),
            rotation_id,
            predecessor_hash,
            recipient_key.clone(),
            nonce,
            issued_at,
            expiry,
        );

        let old_grant = OldShareUnlockGrant {
            context: ctx.clone(),
            plan_hash,
            release_certificate_hash: release_hash,
            old_guardian_index: signer_id,
            encrypted_unwrap_key: SealedMessage {
                kem_ciphertext: unwrap_key.clone(),
                payload: AeadCiphertext { nonce: [7; 24], ciphertext: commitment_a.to_vec() },
            },
            encrypted_fragment_key: SealedMessage {
                kem_ciphertext: fragment_key.clone(),
                payload: AeadCiphertext { nonce: [8; 24], ciphertext: commitment_b.to_vec() },
            },
        };
        assert_bound!(mutant, gp_wire::old_share_unlock_grant, &old_grant,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.recipient_key[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.context.issued_at += 1; },
            { mutant.context.expiry += 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.release_certificate_hash[0] ^= 1; },
            { mutant.old_guardian_index = mutant.old_guardian_index.wrapping_add(3).max(1); },
            { mutant.encrypted_unwrap_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_unwrap_key.payload.nonce[0] ^= 1; },
            { mutant.encrypted_unwrap_key.payload.ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.payload.nonce[0] ^= 1; },
            { mutant.encrypted_fragment_key.payload.ciphertext[0] ^= 1; },
        );
        assert_bound!(mutant,
            |grant: &OldShareUnlockGrant| gp_wire::old_share_unlock_grant_payload_context(grant, true),
            &old_grant,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.release_certificate_hash[0] ^= 1; },
            { mutant.old_guardian_index += 1; },
        );
        assert_excluded!(mutant,
            |grant: &OldShareUnlockGrant| gp_wire::old_share_unlock_grant_payload_context(grant, true),
            &old_grant,
            { mutant.encrypted_unwrap_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_unwrap_key.payload.ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.payload.nonce[0] ^= 1; },
        );

        let new_grant = NewShareWrapGrant {
            context: ctx.clone(),
            plan_hash,
            release_certificate_hash: release_hash,
            new_guardian_index: signer_id,
            encrypted_wrap_key: SealedMessage {
                kem_ciphertext: wrap_key.clone(),
                payload: AeadCiphertext { nonce: [9; 24], ciphertext: commitment_a.to_vec() },
            },
            encrypted_fragment_key: SealedMessage {
                kem_ciphertext: fragment_key.clone(),
                payload: AeadCiphertext { nonce: [10; 24], ciphertext: commitment_b.to_vec() },
            },
        };
        assert_bound!(mutant, gp_wire::new_share_wrap_grant, &new_grant,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.release_certificate_hash[0] ^= 1; },
            { mutant.new_guardian_index = mutant.new_guardian_index.wrapping_add(3).max(1); },
            { mutant.encrypted_wrap_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_wrap_key.payload.nonce[0] ^= 1; },
            { mutant.encrypted_wrap_key.payload.ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.payload.nonce[0] ^= 1; },
            { mutant.encrypted_fragment_key.payload.ciphertext[0] ^= 1; },
        );
        assert_bound!(mutant,
            |grant: &NewShareWrapGrant| gp_wire::new_share_wrap_grant_payload_context(grant, false),
            &new_grant,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.release_certificate_hash[0] ^= 1; },
            { mutant.new_guardian_index += 1; },
        );
        assert_excluded!(mutant,
            |grant: &NewShareWrapGrant| gp_wire::new_share_wrap_grant_payload_context(grant, false),
            &new_grant,
            { mutant.encrypted_wrap_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_wrap_key.payload.ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_fragment_key.payload.nonce[0] ^= 1; },
        );

        let message = DpssProtocolMessage {
            context: ctx.clone(),
            plan_hash,
            dpss_suite: DpssSuiteId::default(),
            dpss_session_id: commitment_a,
            qualified_set_commitment: commitment_b,
            phase: DpssPhase::RepairRound1,
            sender_index: signer_id,
            recipient_index: signer_id + 1,
            sequence,
            provider_payload: provider_payload.clone(),
            sender_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::dpss_protocol_message, &message,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.context.issued_at += 1; },
            { mutant.context.expiry += 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.dpss_session_id[0] ^= 1; },
            { mutant.qualified_set_commitment[0] ^= 1; },
            { mutant.phase = DpssPhase::RefreshRound2; },
            { mutant.sender_index = mutant.sender_index.wrapping_add(5).max(1); },
            { mutant.recipient_index = mutant.recipient_index.wrapping_add(5).max(1); },
            { mutant.sequence += 1; },
            { mutant.provider_payload[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::dpss_protocol_message, &message,
            { mutant.sender_signature.push(0); },
        );

        let leaf = PreparedRecordLeaf {
            guardian_index: signer_id,
            fragment_index: signer_id,
            opaque_slot_id: slot_id,
            encrypted_share_hash: commitment_a,
            fragment_hash: commitment_b,
            policy_hash: commitment_c,
        };
        assert_bound!(mutant, gp_wire::prepared_record_leaf_v3, &leaf,
            { mutant.guardian_index = mutant.guardian_index.wrapping_add(3).max(1); },
            { mutant.fragment_index += 1; },
            { mutant.opaque_slot_id[0] ^= 1; },
            { mutant.encrypted_share_hash[0] ^= 1; },
            { mutant.fragment_hash[0] ^= 1; },
            { mutant.policy_hash[0] ^= 1; },
        );

        let fragment_contribution = CiphertextFragmentContribution {
            context: ctx.clone(),
            plan_hash,
            release_certificate_hash: release_hash,
            old_guardian_index: signer_id,
            fragment_index: signer_id,
            ciphertext_fragment: provider_payload.clone(),
            fragment_commitment: commitment_a,
            prepared_record_leaf: leaf.clone(),
            merkle_path_proof: membership.clone(),
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::ciphertext_fragment_contribution, &fragment_contribution,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.release_certificate_hash[0] ^= 1; },
            { mutant.old_guardian_index = mutant.old_guardian_index.wrapping_add(3).max(1); },
            { mutant.fragment_index += 1; },
            { mutant.ciphertext_fragment[0] ^= 1; },
            { mutant.fragment_commitment[0] ^= 1; },
            { mutant.prepared_record_leaf.opaque_slot_id[0] ^= 1; },
            { mutant.prepared_record_leaf.fragment_hash[0] ^= 1; },
            { mutant.merkle_path_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::ciphertext_fragment_contribution, &fragment_contribution,
            { mutant.guardian_signature.push(0); },
        );

        let prepared_ack = NewGuardianPreparedAck {
            context: ctx.clone(),
            plan_hash,
            dpss_result_commitment: commitment_a,
            guardian_material_root: commitment_b,
            new_guardian_index: leaf.guardian_index,
            prepared_record_leaf: leaf.clone(),
            durable_write_generation: write_generation,
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::new_guardian_prepared_ack, &prepared_ack,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.context.issued_at += 1; },
            { mutant.context.expiry += 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.dpss_result_commitment[0] ^= 1; },
            { mutant.guardian_material_root[0] ^= 1; },
            { mutant.new_guardian_index = mutant.new_guardian_index.wrapping_add(3).max(1); mutant.prepared_record_leaf.guardian_index = mutant.new_guardian_index; },
            { mutant.prepared_record_leaf.fragment_index += 1; },
            { mutant.prepared_record_leaf.opaque_slot_id[0] ^= 1; },
            { mutant.prepared_record_leaf.policy_hash[0] ^= 1; },
            { mutant.durable_write_generation += 1; },
        );
        assert_excluded!(mutant, gp_wire::new_guardian_prepared_ack, &prepared_ack,
            { mutant.guardian_signature.push(0); },
        );

        let handoff_ack = OldGuardianHandoffAck {
            context: ctx.clone(),
            plan_hash,
            dpss_result_commitment: commitment_a,
            qualified_set_commitment: commitment_c,
            old_guardian_index: signer_id,
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::old_guardian_handoff_ack, &handoff_ack,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.dpss_result_commitment[0] ^= 1; },
            { mutant.qualified_set_commitment[0] ^= 1; },
            { mutant.old_guardian_index = mutant.old_guardian_index.wrapping_add(3).max(1); },
        );
        assert_excluded!(mutant, gp_wire::old_guardian_handoff_ack, &handoff_ack,
            { mutant.guardian_signature.push(0); },
        );

        let second_prepared = NewGuardianPreparedAck {
            new_guardian_index: leaf.guardian_index + 1,
            prepared_record_leaf: PreparedRecordLeaf {
                guardian_index: leaf.guardian_index + 1,
                ..leaf.clone()
            },
            ..prepared_ack.clone()
        };
        let second_handoff = OldGuardianHandoffAck {
            old_guardian_index: signer_id + 1,
            ..handoff_ack.clone()
        };
        let successor = config_ref(
            config_id, payload_generation, authorization_epoch, guardian_epoch + 1, commitment_c,
        );
        let ready_certificate = RotationReadyCertificate {
            context: ctx.clone(),
            plan_hash,
            successor,
            dpss_result_commitment: commitment_a,
            guardian_material_root: commitment_b,
            encrypted_descriptor_hash: commitment_c,
            prepared_acks: vec![prepared_ack.clone(), second_prepared],
            old_handoff_acks: vec![handoff_ack.clone(), second_handoff],
        };
        assert_bound!(mutant, gp_wire::rotation_ready_certificate, &ready_certificate,
            { mutant.context.nonce[0] ^= 1; for ack in &mut mutant.prepared_acks { ack.context.nonce[0] ^= 1; } for ack in &mut mutant.old_handoff_acks { ack.context.nonce[0] ^= 1; } },
            { mutant.context.recipient_key[0] ^= 1; for ack in &mut mutant.prepared_acks { ack.context.recipient_key[0] ^= 1; } for ack in &mut mutant.old_handoff_acks { ack.context.recipient_key[0] ^= 1; } },
            { mutant.context.rotation_id[0] ^= 1; for ack in &mut mutant.prepared_acks { ack.context.rotation_id[0] ^= 1; } for ack in &mut mutant.old_handoff_acks { ack.context.rotation_id[0] ^= 1; } },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; for ack in &mut mutant.prepared_acks { ack.context.config_ref.epoch_binding[0] ^= 1; } for ack in &mut mutant.old_handoff_acks { ack.context.config_ref.epoch_binding[0] ^= 1; } },
            { mutant.context.issued_at += 1; for ack in &mut mutant.prepared_acks { ack.context.issued_at += 1; } for ack in &mut mutant.old_handoff_acks { ack.context.issued_at += 1; } },
            { mutant.context.expiry += 1; for ack in &mut mutant.prepared_acks { ack.context.expiry += 1; } for ack in &mut mutant.old_handoff_acks { ack.context.expiry += 1; } },
            { mutant.plan_hash[0] ^= 1; for ack in &mut mutant.prepared_acks { ack.plan_hash[0] ^= 1; } for ack in &mut mutant.old_handoff_acks { ack.plan_hash[0] ^= 1; } },
            { mutant.dpss_result_commitment[0] ^= 1; for ack in &mut mutant.prepared_acks { ack.dpss_result_commitment[0] ^= 1; } for ack in &mut mutant.old_handoff_acks { ack.dpss_result_commitment[0] ^= 1; } },
            { mutant.guardian_material_root[0] ^= 1; for ack in &mut mutant.prepared_acks { ack.guardian_material_root[0] ^= 1; } },
            { mutant.successor.epoch_binding[0] ^= 1; },
            { mutant.successor.guardian_epoch += 1; },
            { mutant.encrypted_descriptor_hash[0] ^= 1; },
            { mutant.prepared_acks[1].new_guardian_index = mutant.prepared_acks[1].new_guardian_index.wrapping_add(3).max(1); mutant.prepared_acks[1].prepared_record_leaf.guardian_index = mutant.prepared_acks[1].new_guardian_index; },
            { mutant.prepared_acks[0].prepared_record_leaf.fragment_index += 1; },
            { mutant.prepared_acks[0].durable_write_generation += 1; },
            { mutant.prepared_acks[0].guardian_signature[0] ^= 1; },
            { mutant.old_handoff_acks[0].qualified_set_commitment[0] ^= 1; },
            { mutant.old_handoff_acks[0].guardian_signature[0] ^= 1; },
        );

        let witness_ack = WitnessActivationAck {
            context: ctx.clone(),
            plan_hash,
            activation_certificate_hash: activation_hash,
            witness_id: signer_id,
            predecessor_epoch: guardian_epoch,
            predecessor_capsule_hash: predecessor_hash,
            successor_epoch: guardian_epoch + 1,
            successor_capsule_hash: commitment_c,
            witness_public_key: guardian_key,
            witness_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::witness_activation_ack, &witness_ack,
            { mutant.context.nonce[0] ^= 1; },
            { mutant.context.rotation_id[0] ^= 1; },
            { mutant.context.config_ref.epoch_binding[0] ^= 1; },
            { mutant.context.issued_at += 1; },
            { mutant.context.expiry += 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.activation_certificate_hash[0] ^= 1; },
            { mutant.witness_id = mutant.witness_id.wrapping_add(3).max(1); },
            { mutant.predecessor_epoch += 1; },
            { mutant.predecessor_capsule_hash[0] ^= 1; },
            { mutant.successor_epoch += 1; },
            { mutant.successor_capsule_hash[0] ^= 1; },
            { mutant.witness_public_key[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::witness_activation_ack, &witness_ack,
            { mutant.witness_signature.push(0); },
        );

        let cancel_ack = WitnessRotationCancelAck {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            rotation_id,
            plan_hash,
            cancel_certificate_hash: activation_hash,
            witness_id: signer_id,
            witness_public_key: guardian_key,
            witness_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::witness_rotation_cancel_ack, &cancel_ack,
            { mutant.config_id[0] ^= 1; },
            { mutant.rotation_id[0] ^= 1; },
            { mutant.plan_hash[0] ^= 1; },
            { mutant.cancel_certificate_hash[0] ^= 1; },
            { mutant.witness_id = mutant.witness_id.wrapping_add(3).max(1); },
            { mutant.witness_public_key[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::witness_rotation_cancel_ack, &cancel_ack,
            { mutant.witness_signature.push(0); },
        );

        let second_witness = WitnessActivationAck {
            witness_id: signer_id + 1,
            ..witness_ack.clone()
        };
        let third_witness = WitnessActivationAck {
            witness_id: signer_id + 2,
            ..witness_ack.clone()
        };
        let qc = EpochActivationQc {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            rotation_id,
            predecessor_epoch: guardian_epoch,
            predecessor_capsule_hash: predecessor_hash,
            successor_epoch: guardian_epoch + 1,
            successor_capsule_hash: commitment_c,
            activation_certificate_hash: activation_hash,
            witness_fault_bound: 1,
            witness_acks: vec![witness_ack.clone(), second_witness, third_witness],
        };
        assert_bound!(mutant, gp_wire::epoch_activation_qc, &qc,
            { mutant.config_id[0] ^= 1; for ack in &mut mutant.witness_acks { ack.context.config_ref.config_id[0] ^= 1; } },
            { mutant.rotation_id[0] ^= 1; for ack in &mut mutant.witness_acks { ack.context.rotation_id[0] ^= 1; } },
            { mutant.predecessor_epoch += 1; for ack in &mut mutant.witness_acks { ack.predecessor_epoch += 1; } },
            { mutant.predecessor_capsule_hash[0] ^= 1; for ack in &mut mutant.witness_acks { ack.predecessor_capsule_hash[0] ^= 1; } },
            { mutant.successor_epoch += 1; for ack in &mut mutant.witness_acks { ack.successor_epoch += 1; } },
            { mutant.successor_capsule_hash[0] ^= 1; for ack in &mut mutant.witness_acks { ack.successor_capsule_hash[0] ^= 1; } },
            { mutant.activation_certificate_hash[0] ^= 1; for ack in &mut mutant.witness_acks { ack.activation_certificate_hash[0] ^= 1; } },
            { mutant.witness_fault_bound += 1; },
            { mutant.witness_acks[2].witness_id = mutant.witness_acks[2].witness_id.wrapping_add(3).max(1); },
            { mutant.witness_acks[0].witness_public_key[0] ^= 1; },
            { mutant.witness_acks[0].context.nonce[0] ^= 1; },
            { mutant.witness_acks[0].witness_signature[0] ^= 1; },
        );

        let challenge = EpochReadChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            client_nonce: nonce,
            response_recipient_key: recipient_key.clone(),
            issued_at,
            expiry,
        };
        assert_bound!(mutant, gp_wire::epoch_read_challenge, &challenge,
            { mutant.config_id[0] ^= 1; },
            { mutant.client_nonce[0] ^= 1; },
            { mutant.response_recipient_key[0] ^= 1; },
            { mutant.issued_at += 1; },
            { mutant.expiry += 1; },
        );

        let read_response = WitnessEpochReadResponse {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            client_nonce: nonce,
            witness_id: signer_id,
            highest_guardian_epoch: retired_epoch,
            capsule_hash: commitment_c,
            witness_public_key: guardian_key,
            witness_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::witness_epoch_read_response, &read_response,
            { mutant.config_id[0] ^= 1; },
            { mutant.client_nonce[0] ^= 1; },
            { mutant.witness_id = mutant.witness_id.wrapping_add(3).max(1); },
            { mutant.highest_guardian_epoch += 1; },
            { mutant.capsule_hash[0] ^= 1; },
            { mutant.witness_public_key[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::witness_epoch_read_response, &read_response,
            { mutant.witness_signature.push(0); },
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn recovery_v3_transcripts_bind_every_field(
        config_id in id32(),
        epoch_binding in id32(),
        request_id in id32(),
        recipient_key in bytes(),
        nonce in id32(),
        digest in id32(),
        guardian_key in id32(),
        membership in bytes(),
        signature in bytes(),
        encrypted in bytes(),
        payload_generation in 1_u64..=100,
        authorization_epoch in 1_u64..=100,
        guardian_epoch in 1_u64..=100,
        (requested_at, expiry) in (0_u64..=1_000_000, 1_u64..=2_000_000).prop_map(|(r, e)| (r, e.max(r + 1))),
        signer_id in 1_u16..=50,
        reason_code in 1_u16..=100,
        signer_count in 3_u16..=20,
        signer_threshold in 1_u16..=3,
        (guardian_count, guardian_threshold) in (3_u16..=20, 2_u16..=20).prop_map(|(c, t)| (c, t.min(c))),
        minimum_recovery_delay in 1_u64..=1_000_000,
        max_request_lifetime in 1_u64..=1_000_000,
        index in 1_u16..=50,
        fragment_index in 1_u16..=50,
    ) {
        let config_ref = config_ref(
            config_id, payload_generation, authorization_epoch, guardian_epoch, epoch_binding,
        );
        let request = RecoveryRequestV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref,
            request_id,
            recovery_recipient_key: recipient_key.clone(),
            requested_at,
            nonce,
            expiry,
        };
        assert_bound!(mutant, gp_wire::recovery_request_v3, &request,
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.payload_generation += 1; },
            { mutant.config_ref.authorization_epoch += 1; },
            { mutant.config_ref.guardian_epoch += 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.requested_at += 1; },
            { mutant.nonce[0] ^= 1; },
            { mutant.expiry += 1; },
        );
        assert_bound!(mutant, gp_wire::recovery_request_digest_v3, &request,
            { mutant.request_id[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
        );
        assert_bound!(mutant,
            |request: &RecoveryRequestV3| gp_wire::recovery_authorization_share_context_v3(request, signer_id),
            &request,
            { mutant.request_id[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
        );
        assert_bound!(mutant,
            |(request, id): &(RecoveryRequestV3, u16)| {
                gp_wire::recovery_authorization_share_context_v3(request, *id)
            },
            &(request.clone(), signer_id),
            { mutant.0.request_id[0] ^= 1; },
            { mutant.1 += 1; },
        );

        let contribution = SignerRecoveryContributionV3 {
            request: request.clone(),
            signer_id,
            signer_public_key: guardian_key,
            signer_membership_proof: membership.clone(),
            encrypted_authorization_share: SealedMessage {
                kem_ciphertext: encrypted.clone(),
                payload: AeadCiphertext { nonce: [7; 24], ciphertext: digest.to_vec() },
            },
            signer_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::signer_recovery_contribution_v3, &contribution,
            { mutant.request.request_id[0] ^= 1; },
            { mutant.request.recovery_recipient_key[0] ^= 1; },
            { mutant.request.nonce[0] ^= 1; },
            { mutant.request.config_ref.epoch_binding[0] ^= 1; },
            { mutant.signer_id = mutant.signer_id.wrapping_add(3).max(1); },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
            { mutant.encrypted_authorization_share.kem_ciphertext[0] ^= 1; },
            { mutant.encrypted_authorization_share.payload.nonce[0] ^= 1; },
            { mutant.encrypted_authorization_share.payload.ciphertext[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::signer_recovery_contribution_v3, &contribution,
            { mutant.signer_signature.push(0); },
        );

        let second_contribution = SignerRecoveryContributionV3 {
            signer_id: signer_id + 1,
            ..contribution.clone()
        };
        let begin_certificate = BeginRecoveryCertificateV3 {
            request: request.clone(),
            request_digest: digest,
            signer_contributions: vec![contribution.clone(), second_contribution],
        };
        assert_bound!(mutant, gp_wire::begin_recovery_certificate_v3, &begin_certificate,
            { mutant.request.request_id[0] ^= 1; for item in &mut mutant.signer_contributions { item.request.request_id[0] ^= 1; } },
            { mutant.request.recovery_recipient_key[0] ^= 1; for item in &mut mutant.signer_contributions { item.request.recovery_recipient_key[0] ^= 1; } },
            { mutant.request.nonce[0] ^= 1; for item in &mut mutant.signer_contributions { item.request.nonce[0] ^= 1; } },
            { mutant.request.config_ref.epoch_binding[0] ^= 1; for item in &mut mutant.signer_contributions { item.request.config_ref.epoch_binding[0] ^= 1; } },
            { mutant.request.requested_at += 1; for item in &mut mutant.signer_contributions { item.request.requested_at += 1; } },
            { mutant.request.expiry += 1; for item in &mut mutant.signer_contributions { item.request.expiry += 1; } },
            { mutant.request_digest[0] ^= 1; },
            { mutant.signer_contributions[1].signer_id = mutant.signer_contributions[1].signer_id.wrapping_add(3).max(1); },
            { mutant.signer_contributions[0].signer_public_key[0] ^= 1; },
            { mutant.signer_contributions[0].signer_membership_proof[0] ^= 1; },
            { mutant.signer_contributions[0].encrypted_authorization_share.kem_ciphertext[0] ^= 1; },
            { mutant.signer_contributions[0].encrypted_authorization_share.payload.nonce[0] ^= 1; },
            { mutant.signer_contributions[0].encrypted_authorization_share.payload.ciphertext[0] ^= 1; },
            { mutant.signer_contributions[0].signer_signature[0] ^= 1; },
        );

        let release_vote = SignerRecoveryReleaseVoteV3 {
            request: request.clone(),
            request_digest: digest,
            signer_id,
            signer_public_key: guardian_key,
            signer_membership_proof: membership.clone(),
            signer_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::signer_recovery_release_vote_v3, &release_vote,
            { mutant.request.request_id[0] ^= 1; },
            { mutant.request.recovery_recipient_key[0] ^= 1; },
            { mutant.request.nonce[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.signer_id = mutant.signer_id.wrapping_add(3).max(1); },
            { mutant.signer_public_key[0] ^= 1; },
            { mutant.signer_membership_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::signer_recovery_release_vote_v3, &release_vote,
            { mutant.signer_signature.push(0); },
        );

        let second_release = SignerRecoveryReleaseVoteV3 {
            signer_id: signer_id + 1,
            ..release_vote.clone()
        };
        let release_certificate = RecoveryReleaseCertificateV3 {
            request: request.clone(),
            request_digest: digest,
            votes: vec![release_vote.clone(), second_release],
        };
        assert_bound!(mutant, gp_wire::recovery_release_certificate_v3, &release_certificate,
            { mutant.request.request_id[0] ^= 1; for vote in &mut mutant.votes { vote.request.request_id[0] ^= 1; } },
            { mutant.request.recovery_recipient_key[0] ^= 1; for vote in &mut mutant.votes { vote.request.recovery_recipient_key[0] ^= 1; } },
            { mutant.request.nonce[0] ^= 1; for vote in &mut mutant.votes { vote.request.nonce[0] ^= 1; } },
            { mutant.request.config_ref.epoch_binding[0] ^= 1; for vote in &mut mutant.votes { vote.request.config_ref.epoch_binding[0] ^= 1; } },
            { mutant.request.expiry += 1; for vote in &mut mutant.votes { vote.request.expiry += 1; } },
            { mutant.request_digest[0] ^= 1; for vote in &mut mutant.votes { vote.request_digest[0] ^= 1; } },
            { mutant.votes[1].signer_id = mutant.votes[1].signer_id.wrapping_add(3).max(1); },
            { mutant.votes[0].signer_public_key[0] ^= 1; },
            { mutant.votes[0].signer_membership_proof[0] ^= 1; },
            { mutant.votes[0].signer_signature[0] ^= 1; },
        );

        let owner_cancel = OwnerRecoveryCancelCertificateV3 {
            request: request.clone(),
            request_digest: digest,
            reason_code,
            cancel_response_recipient_key: recipient_key.clone(),
            owner_cancel_public_key: guardian_key,
            owner_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::owner_recovery_cancel_certificate_v3, &owner_cancel,
            { mutant.request.request_id[0] ^= 1; },
            { mutant.request.recovery_recipient_key[0] ^= 1; },
            { mutant.request.nonce[0] ^= 1; },
            { mutant.request.config_ref.epoch_binding[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.reason_code += 1; },
            { mutant.cancel_response_recipient_key[0] ^= 1; },
            { mutant.owner_cancel_public_key[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::owner_recovery_cancel_certificate_v3, &owner_cancel,
            { mutant.owner_signature.push(0); },
        );

        let owner_ack = OwnerRecoveryCancelAckV3 {
            config_ref,
            request_id,
            request_digest: digest,
            cancel_certificate_hash: digest,
            guardian_index: index,
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::owner_recovery_cancel_ack_v3, &owner_ack,
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.payload_generation += 1; },
            { mutant.config_ref.authorization_epoch += 1; },
            { mutant.config_ref.guardian_epoch += 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.cancel_certificate_hash[0] ^= 1; },
            { mutant.guardian_index += 1; },
        );
        assert_excluded!(mutant, gp_wire::owner_recovery_cancel_ack_v3, &owner_ack,
            { mutant.guardian_signature.push(0); },
        );

        let guardian_contribution = GuardianRecoveryContributionV3 {
            config_ref,
            request_id,
            request_digest: digest,
            recovery_recipient_key: recipient_key.clone(),
            nonce,
            guardian_index: index,
            fragment_index,
            encrypted_ciphertext_fragment: AeadCiphertext {
                nonce: [7; 24],
                ciphertext: encrypted.clone(),
            },
            encrypted_dek_share: AeadCiphertext {
                nonce: [8; 24],
                ciphertext: membership.clone(),
            },
            merkle_path_proof: signature.clone(),
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::guardian_recovery_contribution_v3, &guardian_contribution,
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.payload_generation += 1; },
            { mutant.config_ref.authorization_epoch += 1; },
            { mutant.config_ref.guardian_epoch += 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.request_id[0] ^= 1; },
            { mutant.request_digest[0] ^= 1; },
            { mutant.recovery_recipient_key[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
            { mutant.guardian_index += 1; },
            { mutant.fragment_index += 1; },
            { mutant.encrypted_ciphertext_fragment.nonce[0] ^= 1; },
            { mutant.encrypted_ciphertext_fragment.ciphertext[0] ^= 1; },
            { mutant.encrypted_dek_share.nonce[0] ^= 1; },
            { mutant.encrypted_dek_share.ciphertext[0] ^= 1; },
            { mutant.merkle_path_proof[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::guardian_recovery_contribution_v3, &guardian_contribution,
            { mutant.guardian_signature.push(0); },
        );

        let capsule = ConfigCapsuleV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref,
            capsule_hash: digest,
            predecessor_capsule_hash: digest,
            signer_count,
            signer_threshold,
            guardian_count,
            guardian_threshold,
            minimum_recovery_delay,
            max_request_lifetime,
            signer_set_commitment: guardian_key,
            owner_cancel_public_key: guardian_key,
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: guardian_key,
            ciphertext_fragment_root: digest,
            guardian_material_root: digest,
            encrypted_recovery_descriptor: AeadCiphertext {
                nonce: [7; 24],
                ciphertext: encrypted.clone(),
            },
            activation_certificate: None,
            activation_qc: None,
        };
        assert_bound!(mutant, gp_wire::config_capsule_body_v3, &capsule,
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.payload_generation += 1; },
            { mutant.config_ref.authorization_epoch += 1; },
            { mutant.config_ref.guardian_epoch += 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.predecessor_capsule_hash[0] ^= 1; },
            { mutant.signer_count += 1; },
            { mutant.signer_threshold += 1; },
            { mutant.guardian_count += 1; },
            { mutant.guardian_threshold += 1; },
            { mutant.minimum_recovery_delay += 1; },
            { mutant.max_request_lifetime += 1; },
            { mutant.signer_set_commitment[0] ^= 1; },
            { mutant.owner_cancel_public_key[0] ^= 1; },
            { mutant.dpss_public_commitment[0] ^= 1; },
            { mutant.ciphertext_fragment_root[0] ^= 1; },
            { mutant.guardian_material_root[0] ^= 1; },
            { mutant.encrypted_recovery_descriptor.nonce[0] ^= 1; },
            { mutant.encrypted_recovery_descriptor.ciphertext[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::config_capsule_body_v3, &capsule,
            { mutant.capsule_hash[0] ^= 1; },
            { mutant.activation_certificate = Some(RotationActivateCertificate {
                context: rotation_context(config_ref, [1; 32], [2; 32], vec![6; 32], [7; 32], 10, 100),
                plan_hash: [3; 32],
                ready_certificate_hash: [4; 32],
                successor: config_ref,
                successor_capsule_hash: [5; 32],
                votes: vec![],
            }); },
            { mutant.activation_qc = Some(epoch_activation_qc_placeholder()); },
        );

        let policy = GuardianPolicyV3 {
            config_ref,
            epoch_state: GuardianEpochState::Active,
            signer_set_commitment: guardian_key,
            signer_count,
            signer_threshold,
            owner_cancel_public_key: guardian_key,
            minimum_recovery_delay,
            guardian_material_root: digest,
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment: digest,
            predecessor_capsule_hash: digest,
            activation_qc_hash: Some(digest),
            drain_deadline: Some(expiry),
        };
        assert_bound!(mutant, gp_wire::guardian_policy_body_v3, &policy,
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.payload_generation += 1; },
            { mutant.config_ref.authorization_epoch += 1; },
            { mutant.config_ref.guardian_epoch += 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.signer_set_commitment[0] ^= 1; },
            { mutant.signer_count += 1; },
            { mutant.signer_threshold += 1; },
            { mutant.owner_cancel_public_key[0] ^= 1; },
            { mutant.minimum_recovery_delay += 1; },
            { mutant.dpss_public_commitment[0] ^= 1; },
            { mutant.predecessor_capsule_hash[0] ^= 1; },
        );
        assert_excluded!(mutant, gp_wire::guardian_policy_body_v3, &policy,
            { mutant.epoch_state = GuardianEpochState::Prepared; },
            { mutant.guardian_material_root[0] ^= 1; },
            { mutant.activation_qc_hash = None; },
            { mutant.drain_deadline = None; },
        );

        let custody_challenge = CustodyChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref,
            opaque_slot_id: guardian_key,
            challenge_id: digest,
            block_indices: vec![1, 2, 3],
            nonce,
            response_recipient_key: recipient_key.clone(),
            expiry,
        };
        assert_bound!(mutant, gp_wire::custody_challenge, &custody_challenge,
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.opaque_slot_id[0] ^= 1; },
            { mutant.challenge_id[0] ^= 1; },
            { mutant.block_indices[0] += 1; },
            { mutant.block_indices.push(99); },
            { mutant.nonce[0] ^= 1; },
            { mutant.response_recipient_key[0] ^= 1; },
            { mutant.expiry += 1; },
        );

        let custody_proof = CustodyBlockProof {
            block_index: 1,
            block: encrypted.clone(),
            merkle_path: membership.clone(),
        };
        let custody_response = CustodyResponse {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref,
            opaque_slot_id: guardian_key,
            challenge_id: digest,
            nonce,
            guardian_index: index,
            proofs: vec![custody_proof.clone(), CustodyBlockProof { block_index: 2, ..custody_proof.clone() }],
            guardian_signature: signature.clone(),
        };
        assert_bound!(mutant, gp_wire::custody_response, &custody_response,
            { mutant.config_ref.config_id[0] ^= 1; },
            { mutant.config_ref.guardian_epoch += 1; },
            { mutant.config_ref.epoch_binding[0] ^= 1; },
            { mutant.opaque_slot_id[0] ^= 1; },
            { mutant.challenge_id[0] ^= 1; },
            { mutant.nonce[0] ^= 1; },
            { mutant.guardian_index += 1; },
            { mutant.proofs[0].block_index += 1; },
            { mutant.proofs[0].block[0] ^= 1; },
            { mutant.proofs[0].merkle_path[0] ^= 1; },
            { mutant.proofs.push(CustodyBlockProof { block_index: 3, ..mutant.proofs[0].clone() }); },
        );
        assert_excluded!(mutant, gp_wire::custody_response, &custody_response,
            { mutant.guardian_signature.push(0); },
        );
    }
}
