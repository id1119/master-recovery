use gp_types::*;
use proptest::prelude::*;

fn id32() -> impl Strategy<Value = Id32> {
    prop::array::uniform32(0_u8..)
}

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..=128)
}

fn string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 1..=32)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

fn roundtrip<T>(value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_vec(value).expect("serialize");
    let decoded: T = serde_json::from_slice(&encoded).expect("deserialize");
    assert_eq!(*value, decoded);
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

fn aead(seed: u8) -> AeadCiphertext {
    AeadCiphertext {
        nonce: [seed; 24],
        ciphertext: vec![seed; 64],
    }
}

fn sealed(seed: u8) -> SealedMessage {
    SealedMessage {
        kem_ciphertext: vec![seed; 16],
        payload: aead(seed),
    }
}

fn prepared_record_leaf(seed: u8) -> PreparedRecordLeaf {
    PreparedRecordLeaf {
        guardian_index: seed as u16,
        fragment_index: seed as u16 + 1,
        opaque_slot_id: [seed; 32],
        encrypted_share_hash: [seed; 32],
        fragment_hash: [seed; 32],
        policy_hash: [seed; 32],
    }
}

fn policy_v3(config_ref: ConfigRef, seed: u8) -> GuardianPolicyV3 {
    GuardianPolicyV3 {
        config_ref,
        epoch_state: GuardianEpochState::Active,
        signer_set_commitment: [seed; 32],
        signer_count: 3,
        signer_threshold: 2,
        owner_cancel_public_key: [seed; 32],
        minimum_recovery_delay: 60,
        guardian_material_root: [seed; 32],
        dpss_suite: DpssSuiteId::default(),
        dpss_public_commitment: [seed; 32],
        predecessor_capsule_hash: [seed; 32],
        activation_qc_hash: None,
        drain_deadline: None,
    }
}

fn record_v3(config_ref: ConfigRef, seed: u8) -> GuardianRecordV3 {
    GuardianRecordV3 {
        opaque_slot_id: [seed; 32],
        guardian_index: seed as u16,
        fragment_index: seed as u16 + 1,
        encrypted_ciphertext_fragment: aead(seed),
        encrypted_dek_share: aead(seed + 1),
        merkle_path_proof: vec![seed; 16],
        custody_root: [seed; 32],
        policy: policy_v3(config_ref, seed),
    }
}

fn routes(config_id: Id32, seed: u8, count: usize) -> Vec<GuardianRouteV3> {
    (1..=count)
        .map(|index| GuardianRouteV3 {
            guardian_index: index as u16,
            opaque_slot_id: [index as u8; 32],
            mailbox: format!("mbx-{index}"),
            guardian_public_key: [seed; 32],
            session_recipient_key: vec![seed; 16],
            operator_domain_commitment: config_id,
        })
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn config_ref_and_routes_roundtrip(
        config_id in id32(),
        payload_generation in 1_u64..=1_000_000,
        authorization_epoch in 1_u64..=1_000_000,
        guardian_epoch in 1_u64..=1_000_000,
        epoch_binding in id32(),
        guardian_index in 1_u16..=10_000,
        opaque_slot_id in id32(),
        mailbox in string(),
        guardian_public_key in id32(),
        session_recipient_key in bytes(),
        operator_domain_commitment in id32(),
    ) {
        roundtrip(&config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch, epoch_binding));
        roundtrip(&GuardianRouteV3 {
            guardian_index,
            opaque_slot_id,
            mailbox,
            guardian_public_key,
            session_recipient_key,
            operator_domain_commitment,
        });
    }

    #[test]
    fn rotation_artifacts_roundtrip(
        config_id in id32(),
        payload_generation in 1_u64..=1_000_000,
        authorization_epoch in 1_u64..=1_000_000,
        guardian_epoch in 1_u64..=1_000_000,
        epoch_binding in id32(),
        rotation_id in id32(),
        predecessor_hash in id32(),
        recipient_key in bytes(),
        nonce in id32(),
        (issued_at, expiry) in (0_u64..=1_000_000, 1_u64..=2_000_000).prop_map(|(i, e)| (i, e.max(i + 1))),
        plan_hash in id32(),
        old_roster_commitment in id32(),
        new_roster_commitment in id32(),
        signer_id in 1_u16..=50,
        signer_public_key in id32(),
        membership_proof in bytes(),
        signature in bytes(),
        begin_certificate_hash in id32(),
        ready_certificate_hash in id32(),
        release_certificate_hash in id32(),
        cancel_hash in id32(),
        witness_id in 1_u16..=50,
        witness_public_key in id32(),
        witness_signature in bytes(),
        reason_code in 1_u16..=100,
        intent_hash in id32(),
        old_guardian_count in 3_u16..=20,
        old_guardian_threshold in 2_u16..=3,
        data_shards in 1_u16..=10,
        total_shards in 10_u16..=20,
        dpss_session_id in id32(),
        qualified_set_commitment in id32(),
        minimum_delay_secs in 1_u64..=1_000_000,
        preparation_deadline in 1_u64..=1_000_000,
        drain_deadline in 1_u64..=1_000_000,
        sequence in 1_u64..=1_000_000,
        provider_payload in bytes(),
        sender_index in 1_u16..=50,
        recipient_index in 1_u16..=50,
        fragment_index in 1_u16..=50,
        fragment_commitment in id32(),
        custody_root in id32(),
        durable_write_generation in 1_u64..=1_000_000,
        retired_epoch in 1_u64..=1_000_000,
        tombstone_hash in id32(),
        state_code in 1_u8..=3,
        consecutive_failures in 0_u16..=100,
        challenge_id in id32(),
        last_success_at in 0_u64..=1_000_000,
        evidence in prop::collection::vec(id32(), 0..=4),
    ) {
        let context = RotationContext {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch, epoch_binding),
            rotation_id,
            predecessor_capsule_hash: predecessor_hash,
            recipient_key: recipient_key.clone(),
            nonce,
            issued_at,
            expiry,
        };
        roundtrip(&context);

        let successor = config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch + 1, epoch_binding);
        let old_roster = routes(config_id, 1, 3);
        let new_roster = routes(config_id, 2, 4);

        roundtrip(&RotationIntent {
            context: context.clone(),
            reason: RotationReason::ProactiveRefresh,
            old_guardian_count,
            old_guardian_threshold,
            allowed_new_guardian_count: vec![3, 4, 5],
            allowed_new_guardian_threshold: vec![2, 3],
            allowed_dpss_suites: vec![DpssSuiteId::default()],
            selection_constraints_commitment: intent_hash,
            witness_read_qc_hash: cancel_hash,
        });

        roundtrip(&SignerRotationIntentContribution {
            context: context.clone(),
            intent_hash,
            signer_id,
            signer_public_key,
            signer_membership_proof: membership_proof.clone(),
            encrypted_authorization_share: sealed(3),
            signer_signature: signature.clone(),
        });

        roundtrip(&RotationPlan {
            context: context.clone(),
            intent_hash,
            predecessor: context.config_ref.clone(),
            successor,
            old_roster: old_roster.clone(),
            new_roster: new_roster.clone(),
            old_roster_commitment,
            new_roster_commitment,
            old_guardian_threshold,
            new_guardian_threshold: old_guardian_threshold,
            data_shards,
            total_shards,
            dpss_suite: DpssSuiteId::default(),
            dpss_session_id,
            dpss_qualified_set_commitment: qualified_set_commitment,
            minimum_delay_secs: minimum_delay_secs,
            preparation_deadline,
            drain_deadline,
        });

        roundtrip(&SignerRotationBeginVote {
            context: context.clone(),
            intent_hash,
            plan_hash,
            old_roster_commitment,
            new_roster_commitment,
            signer_id,
            signer_public_key,
            signer_membership_proof: membership_proof.clone(),
            signer_signature: signature.clone(),
        });

        roundtrip(&BeginRotationCertificate {
            context: context.clone(),
            intent_hash,
            plan_hash,
            old_roster_commitment,
            new_roster_commitment,
            not_before_wall: issued_at,
            votes: vec![SignerRotationBeginVote {
                context: context.clone(),
                intent_hash,
                plan_hash,
                old_roster_commitment,
                new_roster_commitment,
                signer_id,
                signer_public_key,
                signer_membership_proof: membership_proof.clone(),
                signer_signature: signature.clone(),
            }],
        });

        roundtrip(&OwnerRotationCancelCertificate {
            context: context.clone(),
            plan_hash,
            reason_code,
            cancel_response_recipient_key: recipient_key.clone(),
            owner_cancel_public_key: signer_public_key,
            owner_signature: signature.clone(),
        });

        roundtrip(&OwnerRotationCancelAck {
            context: context.clone(),
            plan_hash,
            cancel_certificate_hash: cancel_hash,
            guardian_index: signer_id,
            guardian_signature: signature.clone(),
        });

        roundtrip(&SignerRotationReleaseVote {
            context: context.clone(),
            plan_hash,
            begin_certificate_hash,
            signer_id,
            signer_public_key,
            signer_membership_proof: membership_proof.clone(),
            signer_signature: signature.clone(),
        });

        roundtrip(&RotationReleaseCertificate {
            context: context.clone(),
            plan_hash,
            begin_certificate_hash,
            votes: vec![SignerRotationReleaseVote {
                context: context.clone(),
                plan_hash,
                begin_certificate_hash,
                signer_id,
                signer_public_key,
                signer_membership_proof: membership_proof.clone(),
                signer_signature: signature.clone(),
            }],
        });

        roundtrip(&OldShareUnlockGrant {
            context: context.clone(),
            plan_hash,
            release_certificate_hash,
            old_guardian_index: signer_id,
            encrypted_unwrap_key: sealed(4),
            encrypted_fragment_key: sealed(5),
        });

        roundtrip(&NewShareWrapGrant {
            context: context.clone(),
            plan_hash,
            release_certificate_hash,
            new_guardian_index: signer_id,
            encrypted_wrap_key: sealed(6),
            encrypted_fragment_key: sealed(7),
        });

        roundtrip(&DpssProtocolMessage {
            context: context.clone(),
            plan_hash,
            dpss_suite: DpssSuiteId::default(),
            dpss_session_id,
            qualified_set_commitment,
            phase: DpssPhase::RefreshRound2,
            sender_index,
            recipient_index,
            sequence,
            provider_payload,
            sender_signature: signature.clone(),
        });

        roundtrip(&CiphertextFragmentContribution {
            context: context.clone(),
            plan_hash,
            release_certificate_hash,
            old_guardian_index: signer_id,
            fragment_index,
            ciphertext_fragment: vec![9; 64],
            fragment_commitment,
            prepared_record_leaf: prepared_record_leaf(3),
            merkle_path_proof: membership_proof.clone(),
            guardian_signature: signature.clone(),
        });

        roundtrip(&PreparedRecordLeaf {
            guardian_index: signer_id,
            fragment_index,
            opaque_slot_id: custody_root,
            encrypted_share_hash: intent_hash,
            fragment_hash: fragment_commitment,
            policy_hash: plan_hash,
        });

        roundtrip(&NewGuardianPreparedAck {
            context: context.clone(),
            plan_hash,
            dpss_result_commitment: qualified_set_commitment,
            guardian_material_root: new_roster_commitment,
            new_guardian_index: signer_id,
            prepared_record_leaf: prepared_record_leaf(5),
            durable_write_generation,
            guardian_signature: signature.clone(),
        });

        roundtrip(&OldGuardianHandoffAck {
            context: context.clone(),
            plan_hash,
            dpss_result_commitment: qualified_set_commitment,
            qualified_set_commitment,
            old_guardian_index: signer_id,
            guardian_signature: signature.clone(),
        });

        roundtrip(&RotationReadyCertificate {
            context: context.clone(),
            plan_hash,
            successor: config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch + 1, epoch_binding),
            dpss_result_commitment: qualified_set_commitment,
            guardian_material_root: new_roster_commitment,
            encrypted_descriptor_hash: custody_root,
            prepared_acks: vec![NewGuardianPreparedAck {
                context: context.clone(),
                plan_hash,
                dpss_result_commitment: qualified_set_commitment,
                guardian_material_root: new_roster_commitment,
                new_guardian_index: signer_id,
                prepared_record_leaf: prepared_record_leaf(6),
                durable_write_generation,
                guardian_signature: signature.clone(),
            }],
            old_handoff_acks: vec![OldGuardianHandoffAck {
                context: context.clone(),
                plan_hash,
                dpss_result_commitment: qualified_set_commitment,
                qualified_set_commitment,
                old_guardian_index: signer_id,
                guardian_signature: signature.clone(),
            }],
        });

        roundtrip(&SignerRotationActivateVote {
            context: context.clone(),
            plan_hash,
            ready_certificate_hash,
            successor_capsule_hash: new_roster_commitment,
            signer_id,
            signer_public_key,
            signer_membership_proof: membership_proof.clone(),
            signer_signature: signature.clone(),
        });

        roundtrip(&RotationActivateCertificate {
            context: context.clone(),
            plan_hash,
            ready_certificate_hash,
            successor: config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch + 1, epoch_binding),
            successor_capsule_hash: new_roster_commitment,
            votes: vec![SignerRotationActivateVote {
                context: context.clone(),
                plan_hash,
                ready_certificate_hash,
                successor_capsule_hash: new_roster_commitment,
                signer_id,
                signer_public_key,
                signer_membership_proof: membership_proof.clone(),
                signer_signature: signature.clone(),
            }],
        });

        roundtrip(&WitnessActivationAck {
            context: context.clone(),
            plan_hash,
            activation_certificate_hash: ready_certificate_hash,
            witness_id,
            predecessor_epoch: issued_at,
            predecessor_capsule_hash: predecessor_hash,
            successor_epoch: expiry,
            successor_capsule_hash: new_roster_commitment,
            witness_public_key,
            witness_signature: witness_signature.clone(),
        });

        roundtrip(&WitnessRotationCancelAck {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            rotation_id,
            plan_hash,
            cancel_certificate_hash: cancel_hash,
            witness_id,
            witness_public_key,
            witness_signature: witness_signature.clone(),
        });

        roundtrip(&EpochActivationQc {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            rotation_id,
            predecessor_epoch: issued_at,
            predecessor_capsule_hash: predecessor_hash,
            successor_epoch: expiry,
            successor_capsule_hash: new_roster_commitment,
            activation_certificate_hash: ready_certificate_hash,
            witness_fault_bound: 0,
            witness_acks: vec![WitnessActivationAck {
                context: context.clone(),
                plan_hash,
                activation_certificate_hash: ready_certificate_hash,
                witness_id,
                predecessor_epoch: issued_at,
                predecessor_capsule_hash: predecessor_hash,
                successor_epoch: expiry,
                successor_capsule_hash: new_roster_commitment,
                witness_public_key,
                witness_signature: witness_signature.clone(),
            }],
        });

        roundtrip(&EpochReadChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            client_nonce: nonce,
            response_recipient_key: recipient_key.clone(),
            issued_at,
            expiry,
        });

        roundtrip(&WitnessEpochReadResponse {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            client_nonce: nonce,
            witness_id,
            highest_guardian_epoch: expiry,
            capsule_hash: new_roster_commitment,
            witness_public_key,
            witness_signature: witness_signature.clone(),
        });

        roundtrip(&RetirementNotice {
            context: context.clone(),
            plan_hash,
            activation_qc_hash: ready_certificate_hash,
            retired_epoch,
            drain_deadline,
        });

        roundtrip(&RetirementAck {
            context: context.clone(),
            plan_hash,
            activation_qc_hash: ready_certificate_hash,
            guardian_index: signer_id,
            retired_epoch,
            tombstone_hash,
            guardian_signature: signature.clone(),
        });

        roundtrip(&SignerRotationAbortVote {
            context: context.clone(),
            plan_hash,
            state_at_abort: match state_code {
                1 => RotationState::Proposed,
                2 => RotationState::Preparing,
                _ => RotationState::Activating,
            },
            reason_code,
            signer_id,
            signer_public_key,
            signer_membership_proof: membership_proof.clone(),
            signer_signature: signature.clone(),
        });

        roundtrip(&AbortRotationCertificate {
            context: context.clone(),
            plan_hash,
            state_at_abort: RotationState::Preparing,
            reason_code,
            votes: vec![SignerRotationAbortVote {
                context: context.clone(),
                plan_hash,
                state_at_abort: RotationState::Preparing,
                reason_code,
                signer_id,
                signer_public_key,
                signer_membership_proof: membership_proof.clone(),
                signer_signature: signature.clone(),
            }],
        });

        roundtrip(&GuardianHealthRecord {
            config_ref: context.config_ref.clone(),
            guardian_index: signer_id,
            state: GuardianHealthState::Healthy,
            consecutive_failures,
            last_challenge_id: Some(challenge_id),
            last_success_at: Some(last_success_at),
            evidence_hashes: evidence,
        });
    }

    #[test]
    fn recovery_artifacts_roundtrip(
        config_id in id32(),
        payload_generation in 1_u64..=1_000_000,
        authorization_epoch in 1_u64..=1_000_000,
        guardian_epoch in 1_u64..=1_000_000,
        epoch_binding in id32(),
        request_id in id32(),
        recipient_key in bytes(),
        (requested_at, expiry) in (0_u64..=1_000_000, 1_u64..=2_000_000).prop_map(|(r, e)| (r, e.max(r + 1))),
        nonce in id32(),
        signer_id in 1_u16..=50,
        signer_public_key in id32(),
        membership_proof in bytes(),
        signature in bytes(),
        reason_code in 1_u16..=100,
        guardian_index in 1_u16..=50,
        fragment_index in 1_u16..=50,
        capsule_hash in id32(),
        predecessor_capsule_hash in id32(),
        signer_count in 3_u16..=20,
        signer_threshold in 2_u16..=3,
        guardian_count in 3_u16..=20,
        guardian_threshold in 2_u16..=3,
        minimum_recovery_delay in 1_u64..=1_000_000,
        max_request_lifetime in 1_u64..=1_000_000,
        owner_cancel_public_key in id32(),
        dpss_public_commitment in id32(),
        guardian_material_root in id32(),
        data_shards in 1_u16..=10,
        total_shards in 10_u16..=20,
        ciphertext_len in 1_u64..=1_000_000,
        payload_nonce in prop::array::uniform24(0_u8..),
        dpss_public_package in bytes(),
        opaque_slot_id in id32(),
        challenge_id in id32(),
        block_indices in prop::collection::vec(1_u32..=100, 1..=4),
        block in bytes(),
        merkle_path in bytes(),
        routes_len in 1_usize..=8,
    ) {
        let config_ref = config_ref(config_id, payload_generation, authorization_epoch, guardian_epoch, epoch_binding);
        let request = RecoveryRequestV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config_ref.clone(),
            request_id,
            recovery_recipient_key: recipient_key.clone(),
            requested_at,
            nonce,
            expiry,
        };
        roundtrip(&request);

        roundtrip(&SignerRecoveryContributionV3 {
            request: request.clone(),
            signer_id,
            signer_public_key,
            signer_membership_proof: membership_proof.clone(),
            encrypted_authorization_share: sealed(1),
            signer_signature: signature.clone(),
        });

        roundtrip(&BeginRecoveryCertificateV3 {
            request: request.clone(),
            request_digest: capsule_hash,
            signer_contributions: vec![SignerRecoveryContributionV3 {
                request: request.clone(),
                signer_id,
                signer_public_key,
                signer_membership_proof: membership_proof.clone(),
                encrypted_authorization_share: sealed(1),
                signer_signature: signature.clone(),
            }],
        });

        roundtrip(&SignerRecoveryReleaseVoteV3 {
            request: request.clone(),
            request_digest: capsule_hash,
            signer_id,
            signer_public_key,
            signer_membership_proof: membership_proof.clone(),
            signer_signature: signature.clone(),
        });

        roundtrip(&RecoveryReleaseCertificateV3 {
            request: request.clone(),
            request_digest: capsule_hash,
            votes: vec![SignerRecoveryReleaseVoteV3 {
                request: request.clone(),
                request_digest: capsule_hash,
                signer_id,
                signer_public_key,
                signer_membership_proof: membership_proof.clone(),
                signer_signature: signature.clone(),
            }],
        });

        roundtrip(&OwnerRecoveryCancelCertificateV3 {
            request: request.clone(),
            request_digest: capsule_hash,
            reason_code,
            cancel_response_recipient_key: recipient_key.clone(),
            owner_cancel_public_key,
            owner_signature: signature.clone(),
        });

        roundtrip(&OwnerRecoveryCancelAckV3 {
            config_ref: config_ref.clone(),
            request_id,
            request_digest: capsule_hash,
            cancel_certificate_hash: capsule_hash,
            guardian_index,
            guardian_signature: signature.clone(),
        });

        roundtrip(&GuardianRecoveryContributionV3 {
            config_ref: config_ref.clone(),
            request_id,
            request_digest: capsule_hash,
            recovery_recipient_key: recipient_key.clone(),
            nonce,
            guardian_index,
            fragment_index,
            encrypted_ciphertext_fragment: aead(2),
            encrypted_dek_share: aead(3),
            merkle_path_proof: merkle_path.clone(),
            guardian_signature: signature.clone(),
        });

        roundtrip(&RecoveryDescriptorV3 {
            config_ref: config_ref.clone(),
            guardians: routes(config_id, 4, routes_len),
            guardian_material_root,
            data_shards,
            total_shards,
            ciphertext_len,
            payload_nonce,
            dpss_suite: DpssSuiteId::default(),
            dpss_public_package,
            dpss_public_commitment,
        });

        roundtrip(&ConfigCapsuleV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config_ref.clone(),
            capsule_hash,
            predecessor_capsule_hash,
            signer_count,
            signer_threshold,
            guardian_count,
            guardian_threshold,
            minimum_recovery_delay,
            max_request_lifetime,
            signer_set_commitment: signer_public_key,
            owner_cancel_public_key,
            dpss_suite: DpssSuiteId::default(),
            dpss_public_commitment,
            ciphertext_fragment_root: capsule_hash,
            guardian_material_root,
            encrypted_recovery_descriptor: aead(5),
            activation_certificate: None,
            activation_qc: None,
        });

        roundtrip(&RecoveryCardV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_id,
            signer_mailboxes: vec!["signer-1".to_string()],
            signer_set_commitment: signer_public_key,
            owner_cancel_public_key,
            witness_fault_bound: 1,
            witnesses: vec![WitnessPin {
                witness_id: guardian_index,
                mailbox: "witness-1".to_string(),
                public_key: signer_public_key,
            }],
            relay_bases: vec!["relay-1".to_string()],
        });

        roundtrip(&policy_v3(config_ref.clone(), 7));

        roundtrip(&record_v3(config_ref.clone(), 8));

        roundtrip(&CustodyChallenge {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config_ref.clone(),
            opaque_slot_id,
            challenge_id,
            block_indices: block_indices.clone(),
            nonce,
            response_recipient_key: recipient_key.clone(),
            expiry,
        });

        let proofs: Vec<CustodyBlockProof> = block_indices
            .into_iter()
            .map(|block_index| CustodyBlockProof {
                block_index,
                block: block.clone(),
                merkle_path: merkle_path.clone(),
            })
            .collect();
        roundtrip(&CustodyResponse {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: config_ref.clone(),
            opaque_slot_id,
            challenge_id,
            nonce,
            guardian_index,
            proofs,
            guardian_signature: signature,
        });
    }
}

#[test]
fn legacy_card_and_v2_artifacts_roundtrip() {
    let guardians = (1..=3u16)
        .map(|index| GuardianRoute {
            mailbox: format!("mbx-{index}"),
            opaque_slot_id: [index as u8; 32],
            guardian_index: index,
            guardian_public_key: [index as u8; 32],
        })
        .collect();
    let card = RecoveryCard {
        config_id: [1; 32],
        capsule_locators: vec!["capsule-1".to_string()],
        capsule_locator: Some("capsule-0".to_string()),
        signer_mailboxes: vec!["signer-1".to_string()],
        relay_bases: vec!["relay-1".to_string()],
        signer_set_commitment: [2; 32],
        owner_cancel_public_key: [15; 32],
    };
    roundtrip(&card);

    let descriptor = RecoveryDescriptor {
        guardians,
        guardian_material_root: [23; 32],
        data_shards: 4,
        total_shards: 6,
        ciphertext_len: 1024,
        payload_nonce: [24; 24],
    };
    roundtrip(&descriptor);

    let request = RecoveryRequest {
        protocol_version: 2,
        crypto_suite: CryptoSuite::XWingXChaCha20Poly1305Ed25519,
        config_id: [1; 32],
        config_version: 7,
        request_id: [7; 32],
        recovery_recipient_key: vec![8; 32],
        requested_at: 100,
        nonce: [9; 32],
        expiry: 200,
    };
    let contribution = SignerContribution {
        request: request.clone(),
        signer_id: 1,
        signer_public_key: [10; 32],
        signer_signature: vec![13],
        signer_membership_proof: vec![11],
        encrypted_a_share: sealed(4),
    };
    roundtrip(&contribution);
    roundtrip(&BeginRecoveryCertificate {
        request: request.clone(),
        signer_contributions: vec![contribution],
    });
    roundtrip(&ReleaseVote {
        protocol_version: 2,
        config_id: [1; 32],
        config_version: 7,
        request_id: [7; 32],
        request_digest: [12; 32],
        recovery_recipient_key: vec![8; 32],
        nonce: [9; 32],
        signer_id: 1,
        signer_public_key: [10; 32],
        signer_membership_proof: vec![11],
        signer_signature: vec![13],
    });
    roundtrip(&ReleaseCertificate { votes: vec![] });
    roundtrip(&OwnerCancelCertificate {
        protocol_version: 2,
        config_id: [1; 32],
        config_version: 7,
        request_id: [7; 32],
        request_digest: [12; 32],
        recovery_recipient_key: vec![8; 32],
        cancel_response_recipient_key: vec![14; 32],
        reason_code: 1,
        nonce: [9; 32],
        issued_at: 150,
        owner_cancel_public_key: [15; 32],
        owner_signature: vec![16],
    });
    roundtrip(&OwnerCancelAck {
        protocol_version: 2,
        config_id: [1; 32],
        config_version: 7,
        request_id: [7; 32],
        request_digest: [12; 32],
        owner_cancel_transcript_digest: [17; 32],
        guardian_index: 2,
        guardian_signature: vec![18],
    });
    roundtrip(&GuardianContribution {
        protocol_version: 2,
        config_id: [1; 32],
        config_version: 7,
        request_id: [7; 32],
        request_digest: [12; 32],
        guardian_index: 2,
        ciphertext_fragment: vec![20; 64],
        encrypted_dek_share: aead(6),
        merkle_path_proof: vec![21],
        guardian_signature: vec![22],
    });
    roundtrip(&ConfigCapsule {
        protocol_version: 2,
        crypto_suite: CryptoSuite::XWingXChaCha20Poly1305Ed25519,
        config_id: [1; 32],
        config_version: 7,
        signer_count: 3,
        signer_threshold: 2,
        guardian_count: 3,
        guardian_threshold: 2,
        minimum_recovery_delay: 60,
        signer_set_commitment: [2; 32],
        owner_cancel_public_key: [15; 32],
        guardian_material_commitment: [23; 32],
        encrypted_recovery_descriptor: aead(7),
        max_request_lifetime: 3600,
    });
    roundtrip(&SignerPolicy {
        config_id: [1; 32],
        config_version: 7,
        signer_set_commitment: [2; 32],
        signer_threshold: 2,
    });
    roundtrip(&GuardianPolicy {
        config_id: [1; 32],
        config_version: 7,
        signer_set_commitment: [2; 32],
        signer_count: 3,
        signer_threshold: 2,
        owner_cancel_public_key: [15; 32],
        minimum_recovery_delay: 60,
        guardian_material_root: [23; 32],
    });
    roundtrip(&GuardianRecord {
        opaque_slot_id: [26; 32],
        guardian_index: 2,
        ciphertext_fragment: vec![27; 64],
        encrypted_dek_share: aead(28),
        merkle_path_proof: vec![29],
        policy: GuardianPolicy {
            config_id: [1; 32],
            config_version: 7,
            signer_set_commitment: [2; 32],
            signer_count: 3,
            signer_threshold: 2,
            owner_cancel_public_key: [15; 32],
            minimum_recovery_delay: 60,
            guardian_material_root: [23; 32],
        },
    });
    roundtrip(&AeadCiphertext {
        nonce: [30; 24],
        ciphertext: vec![31; 16],
    });
    roundtrip(&SealedMessage {
        kem_ciphertext: vec![32; 16],
        payload: aead(33),
    });
    roundtrip(&SetupPolicy {
        signer_count: 3,
        signer_threshold: 2,
        guardian_count: 3,
        guardian_threshold: 2,
        minimum_recovery_delay: 60,
    });
    roundtrip(&PendingRecovery {
        request_id: [34; 32],
        config_id: [1; 32],
        config_version: 7,
        recipient: vec![35; 32],
        started_at_monotonic: 1,
        not_before: 2,
        state: RecoveryState::DelayPending,
    });
}
