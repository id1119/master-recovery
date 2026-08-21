use gp_core::{Action, CoreError, GuardianMachine, RecoveryEvent, RecoveryMachine};
use gp_types::{CryptoSuite, PROTOCOL_VERSION, RecoveryRequest, RecoveryState};
use proptest::prelude::*;

fn event_strategy() -> impl Strategy<Value = RecoveryEvent> {
    prop_oneof![
        Just(RecoveryEvent::RequestCreated),
        Just(RecoveryEvent::ApprovalThresholdReached),
        Just(RecoveryEvent::BeginAccepted),
        Just(RecoveryEvent::ReleaseCertificateReady),
        Just(RecoveryEvent::GuardianThresholdReached),
        Just(RecoveryEvent::OwnerCancelObserved),
        Just(RecoveryEvent::ExpiryReached),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelState {
    Active(RecoveryState),
    Terminal(RecoveryState),
}

struct Model {
    state: ModelState,
    not_before: Option<u64>,
}

impl Model {
    fn new() -> Self {
        Self {
            state: ModelState::Active(RecoveryState::Created),
            not_before: None,
        }
    }

    fn step(
        &mut self,
        event: &RecoveryEvent,
        now: u64,
        delay: u64,
    ) -> Result<Vec<Action>, CoreError> {
        match self.state {
            ModelState::Terminal(state) => {
                let err = if state == RecoveryState::Cancelled {
                    CoreError::Cancelled
                } else {
                    CoreError::Expired
                };
                Err(err)
            }
            ModelState::Active(from) => {
                let (to, actions) = match (from, event) {
                    (RecoveryState::Created, RecoveryEvent::RequestCreated) => (
                        RecoveryState::AwaitingApprovals,
                        vec![Action::RequestSignerApprovals],
                    ),
                    (RecoveryState::AwaitingApprovals, RecoveryEvent::ApprovalThresholdReached) => {
                        (
                            RecoveryState::Authorized,
                            vec![
                                Action::DecryptRecoveryDescriptor,
                                Action::SendBeginCertificate,
                            ],
                        )
                    }
                    (RecoveryState::AwaitingApprovals, RecoveryEvent::OwnerCancelObserved)
                    | (RecoveryState::Authorized, RecoveryEvent::OwnerCancelObserved)
                    | (RecoveryState::DelayPending, RecoveryEvent::OwnerCancelObserved) => (
                        RecoveryState::Cancelled,
                        vec![Action::RefuseRelease, Action::ZeroizeRecoverySecrets],
                    ),
                    (RecoveryState::Authorized, RecoveryEvent::BeginAccepted) => {
                        self.not_before = Some(now.saturating_add(delay));
                        (
                            RecoveryState::DelayPending,
                            vec![
                                Action::WaitUntil(now.saturating_add(delay)),
                                Action::RequestReleaseVotes,
                            ],
                        )
                    }
                    (RecoveryState::DelayPending, RecoveryEvent::ReleaseCertificateReady) => {
                        if now < self.not_before.unwrap_or(u64::MAX) {
                            return Err(CoreError::InvalidTransition { from });
                        }
                        (
                            RecoveryState::Releasing,
                            vec![Action::RequestGuardianContributions],
                        )
                    }
                    (RecoveryState::Releasing, RecoveryEvent::GuardianThresholdReached) => (
                        RecoveryState::Completed,
                        vec![Action::ReconstructLocally, Action::ZeroizeRecoverySecrets],
                    ),
                    (RecoveryState::Created, RecoveryEvent::ExpiryReached)
                    | (RecoveryState::AwaitingApprovals, RecoveryEvent::ExpiryReached)
                    | (RecoveryState::Authorized, RecoveryEvent::ExpiryReached)
                    | (RecoveryState::DelayPending, RecoveryEvent::ExpiryReached)
                    | (RecoveryState::Releasing, RecoveryEvent::ExpiryReached)
                    | (RecoveryState::Completed, RecoveryEvent::ExpiryReached) => (
                        RecoveryState::Expired,
                        vec![Action::RefuseRelease, Action::ZeroizeRecoverySecrets],
                    ),
                    _ => return Err(CoreError::InvalidTransition { from }),
                };
                self.state = match to {
                    RecoveryState::Cancelled | RecoveryState::Expired => ModelState::Terminal(to),
                    other => ModelState::Active(other),
                };
                Ok(actions)
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn random_sequences_agree_with_spec_model(
        events in prop::collection::vec(event_strategy(), 0..64),
        nows in prop::collection::vec(0_u64..=20, 64),
        delays in prop::collection::vec(0_u64..=5, 64),
    ) {
        let mut machine = RecoveryMachine::default();
        let mut model = Model::new();
        for (i, event) in events.iter().enumerate() {
            let now = nows[i.min(nows.len() - 1)];
            let delay = delays[i.min(delays.len() - 1)];
            let actual = machine.apply(event.clone(), now, delay);
            let expected = model.step(event, now, delay);
            match (actual, expected) {
                (Ok(actions), Ok(expected_actions)) => {
                    prop_assert_eq!(
                        actions, expected_actions,
                        "action divergence at step {}",
                        i
                    );
                }
                (Err(CoreError::InvalidTransition { from }), Err(CoreError::InvalidTransition { from: expected_from })) => {
                    prop_assert_eq!(from, expected_from, "invalid transition mismatch at step {}", i);
                }
                (Err(actual_err), Err(expected_err)) => {
                    prop_assert_eq!(actual_err, expected_err, "error mismatch at step {}", i);
                }
                (actual, expected) => {
                    panic!("model divergence at step {i}: actual={actual:?} expected={expected:?}");
                }
            }
            let state = machine.state();
            let model_state = match model.state {
                ModelState::Active(s) | ModelState::Terminal(s) => s,
            };
            prop_assert_eq!(state, model_state, "state divergence at step {}", i);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn cancelled_and_expired_are_permanent(
        events in prop::collection::vec(event_strategy(), 0..64),
        nows in prop::collection::vec(0_u64..=20, 64),
        delays in prop::collection::vec(0_u64..=5, 64),
    ) {
        let mut machine = RecoveryMachine::default();
        for (i, event) in events.iter().enumerate() {
            let now = nows[i.min(nows.len() - 1)];
            let delay = delays[i.min(delays.len() - 1)];
            let _ = machine.apply(event.clone(), now, delay);
            let state = machine.state();
            if state == RecoveryState::Cancelled {
                for later in events.iter().skip(i) {
                    let now = nows[i.min(nows.len() - 1)];
                    prop_assert_eq!(
                        machine.apply(later.clone(), now, delay),
                        Err(CoreError::Cancelled)
                    );
                }
                break;
            }
            if state == RecoveryState::Expired {
                for later in events.iter().skip(i) {
                    prop_assert_eq!(
                        machine.apply(later.clone(), now, delay),
                        Err(CoreError::Expired)
                    );
                }
                break;
            }
        }
    }
}

fn request(
    config_version: u64,
    request_id: [u8; 32],
    nonce: [u8; 32],
    requested_at: u64,
    expiry: u64,
) -> RecoveryRequest {
    RecoveryRequest {
        protocol_version: PROTOCOL_VERSION,
        crypto_suite: CryptoSuite::default(),
        config_id: [1; 32],
        config_version,
        request_id,
        recovery_recipient_key: vec![3; 1216],
        requested_at,
        nonce,
        expiry,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn guardian_machine_threat_scenarios(
        delay in 0_u64..=10,
        wall in 0_u64..=100,
        monotonic in 0_u64..=100,
        expiry in 50_u64..=200,
        requested_at in 0_u64..=40,
        version in 1_u64..=10,
    ) {
        let mut machine = GuardianMachine::new([1; 32], version);
        let req = request(version, [2; 32], [3; 32], requested_at.min(wall), expiry);
        let digest = [9; 32];
        let wrong_digest = [8; 32];

        if requested_at > wall {
            let future_request = request(version, [2; 32], [3; 32], requested_at, expiry);
            prop_assert_eq!(
                machine.begin_at(&future_request, digest, wall, monotonic, delay, true),
                Err(CoreError::InvalidRequest)
            );
        }

        let stale = request(version + 1, [2; 32], [3; 32], requested_at, expiry);
        prop_assert_eq!(
            machine.begin_at(&stale, digest, wall, monotonic, delay, true),
            Err(CoreError::StaleConfiguration)
        );
        prop_assert_eq!(
            machine.begin_at(&req, digest, wall, monotonic, delay, false),
            Err(CoreError::FailClosed)
        );
        if wall >= expiry {
            prop_assert_eq!(
                machine.begin_at(&req, digest, wall, monotonic, delay, true),
                Err(CoreError::Expired)
            );
        } else {
            let not_before = monotonic.saturating_add(delay);
            prop_assert_eq!(
                machine.begin_at(&req, digest, wall, monotonic, delay, true),
                Ok(not_before)
            );
            prop_assert_eq!(
                machine.state(&req.request_id),
                Some(RecoveryState::DelayPending)
            );

            let duplicate = request(version, [2; 32], [4; 32], requested_at.min(wall), expiry);
            prop_assert_eq!(
                machine.begin_at(&duplicate, digest, wall, monotonic, delay, true),
                Err(CoreError::Replay)
            );
            let duplicate_nonce = request(version, [5; 32], [3; 32], requested_at.min(wall), expiry);
            prop_assert_eq!(
                machine.begin_at(&duplicate_nonce, digest, wall, monotonic, delay, true),
                Err(CoreError::Replay)
            );

            prop_assert_eq!(
                machine.cancel(req.request_id, wrong_digest, true),
                Err(CoreError::RequestMismatch)
            );
            prop_assert_eq!(machine.cancel(req.request_id, digest, true), Ok(()));
            prop_assert_eq!(
                machine.state(&req.request_id),
                Some(RecoveryState::Cancelled)
            );
            prop_assert_eq!(
                machine.authorize_release_at(req.request_id, digest, wall, monotonic, true, true),
                Err(CoreError::Cancelled)
            );
            prop_assert_eq!(machine.cancel(req.request_id, digest, true), Ok(()));

            let req2 = request(version, [6; 32], [7; 32], requested_at.min(wall), expiry);
            let digest2 = [10; 32];
            prop_assert_eq!(
                machine.begin_at(&req2, digest2, wall, monotonic, delay, true),
                Ok(monotonic.saturating_add(delay))
            );
            prop_assert_eq!(
                machine.authorize_release_at(req2.request_id, digest2, wall, monotonic, true, false),
                Err(CoreError::FailClosed)
            );
            prop_assert_eq!(
                machine.authorize_release_at(req2.request_id, digest2, wall, monotonic, false, true),
                Err(CoreError::FailClosed)
            );
            if monotonic < not_before {
                prop_assert_eq!(
                    machine.authorize_release_at(req2.request_id, digest2, wall, monotonic, true, true),
                    Err(CoreError::DelayNotElapsed)
                );
            }
            prop_assert_eq!(
                machine.authorize_release_at(req2.request_id, digest2, wall, monotonic.saturating_add(delay), true, true),
                Ok(())
            );
            prop_assert_eq!(
                machine.state(&req2.request_id),
                Some(RecoveryState::Releasing)
            );
            if wall.saturating_add(delay) >= expiry {
                prop_assert_eq!(
                    machine.authorize_release_at(req2.request_id, digest2, expiry, expiry, true, true),
                    Err(CoreError::Expired)
                );
            }
            prop_assert_eq!(
                machine.authorize_release_at([0; 32], digest2, wall, monotonic, true, true),
                Err(CoreError::UnknownRequest)
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn interleaved_requests_keep_request_scoped_bookkeeping(
        delay in 0_u64..=10,
        wall in 0_u64..=100,
        monotonic in 0_u64..=100,
        expiry in 100_u64..=200,
        requested_at in 0_u64..=40,
        version in 1_u64..=10,
    ) {
        let mut machine = GuardianMachine::new([1; 32], version);
        let a = request(version, [2; 32], [3; 32], requested_at.min(wall), expiry);
        let b = request(version, [4; 32], [5; 32], requested_at.min(wall), expiry);
        let digest_a = [9; 32];
        let digest_b = [10; 32];

        prop_assert!(machine.begin_at(&a, digest_a, wall, monotonic, delay, true).is_ok());
        prop_assert!(machine.begin_at(&b, digest_b, wall, monotonic, delay, true).is_ok());
        prop_assert_eq!(machine.state(&a.request_id), Some(RecoveryState::DelayPending));
        prop_assert_eq!(machine.state(&b.request_id), Some(RecoveryState::DelayPending));

        // Cancelling A with the wrong digest must not disturb B, and must not
        // mark A cancelled.
        prop_assert_eq!(
            machine.cancel(a.request_id, digest_b, true),
            Err(CoreError::RequestMismatch)
        );
        prop_assert_eq!(machine.state(&a.request_id), Some(RecoveryState::DelayPending));
        prop_assert_eq!(machine.state(&b.request_id), Some(RecoveryState::DelayPending));

        // Cancelling A with the correct digest kills only A.
        prop_assert_eq!(machine.cancel(a.request_id, digest_a, true), Ok(()));
        prop_assert_eq!(machine.state(&a.request_id), Some(RecoveryState::Cancelled));
        prop_assert_eq!(machine.state(&b.request_id), Some(RecoveryState::DelayPending));
        prop_assert_eq!(
            machine.authorize_release_at(a.request_id, digest_a, wall, monotonic, true, true),
            Err(CoreError::Cancelled)
        );

        // B is unaffected by A's cancellation and can still be released once
        // its delay elapses.
        if monotonic.saturating_add(delay) < expiry {
            prop_assert_eq!(
                machine.authorize_release_at(
                    b.request_id,
                    digest_b,
                    wall,
                    monotonic.saturating_add(delay),
                    true,
                    true,
                ),
                Ok(())
            );
            prop_assert_eq!(machine.state(&b.request_id), Some(RecoveryState::Releasing));
        }
    }

    #[test]
    fn replay_across_recipient_is_rejected(
        delay in 0_u64..=10,
        wall in 0_u64..=100,
        monotonic in 0_u64..=100,
        expiry in 100_u64..=200,
        requested_at in 0_u64..=40,
        version in 1_u64..=10,
        recipient_key in prop::collection::vec(any::<u8>(), 1216..=1216),
    ) {
        let mut machine = GuardianMachine::new([1; 32], version);
        let original = RecoveryRequest {
            recovery_recipient_key: recipient_key.clone(),
            ..request(version, [2; 32], [3; 32], requested_at.min(wall), expiry)
        };
        let digest = [9; 32];
        prop_assert!(machine.begin_at(&original, digest, wall, monotonic, delay, true).is_ok());

        // Same request_id and same nonce, but a different recovery recipient:
        // the exact "swap the recipient on a captured request" attack. The
        // machine must reject it as a replay of the original request.
        let different_recipient = RecoveryRequest {
            recovery_recipient_key: vec![0xEE; 1216],
            ..original.clone()
        };
        prop_assert_eq!(
            machine.begin_at(&different_recipient, digest, wall, monotonic, delay, true),
            Err(CoreError::Replay),
            "re-binding a captured request to a new recipient must be a replay"
        );
        // The pending entry still belongs to the original request: releasing
        // requires the original digest, and any other digest is a mismatch.
        prop_assert_eq!(
            machine.authorize_release_at(original.request_id, [0xAB; 32], wall, monotonic, true, true),
            Err(CoreError::RequestMismatch),
            "recipient swap must not re-bind the pending entry to a new digest"
        );
        prop_assert_eq!(
            machine.state(&original.request_id),
            Some(RecoveryState::DelayPending)
        );

        // Same nonce with a fresh request_id is also a replay...
        let new_id_same_nonce = request(version, [7; 32], [3; 32], requested_at.min(wall), expiry);
        prop_assert_eq!(
            machine.begin_at(&new_id_same_nonce, digest, wall, monotonic, delay, true),
            Err(CoreError::Replay)
        );

        // ...but a genuinely fresh request with a fresh nonce still works.
        let fresh = request(version, [8; 32], [6; 32], requested_at.min(wall), expiry);
        prop_assert!(machine.begin_at(&fresh, digest, wall, monotonic, delay, true).is_ok());
        let _ = recipient_key;
    }
}
