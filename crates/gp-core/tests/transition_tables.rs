//! Exhaustive transition tables for the recovery state machines, plus
//! fail-closed and try_state-style observable invariants.
//!
//! Every (state, event) pair is driven deterministically and its exact
//! outcome is pinned: resulting state, action vector, or error variant.
//! After every rejected event the machine must be bit-identical (fail
//! closed: no partial mutation, no hidden alternate state).

use gp_core::{Action, CoreError, GuardianMachine, RecoveryEvent, RecoveryMachine};
use gp_types::{CryptoSuite, PROTOCOL_VERSION, RecoveryRequest, RecoveryState};

/// Fixed clock values for the matrix: `NOW` is always past the `not_before`
/// installed by `DELAY` in the `DelayPending` builder, so the release row is
/// the successful one and the too-early row is a dedicated test.
const NOW: u64 = 15;
const DELAY: u64 = 10;

#[derive(Debug, Eq, PartialEq)]
enum Expect {
    Ok(RecoveryState, Vec<Action>),
    Err(CoreError),
}

fn build(from: RecoveryState) -> RecoveryMachine {
    let mut machine = RecoveryMachine::default();
    match from {
        RecoveryState::Created => {}
        RecoveryState::AwaitingApprovals => {
            machine
                .apply(RecoveryEvent::RequestCreated, 0, DELAY)
                .unwrap();
        }
        RecoveryState::Authorized => {
            machine
                .apply(RecoveryEvent::RequestCreated, 0, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::ApprovalThresholdReached, 1, DELAY)
                .unwrap();
        }
        RecoveryState::DelayPending => {
            machine
                .apply(RecoveryEvent::RequestCreated, 0, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::ApprovalThresholdReached, 1, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::BeginAccepted, 2, DELAY)
                .unwrap();
        }
        RecoveryState::Releasing => {
            machine
                .apply(RecoveryEvent::RequestCreated, 0, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::ApprovalThresholdReached, 1, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::BeginAccepted, 2, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::ReleaseCertificateReady, 13, DELAY)
                .unwrap();
        }
        RecoveryState::Completed => {
            machine
                .apply(RecoveryEvent::RequestCreated, 0, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::ApprovalThresholdReached, 1, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::BeginAccepted, 2, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::ReleaseCertificateReady, 13, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::GuardianThresholdReached, 14, DELAY)
                .unwrap();
        }
        RecoveryState::Cancelled => {
            machine
                .apply(RecoveryEvent::RequestCreated, 0, DELAY)
                .unwrap();
            machine
                .apply(RecoveryEvent::OwnerCancelObserved, 1, DELAY)
                .unwrap();
        }
        RecoveryState::Expired => {
            machine
                .apply(RecoveryEvent::ExpiryReached, 0, DELAY)
                .unwrap();
        }
    }
    assert_eq!(machine.state(), from, "builder for {from:?} is broken");
    machine
}

fn outcome(machine: &mut RecoveryMachine, event: &RecoveryEvent) -> Expect {
    let before = machine.state();
    match machine.apply(event.clone(), NOW, DELAY) {
        Ok(actions) => {
            let after = machine.state();
            assert_ne!(
                before, after,
                "accepted event {event:?} must move state from {before:?}"
            );
            Expect::Ok(after, actions)
        }
        Err(error) => {
            assert_eq!(
                machine.state(),
                before,
                "fail-closed: {event:?} rejected from {before:?} must not mutate state"
            );
            Expect::Err(error)
        }
    }
}

#[test]
fn every_state_event_pair_has_an_exact_outcome() {
    let refuse = vec![Action::RefuseRelease, Action::ZeroizeRecoverySecrets];
    let rows: [(RecoveryState, RecoveryEvent, Expect); 56] = [
        // Created
        (
            RecoveryState::Created,
            RecoveryEvent::RequestCreated,
            Expect::Ok(
                RecoveryState::AwaitingApprovals,
                vec![Action::RequestSignerApprovals],
            ),
        ),
        (
            RecoveryState::Created,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Created,
            }),
        ),
        (
            RecoveryState::Created,
            RecoveryEvent::BeginAccepted,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Created,
            }),
        ),
        (
            RecoveryState::Created,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Created,
            }),
        ),
        (
            RecoveryState::Created,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Created,
            }),
        ),
        (
            RecoveryState::Created,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Created,
            }),
        ),
        (
            RecoveryState::Created,
            RecoveryEvent::ExpiryReached,
            Expect::Ok(RecoveryState::Expired, refuse.clone()),
        ),
        // AwaitingApprovals
        (
            RecoveryState::AwaitingApprovals,
            RecoveryEvent::RequestCreated,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::AwaitingApprovals,
            }),
        ),
        (
            RecoveryState::AwaitingApprovals,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Ok(
                RecoveryState::Authorized,
                vec![
                    Action::DecryptRecoveryDescriptor,
                    Action::SendBeginCertificate,
                ],
            ),
        ),
        (
            RecoveryState::AwaitingApprovals,
            RecoveryEvent::BeginAccepted,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::AwaitingApprovals,
            }),
        ),
        (
            RecoveryState::AwaitingApprovals,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::AwaitingApprovals,
            }),
        ),
        (
            RecoveryState::AwaitingApprovals,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::AwaitingApprovals,
            }),
        ),
        (
            RecoveryState::AwaitingApprovals,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Ok(RecoveryState::Cancelled, refuse.clone()),
        ),
        (
            RecoveryState::AwaitingApprovals,
            RecoveryEvent::ExpiryReached,
            Expect::Ok(RecoveryState::Expired, refuse.clone()),
        ),
        // Authorized
        (
            RecoveryState::Authorized,
            RecoveryEvent::RequestCreated,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Authorized,
            }),
        ),
        (
            RecoveryState::Authorized,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Authorized,
            }),
        ),
        (
            RecoveryState::Authorized,
            RecoveryEvent::BeginAccepted,
            Expect::Ok(
                RecoveryState::DelayPending,
                vec![Action::WaitUntil(NOW + DELAY), Action::RequestReleaseVotes],
            ),
        ),
        (
            RecoveryState::Authorized,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Authorized,
            }),
        ),
        (
            RecoveryState::Authorized,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Authorized,
            }),
        ),
        (
            RecoveryState::Authorized,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Ok(RecoveryState::Cancelled, refuse.clone()),
        ),
        (
            RecoveryState::Authorized,
            RecoveryEvent::ExpiryReached,
            Expect::Ok(RecoveryState::Expired, refuse.clone()),
        ),
        // DelayPending
        (
            RecoveryState::DelayPending,
            RecoveryEvent::RequestCreated,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::DelayPending,
            }),
        ),
        (
            RecoveryState::DelayPending,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::DelayPending,
            }),
        ),
        (
            RecoveryState::DelayPending,
            RecoveryEvent::BeginAccepted,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::DelayPending,
            }),
        ),
        (
            RecoveryState::DelayPending,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Ok(
                RecoveryState::Releasing,
                vec![Action::RequestGuardianContributions],
            ),
        ),
        (
            RecoveryState::DelayPending,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::DelayPending,
            }),
        ),
        (
            RecoveryState::DelayPending,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Ok(RecoveryState::Cancelled, refuse.clone()),
        ),
        (
            RecoveryState::DelayPending,
            RecoveryEvent::ExpiryReached,
            Expect::Ok(RecoveryState::Expired, refuse.clone()),
        ),
        // Releasing
        (
            RecoveryState::Releasing,
            RecoveryEvent::RequestCreated,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Releasing,
            }),
        ),
        (
            RecoveryState::Releasing,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Releasing,
            }),
        ),
        (
            RecoveryState::Releasing,
            RecoveryEvent::BeginAccepted,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Releasing,
            }),
        ),
        (
            RecoveryState::Releasing,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Releasing,
            }),
        ),
        (
            RecoveryState::Releasing,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Ok(
                RecoveryState::Completed,
                vec![Action::ReconstructLocally, Action::ZeroizeRecoverySecrets],
            ),
        ),
        (
            RecoveryState::Releasing,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Releasing,
            }),
        ),
        (
            RecoveryState::Releasing,
            RecoveryEvent::ExpiryReached,
            Expect::Ok(RecoveryState::Expired, refuse.clone()),
        ),
        // Completed
        (
            RecoveryState::Completed,
            RecoveryEvent::RequestCreated,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Completed,
            }),
        ),
        (
            RecoveryState::Completed,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Completed,
            }),
        ),
        (
            RecoveryState::Completed,
            RecoveryEvent::BeginAccepted,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Completed,
            }),
        ),
        (
            RecoveryState::Completed,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Completed,
            }),
        ),
        (
            RecoveryState::Completed,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Completed,
            }),
        ),
        (
            RecoveryState::Completed,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Err(CoreError::InvalidTransition {
                from: RecoveryState::Completed,
            }),
        ),
        (
            RecoveryState::Completed,
            RecoveryEvent::ExpiryReached,
            Expect::Ok(RecoveryState::Expired, refuse.clone()),
        ),
        // Cancelled is absorbing: every event is refused with Cancelled.
        (
            RecoveryState::Cancelled,
            RecoveryEvent::RequestCreated,
            Expect::Err(CoreError::Cancelled),
        ),
        (
            RecoveryState::Cancelled,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Err(CoreError::Cancelled),
        ),
        (
            RecoveryState::Cancelled,
            RecoveryEvent::BeginAccepted,
            Expect::Err(CoreError::Cancelled),
        ),
        (
            RecoveryState::Cancelled,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Err(CoreError::Cancelled),
        ),
        (
            RecoveryState::Cancelled,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Err(CoreError::Cancelled),
        ),
        (
            RecoveryState::Cancelled,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Err(CoreError::Cancelled),
        ),
        (
            RecoveryState::Cancelled,
            RecoveryEvent::ExpiryReached,
            Expect::Err(CoreError::Cancelled),
        ),
        // Expired is absorbing: every event is refused with Expired.
        (
            RecoveryState::Expired,
            RecoveryEvent::RequestCreated,
            Expect::Err(CoreError::Expired),
        ),
        (
            RecoveryState::Expired,
            RecoveryEvent::ApprovalThresholdReached,
            Expect::Err(CoreError::Expired),
        ),
        (
            RecoveryState::Expired,
            RecoveryEvent::BeginAccepted,
            Expect::Err(CoreError::Expired),
        ),
        (
            RecoveryState::Expired,
            RecoveryEvent::ReleaseCertificateReady,
            Expect::Err(CoreError::Expired),
        ),
        (
            RecoveryState::Expired,
            RecoveryEvent::GuardianThresholdReached,
            Expect::Err(CoreError::Expired),
        ),
        (
            RecoveryState::Expired,
            RecoveryEvent::OwnerCancelObserved,
            Expect::Err(CoreError::Expired),
        ),
        (
            RecoveryState::Expired,
            RecoveryEvent::ExpiryReached,
            Expect::Err(CoreError::Expired),
        ),
    ];

    for (state, event, expected) in rows {
        let mut machine = build(state);
        let actual = outcome(&mut machine, &event);
        assert_eq!(actual, expected, "divergence for {state:?} + {event:?}");
    }
}

#[test]
fn delay_pending_rejects_early_release_without_losing_the_deadline() {
    let mut machine = build(RecoveryState::DelayPending);
    assert_eq!(
        machine.apply(RecoveryEvent::ReleaseCertificateReady, NOW - 4, DELAY),
        Err(CoreError::InvalidTransition {
            from: RecoveryState::DelayPending
        })
    );
    assert_eq!(machine.state(), RecoveryState::DelayPending);
    let actions = machine
        .apply(RecoveryEvent::ReleaseCertificateReady, NOW, DELAY)
        .unwrap();
    assert_eq!(
        actions,
        vec![Action::RequestGuardianContributions],
        "the rejected early release must not have consumed or reset not_before"
    );
    assert_eq!(machine.state(), RecoveryState::Releasing);
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

/// try_state-style observable invariants: every public mutation must leave
/// per-request bookkeeping consistent with the recovery state model.
fn assert_guardian_invariants(machine: &mut GuardianMachine, observed: &[[u8; 32]]) {
    for request_id in observed {
        match machine.state(request_id) {
            None => {}
            Some(RecoveryState::Cancelled) => {
                assert!(
                    machine
                        .authorize_release_at(*request_id, [0; 32], 0, 0, true, true)
                        .is_err(),
                    "a cancelled request must never authorize release"
                );
            }
            Some(RecoveryState::Expired) => {
                assert!(
                    machine
                        .authorize_release_at(*request_id, [0; 32], 0, 0, true, true)
                        .is_err(),
                    "an expired request must never authorize release"
                );
            }
            Some(RecoveryState::DelayPending | RecoveryState::Releasing) => {
                assert!(
                    machine
                        .authorize_release_at(*request_id, [0; 32], 0, 0, true, true)
                        .is_err(),
                    "a live request must never release under a wrong digest"
                );
            }
            Some(
                RecoveryState::Created
                | RecoveryState::AwaitingApprovals
                | RecoveryState::Authorized
                | RecoveryState::Completed,
            ) => {
                panic!(
                    "guardian bookkeeping must never report {request_id:?} as {:#?}",
                    machine.state(request_id)
                );
            }
        }
    }
    assert_eq!(
        machine.state(&[0xFE; 32]),
        None,
        "an unobserved request id must never be reported"
    );
}

#[test]
fn guardian_scenario_keeps_try_state_invariants_after_every_mutation() {
    let version = 1_u64;
    let mut machine = GuardianMachine::new([1; 32], version);
    let observed = [[2; 32], [6; 32], [8; 32]];
    let digest_a = [9; 32];
    let digest_b = [10; 32];
    let digest_c = [11; 32];

    // Request A: begin, wrong-digest cancel (no-op), real cancel (tombstone).
    let a = request(version, observed[0], [3; 32], 0, 100);
    let not_before_a = machine.begin(&a, digest_a, 0, 10, true).unwrap();
    assert_eq!(not_before_a, 10);
    assert_eq!(
        machine.state(&observed[0]),
        Some(RecoveryState::DelayPending)
    );
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(
        machine.cancel(observed[0], digest_b, true),
        Err(CoreError::RequestMismatch)
    );
    assert_eq!(
        machine.state(&observed[0]),
        Some(RecoveryState::DelayPending)
    );
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(machine.cancel(observed[0], digest_a, true), Ok(()));
    assert_eq!(machine.state(&observed[0]), Some(RecoveryState::Cancelled));
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(
        machine.authorize_release(observed[0], digest_a, 20, true, true),
        Err(CoreError::Cancelled)
    );
    assert_eq!(machine.cancel(observed[0], digest_a, true), Ok(()));
    assert_guardian_invariants(&mut machine, &observed);

    // Request B: begin, ambiguous/failed certificates are fail-closed,
    // release before the delay is refused, release after is idempotent.
    let b = request(version, observed[1], [4; 32], 0, 100);
    let not_before_b = machine.begin(&b, digest_b, 0, 10, true).unwrap();
    assert_eq!(not_before_b, 10);
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(
        machine.authorize_release(observed[1], digest_b, 5, true, true),
        Err(CoreError::DelayNotElapsed)
    );
    assert_eq!(
        machine.state(&observed[1]),
        Some(RecoveryState::DelayPending)
    );
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(
        machine.authorize_release(observed[1], digest_b, 20, true, false),
        Err(CoreError::FailClosed)
    );
    assert_eq!(
        machine.authorize_release(observed[1], digest_b, 20, false, true),
        Err(CoreError::FailClosed)
    );
    assert_eq!(
        machine.state(&observed[1]),
        Some(RecoveryState::DelayPending)
    );
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(
        machine.authorize_release(observed[1], digest_b, 20, true, true),
        Ok(())
    );
    assert_eq!(machine.state(&observed[1]), Some(RecoveryState::Releasing));
    assert_eq!(
        machine.authorize_release(observed[1], digest_b, 20, true, true),
        Ok(()),
        "releasing a request that is already Releasing must stay idempotent"
    );
    assert_eq!(machine.state(&observed[1]), Some(RecoveryState::Releasing));
    assert_guardian_invariants(&mut machine, &observed);

    // Request C: expiry crossing moves the pending entry to Expired and the
    // entry is then terminal; a replay of the same id is still rejected.
    let c = request(version, observed[2], [5; 32], 0, 40);
    let not_before_c = machine.begin(&c, digest_c, 0, 10, true).unwrap();
    assert_eq!(not_before_c, 10);
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(
        machine.authorize_release_at(observed[2], digest_c, 50, 10, true, true),
        Err(CoreError::Expired)
    );
    assert_eq!(machine.state(&observed[2]), Some(RecoveryState::Expired));
    assert_guardian_invariants(&mut machine, &observed);

    assert_eq!(
        machine.begin(&c, digest_c, 0, 10, true),
        Err(CoreError::Replay),
        "an expired pending entry must still replay-protect its request id"
    );

    // Cross-request isolation after the whole scenario.
    assert_eq!(machine.state(&observed[0]), Some(RecoveryState::Cancelled));
    assert_eq!(machine.state(&observed[1]), Some(RecoveryState::Releasing));
    assert_eq!(machine.state(&observed[2]), Some(RecoveryState::Expired));
    assert_guardian_invariants(&mut machine, &observed);
}
