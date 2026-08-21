//! Kani proof harnesses for the recovery and guardian state machines.
//!
//! Compiled only under `cargo kani` (the `kani` cfg is set exclusively by
//! the Kani toolchain). Each harness verifies an invariant of the state
//! machines for every input, not just sampled ones.

use super::{Action, CoreError, GuardianMachine, RecoveryEvent, RecoveryMachine};
use gp_types::{CryptoSuite, Id32, PROTOCOL_VERSION, RecoveryRequest, RecoveryState};

fn any_state() -> RecoveryState {
    match kani::any::<u8>() % 8 {
        0 => RecoveryState::Created,
        1 => RecoveryState::AwaitingApprovals,
        2 => RecoveryState::Authorized,
        3 => RecoveryState::DelayPending,
        4 => RecoveryState::Releasing,
        5 => RecoveryState::Completed,
        6 => RecoveryState::Cancelled,
        _ => RecoveryState::Expired,
    }
}

fn any_event() -> RecoveryEvent {
    match kani::any::<u8>() % 7 {
        0 => RecoveryEvent::RequestCreated,
        1 => RecoveryEvent::ApprovalThresholdReached,
        2 => RecoveryEvent::BeginAccepted,
        3 => RecoveryEvent::ReleaseCertificateReady,
        4 => RecoveryEvent::GuardianThresholdReached,
        5 => RecoveryEvent::OwnerCancelObserved,
        _ => RecoveryEvent::ExpiryReached,
    }
}

fn any_machine() -> RecoveryMachine {
    RecoveryMachine {
        state: any_state(),
        not_before: kani::any(),
    }
}

fn any_request() -> RecoveryRequest {
    RecoveryRequest {
        protocol_version: kani::any(),
        crypto_suite: CryptoSuite::default(),
        config_id: kani::any(),
        config_version: kani::any(),
        request_id: kani::any(),
        recovery_recipient_key: kani::any::<[u8; 32]>().to_vec(),
        requested_at: kani::any(),
        nonce: kani::any(),
        expiry: kani::any(),
    }
}

#[kani::proof]
fn apply_never_panics() {
    let mut machine = any_machine();
    let event = any_event();
    let now: u64 = kani::any();
    let delay: u64 = kani::any();
    let _ = machine.apply(event, now, delay);
}

#[kani::proof]
fn terminal_states_are_absorbing() {
    let mut machine = any_machine();
    let event = any_event();
    let now: u64 = kani::any();
    let delay: u64 = kani::any();
    let before = machine.state();
    let result = machine.apply(event, now, delay);
    match before {
        RecoveryState::Cancelled => {
            assert!(matches!(result, Err(CoreError::Cancelled)));
            assert_eq!(machine.state(), before);
        }
        RecoveryState::Expired => {
            assert!(matches!(result, Err(CoreError::Expired)));
            assert_eq!(machine.state(), before);
        }
        _ => {}
    }
}

#[kani::proof]
fn apply_does_not_mutate_on_error() {
    let mut machine = any_machine();
    let event = any_event();
    let now: u64 = kani::any();
    let delay: u64 = kani::any();
    let before = machine.clone();
    let result = machine.apply(event, now, delay);
    if result.is_err() {
        assert_eq!(machine, before);
    }
}

#[kani::proof]
fn not_before_holds_until_delay_pending() {
    let mut machine = RecoveryMachine::default();
    for _ in 0..3 {
        let event = any_event();
        let now: u64 = kani::any();
        let delay: u64 = kani::any();
        let _ = machine.apply(event, now, delay);
    }
    match machine.state() {
        RecoveryState::Created | RecoveryState::AwaitingApprovals | RecoveryState::Authorized => {
            assert!(machine.not_before.is_none())
        }
        _ => {}
    }
}

#[kani::proof]
fn begin_accepted_sets_exact_delay() {
    let mut machine = RecoveryMachine {
        state: RecoveryState::Authorized,
        not_before: kani::any(),
    };
    let now: u64 = kani::any();
    let delay: u64 = kani::any();
    let expected = now.saturating_add(delay);
    let result = machine.apply(RecoveryEvent::BeginAccepted, now, delay);
    assert!(matches!(
        &result,
        Ok(actions) if actions == &vec![Action::WaitUntil(expected), Action::RequestReleaseVotes]
    ));
    assert_eq!(machine.state(), RecoveryState::DelayPending);
    assert_eq!(machine.not_before, Some(expected));
}

#[kani::proof]
fn release_ready_requires_elapsed_delay() {
    let mut machine = RecoveryMachine {
        state: RecoveryState::DelayPending,
        not_before: kani::any(),
    };
    let now: u64 = kani::any();
    let delay: u64 = kani::any();
    let result = machine.apply(RecoveryEvent::ReleaseCertificateReady, now, delay);
    match machine.not_before {
        Some(not_before) if now < not_before => {
            assert!(matches!(
                result,
                Err(CoreError::InvalidTransition {
                    from: RecoveryState::DelayPending
                })
            ));
            assert_eq!(machine.state(), RecoveryState::DelayPending);
        }
        None if now != u64::MAX => {
            assert!(matches!(
                result,
                Err(CoreError::InvalidTransition {
                    from: RecoveryState::DelayPending
                })
            ));
            assert_eq!(machine.state(), RecoveryState::DelayPending);
        }
        _ => {
            assert!(matches!(
                &result,
                Ok(actions) if actions == &vec![Action::RequestGuardianContributions]
            ));
            assert_eq!(machine.state(), RecoveryState::Releasing);
        }
    }
}

#[kani::proof]
fn expiry_reached_expires_from_any_state() {
    let mut machine = any_machine();
    let now: u64 = kani::any();
    let delay: u64 = kani::any();
    let before = machine.state();
    let result = machine.apply(RecoveryEvent::ExpiryReached, now, delay);
    match before {
        RecoveryState::Cancelled => {
            assert!(matches!(result, Err(CoreError::Cancelled)));
        }
        RecoveryState::Expired => {
            assert!(matches!(result, Err(CoreError::Expired)));
        }
        _ => {
            assert!(matches!(
                &result,
                Ok(actions) if actions == &vec![Action::RefuseRelease, Action::ZeroizeRecoverySecrets]
            ));
            assert_eq!(machine.state(), RecoveryState::Expired);
        }
    }
}

#[kani::proof]
fn validate_request_never_panics() {
    let machine = GuardianMachine::new(kani::any(), kani::any());
    let request = any_request();
    let _ = machine.validate_request(&request);
}

/// Harnesses below this line drive `GuardianMachine::begin`, `cancel` and
/// `authorize_release`, which insert into and search `BTreeMap`/`BTreeSet`.
/// CBMC cannot bound `alloc::collections::btree::search::find_key_index`:
/// because the map is built by symbolic operations the node length stays
/// symbolic, so the search loop unwinds without limit. A CI run was observed
/// still unrolling that loop at iteration 677, one iteration per second, each
/// re-running a 32-step memcmp; the job hit the 6 hour ceiling without ever
/// reaching a verification result.
///
/// Shrinking the symbolic key domain does not help, because the loop bound
/// does not depend on key values. These two harnesses are therefore gated
/// behind `kani_unbounded`, which CI does not set. The properties they state
/// are covered by concrete tests instead: `tests/transition_tables.rs`
/// exhaustively enumerates the guardian transitions, and `tests/invariants.rs`
/// covers replay, cancellation and fail-closed behaviour under proptest.
///
/// Run them locally with:
///   RUSTFLAGS="--cfg kani_unbounded" cargo kani -p gp-core
#[cfg(kani_unbounded)]
#[kani::proof]
fn validate_request_passes_implies_registered() {
    let request = any_request();
    let mut machine = GuardianMachine::new(kani::any(), kani::any());
    kani::assume(machine.validate_request(&request).is_ok());
    let digest: Id32 = kani::any();
    let wall_now: u64 = kani::any();
    let delay: u64 = kani::any();
    let certificate_valid: bool = kani::any();

    let result = machine.begin(&request, digest, wall_now, delay, certificate_valid);
    match result {
        Ok(not_before) => {
            assert_eq!(not_before, wall_now.saturating_add(delay));
            assert!(machine.seen.contains(&request.request_id));
            assert!(machine.seen_nonces.contains(&request.nonce));
            let entry = machine.pending.get(&request.request_id);
            assert!(entry.is_some());
            let entry = entry.unwrap();
            assert_eq!(entry.request_digest, digest);
            assert_eq!(entry.pending.request_id, request.request_id);
            assert_eq!(entry.pending.state, RecoveryState::DelayPending);
            assert_eq!(entry.expiry, request.expiry);
        }
        Err(error) => {
            assert!(matches!(
                error,
                CoreError::FailClosed | CoreError::InvalidRequest | CoreError::Expired
            ));
            assert!(machine.seen.is_empty());
            assert!(machine.seen_nonces.is_empty());
            assert!(machine.pending.is_empty());
        }
    }
}

#[cfg(kani_unbounded)]
#[kani::proof]
fn cancelled_requests_are_fail_closed() {
    let mut machine = GuardianMachine::new(kani::any(), kani::any());
    let request = any_request();
    let digest: Id32 = kani::any();
    let wall_now: u64 = kani::any();
    let delay: u64 = kani::any();
    let certificate_valid: bool = kani::any();

    let _ = machine.begin(&request, digest, wall_now, delay, certificate_valid);
    let cancel_result = machine.cancel(request.request_id, digest, true);
    assert!(cancel_result.is_ok());
    assert_eq!(
        machine.state(&request.request_id),
        Some(RecoveryState::Cancelled)
    );

    let retry = any_request();
    kani::assume(retry.request_id == request.request_id);
    assert!(matches!(
        machine.begin(&retry, digest, wall_now, delay, certificate_valid),
        Err(CoreError::StaleConfiguration)
            | Err(CoreError::FailClosed)
            | Err(CoreError::InvalidRequest)
            | Err(CoreError::Expired)
            | Err(CoreError::Cancelled)
    ));

    let state_unambiguous: bool = kani::any();
    assert_eq!(
        machine.authorize_release(
            request.request_id,
            digest,
            wall_now,
            certificate_valid,
            state_unambiguous
        ),
        Err(CoreError::Cancelled)
    );

    assert_eq!(
        machine.state(&request.request_id),
        Some(RecoveryState::Cancelled)
    );
    if let Some(entry) = machine.pending.get(&request.request_id) {
        assert_eq!(entry.pending.state, RecoveryState::Cancelled);
    }
}
