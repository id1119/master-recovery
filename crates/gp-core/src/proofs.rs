//! Kani proof harnesses for the recovery state machine.
//!
//! Compiled only under `cargo kani` (the `kani` cfg is set exclusively by
//! the Kani toolchain). Each harness verifies an invariant of
//! `RecoveryMachine::apply` for every input, not just sampled ones.

use super::{Action, CoreError, RecoveryEvent, RecoveryMachine};
use gp_types::RecoveryState;

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
