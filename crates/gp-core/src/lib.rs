//! Deterministic, I/O-free recovery state machines.

use std::collections::{BTreeMap, BTreeSet};

use gp_types::{Id32, PROTOCOL_VERSION, PendingRecovery, RecoveryRequest, RecoveryState};

mod rotation;
pub use rotation::*;

#[cfg(kani)]
mod proofs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryEvent {
    RequestCreated,
    ApprovalThresholdReached,
    BeginAccepted,
    ReleaseCertificateReady,
    GuardianThresholdReached,
    OwnerCancelObserved,
    ExpiryReached,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Action {
    RequestSignerApprovals,
    DecryptRecoveryDescriptor,
    SendBeginCertificate,
    WaitUntil(u64),
    RequestReleaseVotes,
    RequestGuardianContributions,
    ReconstructLocally,
    RefuseRelease,
    ZeroizeRecoverySecrets,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CoreError {
    #[error("invalid transition from {from:?}")]
    InvalidTransition { from: RecoveryState },
    #[error("request is stale or for another configuration")]
    StaleConfiguration,
    #[error("request id has already been observed")]
    Replay,
    #[error("request is not pending")]
    UnknownRequest,
    #[error("guardian delay has not elapsed")]
    DelayNotElapsed,
    #[error("request has expired")]
    Expired,
    #[error("request is permanently cancelled")]
    Cancelled,
    #[error("certificate state is ambiguous or invalid")]
    FailClosed,
    #[error("request digest does not match pending recovery")]
    RequestMismatch,
    #[error("request fields are invalid for this protocol")]
    InvalidRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryMachine {
    state: RecoveryState,
    not_before: Option<u64>,
}

impl Default for RecoveryMachine {
    fn default() -> Self {
        Self {
            state: RecoveryState::Created,
            not_before: None,
        }
    }
}

impl RecoveryMachine {
    #[must_use]
    pub fn state(&self) -> RecoveryState {
        self.state
    }

    pub fn apply(
        &mut self,
        event: RecoveryEvent,
        now: u64,
        delay: u64,
    ) -> Result<Vec<Action>, CoreError> {
        if self.state == RecoveryState::Cancelled {
            return Err(CoreError::Cancelled);
        }
        if self.state == RecoveryState::Expired {
            return Err(CoreError::Expired);
        }

        let actions = match (&self.state, event) {
            (RecoveryState::Created, RecoveryEvent::RequestCreated) => {
                self.state = RecoveryState::AwaitingApprovals;
                vec![Action::RequestSignerApprovals]
            }
            (RecoveryState::AwaitingApprovals, RecoveryEvent::ApprovalThresholdReached) => {
                self.state = RecoveryState::Authorized;
                vec![
                    Action::DecryptRecoveryDescriptor,
                    Action::SendBeginCertificate,
                ]
            }
            (RecoveryState::Authorized, RecoveryEvent::BeginAccepted) => {
                let not_before = now.saturating_add(delay);
                self.not_before = Some(not_before);
                self.state = RecoveryState::DelayPending;
                vec![Action::WaitUntil(not_before), Action::RequestReleaseVotes]
            }
            (RecoveryState::DelayPending, RecoveryEvent::ReleaseCertificateReady)
                if now >= self.not_before.unwrap_or(u64::MAX) =>
            {
                self.state = RecoveryState::Releasing;
                vec![Action::RequestGuardianContributions]
            }
            (RecoveryState::Releasing, RecoveryEvent::GuardianThresholdReached) => {
                self.state = RecoveryState::Completed;
                vec![Action::ReconstructLocally, Action::ZeroizeRecoverySecrets]
            }
            (
                RecoveryState::AwaitingApprovals
                | RecoveryState::Authorized
                | RecoveryState::DelayPending,
                RecoveryEvent::OwnerCancelObserved,
            ) => {
                self.state = RecoveryState::Cancelled;
                vec![Action::RefuseRelease, Action::ZeroizeRecoverySecrets]
            }
            (_, RecoveryEvent::ExpiryReached) => {
                self.state = RecoveryState::Expired;
                vec![Action::RefuseRelease, Action::ZeroizeRecoverySecrets]
            }
            (from, _) => return Err(CoreError::InvalidTransition { from: *from }),
        };
        Ok(actions)
    }
}

#[derive(Clone, Debug)]
struct GuardianPending {
    pending: PendingRecovery,
    request_digest: Id32,
    expiry: u64,
}

#[derive(Clone, Debug)]
pub struct GuardianMachine {
    config_id: Id32,
    current_version: u64,
    seen: BTreeSet<Id32>,
    seen_nonces: BTreeSet<Id32>,
    pending: BTreeMap<Id32, GuardianPending>,
    cancelled: BTreeMap<Id32, Id32>,
}

impl GuardianMachine {
    #[must_use]
    pub fn new(config_id: Id32, current_version: u64) -> Self {
        Self {
            config_id,
            current_version,
            seen: BTreeSet::new(),
            seen_nonces: BTreeSet::new(),
            pending: BTreeMap::new(),
            cancelled: BTreeMap::new(),
        }
    }

    pub fn begin(
        &mut self,
        request: &RecoveryRequest,
        request_digest: Id32,
        now: u64,
        delay: u64,
        certificate_valid: bool,
    ) -> Result<u64, CoreError> {
        self.begin_at(request, request_digest, now, now, delay, certificate_valid)
    }

    pub fn begin_at(
        &mut self,
        request: &RecoveryRequest,
        request_digest: Id32,
        wall_now: u64,
        monotonic_now: u64,
        delay: u64,
        certificate_valid: bool,
    ) -> Result<u64, CoreError> {
        self.validate_request(request)?;
        if !certificate_valid {
            return Err(CoreError::FailClosed);
        }
        if request.requested_at > wall_now {
            return Err(CoreError::InvalidRequest);
        }
        if wall_now >= request.expiry {
            return Err(CoreError::Expired);
        }
        if let Some(cancelled_digest) = self.cancelled.get(&request.request_id) {
            return if cancelled_digest == &request_digest {
                Err(CoreError::Cancelled)
            } else {
                Err(CoreError::RequestMismatch)
            };
        }
        if self.seen.contains(&request.request_id) || self.seen_nonces.contains(&request.nonce) {
            return Err(CoreError::Replay);
        }
        self.seen.insert(request.request_id);
        self.seen_nonces.insert(request.nonce);
        let not_before = monotonic_now.saturating_add(delay);
        self.pending.insert(
            request.request_id,
            GuardianPending {
                pending: PendingRecovery {
                    request_id: request.request_id,
                    config_id: request.config_id,
                    config_version: request.config_version,
                    recipient: request.recovery_recipient_key.clone(),
                    started_at_monotonic: monotonic_now,
                    not_before,
                    state: RecoveryState::DelayPending,
                },
                request_digest,
                expiry: request.expiry,
            },
        );
        Ok(not_before)
    }

    pub fn cancel(
        &mut self,
        request_id: Id32,
        request_digest: Id32,
        certificate_valid: bool,
    ) -> Result<(), CoreError> {
        if !certificate_valid {
            return Err(CoreError::FailClosed);
        }
        if let Some(cancelled_digest) = self.cancelled.get(&request_id) {
            return if cancelled_digest == &request_digest {
                Ok(())
            } else {
                Err(CoreError::RequestMismatch)
            };
        }
        if let Some(pending) = self.pending.get_mut(&request_id) {
            if pending.request_digest != request_digest {
                return Err(CoreError::RequestMismatch);
            }
            pending.pending.state = RecoveryState::Cancelled;
        }
        self.cancelled.insert(request_id, request_digest);
        Ok(())
    }

    pub fn authorize_release(
        &mut self,
        request_id: Id32,
        request_digest: Id32,
        now: u64,
        certificate_valid: bool,
        state_unambiguous: bool,
    ) -> Result<(), CoreError> {
        self.authorize_release_at(
            request_id,
            request_digest,
            now,
            now,
            certificate_valid,
            state_unambiguous,
        )
    }

    pub fn authorize_release_at(
        &mut self,
        request_id: Id32,
        request_digest: Id32,
        wall_now: u64,
        monotonic_now: u64,
        certificate_valid: bool,
        state_unambiguous: bool,
    ) -> Result<(), CoreError> {
        if let Some(cancelled_digest) = self.cancelled.get(&request_id) {
            return if cancelled_digest == &request_digest {
                Err(CoreError::Cancelled)
            } else {
                Err(CoreError::RequestMismatch)
            };
        }
        if !certificate_valid || !state_unambiguous {
            return Err(CoreError::FailClosed);
        }
        let pending = self
            .pending
            .get_mut(&request_id)
            .ok_or(CoreError::UnknownRequest)?;
        if pending.request_digest != request_digest {
            return Err(CoreError::RequestMismatch);
        }
        if wall_now >= pending.expiry {
            pending.pending.state = RecoveryState::Expired;
            return Err(CoreError::Expired);
        }
        if monotonic_now < pending.pending.not_before {
            return Err(CoreError::DelayNotElapsed);
        }
        pending.pending.state = RecoveryState::Releasing;
        Ok(())
    }

    #[must_use]
    pub fn state(&self, request_id: &Id32) -> Option<RecoveryState> {
        if self.cancelled.contains_key(request_id) {
            Some(RecoveryState::Cancelled)
        } else {
            self.pending
                .get(request_id)
                .map(|entry| entry.pending.state)
        }
    }

    fn validate_request(&self, request: &RecoveryRequest) -> Result<(), CoreError> {
        if request.protocol_version != PROTOCOL_VERSION
            || request.config_id != self.config_id
            || request.config_version != self.current_version
        {
            Err(CoreError::StaleConfiguration)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_types::{CryptoSuite, PROTOCOL_VERSION};

    fn request(version: u64) -> RecoveryRequest {
        RecoveryRequest {
            protocol_version: PROTOCOL_VERSION,
            crypto_suite: CryptoSuite::default(),
            config_id: [1; 32],
            config_version: version,
            request_id: [2; 32],
            recovery_recipient_key: vec![3; 1216],
            requested_at: 10,
            nonce: [4; 32],
            expiry: 100,
        }
    }

    #[test]
    fn exact_state_sequence() {
        let mut machine = RecoveryMachine::default();
        machine.apply(RecoveryEvent::RequestCreated, 0, 10).unwrap();
        machine
            .apply(RecoveryEvent::ApprovalThresholdReached, 1, 10)
            .unwrap();
        machine.apply(RecoveryEvent::BeginAccepted, 2, 10).unwrap();
        assert!(
            machine
                .apply(RecoveryEvent::ReleaseCertificateReady, 11, 10)
                .is_err()
        );
        machine
            .apply(RecoveryEvent::ReleaseCertificateReady, 12, 10)
            .unwrap();
        machine
            .apply(RecoveryEvent::GuardianThresholdReached, 13, 10)
            .unwrap();
        assert_eq!(machine.state(), RecoveryState::Completed);
    }

    #[test]
    fn cancellation_is_permanent() {
        let mut guardian = GuardianMachine::new([1; 32], 1);
        guardian.begin(&request(1), [9; 32], 10, 5, true).unwrap();
        guardian.cancel([2; 32], [9; 32], true).unwrap();
        assert_eq!(
            guardian.authorize_release([2; 32], [9; 32], 20, true, true),
            Err(CoreError::Cancelled)
        );
    }

    #[test]
    fn cancellation_observed_before_begin_is_a_permanent_tombstone() {
        let mut guardian = GuardianMachine::new([1; 32], 1);
        guardian.cancel([2; 32], [9; 32], true).unwrap();
        assert_eq!(
            guardian.begin(&request(1), [9; 32], 10, 5, true),
            Err(CoreError::Cancelled)
        );
        assert_eq!(guardian.state(&[2; 32]), Some(RecoveryState::Cancelled));
    }

    #[test]
    fn guardian_separates_wall_expiry_from_monotonic_delay() {
        let recovery = request(1);
        let digest = [9; 32];
        let mut guardian = GuardianMachine::new(recovery.config_id, recovery.config_version);
        let not_before = guardian
            .begin_at(&recovery, digest, 10, 1_000, 20, true)
            .unwrap();
        assert_eq!(not_before, 1_020);
        assert_eq!(
            guardian.authorize_release_at(recovery.request_id, digest, 20, 1_019, true, true),
            Err(CoreError::DelayNotElapsed)
        );
        guardian
            .authorize_release_at(recovery.request_id, digest, 20, 1_020, true, true)
            .unwrap();
    }

    #[test]
    fn stale_version_and_replay_are_rejected() {
        let mut guardian = GuardianMachine::new([1; 32], 2);
        assert_eq!(
            guardian.begin(&request(1), [9; 32], 10, 5, true),
            Err(CoreError::StaleConfiguration)
        );
        guardian.begin(&request(2), [9; 32], 10, 5, true).unwrap();
        assert_eq!(
            guardian.begin(&request(2), [9; 32], 10, 5, true),
            Err(CoreError::Replay)
        );

        let mut reused_nonce = request(2);
        reused_nonce.request_id = [8; 32];
        assert_eq!(
            guardian.begin(&reused_nonce, [7; 32], 10, 5, true),
            Err(CoreError::Replay)
        );
    }

    fn completed_machine() -> RecoveryMachine {
        let mut machine = RecoveryMachine::default();
        machine.apply(RecoveryEvent::RequestCreated, 0, 10).unwrap();
        machine
            .apply(RecoveryEvent::ApprovalThresholdReached, 1, 10)
            .unwrap();
        machine.apply(RecoveryEvent::BeginAccepted, 2, 10).unwrap();
        machine
            .apply(RecoveryEvent::ReleaseCertificateReady, 12, 10)
            .unwrap();
        machine
            .apply(RecoveryEvent::GuardianThresholdReached, 13, 10)
            .unwrap();
        machine
    }

    #[test]
    fn completed_transitions_to_expired_via_expiry_reached() {
        let mut machine = completed_machine();
        assert_eq!(machine.state(), RecoveryState::Completed);
        let actions = machine.apply(RecoveryEvent::ExpiryReached, 14, 10).unwrap();
        assert_eq!(
            actions,
            vec![Action::RefuseRelease, Action::ZeroizeRecoverySecrets]
        );
        assert_eq!(machine.state(), RecoveryState::Expired);
    }

    #[test]
    fn completed_refuses_owner_cancel() {
        let mut machine = completed_machine();
        assert_eq!(
            machine.apply(RecoveryEvent::OwnerCancelObserved, 13, 10),
            Err(CoreError::InvalidTransition {
                from: RecoveryState::Completed
            })
        );
        assert_eq!(machine.state(), RecoveryState::Completed);
    }

    #[test]
    fn expired_is_absorbing() {
        let mut machine = RecoveryMachine::default();
        machine.apply(RecoveryEvent::RequestCreated, 0, 10).unwrap();
        machine.apply(RecoveryEvent::ExpiryReached, 1, 10).unwrap();
        assert_eq!(machine.state(), RecoveryState::Expired);
        for event in vec![
            RecoveryEvent::RequestCreated,
            RecoveryEvent::ApprovalThresholdReached,
            RecoveryEvent::BeginAccepted,
            RecoveryEvent::ReleaseCertificateReady,
            RecoveryEvent::GuardianThresholdReached,
            RecoveryEvent::OwnerCancelObserved,
            RecoveryEvent::ExpiryReached,
        ] {
            assert_eq!(machine.apply(event, 2, 10), Err(CoreError::Expired));
            assert_eq!(machine.state(), RecoveryState::Expired);
        }
    }

    #[test]
    fn cancelled_refuses_begin_and_release() {
        let mut machine = RecoveryMachine::default();
        machine.apply(RecoveryEvent::RequestCreated, 0, 10).unwrap();
        machine
            .apply(RecoveryEvent::OwnerCancelObserved, 1, 10)
            .unwrap();
        assert_eq!(machine.state(), RecoveryState::Cancelled);
        for event in vec![
            RecoveryEvent::BeginAccepted,
            RecoveryEvent::ReleaseCertificateReady,
            RecoveryEvent::GuardianThresholdReached,
            RecoveryEvent::ExpiryReached,
            RecoveryEvent::OwnerCancelObserved,
        ] {
            assert_eq!(machine.apply(event, 2, 10), Err(CoreError::Cancelled));
            assert_eq!(machine.state(), RecoveryState::Cancelled);
        }
    }
}
