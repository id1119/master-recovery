//! Deterministic protocol-v3 guardian rotation, witness, and epoch-bound
//! recovery state machines. Clocks, certificate results, durability results,
//! and network observations are injected by callers.

use std::collections::{BTreeMap, BTreeSet};

use gp_types::{ConfigRef, Id32, RecoveryRequestV3, RecoveryState, RotationState};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotationEvent {
    BeginAccepted {
        monotonic_now: u64,
        delay_secs: u64,
        certificate_valid: bool,
    },
    ReleaseAccepted {
        monotonic_now: u64,
        certificate_valid: bool,
        state_unambiguous: bool,
    },
    PreparationComplete {
        prepared_count: u16,
        expected_count: u16,
        dpss_result_valid: bool,
        fragments_valid: bool,
    },
    ActivationAuthorized {
        certificate_valid: bool,
        exact_capsule: bool,
    },
    WitnessQcObserved {
        qc_valid: bool,
        exact_successor: bool,
        drain_deadline: u64,
    },
    DrainStarted,
    DrainDeadlineReached {
        monotonic_now: u64,
    },
    OwnerCancelObserved {
        certificate_valid: bool,
    },
    AbortObserved {
        certificate_valid: bool,
    },
    ConflictObserved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotationAction {
    PersistBeginAndWaitUntil(u64),
    BeginDpssAndFragmentRepair,
    AssembleReadyCertificate,
    RequestSignerActivation,
    SubmitToWitnesses,
    ActivateSuccessorAndDrainOld { drain_deadline: u64 },
    RefuseNewOldEpochBegins,
    RetireOldEpoch,
    AbortAndErasePreparedState,
    FailClosed,
}

#[derive(Debug, thiserror::Error, Clone, Eq, PartialEq)]
pub enum RotationError {
    #[error("invalid rotation transition from {from:?}")]
    InvalidTransition { from: RotationState },
    #[error("certificate, result, or quorum is invalid")]
    InvalidEvidence,
    #[error("rotation delay has not elapsed")]
    DelayNotElapsed,
    #[error("not all advertised successor records are durable")]
    IncompletePreparation,
    #[error("rotation has a permanent cancellation/abort tombstone")]
    Aborted,
    #[error("rotation state is ambiguous; fail closed")]
    FailClosed,
    #[error("successor is not the exact next guardian epoch")]
    InvalidSuccessor,
    #[error("another successor is already locked for this predecessor")]
    PredecessorLocked,
    #[error("witness request is stale or replayed")]
    Replay,
    #[error("request is not bound to the active or draining epoch")]
    StaleEpoch,
    #[error("recovery request was not found")]
    UnknownRequest,
    #[error("recovery request transcript does not match")]
    RequestMismatch,
    #[error("recovery request is cancelled")]
    Cancelled,
    #[error("recovery request is expired")]
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationMachine {
    rotation_id: Id32,
    plan_hash: Id32,
    predecessor: ConfigRef,
    successor: ConfigRef,
    state: RotationState,
    not_before: Option<u64>,
    drain_deadline: Option<u64>,
    tombstoned: bool,
    ambiguous: bool,
}

impl RotationMachine {
    pub fn new(
        rotation_id: Id32,
        plan_hash: Id32,
        predecessor: ConfigRef,
        successor: ConfigRef,
    ) -> Result<Self, RotationError> {
        if !successor.is_direct_successor_of(&predecessor) {
            return Err(RotationError::InvalidSuccessor);
        }
        Ok(Self {
            rotation_id,
            plan_hash,
            predecessor,
            successor,
            state: RotationState::Proposed,
            not_before: None,
            drain_deadline: None,
            tombstoned: false,
            ambiguous: false,
        })
    }

    #[must_use]
    pub fn state(&self) -> RotationState {
        self.state
    }

    #[must_use]
    pub fn rotation_id(&self) -> Id32 {
        self.rotation_id
    }

    #[must_use]
    pub fn plan_hash(&self) -> Id32 {
        self.plan_hash
    }

    #[must_use]
    pub fn predecessor(&self) -> ConfigRef {
        self.predecessor
    }

    #[must_use]
    pub fn successor(&self) -> ConfigRef {
        self.successor
    }

    #[must_use]
    pub fn not_before(&self) -> Option<u64> {
        self.not_before
    }

    #[must_use]
    pub fn drain_deadline(&self) -> Option<u64> {
        self.drain_deadline
    }

    pub fn apply(&mut self, event: RotationEvent) -> Result<Vec<RotationAction>, RotationError> {
        if self.ambiguous {
            return Err(RotationError::FailClosed);
        }
        if self.tombstoned {
            return Err(RotationError::Aborted);
        }

        if event == RotationEvent::ConflictObserved {
            self.ambiguous = true;
            return Ok(vec![RotationAction::FailClosed]);
        }

        match (self.state, event) {
            (
                RotationState::Proposed,
                RotationEvent::BeginAccepted {
                    monotonic_now,
                    delay_secs,
                    certificate_valid: true,
                },
            ) => {
                let not_before = monotonic_now.saturating_add(delay_secs);
                self.not_before = Some(not_before);
                self.state = RotationState::DelayPending;
                Ok(vec![RotationAction::PersistBeginAndWaitUntil(not_before)])
            }
            (
                RotationState::DelayPending,
                RotationEvent::ReleaseAccepted {
                    monotonic_now,
                    certificate_valid: true,
                    state_unambiguous: true,
                },
            ) => {
                if monotonic_now < self.not_before.unwrap_or(u64::MAX) {
                    return Err(RotationError::DelayNotElapsed);
                }
                self.state = RotationState::Preparing;
                Ok(vec![RotationAction::BeginDpssAndFragmentRepair])
            }
            (
                RotationState::Preparing,
                RotationEvent::PreparationComplete {
                    prepared_count,
                    expected_count,
                    dpss_result_valid: true,
                    fragments_valid: true,
                },
            ) => {
                if expected_count == 0 || prepared_count != expected_count {
                    return Err(RotationError::IncompletePreparation);
                }
                self.state = RotationState::Ready;
                Ok(vec![
                    RotationAction::AssembleReadyCertificate,
                    RotationAction::RequestSignerActivation,
                ])
            }
            (
                RotationState::Ready,
                RotationEvent::ActivationAuthorized {
                    certificate_valid: true,
                    exact_capsule: true,
                },
            ) => {
                self.state = RotationState::Activating;
                Ok(vec![RotationAction::SubmitToWitnesses])
            }
            (
                RotationState::Activating,
                RotationEvent::WitnessQcObserved {
                    qc_valid: true,
                    exact_successor: true,
                    drain_deadline,
                },
            ) => {
                self.drain_deadline = Some(drain_deadline);
                self.state = RotationState::Active;
                Ok(vec![RotationAction::ActivateSuccessorAndDrainOld {
                    drain_deadline,
                }])
            }
            (RotationState::Active, RotationEvent::DrainStarted) => {
                self.state = RotationState::Draining;
                Ok(vec![RotationAction::RefuseNewOldEpochBegins])
            }
            (RotationState::Draining, RotationEvent::DrainDeadlineReached { monotonic_now }) => {
                if monotonic_now < self.drain_deadline.unwrap_or(u64::MAX) {
                    return Err(RotationError::DelayNotElapsed);
                }
                self.state = RotationState::Retired;
                Ok(vec![RotationAction::RetireOldEpoch])
            }
            (
                RotationState::Proposed
                | RotationState::DelayPending
                | RotationState::Preparing
                | RotationState::Ready
                | RotationState::Activating,
                RotationEvent::OwnerCancelObserved {
                    certificate_valid: true,
                }
                | RotationEvent::AbortObserved {
                    certificate_valid: true,
                },
            ) => {
                self.state = RotationState::Aborted;
                self.tombstoned = true;
                Ok(vec![RotationAction::AbortAndErasePreparedState])
            }
            (
                _,
                RotationEvent::BeginAccepted {
                    certificate_valid: false,
                    ..
                }
                | RotationEvent::ReleaseAccepted {
                    certificate_valid: false,
                    ..
                }
                | RotationEvent::ReleaseAccepted {
                    state_unambiguous: false,
                    ..
                }
                | RotationEvent::PreparationComplete {
                    dpss_result_valid: false,
                    ..
                }
                | RotationEvent::PreparationComplete {
                    fragments_valid: false,
                    ..
                }
                | RotationEvent::ActivationAuthorized {
                    certificate_valid: false,
                    ..
                }
                | RotationEvent::ActivationAuthorized {
                    exact_capsule: false,
                    ..
                }
                | RotationEvent::WitnessQcObserved {
                    qc_valid: false, ..
                }
                | RotationEvent::WitnessQcObserved {
                    exact_successor: false,
                    ..
                }
                | RotationEvent::OwnerCancelObserved {
                    certificate_valid: false,
                }
                | RotationEvent::AbortObserved {
                    certificate_valid: false,
                },
            ) => Err(RotationError::InvalidEvidence),
            (from, _) => Err(RotationError::InvalidTransition { from }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WitnessAction {
    PersistSuccessorBeforeAck {
        predecessor_epoch: u64,
        predecessor_hash: Id32,
        successor_epoch: u64,
        successor_hash: Id32,
    },
    SignFreshRead {
        client_nonce: Id32,
        highest_guardian_epoch: u64,
        capsule_hash: Id32,
    },
    FailClosed,
}

/// Deterministic model of one card-pinned Byzantine-register witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpochWitnessMachine {
    config_id: Id32,
    highest_epoch: u64,
    highest_capsule_hash: Id32,
    predecessor_locks: BTreeMap<Id32, Id32>,
    seen_read_nonces: BTreeSet<Id32>,
    ambiguous: bool,
}

impl EpochWitnessMachine {
    #[must_use]
    pub fn new(config_id: Id32, highest_epoch: u64, highest_capsule_hash: Id32) -> Self {
        Self {
            config_id,
            highest_epoch,
            highest_capsule_hash,
            predecessor_locks: BTreeMap::new(),
            seen_read_nonces: BTreeSet::new(),
            ambiguous: false,
        }
    }

    pub fn accept_successor(
        &mut self,
        predecessor: ConfigRef,
        predecessor_capsule_hash: Id32,
        successor: ConfigRef,
        successor_capsule_hash: Id32,
        activation_certificate_valid: bool,
    ) -> Result<WitnessAction, RotationError> {
        if self.ambiguous {
            return Err(RotationError::FailClosed);
        }
        if !activation_certificate_valid {
            return Err(RotationError::InvalidEvidence);
        }
        if predecessor.config_id != self.config_id
            || predecessor.guardian_epoch != self.highest_epoch
            || predecessor_capsule_hash != self.highest_capsule_hash
            || !successor.is_direct_successor_of(&predecessor)
        {
            return Err(RotationError::InvalidSuccessor);
        }
        if let Some(locked_hash) = self.predecessor_locks.get(&predecessor_capsule_hash) {
            if locked_hash == &successor_capsule_hash {
                return Ok(WitnessAction::PersistSuccessorBeforeAck {
                    predecessor_epoch: predecessor.guardian_epoch,
                    predecessor_hash: predecessor_capsule_hash,
                    successor_epoch: successor.guardian_epoch,
                    successor_hash: successor_capsule_hash,
                });
            }
            return Err(RotationError::PredecessorLocked);
        }

        // This update represents the durable state mutation. The caller must
        // persist the machine before turning the returned action into an ack.
        self.predecessor_locks
            .insert(predecessor_capsule_hash, successor_capsule_hash);
        self.highest_epoch = successor.guardian_epoch;
        self.highest_capsule_hash = successor_capsule_hash;
        Ok(WitnessAction::PersistSuccessorBeforeAck {
            predecessor_epoch: predecessor.guardian_epoch,
            predecessor_hash: predecessor_capsule_hash,
            successor_epoch: successor.guardian_epoch,
            successor_hash: successor_capsule_hash,
        })
    }

    pub fn fresh_read(
        &mut self,
        config_id: Id32,
        client_nonce: Id32,
        issued_at: u64,
        expiry: u64,
        now: u64,
    ) -> Result<WitnessAction, RotationError> {
        if self.ambiguous {
            return Err(RotationError::FailClosed);
        }
        if config_id != self.config_id
            || issued_at > now
            || now >= expiry
            || !self.seen_read_nonces.insert(client_nonce)
        {
            return Err(RotationError::Replay);
        }
        Ok(WitnessAction::SignFreshRead {
            client_nonce,
            highest_guardian_epoch: self.highest_epoch,
            capsule_hash: self.highest_capsule_hash,
        })
    }

    pub fn observe_same_epoch_conflict(
        &mut self,
        guardian_epoch: u64,
        capsule_hash: Id32,
    ) -> Result<WitnessAction, RotationError> {
        if guardian_epoch == self.highest_epoch && capsule_hash != self.highest_capsule_hash {
            self.ambiguous = true;
            Ok(WitnessAction::FailClosed)
        } else {
            Err(RotationError::InvalidEvidence)
        }
    }

    #[must_use]
    pub fn highest(&self) -> (u64, Id32) {
        (self.highest_epoch, self.highest_capsule_hash)
    }
}

#[derive(Clone, Debug)]
struct PendingEpochRecovery {
    config_ref: ConfigRef,
    request_digest: Id32,
    nonce: Id32,
    not_before: u64,
    expiry: u64,
    state: RecoveryState,
}

/// Accepts new Begins only for the current active epoch while allowing exact
/// pre-activation requests to finish on a draining predecessor.
#[derive(Clone, Debug)]
pub struct EpochRecoveryMachine {
    active: ConfigRef,
    draining: BTreeMap<u64, u64>,
    pending: BTreeMap<Id32, PendingEpochRecovery>,
    seen_request_ids: BTreeSet<Id32>,
    seen_nonces: BTreeSet<Id32>,
    cancelled: BTreeMap<Id32, Id32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochReleaseAuthorization {
    pub request_id: Id32,
    pub request_digest: Id32,
    pub config_ref: ConfigRef,
    pub wall_now: u64,
    pub monotonic_now: u64,
    pub certificate_valid: bool,
    pub state_unambiguous: bool,
}

impl EpochRecoveryMachine {
    #[must_use]
    pub fn new(active: ConfigRef) -> Self {
        Self {
            active,
            draining: BTreeMap::new(),
            pending: BTreeMap::new(),
            seen_request_ids: BTreeSet::new(),
            seen_nonces: BTreeSet::new(),
            cancelled: BTreeMap::new(),
        }
    }

    pub fn begin(
        &mut self,
        request: &RecoveryRequestV3,
        request_digest: Id32,
        wall_now: u64,
        monotonic_now: u64,
        delay_secs: u64,
        certificate_valid: bool,
    ) -> Result<u64, RotationError> {
        if !certificate_valid {
            return Err(RotationError::InvalidEvidence);
        }
        if request.config_ref != self.active {
            return Err(RotationError::StaleEpoch);
        }
        if request.requested_at > wall_now || wall_now >= request.expiry {
            return Err(RotationError::Expired);
        }
        if let Some(cancelled_digest) = self.cancelled.get(&request.request_id) {
            return if cancelled_digest == &request_digest {
                Err(RotationError::Cancelled)
            } else {
                Err(RotationError::RequestMismatch)
            };
        }
        if !self.seen_request_ids.insert(request.request_id)
            || !self.seen_nonces.insert(request.nonce)
        {
            return Err(RotationError::Replay);
        }
        let not_before = monotonic_now.saturating_add(delay_secs);
        self.pending.insert(
            request.request_id,
            PendingEpochRecovery {
                config_ref: request.config_ref,
                request_digest,
                nonce: request.nonce,
                not_before,
                expiry: request.expiry,
                state: RecoveryState::DelayPending,
            },
        );
        Ok(not_before)
    }

    pub fn activate_successor(
        &mut self,
        successor: ConfigRef,
        drain_deadline: u64,
        qc_valid: bool,
    ) -> Result<(), RotationError> {
        if !qc_valid {
            return Err(RotationError::InvalidEvidence);
        }
        if !successor.is_direct_successor_of(&self.active) {
            return Err(RotationError::InvalidSuccessor);
        }
        self.draining
            .insert(self.active.guardian_epoch, drain_deadline);
        self.active = successor;
        Ok(())
    }

    pub fn authorize_release(
        &mut self,
        authorization: EpochReleaseAuthorization,
    ) -> Result<(), RotationError> {
        let EpochReleaseAuthorization {
            request_id,
            request_digest,
            config_ref,
            wall_now,
            monotonic_now,
            certificate_valid,
            state_unambiguous,
        } = authorization;
        if !certificate_valid || !state_unambiguous {
            return Err(RotationError::InvalidEvidence);
        }
        if let Some(cancelled_digest) = self.cancelled.get(&request_id) {
            return if cancelled_digest == &request_digest {
                Err(RotationError::Cancelled)
            } else {
                Err(RotationError::RequestMismatch)
            };
        }
        let pending = self
            .pending
            .get_mut(&request_id)
            .ok_or(RotationError::UnknownRequest)?;
        if pending.request_digest != request_digest || pending.config_ref != config_ref {
            return Err(RotationError::RequestMismatch);
        }
        if config_ref != self.active && !self.draining.contains_key(&config_ref.guardian_epoch) {
            return Err(RotationError::StaleEpoch);
        }
        if wall_now >= pending.expiry {
            pending.state = RecoveryState::Expired;
            return Err(RotationError::Expired);
        }
        if monotonic_now < pending.not_before {
            return Err(RotationError::DelayNotElapsed);
        }
        pending.state = RecoveryState::Releasing;
        Ok(())
    }

    pub fn cancel(
        &mut self,
        request_id: Id32,
        request_digest: Id32,
        certificate_valid: bool,
    ) -> Result<(), RotationError> {
        if !certificate_valid {
            return Err(RotationError::InvalidEvidence);
        }
        if let Some(existing) = self.cancelled.get(&request_id) {
            return if existing == &request_digest {
                Ok(())
            } else {
                Err(RotationError::RequestMismatch)
            };
        }
        if let Some(pending) = self.pending.get_mut(&request_id) {
            if pending.request_digest != request_digest {
                return Err(RotationError::RequestMismatch);
            }
            pending.state = RecoveryState::Cancelled;
        }
        self.cancelled.insert(request_id, request_digest);
        Ok(())
    }

    pub fn retire_draining_epoch(
        &mut self,
        guardian_epoch: u64,
        monotonic_now: u64,
    ) -> Result<(), RotationError> {
        let deadline = self
            .draining
            .get(&guardian_epoch)
            .copied()
            .ok_or(RotationError::StaleEpoch)?;
        if monotonic_now < deadline {
            return Err(RotationError::DelayNotElapsed);
        }
        if self.pending.values().any(|pending| {
            pending.config_ref.guardian_epoch == guardian_epoch
                && matches!(
                    pending.state,
                    RecoveryState::DelayPending | RecoveryState::Releasing
                )
        }) {
            return Err(RotationError::FailClosed);
        }
        self.draining.remove(&guardian_epoch);
        Ok(())
    }

    #[must_use]
    pub fn state(&self, request_id: &Id32) -> Option<RecoveryState> {
        if self.cancelled.contains_key(request_id) {
            Some(RecoveryState::Cancelled)
        } else {
            self.pending.get(request_id).map(|pending| pending.state)
        }
    }

    #[must_use]
    pub fn active(&self) -> ConfigRef {
        self.active
    }

    #[must_use]
    pub fn request_nonce(&self, request_id: &Id32) -> Option<Id32> {
        self.pending.get(request_id).map(|pending| pending.nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gp_types::PROTOCOL_VERSION_V3;

    fn config(epoch: u64, marker: u8) -> ConfigRef {
        ConfigRef {
            config_id: [1; 32],
            payload_generation: 1,
            authorization_epoch: 1,
            guardian_epoch: epoch,
            epoch_binding: [marker; 32],
        }
    }

    fn machine() -> RotationMachine {
        RotationMachine::new([7; 32], [8; 32], config(1, 1), config(2, 2)).unwrap()
    }

    #[test]
    fn exact_rotation_transition_table_has_no_activation_shortcut() {
        let mut machine = machine();
        assert!(matches!(
            machine.apply(RotationEvent::ActivationAuthorized {
                certificate_valid: true,
                exact_capsule: true
            }),
            Err(RotationError::InvalidTransition { .. })
        ));
        machine
            .apply(RotationEvent::BeginAccepted {
                monotonic_now: 100,
                delay_secs: 20,
                certificate_valid: true,
            })
            .unwrap();
        assert_eq!(machine.state(), RotationState::DelayPending);
        assert_eq!(
            machine.apply(RotationEvent::ReleaseAccepted {
                monotonic_now: 119,
                certificate_valid: true,
                state_unambiguous: true,
            }),
            Err(RotationError::DelayNotElapsed)
        );
        machine
            .apply(RotationEvent::ReleaseAccepted {
                monotonic_now: 120,
                certificate_valid: true,
                state_unambiguous: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::PreparationComplete {
                prepared_count: 8,
                expected_count: 8,
                dpss_result_valid: true,
                fragments_valid: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::ActivationAuthorized {
                certificate_valid: true,
                exact_capsule: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::WitnessQcObserved {
                qc_valid: true,
                exact_successor: true,
                drain_deadline: 200,
            })
            .unwrap();
        assert_eq!(machine.state(), RotationState::Active);
        machine.apply(RotationEvent::DrainStarted).unwrap();
        machine
            .apply(RotationEvent::DrainDeadlineReached { monotonic_now: 200 })
            .unwrap();
        assert_eq!(machine.state(), RotationState::Retired);
    }

    #[test]
    fn every_successor_record_is_required() {
        let mut machine = machine();
        machine
            .apply(RotationEvent::BeginAccepted {
                monotonic_now: 0,
                delay_secs: 1,
                certificate_valid: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::ReleaseAccepted {
                monotonic_now: 1,
                certificate_valid: true,
                state_unambiguous: true,
            })
            .unwrap();
        assert_eq!(
            machine.apply(RotationEvent::PreparationComplete {
                prepared_count: 5,
                expected_count: 8,
                dpss_result_valid: true,
                fragments_valid: true,
            }),
            Err(RotationError::IncompletePreparation)
        );
        assert_eq!(machine.state(), RotationState::Preparing);
    }

    #[test]
    fn cancel_before_begin_is_a_permanent_tombstone() {
        let mut machine = machine();
        machine
            .apply(RotationEvent::OwnerCancelObserved {
                certificate_valid: true,
            })
            .unwrap();
        assert_eq!(machine.state(), RotationState::Aborted);
        assert_eq!(
            machine.apply(RotationEvent::BeginAccepted {
                monotonic_now: 0,
                delay_secs: 1,
                certificate_valid: true,
            }),
            Err(RotationError::Aborted)
        );
    }

    #[test]
    fn every_pre_activation_state_aborts_without_an_activation_path() {
        for target in [
            RotationState::Proposed,
            RotationState::DelayPending,
            RotationState::Preparing,
            RotationState::Ready,
            RotationState::Activating,
        ] {
            let mut machine = machine();
            if target != RotationState::Proposed {
                machine
                    .apply(RotationEvent::BeginAccepted {
                        monotonic_now: 0,
                        delay_secs: 1,
                        certificate_valid: true,
                    })
                    .unwrap();
            }
            if matches!(
                target,
                RotationState::Preparing | RotationState::Ready | RotationState::Activating
            ) {
                machine
                    .apply(RotationEvent::ReleaseAccepted {
                        monotonic_now: 1,
                        certificate_valid: true,
                        state_unambiguous: true,
                    })
                    .unwrap();
            }
            if matches!(target, RotationState::Ready | RotationState::Activating) {
                machine
                    .apply(RotationEvent::PreparationComplete {
                        prepared_count: 8,
                        expected_count: 8,
                        dpss_result_valid: true,
                        fragments_valid: true,
                    })
                    .unwrap();
            }
            if target == RotationState::Activating {
                machine
                    .apply(RotationEvent::ActivationAuthorized {
                        certificate_valid: true,
                        exact_capsule: true,
                    })
                    .unwrap();
            }
            assert_eq!(machine.state(), target);
            machine
                .apply(RotationEvent::AbortObserved {
                    certificate_valid: true,
                })
                .unwrap();
            assert_eq!(machine.state(), RotationState::Aborted);
            assert_eq!(
                machine.apply(RotationEvent::WitnessQcObserved {
                    qc_valid: true,
                    exact_successor: true,
                    drain_deadline: 100,
                }),
                Err(RotationError::Aborted)
            );
        }
    }

    #[test]
    fn owner_cancel_immediately_before_witness_qc_prevents_activation() {
        let mut machine = machine();
        machine
            .apply(RotationEvent::BeginAccepted {
                monotonic_now: 10,
                delay_secs: 1,
                certificate_valid: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::ReleaseAccepted {
                monotonic_now: 11,
                certificate_valid: true,
                state_unambiguous: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::PreparationComplete {
                prepared_count: 8,
                expected_count: 8,
                dpss_result_valid: true,
                fragments_valid: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::ActivationAuthorized {
                certificate_valid: true,
                exact_capsule: true,
            })
            .unwrap();
        machine
            .apply(RotationEvent::OwnerCancelObserved {
                certificate_valid: true,
            })
            .unwrap();
        assert_eq!(machine.state(), RotationState::Aborted);
    }

    #[test]
    fn witness_locks_exactly_one_child_and_fresh_reads_reject_replay() {
        let old = config(1, 1);
        let first = config(2, 2);
        let second = config(2, 3);
        let mut witness = EpochWitnessMachine::new(old.config_id, 1, [1; 32]);
        witness
            .accept_successor(old, [1; 32], first, [2; 32], true)
            .unwrap();

        // Replaying the already accepted write is idempotent only when it is
        // expressed against the now-current predecessor; a competing sibling
        // can never pass the current/predecessor check.
        assert_eq!(
            witness.accept_successor(old, [1; 32], second, [3; 32], true),
            Err(RotationError::InvalidSuccessor)
        );
        witness
            .fresh_read(old.config_id, [9; 32], 10, 20, 10)
            .unwrap();
        assert_eq!(
            witness.fresh_read(old.config_id, [9; 32], 10, 20, 10),
            Err(RotationError::Replay)
        );
        assert_eq!(witness.highest(), (2, [2; 32]));
    }

    #[test]
    fn pending_old_epoch_recovery_drains_without_delay_reset() {
        let old = config(1, 1);
        let new = config(2, 2);
        let request = RecoveryRequestV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: old,
            request_id: [3; 32],
            recovery_recipient_key: vec![4; 32],
            requested_at: 10,
            nonce: [5; 32],
            expiry: 200,
        };
        let mut recovery = EpochRecoveryMachine::new(old);
        assert_eq!(
            recovery.begin(&request, [6; 32], 10, 100, 20, true),
            Ok(120)
        );
        recovery.activate_successor(new, 250, true).unwrap();
        assert_eq!(recovery.active(), new);
        recovery
            .authorize_release(EpochReleaseAuthorization {
                request_id: [3; 32],
                request_digest: [6; 32],
                config_ref: old,
                wall_now: 20,
                monotonic_now: 120,
                certificate_valid: true,
                state_unambiguous: true,
            })
            .unwrap();

        let mut stale = request.clone();
        stale.request_id = [8; 32];
        stale.nonce = [9; 32];
        assert_eq!(
            recovery.begin(&stale, [10; 32], 20, 120, 20, true),
            Err(RotationError::StaleEpoch)
        );
    }

    #[test]
    fn old_request_cancellation_does_not_abort_rotation() {
        let old = config(1, 1);
        let request = RecoveryRequestV3 {
            protocol_version: PROTOCOL_VERSION_V3,
            config_ref: old,
            request_id: [3; 32],
            recovery_recipient_key: vec![4; 32],
            requested_at: 10,
            nonce: [5; 32],
            expiry: 200,
        };
        let mut recovery = EpochRecoveryMachine::new(old);
        recovery.begin(&request, [6; 32], 10, 10, 20, true).unwrap();
        recovery.cancel([3; 32], [6; 32], true).unwrap();
        assert_eq!(recovery.state(&[3; 32]), Some(RecoveryState::Cancelled));

        let rotation = machine();
        assert_eq!(rotation.state(), RotationState::Proposed);
    }
}
