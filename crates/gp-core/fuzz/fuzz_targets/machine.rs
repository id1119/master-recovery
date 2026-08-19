#![no_main]

use gp_core::{CoreError, RecoveryEvent, RecoveryMachine};
use gp_types::RecoveryState;
use libfuzzer_sys::fuzz_target;

const EVENTS: [RecoveryEvent; 7] = [
    RecoveryEvent::RequestCreated,
    RecoveryEvent::ApprovalThresholdReached,
    RecoveryEvent::BeginAccepted,
    RecoveryEvent::ReleaseCertificateReady,
    RecoveryEvent::GuardianThresholdReached,
    RecoveryEvent::OwnerCancelObserved,
    RecoveryEvent::ExpiryReached,
];

fuzz_target!(|data: &[u8]| {
    let mut machine = RecoveryMachine::default();
    for chunk in data.chunks(17) {
        if chunk.len() < 17 {
            break;
        }
        let event = EVENTS[chunk[0] as usize % EVENTS.len()].clone();
        let now = u64::from_le_bytes(chunk[1..9].try_into().unwrap());
        let delay = u64::from_le_bytes(chunk[9..17].try_into().unwrap());
        let before = machine.state();
        match machine.apply(event, now, delay) {
            Ok(_) => {
                assert!(
                    before != RecoveryState::Cancelled && before != RecoveryState::Expired,
                    "terminal state accepted a transition"
                );
            }
            Err(error) => {
                assert_eq!(machine.state(), before, "failed apply must not mutate state");
                match before {
                    RecoveryState::Cancelled => {
                        assert!(matches!(error, CoreError::Cancelled));
                    }
                    RecoveryState::Expired => {
                        assert!(matches!(error, CoreError::Expired));
                    }
                    _ => {}
                }
            }
        }
    }
});