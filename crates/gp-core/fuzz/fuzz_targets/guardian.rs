#![no_main]

use gp_core::{CoreError, GuardianMachine};
use gp_types::{CryptoSuite, PROTOCOL_VERSION, RecoveryRequest, RecoveryState};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 104 {
        return;
    }
    let wall = u64::from_le_bytes(data[0..8].try_into().unwrap()) % 1_000_000;
    let monotonic = u64::from_le_bytes(data[8..16].try_into().unwrap()) % 1_000_000;
    let delay = u64::from_le_bytes(data[16..24].try_into().unwrap()) % 1000;
    let wall2 = u64::from_le_bytes(data[24..32].try_into().unwrap()) % 1_000_000;
    let mono2 = u64::from_le_bytes(data[32..40].try_into().unwrap()) % 1_000_000;
    let expiry = wall + 1 + (monotonic % 1000);
    let request = RecoveryRequest {
        protocol_version: PROTOCOL_VERSION,
        crypto_suite: CryptoSuite::default(),
        config_id: [1; 32],
        config_version: 1,
        request_id: data[40..72].try_into().unwrap(),
        recovery_recipient_key: data[104..].to_vec(),
        requested_at: wall,
        nonce: data[72..104].try_into().unwrap(),
        expiry,
    };
    let digest = [9; 32];
    let other_digest = [10; 32];

    let mut machine = GuardianMachine::new([1; 32], 1);
    let Ok(not_before) = machine.begin_at(&request, digest, wall, monotonic, delay, true)
    else {
        return;
    };
    assert_eq!(
        machine.state(&request.request_id),
        Some(RecoveryState::DelayPending)
    );
    if wall2 >= expiry {
        assert!(matches!(
            machine.authorize_release_at(request.request_id, digest, wall2, mono2, true, true),
            Err(CoreError::Expired)
        ));
        assert_eq!(
            machine.state(&request.request_id),
            Some(RecoveryState::Expired)
        );
    } else if mono2 < not_before {
        assert!(matches!(
            machine.authorize_release_at(request.request_id, digest, wall2, mono2, true, true),
            Err(CoreError::DelayNotElapsed)
        ));
        assert_eq!(
            machine.state(&request.request_id),
            Some(RecoveryState::DelayPending)
        );
    } else {
        assert_eq!(
            machine.authorize_release_at(request.request_id, digest, wall2, mono2, true, true),
            Ok(())
        );
        assert_eq!(
            machine.state(&request.request_id),
            Some(RecoveryState::Releasing)
        );
    }

    let mut cancelled = GuardianMachine::new([1; 32], 1);
    let _ = cancelled.begin_at(&request, digest, wall, monotonic, delay, true);
    assert!(cancelled.cancel(request.request_id, digest, true).is_ok());
    assert_eq!(
        cancelled.state(&request.request_id),
        Some(RecoveryState::Cancelled)
    );
    assert!(matches!(
        cancelled.begin_at(&request, digest, wall, monotonic, delay, true),
        Err(CoreError::Cancelled)
    ));
    assert!(matches!(
        cancelled.begin_at(&request, other_digest, wall, monotonic, delay, true),
        Err(CoreError::RequestMismatch)
    ));
    assert!(matches!(
        cancelled.authorize_release_at(request.request_id, digest, wall, monotonic, true, true),
        Err(CoreError::Cancelled)
    ));
});