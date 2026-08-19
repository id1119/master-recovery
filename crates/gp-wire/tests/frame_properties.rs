//! Property tests for the canonical wire framing.
//!
//! The frame format is a 4-byte big-endian length prefix followed by the
//! payload. These tests pin the format as a spec: framing must round-trip,
//! framing must be canonical (injective), and malformed input must never
//! panic or silently succeed.

use gp_wire::{WireError, deframe, frame};
use proptest::prelude::*;

const MAX_FIELD_LEN: usize = 16 * 1024 * 1024;

proptest! {
    #[test]
    fn deframe_roundtrips_frame(payload in proptest::collection::vec(any::<u8>(), 0..=4096)) {
        let encoded = frame(&payload).unwrap();
        prop_assert_eq!(deframe(&encoded).unwrap(), payload.as_slice());
    }

    #[test]
    fn deframe_is_canonical(
        encoded in proptest::collection::vec(any::<u8>(), 0..=4096)
    ) {
        if let Ok(payload) = deframe(&encoded) {
            prop_assert_eq!(frame(payload).unwrap(), encoded);
        }
    }

    #[test]
    fn deframe_never_panics(bytes in any::<[u8; 64]>()) {
        let _ = deframe(&bytes);
    }
}

#[test]
fn frame_rejects_oversized_payload() {
    let big = vec![0u8; MAX_FIELD_LEN + 1];
    assert!(matches!(frame(&big), Err(WireError::FieldTooLarge)));
}

#[test]
fn frame_accepts_maximum_payload() {
    let max = vec![7u8; MAX_FIELD_LEN];
    let encoded = frame(&max).unwrap();
    assert_eq!(deframe(&encoded).unwrap(), max.as_slice());
}

#[test]
fn deframe_rejects_malformed_frames() {
    let payload = b"protocol message";
    let encoded = frame(payload).unwrap();

    assert!(
        deframe(&encoded[..3]).is_err(),
        "prefix shorter than 4 bytes"
    );
    assert!(
        deframe(&encoded[..encoded.len() - 1]).is_err(),
        "truncated body"
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(deframe(&trailing).is_err(), "trailing garbage");

    let mut lying = vec![0, 0, 0, 255];
    lying.extend_from_slice(payload);
    assert!(deframe(&lying).is_err(), "prefix longer than body");

    let mut huge = vec![0, 1, 0, 0];
    huge.extend_from_slice(payload);
    assert!(deframe(&huge).is_err(), "prefix above max field length");
}

#[test]
fn deframe_rejects_empty_input() {
    assert!(matches!(deframe(&[]), Err(WireError::InvalidFrame)));
}
