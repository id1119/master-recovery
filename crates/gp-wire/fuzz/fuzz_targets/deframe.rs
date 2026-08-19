#![no_main]

use gp_wire::{deframe, frame};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(payload) = deframe(data) {
        assert_eq!(frame(payload).unwrap(), data, "deframe must be canonical");
    }
});