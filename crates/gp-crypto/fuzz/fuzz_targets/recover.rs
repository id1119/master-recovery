#![no_main]

use gp_crypto::recover_secret;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let shares: Vec<&[u8]> = data.chunks(33).take(3).collect();
    let _ = recover_secret(&shares, 3);
});