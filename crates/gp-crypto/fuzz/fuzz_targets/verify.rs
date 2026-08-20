#![no_main]

use gp_crypto::verify;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let public_key: [u8; 32] = data[..32].try_into().unwrap();
    let signature: [u8; 64] = data[32..96].try_into().unwrap();
    let _ = verify(&public_key, &data[96..], &signature);
});
