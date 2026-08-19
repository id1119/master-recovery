#![no_main]

use gp_types::{CryptoSuite, OwnerCancelCertificate, RecoveryRequest, ReleaseVote};
use gp_wire::{owner_cancel, recovery_request, release_vote};
use libfuzzer_sys::fuzz_target;

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        Some(self.take(N)?.try_into().unwrap())
    }

    fn vec(&mut self) -> Option<Vec<u8>> {
        let len = usize::from(self.u16()?);
        Some(self.take(len)?.to_vec())
    }
}

fn request(cursor: &mut Cursor) -> Option<RecoveryRequest> {
    let protocol_version = cursor.u16()?;
    let config_version = cursor.u64()?;
    let config_id = cursor.array()?;
    let request_id = cursor.array()?;
    let requested_at = cursor.u64()?;
    let nonce = cursor.array()?;
    let expiry = cursor.u64()?;
    let recovery_recipient_key = cursor.vec()?;
    Some(RecoveryRequest {
        protocol_version,
        crypto_suite: CryptoSuite::default(),
        config_id,
        config_version,
        request_id,
        recovery_recipient_key,
        requested_at,
        nonce,
        expiry,
    })
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let Some(request) = request(&mut cursor) else {
        return;
    };
    if let Ok(transcript) = recovery_request(&request) {
        assert_eq!(
            recovery_request(&request).unwrap(),
            transcript,
            "recovery_request must be deterministic"
        );
    }

    let Some(request_digest) = cursor.array::<32>() else {
        return;
    };
    let Some(signer_id) = cursor.u16() else {
        return;
    };
    let Some(signer_public_key) = cursor.array::<32>() else {
        return;
    };
    let Some(signer_membership_proof) = cursor.vec() else {
        return;
    };
    let Some(signer_signature) = cursor.vec() else {
        return;
    };
    let vote = ReleaseVote {
        protocol_version: request.protocol_version,
        config_id: request.config_id,
        config_version: request.config_version,
        request_id: request.request_id,
        request_digest,
        recovery_recipient_key: request.recovery_recipient_key.clone(),
        nonce: request.nonce,
        signer_id,
        signer_public_key,
        signer_membership_proof,
        signer_signature,
    };
    if let Ok(transcript) = release_vote(&vote) {
        assert_eq!(
            release_vote(&vote).unwrap(),
            transcript,
            "release_vote must be deterministic"
        );
    }

    let Some(reason_code) = cursor.u16() else {
        return;
    };
    let Some(issued_at) = cursor.u64() else {
        return;
    };
    let Some(owner_cancel_public_key) = cursor.array::<32>() else {
        return;
    };
    let Some(cancel_response_recipient_key) = cursor.vec() else {
        return;
    };
    let certificate = OwnerCancelCertificate {
        protocol_version: request.protocol_version,
        config_id: request.config_id,
        config_version: request.config_version,
        request_id: request.request_id,
        request_digest,
        recovery_recipient_key: request.recovery_recipient_key.clone(),
        cancel_response_recipient_key,
        reason_code,
        nonce: request.nonce,
        issued_at,
        owner_cancel_public_key,
        owner_signature: Vec::new(),
    };
    if let Ok(transcript) = owner_cancel(&certificate) {
        assert_eq!(
            owner_cancel(&certificate).unwrap(),
            transcript,
            "owner_cancel must be deterministic"
        );
    }
});