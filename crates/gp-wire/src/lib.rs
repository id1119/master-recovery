//! Canonical, length-prefixed protocol transcripts.

use gp_types::{
    CryptoSuite, GuardianContribution, OwnerCancelAck, OwnerCancelCertificate, RecoveryRequest,
    ReleaseVote, SealedMessage,
};

const MAX_FIELD_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("canonical field exceeds maximum length")]
    FieldTooLarge,
    #[error("invalid or incomplete frame")]
    InvalidFrame,
}

pub fn frame(payload: &[u8]) -> Result<Vec<u8>, WireError> {
    if payload.len() > MAX_FIELD_LEN {
        return Err(WireError::FieldTooLarge);
    }
    let len = u32::try_from(payload.len()).map_err(|_| WireError::FieldTooLarge)?;
    let mut output = Vec::with_capacity(payload.len() + 4);
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn deframe(frame: &[u8]) -> Result<&[u8], WireError> {
    let prefix: [u8; 4] = frame
        .get(..4)
        .ok_or(WireError::InvalidFrame)?
        .try_into()
        .map_err(|_| WireError::InvalidFrame)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_FIELD_LEN || frame.len() != length + 4 {
        return Err(WireError::InvalidFrame);
    }
    Ok(&frame[4..])
}

#[derive(Default)]
struct Transcript(Vec<u8>);

impl Transcript {
    fn domain(&mut self, value: &'static [u8]) -> Result<(), WireError> {
        self.bytes(value)
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(value.len()).map_err(|_| WireError::FieldTooLarge)?;
        if value.len() > MAX_FIELD_LEN {
            return Err(WireError::FieldTooLarge);
        }
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(value);
        Ok(())
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn finish(self) -> Vec<u8> {
        self.0
    }
}

fn suite_id(suite: CryptoSuite) -> u16 {
    match suite {
        CryptoSuite::XWingXChaCha20Poly1305Ed25519 => 1,
    }
}

pub fn recovery_request(request: &RecoveryRequest) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-request/v1")?;
    out.u16(request.protocol_version);
    out.u16(suite_id(request.crypto_suite));
    out.bytes(&request.config_id)?;
    out.u64(request.config_version);
    out.bytes(&request.request_id)?;
    out.bytes(&request.recovery_recipient_key)?;
    out.u64(request.requested_at);
    out.bytes(&request.nonce)?;
    out.u64(request.expiry);
    Ok(out.finish())
}

pub fn signer_approval(
    request: &RecoveryRequest,
    signer_id: u16,
    encrypted_share: &SealedMessage,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-approval/v1")?;
    out.bytes(&recovery_request(request)?)?;
    out.u16(signer_id);
    out.bytes(&encrypted_share.kem_ciphertext)?;
    out.bytes(&encrypted_share.payload.nonce)?;
    out.bytes(&encrypted_share.payload.ciphertext)?;
    Ok(out.finish())
}

pub fn signer_leaf(signer_id: u16, public_key: &[u8; 32]) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/signer-leaf/v1")?;
    out.u16(signer_id);
    out.bytes(public_key)?;
    Ok(out.finish())
}

pub fn request_digest_preimage(request: &RecoveryRequest) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-request-digest/v1")?;
    out.bytes(&recovery_request(request)?)?;
    Ok(out.finish())
}

pub fn descriptor_context(config_id: &[u8; 32], config_version: u64) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recovery-descriptor-context/v1")?;
    out.bytes(config_id)?;
    out.u64(config_version);
    Ok(out.finish())
}

pub fn recipient_share_context(
    request: &RecoveryRequest,
    signer_id: u16,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recipient-a-share-context/v1")?;
    out.bytes(&recovery_request(request)?)?;
    out.u16(signer_id);
    Ok(out.finish())
}

pub fn guardian_release_context(
    request: &RecoveryRequest,
    guardian_index: u16,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/recipient-guardian-contribution/v1")?;
    out.bytes(&recovery_request(request)?)?;
    out.u16(guardian_index);
    Ok(out.finish())
}

pub fn owner_cancel(certificate: &OwnerCancelCertificate) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/owner-hard-cancel/v1")?;
    out.u16(certificate.protocol_version);
    out.bytes(&certificate.config_id)?;
    out.u64(certificate.config_version);
    out.bytes(&certificate.request_id)?;
    out.bytes(&certificate.request_digest)?;
    out.bytes(&certificate.recovery_recipient_key)?;
    out.bytes(&certificate.cancel_response_recipient_key)?;
    out.u16(certificate.reason_code);
    out.bytes(&certificate.nonce)?;
    out.u64(certificate.issued_at);
    out.bytes(&certificate.owner_cancel_public_key)?;
    Ok(out.finish())
}

pub fn owner_cancel_ack(ack: &OwnerCancelAck) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/owner-hard-cancel-ack/v1")?;
    out.u16(ack.protocol_version);
    out.bytes(&ack.config_id)?;
    out.u64(ack.config_version);
    out.bytes(&ack.request_id)?;
    out.bytes(&ack.request_digest)?;
    out.bytes(&ack.owner_cancel_transcript_digest)?;
    out.u16(ack.guardian_index);
    Ok(out.finish())
}

pub fn release_vote(vote: &ReleaseVote) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/release-vote/v1")?;
    out.u16(vote.protocol_version);
    out.bytes(&vote.config_id)?;
    out.u64(vote.config_version);
    out.bytes(&vote.request_id)?;
    out.bytes(&vote.request_digest)?;
    out.bytes(&vote.recovery_recipient_key)?;
    out.bytes(&vote.nonce)?;
    out.u16(vote.signer_id);
    out.bytes(&vote.signer_public_key)?;
    out.bytes(&vote.signer_membership_proof)?;
    Ok(out.finish())
}

pub fn guardian_contribution(contribution: &GuardianContribution) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/guardian-contribution/v1")?;
    out.u16(contribution.protocol_version);
    out.bytes(&contribution.config_id)?;
    out.u64(contribution.config_version);
    out.bytes(&contribution.request_id)?;
    out.bytes(&contribution.request_digest)?;
    out.u16(contribution.guardian_index);
    out.bytes(&contribution.ciphertext_fragment)?;
    out.bytes(&contribution.encrypted_dek_share.nonce)?;
    out.bytes(&contribution.encrypted_dek_share.ciphertext)?;
    out.bytes(&contribution.merkle_path_proof)?;
    Ok(out.finish())
}

pub fn guardian_leaf(
    config_id: &[u8; 32],
    config_version: u64,
    guardian_index: u16,
    fragment_hash: &[u8; 32],
    encrypted_share_hash: &[u8; 32],
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/guardian-leaf/v1")?;
    out.bytes(config_id)?;
    out.u64(config_version);
    out.u16(guardian_index);
    out.bytes(fragment_hash)?;
    out.bytes(encrypted_share_hash)?;
    Ok(out.finish())
}

pub fn guardian_share_context(
    config_id: &[u8; 32],
    config_version: u64,
    guardian_index: u16,
) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/guardian-dek-share-context/v1")?;
    out.bytes(config_id)?;
    out.u64(config_version);
    out.u16(guardian_index);
    Ok(out.finish())
}

pub fn payload_context(config_id: &[u8; 32], config_version: u64) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/payload-context/v1")?;
    out.bytes(config_id)?;
    out.u64(config_version);
    Ok(out.finish())
}

pub fn node_provision_context(node_id: &str, role: &str) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/network-node-provision/v1")?;
    out.bytes(node_id.as_bytes())?;
    out.bytes(role.as_bytes())?;
    Ok(out.finish())
}

pub fn mailbox_transport_context(mailbox: &str, direction: &str) -> Result<Vec<u8>, WireError> {
    let mut out = Transcript::default();
    out.domain(b"gp/network-mailbox-transport/v1")?;
    out.bytes(mailbox.as_bytes())?;
    out.bytes(direction.as_bytes())?;
    Ok(out.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RecoveryRequest {
        RecoveryRequest {
            protocol_version: gp_types::PROTOCOL_VERSION,
            crypto_suite: CryptoSuite::default(),
            config_id: [1; 32],
            config_version: 1,
            request_id: [2; 32],
            recovery_recipient_key: vec![3; 32],
            requested_at: 10,
            nonce: [4; 32],
            expiry: 20,
        }
    }

    #[test]
    fn recipient_changes_canonical_transcript() {
        let first = recovery_request(&request()).unwrap();
        let mut changed = request();
        changed.recovery_recipient_key[0] ^= 1;
        assert_ne!(first, recovery_request(&changed).unwrap());
    }

    #[test]
    fn length_prefixed_frame_round_trip_and_truncation_failure() {
        let encoded = frame(b"protocol message").unwrap();
        assert_eq!(deframe(&encoded).unwrap(), b"protocol message");
        assert!(deframe(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn release_vote_binds_signer_membership_material() {
        let mut vote = ReleaseVote {
            protocol_version: gp_types::PROTOCOL_VERSION,
            config_id: [1; 32],
            config_version: 1,
            request_id: [2; 32],
            request_digest: [3; 32],
            recovery_recipient_key: vec![4; 1216],
            nonce: [5; 32],
            signer_id: 2,
            signer_public_key: [6; 32],
            signer_membership_proof: vec![7; 64],
            signer_signature: vec![],
        };
        let original = release_vote(&vote).unwrap();
        vote.signer_membership_proof[0] ^= 1;
        assert_ne!(original, release_vote(&vote).unwrap());
    }

    #[test]
    fn network_mailbox_context_binds_mailbox_and_direction() {
        let request = mailbox_transport_context("mailbox-a", "request").unwrap();
        assert_ne!(
            request,
            mailbox_transport_context("mailbox-a", "response").unwrap()
        );
        assert_ne!(
            request,
            mailbox_transport_context("mailbox-b", "request").unwrap()
        );
    }

    #[test]
    fn owner_cancel_binds_recovery_and_ack_recipients() {
        let mut certificate = OwnerCancelCertificate {
            protocol_version: gp_types::PROTOCOL_VERSION,
            config_id: [1; 32],
            config_version: 1,
            request_id: [2; 32],
            request_digest: [3; 32],
            recovery_recipient_key: vec![4; 1216],
            cancel_response_recipient_key: vec![5; 1216],
            reason_code: 1,
            nonce: [6; 32],
            issued_at: 10,
            owner_cancel_public_key: [7; 32],
            owner_signature: vec![],
        };
        let original = owner_cancel(&certificate).unwrap();
        certificate.recovery_recipient_key[0] ^= 1;
        assert_ne!(original, owner_cancel(&certificate).unwrap());
        certificate.recovery_recipient_key[0] ^= 1;
        certificate.cancel_response_recipient_key[0] ^= 1;
        assert_ne!(original, owner_cancel(&certificate).unwrap());
    }
}
