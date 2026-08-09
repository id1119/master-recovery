# Security Model

## 1. Security Goals

### Content Confidentiality

The plaintext secret should exist only on:

- the owner client during setup,
- the recovery client during final reconstruction.

### Threshold Authorization

Fewer than `s` valid signer A shares must not reconstruct A.

### Threshold Custody

Fewer than `k` valid guardian DEK shares must not reconstruct DEK.

### Separation

- guardian material alone must not be enough to decrypt the DEK shares because they are wrapped under keys derived from A,
- signer material alone must not be enough because signers do not possess the guardian-stored encrypted DEK shares and ciphertext fragments,
- the relay/config store must possess neither complete path.

### Exact Recipient Binding

Every approval and released contribution must be bound to the exact fresh recovery recipient and exact request.

### Replay Resistance

Old request ids, reused nonces, expired requests, and stale config versions must not be reusable by signers or guardians.

### Integrity

Corrupted guardian material must be detected before reconstruction.

## 2. Threat Assumptions

### Signer Threshold Compromise

If an attacker compromises the signer threshold, it can authorize a malicious recovery and reconstruct A.

The delay and cancellation mechanism provide a reaction window; they do not make a compromised signer threshold harmless.

### Guardian Threshold Compromise

Enough malicious guardians may ignore their own delay policy and expose all of their stored material.

Because their DEK shares are encrypted under A-derived keys, guardian compromise alone must not reveal the secret without A.

### Combined Failure

An attacker that crosses both relevant threshold assumptions can recover early.

Do not market the protocol as requiring two independently compromised quorums for every possible attack path. The correct statement is that the design separates authorization material from custody material and removes any single guardian or relay as an ultimate authority.

### Relay Failure

A relay can always drop or delay traffic. Availability cannot be cryptographically forced.

Authenticated messages prevent successful unnoticed modification or recipient substitution.

### Endpoint Knowledge

A signer asked to approve a request knows it is participating in some recovery.

A selected guardian that releases a slot knows that one of its opaque stored records is being accessed/released.

The protocol aims to hide owner identity and global relationship metadata, not the local fact that an endpoint was asked to act.

## 3. Delay Model

The 24-hour delay is guardian-policy enforced with a monotonic clock.

It is not a trust-free cryptographic timelock.

The protocol does not use drand as a security-critical delay because the project requires a PQ-oriented threat model and the current design intentionally avoids that dependency.

The simulator may compress the delay for visualization, but the production configuration must enforce at least 24 hours.

## 4. Cancellation Model

Recovery uses two signer phases:

1. BeginRecoveryCertificate starts the guardian-local delay.
2. ReleaseCertificate is required after the delay before release.

Cancellation is threshold-signed and request-specific.

A guardian that observes a valid cancellation must never release for that request.

If cancellation is observed before Begin because the network reordered
messages, the guardian stores a tombstone and rejects the later Begin.

A signer that has cancelled must not later issue a release vote for the same request.

Guardians fail closed when release state is ambiguous.

This design reduces reliance on proving the absence of a cancellation message over an unreliable network.

## 5. Post-Quantum Scope

The prototype is post-quantum-skewed, not fully post-quantum.

- transport key establishment uses X-Wing (ML-KEM-768 plus X25519),
- symmetric encryption uses 256-bit keys,
- Shamir and Reed-Solomon are not the PQ weak point,
- signer signatures remain Ed25519 in the hackathon path and are therefore classical.

The UI and documentation must not call the whole system fully post-quantum while Ed25519 remains security-critical.

## 6. Security Invariants

1. No plaintext secret is stored by signers, guardians, relay nodes, or the config store.
2. Fewer than s valid A shares do not reconstruct A.
3. Fewer than k valid DEK shares do not reconstruct DEK.
4. A wrong A fails to decrypt guardian DEK shares.
5. A guardian releases only for the exact approved request/recipient after its local delay and required release certificate.
6. A valid observed cancellation permanently kills the request for an honest guardian.
7. Tampered guardian material is rejected before reconstruction.
8. A stale config version, replayed request id, or reused request nonce is rejected.
9. Release and cancellation votes prove pseudonymous signer membership against the pinned signer-set commitment.
10. The guardian roster is not stored publicly in plaintext.
11. Final plaintext reconstruction occurs only on the recovery client.

## 7. Explicit Non-Claims

Do not claim:

- bug-free software,
- perfect anonymity,
- information-theoretic metadata privacy,
- unconditional 24-hour cryptographic timelock,
- full PQ security while Ed25519 remains in the authorization path,
- availability against an adversary that can drop all routes,
- metadata privacy against every possible threshold collusion.
