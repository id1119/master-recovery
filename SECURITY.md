# Security Model

## Protocol-v3 rotation security

Guardian rotation is not a recovery authority. It requires signer-threshold
Begin -> Delay -> Release and a second signer-threshold Activate decision.
The setup-time owner cancellation key can permanently abort the exact rotation
before activation. The coordinator may reconstruct A to open the private
roster and derive per-slot grants, and may reconstruct encrypted ciphertext C;
it never receives D_i or DEK on the ordinary RTS/refresh path.

A non-owner abort needs a threshold of distinct signer votes bound to the
exact plan and pre-activation state. One compromised signer cannot force an
abort, and predecessor plan locks are released only after signers validate the
assembled threshold certificate. The owner path instead unlocks signers only
after they validate the owner certificate and its witness-veto quorum, so it
still works in the narrow race after Activate votes. Owner cancellation is
independently complete
after both `2f+1` authenticated witness vetoes and `n-k+1` authenticated
old-guardian tombstone acknowledgements. The first quorum prevents activation
or QC finalization even if Activate votes were already collected; the second
leaves fewer than the old handoff threshold even if signer cleanup is delayed.
The removed guardian is never an availability dependency: the old
threshold supplies RTS material, and an available removed guardian receives a
best-effort activation notice only to enter draining. Each old ciphertext
fragment contribution proves its full committed record leaf against the
predecessor material root before reconstruction.

The public capsule also binds a stable, domain-separated Merkle root over the
raw deterministic Reed-Solomon fragment set for the immutable payload
generation. After reconstruction, the coordinator must reproduce that root;
each successor verifies its exact fragment, index, shard count and proof before
durable preparation. This prevents a coordinator from activating a successor
set whose locally committed records contain corrupted or permuted fragments.

Although the rotation coordinator reconstructs A and can derive each new
guardian's wrapping key, it never receives the corresponding wrapped DEK share
or full guardian record. Successors retain those locally and expose only a
commitment leaf; otherwise ciphertext plus the coordinator-known wrapping key
would be equivalent to disclosing each share and would let the coordinator
reconstruct DEK. Each preparation acknowledgement signs the exact assembled
material root, and signer activation rejects any Ready certificate whose root
differs from an acknowledgement or the successor capsule.

Atomicity is old-ACTIVE/new-PREPARED until a 2f+1 witness activation QC exists.
Every advertised successor record is required. Witness predecessor locks and
fresh-nonce quorum reads reject forks and rollback under the stated f bound;
an unavailable/ambiguous quorum fails closed. A request begun on the old epoch
keeps its original delay, expiry and cancellation path while that epoch
drains. New old-epoch Begins are forbidden after activation.

Proactive security is conditional: independently refreshed epoch shares plus
secure erasure prevent accumulation only when the attacker compromises fewer
than the threshold within each epoch and never retains a complete threshold.
Rotation cannot undo a previously learned DEK, plaintext or complete old
threshold. ZF FROST and Ed25519 are classical. The selected library's later
refresh-DKG integration needs an external review of this exact use before
production.

### Dependency-audit disposition (2026-08-14)

`cargo audit` reports no known vulnerabilities and one allowed unmaintained
warning, `RUSTSEC-2023-0089` for `atomic-polyfill 1.0.3`. It is present only in
the all-target dependency graph through
`frost-core 3.0.0 -> postcard 1.1.3 -> heapless 0.7.17`; the native dependency
graph does not select it, because `heapless` uses it only for specific embedded
targets. `frost-ristretto255 3.0.0` is the current published provider and its
serialization feature is required for bounded authenticated protocol
messages. The warning is therefore accepted for this native hackathon
prototype, but those embedded targets are unsupported and production release
remains gated on upgrading the provider chain or an external review-approved
patch. This disposition is not a claim that the FROST integration itself has
been audited.

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

The delay and owner hard-cancellation mechanism provide a reaction window while the owner retains its per-config cancellation key; they do not make a compromised signer threshold harmless.

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

## 4. Owner Hard-Cancellation Model

Recovery uses two signer approval phases:

1. BeginRecoveryCertificate starts the guardian-local delay.
2. ReleaseCertificate is required after the delay before release.

Cancellation is owner-only and request-specific. Setup creates an independent
per-config cancellation signing key. Its private half remains only in the
owner's private control state; guardians pin the public half.

A guardian that observes a valid owner signature must never release for that request.

If cancellation is observed before Begin because the network reordered
messages, the guardian stores a tombstone and rejects the later Begin.

The guardian persists that tombstone before returning a signed
`OwnerCancelAck` bound to the exact cancellation transcript. The owner accepts
the distributed cancel as complete only after verifying acknowledgements from
at least `n - k + 1` distinct guardians. This leaves fewer than `k` guardians
available to satisfy the DEK recovery threshold. The guarantee assumes an
acknowledging guardian is honest; a malicious node can sign and later violate
its promise.

An honest guardian records release before transmitting its contribution and
will not acknowledge a later cancellation. Cancellation is therefore a
reaction-window mechanism, not a way to revoke shares already delivered to a
recovery client.

Signers cannot cancel. The owner cancellation key cannot authorize Begin or
Release and cannot decrypt protocol material.

Guardians fail closed when release state is ambiguous.

The owner key is a single point of availability for cancellation. Losing it
does not expose the secret, but it removes the owner's ability to cancel. Its
compromise permits denial of service through valid cancellations, not recovery.

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
6. A valid observed owner hard cancellation permanently kills the request for an honest guardian.
7. Tampered guardian material is rejected before reconstruction.
8. A stale config version, replayed request id, or reused request nonce is rejected.
9. Release votes prove pseudonymous signer membership against the pinned signer-set commitment; owner cancellation proves possession of the pinned per-config cancellation private key.
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
