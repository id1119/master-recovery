# Protocol Specification

## 1. Core Objects

For each protected secret:

```text
A   = random authorization key
DEK = random data-encryption key
```

A is shared among authorization signers with threshold `s-of-m`.

DEK is shared among storage guardians with threshold `k-of-n`, but each guardian's DEK share is encrypted under a per-guardian key derived from A.

The plaintext secret is encrypted with DEK before any erasure coding.

## 2. Setup

### 2.1 Create Configuration

Generate:

- `config_id`: random 256-bit opaque id,
- `config_version`: initial version,
- A,
- DEK,
- signer set,
- guardian set,
- thresholds,
- minimum recovery delay.

### 2.2 Split A to Signers

```text
A -> Shamir(s-of-m) -> A_share_i
```

Signer i receives exactly one A share plus its private signer state.

Signer keys are independently generated.

### 2.3 Encrypt the Secret

```text
C = XChaCha20Poly1305_Encrypt(DEK, secret, payload_context)
```

### 2.4 Erasure-Code the Ciphertext

```text
C -> Reed-Solomon(k-of-n) -> F_i
```

Any k valid fragments reconstruct C.

### 2.5 Split the DEK

```text
DEK -> Shamir(k-of-n) -> D_i
```

### 2.6 Encrypt Each Guardian DEK Share Under A

For guardian i:

```text
K_i = HKDF-SHA256(
    A,
    "gp/guardian-dek-share/v1" || config_id || config_version || i
)

E_i = XChaCha20Poly1305_Encrypt(K_i, D_i, guardian_share_context)
```

Guardian i never stores plaintext `D_i`.

### 2.7 Commit Guardian Material

For each i:

```text
leaf_i = SHA256(
    "gp/guardian-leaf/v1" ||
    config_id ||
    config_version ||
    i ||
    SHA256(F_i) ||
    SHA256(E_i)
)
```

Build a Merkle root over all leaves.

### 2.8 Guardian Record

Guardian i stores:

```text
GuardianRecord_i {
    opaque_slot_id,
    F_i,
    E_i,
    integrity_proof,
    policy_record
}
```

`policy_record` contains only pseudonymous information needed to verify recovery and enforce the delay.
It pins the signer count as well as the signer threshold and signer-set root so
a standalone guardian can verify Merkle membership proofs without privileged
simulator state or a public signer registry.

### 2.9 Recovery Descriptor

Create:

```text
RecoveryDescriptor {
    guardian opaque mailbox handles,
    opaque slot ids,
    guardian indices,
    integrity roots,
    erasure parameters,
    required recovery metadata
}
```

Encrypt it under:

```text
K_descriptor = HKDF(A, "gp/recovery-descriptor/v1" || config_id || config_version)
```

The plaintext guardian roster is not public.

### 2.10 Config Capsule

Publish/redundantly store the pseudonymous Config Capsule containing:

- protocol and crypto-suite versions,
- config id/version,
- thresholds,
- delay,
- signer-set commitment,
- guardian-material commitment,
- encrypted Recovery Descriptor,
- replay-protection parameters.

### 2.11 Recovery Card

Create a privacy-sensitive, non-confidential locator containing:

- config id,
- Config Capsule locator,
- signer opaque mailbox handles,
- signer-set commitment.

It contains no secret key material and no guardian roster.

## 3. Recovery

### 3.1 Fresh Device

The recovery client starts with blank secret state and scans the Recovery Card.

It retrieves the Config Capsule.

### 3.2 Fresh Recovery Recipient

Generate a new one-time KEM recovery-recipient keypair.

The decapsulation key remains only on the recovery device.

### 3.3 Recovery Request

Create a unique RecoveryRequest bound to:

- protocol version,
- crypto suite,
- config id/version,
- request id,
- recovery recipient,
- requested time,
- nonce,
- expiry.

### 3.4 Signer Approval

Each signer independently performs the external/social identity check.

An approving signer returns:

- signature over the exact request transcript,
- signer membership proof,
- its A share encrypted to the exact recovery recipient.

The recovery client accepts only distinct valid signer contributions for the exact request.

### 3.5 Reconstruct A

After s valid signer contributions:

```text
A_share_1 ... A_share_s -> A
```

The recovery client decrypts the Recovery Descriptor and learns the guardian routing/slot information.

### 3.6 Begin Recovery

The recovery client sends the threshold-valid signer approvals to selected guardians as a BeginRecoveryCertificate through the metadata-resistant transport.

Each honest guardian validates the certificate and records a local monotonic `not_before` time.

### 3.7 Delay

Before `not_before`, an honest guardian does not release its contribution.

No drand timelock is used.

### 3.8 Cancellation

During the delay, threshold-valid signed cancellation votes can form a CancelCertificate for the exact request.

A guardian that observes a valid cancellation marks the request permanently cancelled.

Each vote includes the signer's pseudonymous public key and Merkle membership
proof. The guardian verifies that proof against its pinned signer-set
commitment before counting the signature. A valid cancellation observed before
Begin is stored as a request-specific tombstone and rejects a later reordered
Begin.

Each cancellation vote includes a canonical digest of the complete immutable
RecoveryRequest, binding the vote to its exact recovery recipient, nonce,
expiry, and crypto suite.

A signer that has cancelled a request must not sign that request's release phase.

### 3.9 Release Certificate

After the delay window, the recovery client obtains the configured signer threshold of fresh release votes bound to the same immutable RecoveryRequest.

These form the ReleaseCertificate.

Each release vote includes the signer's pseudonymous public key and Merkle
membership proof, allowing every guardian to validate the certificate without
a public signer registry or privileged simulator state.

A guardian releases only if:

- BeginRecoveryCertificate was valid,
- its local delay elapsed,
- the request is not expired,
- no valid cancellation was observed,
- ReleaseCertificate is valid,
- config version is current.

On ambiguous or partitioned state, the guardian fails closed.

### 3.10 Guardian Contribution

Guardian i returns the exact committed:

- F_i,
- E_i,
- Merkle proof,
- guardian signature,

all encrypted to the approved recovery recipient.

The signed contribution includes the same canonical request digest, so its
request id cannot be rebound to another recipient or transcript.

### 3.11 Final Reconstruction

The recovery client:

1. verifies guardian contributions,
2. rejects corrupted contributions,
3. obtains k valid guardian responses,
4. derives each `K_i` from A,
5. decrypts each `E_i` to obtain `D_i`,
6. reconstructs DEK from k valid `D_i`,
7. reconstructs C from k valid `F_i`,
8. decrypts C with DEK,
9. outputs the secret locally,
10. zeroizes temporary secret material.

## 4. Rotation

After successful recovery, create a new configuration version with fresh:

- A,
- DEK,
- signer shares,
- guardian DEK shares,
- encrypted DEK shares,
- ciphertext fragments,
- opaque slot ids,
- request/replay state.

Old versions become invalid.
