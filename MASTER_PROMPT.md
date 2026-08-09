# Master Prompt — Hackathon Prototype Build

This is a build and demo instruction set for a hackathon, not a research program.

We are building a **metadata-resistant, post-quantum-skewed, decentralized secret recovery protocol**. A user can store any secret with independent storage guardians and later recover it from a brand-new device after a minimum delay, with recovery approved by trusted signers. The network should learn as little as possible about who owns a secret, which guardians hold its material, and when a real recovery is happening.

The prototype succeeds if:

- it runs end-to-end,
- it is fully visualizable in the GUI simulator,
- it uses real, maintained cryptographic primitives without inventing crypto,
- it survives a live demo with an offline or malicious guardian,
- it survives a cancellation race,
- its metadata-resistance claims are precise and visible in the simulator,
- it never silently claims guarantees the implemented system does not provide.

Everything below exists to serve that demo.

---

## 1. Rules

- Never invent cryptographic primitives.
- Use real, maintained crates. Verify that a crate exists, is maintained, and compiles before committing to it.
- If a specification detail breaks the security model or makes the demo internally inconsistent, stop and report it before implementing it.
- Do not build a general framework. Build the smallest coherent protocol that exercises the full demo path.
- KISS, DRY, and Unix philosophy.
- The same deterministic protocol core must drive both the real local processes and the simulator.
- Do not add cryptographic mechanisms or protocol features that are not in this specification.
- Use the X-Wing X25519 + ML-KEM-768 transport KEM through an existing maintained implementation. Do not implement or modify its hybrid combiner.
- Do not use drand for the security-critical recovery delay.
- Do not use a one-time-pad layer.

---

## 2. Demo — One Script, About Four Minutes

### Leg 1 — Setup

1. The owner types a secret or selects a file in the GUI.
2. The GUI visualizes:
   - secret -> random DEK -> encrypted payload,
   - encrypted payload -> erasure-coded fragments to eight guardians,
   - DEK -> Shamir shares -> encrypted DEK shares to eight guardians,
   - authorization key A -> Shamir shares to three signers.
3. The GUI clearly shows that no guardian receives the plaintext secret or an immediately usable DEK share.

### Leg 2 — Recovery

4. A fresh recovery device starts from blank state and scans the owner's Recovery Card.
5. Two of three signers approve the exact recovery request; the third signer is unavailable.
6. The recovery client reconstructs A, decrypts the private Recovery Descriptor, and learns the guardian routing information without exposing the guardian set publicly.
7. The approved recovery enters the minimum-delay state. In the simulator, the 24-hour delay is compressed to a few seconds.
8. After the delay, the required release certificate is produced and guardians release enough valid encrypted material.
9. The recovery device reconstructs the DEK, reconstructs the encrypted payload, decrypts it locally, and displays the secret.

### Leg 3 — Adversary

10. One guardian becomes malicious or unavailable. It corrupts a fragment or refuses to release.
11. The recovery client detects the corrupted response through authenticated integrity checks and the Merkle commitment, discards it, and obtains replacement contributions until it has the required number of valid guardian responses.
12. Run a cancellation race: the original owner uses the setup-time per-config private cancellation key before release. The recovery request becomes permanently cancelled and no honest guardian that observes it releases for that request.

### Leg 4 — Metadata

13. Toggle metadata mode between OFF, BASIC, and STRONG.
14. In STRONG mode, visualize fixed-size cells, multi-hop mixing, rotating opaque mailbox identifiers, epoch batching, and continuous cover traffic.
15. The passive-observer panel must show that real and dummy packet formats are indistinguishable to the observer, while also showing the metadata that is still inherently visible.

The demo must always be replayable from a fixed seed so it cannot fail on stage.

---

## 3. Actors

### Owner Client

Creates secrets and configurations. The owner's real-world identity is not exposed to storage guardians.

### Authorization Signers

Default: 3 signers, threshold 2.

They are independent trusted people or devices selected by the owner. They:

- verify a recovery request through an external/social process,
- approve the exact recovery recipient and request transcript,
- hold independent Shamir shares of authorization key A,
- later participate in the release certificate.

They never receive the plaintext secret.

Signer secret keys must be independently generated. They must not all be derived from one owner master seed.

### Storage Guardians

Default: 8 guardians, threshold 5.

Each guardian stores:

- one erasure-coded encrypted-payload fragment,
- one encrypted Shamir share of the DEK,
- the integrity material required to verify the contribution,
- an opaque slot/mailbox identifier,
- the minimum pseudonymous policy data required to validate and enforce recovery for that slot.

A guardian must not know the owner's real identity.

### Recovery Client

A brand-new device with none of the original secret material. It generates a fresh throwaway recovery-recipient keypair for every recovery attempt.

### Relay / Mix Layer

An untrusted packet-forwarding layer. It may delay, reorder, duplicate, or drop traffic. It must never be trusted with plaintext secrets.

The relay may redirect packets at the network level, but authenticated protocol objects must make successful request substitution or recovery-recipient redirection fail.

### Config Store

A replicated hackathon-scale store for public/pseudonymous configuration capsules, retrievable through `config_id` or its Recovery Card locator. It contains no plaintext secret, no authorization key A, no DEK, and no plaintext guardian roster.

---

## 4. Cryptographic Stack

The project is **post-quantum-skewed, not fully post-quantum**, because the hackathon signer-signature path uses Ed25519 unless time allows a later ML-DSA migration.

### Transport Key Establishment

Selected profile:

- X-Wing: X25519 + ML-KEM-768 hybrid.

Rules:

- use an existing reviewed construction and maintained implementation,
- do not invent a hybrid combiner,
- use the published X-Wing construction through a maintained generic KEM/HPKE implementation,
- if a correct maintained implementation cannot be verified, stop and report the blocker rather than faking the hybrid.

The PQ claim must never rely on the X25519 half alone.

### AEAD

Use XChaCha20-Poly1305 where supported by the chosen maintained library.

- 256-bit key,
- 192-bit nonce,
- fresh nonce per encryption under the same key,
- explicit associated data binding protocol context.

XChaCha extends the nonce construction; it is not an "extended-key ChaCha" primitive.

### Signatures

Hackathon default:

- Ed25519.

This is classical, not post-quantum. The GUI and documentation must state this explicitly.

If there is time after the demo is complete, the signature abstraction may be migrated to ML-DSA. Do not block the demo on that migration.

### Hash and KDF

- SHA-256 for commitments where a standard cryptographic hash is needed.
- HKDF-SHA256 for deterministic per-context key derivation.
- Explicit domain separation for every derivation and signed transcript.

### Threshold Sharing

Use the maintained `blahaj` Shamir Secret Sharing implementation. Do not use
`sharks`: all released versions are affected by RUSTSEC-2024-0398 and no
patched `sharks` release exists.

Do not implement field arithmetic manually and do not hardcode a custom 256-bit prime merely because the design says "256-bit secret".

### Erasure Coding

Use a maintained Reed-Solomon erasure coding crate over the encrypted payload.

Do not use Berger codes.

Do not rely on Reed-Solomon to authenticate malicious data. Authentication and corruption detection come from AEAD and cryptographic commitments; erasure coding handles availability after invalid contributions are rejected.

---

## 5. Core A / DEK Design

The protocol must make signer authorization cryptographically necessary without creating the previous circular dependency.

There is no separate custody key G and there is no OTP pad store.

At setup generate:

```text
A   = random 256-bit authorization key
DEK = random 256-bit data-encryption key
```

### Signer Side

Split A among the signers:

```text
A -> Shamir(s-of-m) -> A_share_1 ... A_share_m
```

Each signer stores one independent A share.

### Payload Side

Encrypt the secret locally:

```text
C = XChaCha20Poly1305_Encrypt(
        key = DEK,
        plaintext = secret,
        associated_data = payload_context
    )
```

Erasure-code C:

```text
C -> Reed-Solomon(k-of-n) -> F_1 ... F_n
```

### Guardian DEK Shares

Split DEK among guardians:

```text
DEK -> Shamir(k-of-n) -> D_1 ... D_n
```

Do not store `D_i` in plaintext on guardian disks.

For each guardian index i derive a per-share wrapping key from A:

```text
K_i = HKDF-SHA256(
        ikm = A,
        info = "gp/guardian-dek-share/v1" || config_id || config_version || guardian_index
      )
```

Then encrypt the DEK share:

```text
E_i = XChaCha20Poly1305_Encrypt(
        key = K_i,
        plaintext = D_i,
        associated_data = guardian_share_context
      )
```

Guardian i stores:

```text
F_i + E_i + integrity proof + opaque slot id + minimal policy record
```

This gives the intended separation:

- storage guardians alone possess encrypted DEK shares but do not have A,
- signers possess A shares but do not hold the guardian material,
- the relay possesses neither,
- the recovery client can reconstruct only after the signer threshold and guardian release path both succeed.

Do not claim that a compromised signer threshold is harmless. A compromised signer threshold can authorize a malicious recovery; the minimum delay and owner hard-cancellation mechanism provide a reaction window while the owner cancellation key remains available. The exact threat model must remain explicit.

---

## 6. Krawczyk-Lite Storage Layout

The large-secret path is:

```text
plaintext
   -> AEAD(DEK)
   -> ciphertext C
   -> Reed-Solomon erasure coding
   -> F_1 ... F_n
```

Separately:

```text
DEK
   -> Shamir(k-of-n)
   -> D_1 ... D_n
   -> per-share AEAD under A-derived K_i
   -> E_1 ... E_n
```

Guardian i stores one opaque record:

```text
GuardianRecord_i {
    opaque_slot_id,
    ciphertext_fragment = F_i,
    encrypted_dek_share = E_i,
    integrity_proof,
    policy_record
}
```

`policy_record` contains only the pseudonymous configuration values the guardian actually needs to:

- verify the signer-set commitment and thresholds,
- verify the exact request and release certificate,
- enforce the configured delay,
- verify the committed guardian material,
- reject stale config versions and replayed request ids.

It must not contain an owner real-world identity or a public owner-to-guardian mapping.

Per-guardian storage target:

```text
approximately sizeof(C)/k + one small encrypted DEK share + proof/policy overhead
```

---

## 7. Integrity and Corruption Handling

Commit every guardian record's cryptographic payload during setup.

Example leaf:

```text
leaf_i = SHA256(
    "gp/guardian-leaf/v1" ||
    config_id ||
    config_version ||
    guardian_index ||
    SHA256(F_i) ||
    SHA256(E_i)
)
```

Build a Merkle tree and authenticate the root in the Config Capsule and the guardian's local policy record.

On recovery:

- verify AEAD authentication,
- verify the returned `F_i` and `E_i` against the committed leaf and Merkle root,
- reject malformed or tampered contributions,
- treat rejected contributions as erasures,
- request additional guardians until k valid responses are available.

Never assume Reed-Solomon detects malicious tampering.

Commit signer enrollment data as a signer-set Merkle root so signer membership can be proved without publishing a global signer list.

---

## 8. Config, Identity, Config Capsule, and Recovery Descriptor

Each secret receives:

```text
config_id      = random 256-bit opaque identifier
config_version = monotonic version number
```

The owner has a root protocol identity that privately associates the signer set with the configuration. The root identity does not derive signer private keys.

### Config Capsule

The Config Capsule is the retrievable, non-secret/pseudonymous protocol object needed to bootstrap recovery.

It contains logically:

```text
ConfigCapsule {
    protocol_version,
    crypto_suite,
    config_id,
    config_version,

    signer_count,
    signer_threshold,
    owner_cancel_public_key,

    guardian_count,
    guardian_threshold,

    minimum_recovery_delay,

    signer_set_commitment,
    guardian_material_commitment,

    encrypted_recovery_descriptor,
    replay_protection_parameters
}
```

It contains no A, no DEK, no plaintext secret, and no plaintext guardian roster.

For the hackathon, the Config Capsule is stored redundantly by the protocol's config-store process and is retrievable using the Recovery Card's locator/config id.

### Recovery Descriptor

The Recovery Descriptor contains the private recovery-routing material:

```text
RecoveryDescriptor {
    guardian opaque mailbox/routing handles,
    opaque guardian slot ids,
    guardian indices,
    integrity roots,
    erasure parameters,
    recovery metadata needed by the client
}
```

Seal it under a key derived from A:

```text
K_descriptor = HKDF(A, "gp/recovery-descriptor/v1" || config_id || config_version)
```

The guardian roster is therefore not public.

A single signer does not learn the guardian roster merely by approving recovery. A signer-threshold collusion can reconstruct A and therefore can learn the descriptor; this is an explicit threshold assumption, not something to hide in marketing.

### Rotation

After a successful recovery:

- increment config_version,
- generate a new A,
- generate a new DEK,
- generate a new per-config owner cancellation keypair,
- create new signer A shares,
- create new DEK guardian shares,
- create new encrypted DEK shares E_i,
- create new ciphertext fragments and opaque slot ids,
- invalidate old request ids and old configuration versions.

A suspicious cancelled recovery should trigger the same rotation when the legitimate owner still has access.

---

## 9. Recovery Card and Bootstrap

A brand-new device must be able to locate the signers and the Config Capsule without possessing any secret key.

During setup create a small Recovery Card as a QR/string containing:

```text
config_id
config-capsule locator
signer opaque mailbox handles
signer_set_commitment
owner_cancel_public_key
```

The Recovery Card is **non-confidential but privacy-sensitive**.

It contains no A share, DEK share, guardian roster, plaintext secret, decryption key, or owner cancellation private key. Stealing it should not be sufficient to recover a secret, but it can reveal pseudonymous recovery-locator metadata and can be used for spam/phishing attempts against signer mailboxes.

The protocol should therefore rate-limit recovery requests and should not call the card "meaningless if stolen".

There is no public real-identity -> config registry.

---

## 10. Recovery Recipient and Recovery Request

A fresh recovery device generates a fresh KEM recipient keypair for every attempt:

```text
recovery_encapsulation_key
recovery_decapsulation_key
```

The decapsulation key never leaves the recovery device.

Create:

```text
RecoveryRequest {
    protocol_version,
    crypto_suite,
    config_id,
    config_version,
    request_id,
    recovery_recipient_key,
    requested_at,
    nonce,
    expiry
}
```

All approvals must bind to the entire request.

The canonical signed transcript must include:

```text
protocol domain
protocol_version
crypto_suite
config_id
config_version
request_id
recovery_recipient_key
requested_at
nonce
expiry
```

Do not sign vague text such as "I approve recovery".

This is required for replay protection and recovery-recipient binding.

---

## 11. Signer Approval and Reconstruction of A

A signer receives the RecoveryRequest through its opaque mailbox path.

The signer performs the external/social identity check. The cryptographic protocol itself does not magically prove a human identity.

On approval, signer i returns:

```text
SignerContribution {
    request,
    signer_id,
    signer_public_key,
    signer_signature,
    signer_membership_proof,
    encrypted_A_share_i
}
```

`encrypted_A_share_i` is encrypted end-to-end to the exact approved `recovery_recipient_key` using the configured transport cryptographic suite.

The recovery client:

- verifies each signer signature,
- verifies membership against `signer_set_commitment`,
- rejects duplicate signer ids,
- rejects contributions for a different request, recipient, config version, nonce, or expiry,
- decrypts the A shares locally,
- reconstructs A after s valid shares.

After reconstructing A, the recovery client decrypts the Recovery Descriptor and learns the guardian routing information.

A alone is not sufficient to recover the secret because the recovery client still needs the guardian-held encrypted DEK shares and encrypted payload fragments.

---

## 12. Two-Phase Recovery, 24-Hour Delay, and Owner Hard Cancellation

Do not use drand.

The delay is enforced by honest guardians using a monotonic clock.

The protocol uses signer-approved Begin and Release phases. Guardians never infer permission from the absence of an owner cancellation message; they require a valid ReleaseCertificate and locally verify that no owner hard-cancel tombstone exists.

### Phase 1 — Begin Recovery

The recovery client packages the threshold-valid signer approvals into a `BeginRecoveryCertificate` for the exact request.

It sends the request and certificate to the selected guardians through the metadata-resistant transport.

An honest guardian verifies:

- config id/version,
- request id and nonce,
- signer threshold,
- signer membership proofs,
- signer signatures,
- recovery recipient binding,
- expiry,
- local replay state.

If valid, it records:

```text
PendingRecovery {
    request_id,
    config_id,
    config_version,
    recipient,
    started_at_monotonic,
    not_before,
    state = DelayPending
}
```

where:

```text
not_before = started_at_monotonic + configured_delay
```

The production configuration must enforce a minimum delay of 24 hours. The simulator may compress this to seconds.

### Owner Hard Cancellation

Setup generates an independent per-config Ed25519 owner cancellation keypair.
The private key remains only in the owner's private control state. It is never
placed in the Recovery Card, Config Store, signer state, guardian state, or a
network message. The corresponding public key is pinned in the Config Capsule,
Recovery Card, and each guardian's local policy.

Only this setup-time private key can authorize cancellation. Signers cannot
cancel a request and there is no signer cancellation threshold.

The owner signs an `OwnerCancelCertificate` bound to the complete exact
RecoveryRequest, including config id/version, request id/digest, recovery
recipient, nonce, reason, issue time, and a fresh response-recipient key used
for encrypted guardian acknowledgements.

A valid owner hard cancel permanently invalidates the request for every honest
guardian that receives it. A cancellation received before the corresponding
Begin certificate is retained as a tombstone and blocks a later Begin for the
same request id and digest. A conflicting digest fails closed.

Each guardian persists the tombstone before returning a signed
`OwnerCancelAck` bound to the exact cancellation transcript. The owner treats
the distributed hard cancel as complete only after verifying distinct
acknowledgements from at least `n - k + 1` guardians, where `n` is the guardian
count and `k` is the DEK recovery threshold. This leaves fewer than `k`
uncancelled guardians, so an honest acknowledged set can no longer form a
recovery quorum. With the default `n=8, k=5`, four acknowledgements are needed.
A guardian must not acknowledge cancellation if it has already released its
contribution for that request. Cancellation cannot retract material that was
already delivered.

The owner cancellation key has no Begin, Release, descriptor-decryption, A,
DEK, or payload-decryption authority. Its compromise permits denial of service
against recovery requests for that configuration, not recovery of the secret.
If the owner loses the private key, no signer fallback can cancel requests.

There is no public plaintext event log.

### Phase 2 — Release Certificate

After the delay window, the recovery client requests a fresh release approval from the signers for the same immutable RecoveryRequest.

The required signer threshold produces a `ReleaseCertificate` bound to:

- the same config id/version,
- the same request id,
- the same recovery recipient,
- the same nonce.

Each release vote carries the signer's pseudonymous public key and Merkle
membership proof, and the complete vote is signed. Guardians verify membership
against their locally pinned signer-set commitment before counting the vote.

An honest guardian releases only if:

- it previously accepted the BeginRecoveryCertificate,
- its own monotonic `not_before` has elapsed,
- the request has not expired,
- it has not observed a valid owner hard-cancel certificate,
- the ReleaseCertificate is valid for the exact request,
- the config version is still current.

If the guardian is partitioned or cannot validate the release state, it fails closed and does not release.

The delay is a threshold-policy guarantee, not a trust-free cryptographic wall-clock timelock.

Security assumptions must remain visible:

- a compromised signer threshold can authorize a malicious recovery,
- the delay gives the legitimate owner/signers a reaction window but does not make a compromised signer threshold harmless,
- enough malicious storage guardians may ignore their own delay policy, but encrypted DEK shares still require A,
- early recovery therefore depends on failures across the configured threshold assumptions rather than on a single relay or single guardian.

---

## 13. Guardian Release

After the guardian's delay condition and valid ReleaseCertificate are satisfied, guardian i returns:

```text
GuardianContribution {
    protocol_version,
    config_id,
    config_version,
    request_id,
    request_digest,
    guardian_index,
    ciphertext_fragment = F_i,
    encrypted_dek_share = E_i,
    merkle_path_proof,
    guardian_signature
}
```

The entire contribution is also encrypted to the exact approved recovery recipient using the configured transport KEM + AEAD stack.

KEM + AEAD is encryption, not a digital signature. The guardian signature is a separate signature over the canonical contribution transcript.

The contribution must be bound to:

- config id/version,
- request id,
- recovery recipient,
- guardian index.

A contribution from one recovery session must not be reusable in another.

---

## 14. Final Local Recovery

The recovery client performs all plaintext reconstruction locally.

1. Verify signer contributions and reconstruct A from at least s valid A shares.
2. Decrypt the Recovery Descriptor with A.
3. Obtain guardian responses through the metadata-resistant transport after the delay and release phase.
4. Verify each guardian signature, Merkle proof, AEAD authentication, config version, request id, and guardian index.
5. Reject corrupted contributions and obtain replacements until at least k valid guardian records exist.
6. For each valid guardian index i derive:

```text
K_i = HKDF(A, "gp/guardian-dek-share/v1" || config_id || config_version || guardian_index)
```

7. Decrypt `E_i` locally to obtain `D_i`.
8. Reconstruct DEK from at least k valid `D_i` shares.
9. Reconstruct ciphertext C from at least k valid `F_i` fragments.
10. Decrypt C with DEK and the original associated-data context.
11. Output the original secret locally.
12. Zeroize temporary A, DEK, D_i values, recovery decapsulation key, plaintext buffers, and reconstructed intermediate material as soon as practical.

No relay, signer, guardian, or config store reconstructs the plaintext secret.

---

## 15. Metadata Resistance — Stronger and Precise

Metadata resistance is a transport and access-pattern problem, not something encryption alone solves.

The prototype must strengthen metadata resistance as far as the already-defined hackathon scope allows, while staying honest about unavoidable leakage.

### Target Adversary

- passive global network observer,
- curious but protocol-following relay/mix nodes,
- curious individual signers,
- curious individual storage guardians,
- fewer-than-threshold malicious signers or guardians.

The MVP does not claim full metadata privacy against threshold collusion or an active global adversary that controls every mix hop and endpoint.

### M1 — Content Confidentiality

Plaintext secret material exists only on the owner device during setup and the recovery client during final reconstruction.

### M2 — Owner-to-Guardian Unlinkability

A storage guardian must not receive the owner's real-world identity or direct owner network identity as part of normal protocol operation.

### M3 — Guardian-Set Privacy

There is no public owner/config -> guardian roster mapping.

The guardian roster and slot handles live only inside the Recovery Descriptor encrypted under A.

### M4 — Deposit/Recovery Unlinkability

An external observer should not be able to trivially correlate an original deposit with a later recovery through stable direct network routes or stable mailbox identifiers.

### M5 — Timing Resistance

In BASIC and STRONG modes, real requests travel through multi-hop relays with randomized delays.

In STRONG mode:

- traffic is organized in epochs,
- cells are fixed-size within the selected size bucket,
- real and dummy cells use exactly the same outer packet format,
- clients, signers, guardians, and mix nodes maintain cover traffic even when idle,
- cover responses exist as well as cover requests,
- opaque mailbox identifiers rotate,
- routes are multi-hop,
- each hop sees only the information required for that hop,
- recovery traffic is mixed with unrelated/dummy traffic before reaching signers or guardians.

No protocol field such as config id, request id, signer identity, or guardian index should appear in plaintext in the outer transport header unless routing absolutely requires it. Keep such fields inside the end-to-end encrypted payload wherever possible.

### M6 — Size Leakage

Full size hiding is explicitly out of scope.

The system may leak approximate size through:

- number of fixed-size cells,
- selected size bucket,
- total traffic volume over time.

Do not claim otherwise.

### M7 — Endpoint Knowledge

Be explicit about unavoidable endpoint knowledge:

- a signer that is asked to approve a recovery knows that it is participating in some recovery request,
- a selected guardian knows that one of its opaque stored slots is being accessed/released,
- a guardian should not know the owner's real identity,
- a single guardian should not learn the full guardian set,
- a single signer should not learn the guardian set merely by approving,
- a threshold of signers can reconstruct A and therefore can decrypt the Recovery Descriptor; this is part of the signer-threshold trust assumption.

### Metadata Modes

#### OFF

Direct encrypted transport. Useful only as a baseline visualization.

#### BASIC

- multi-hop relay path,
- randomized delays,
- opaque mailbox ids,
- end-to-end encryption,
- no public plaintext event log.

#### STRONG

BASIC plus:

- fixed-size/bucketed cells,
- epoch batching,
- constant or configured-rate cover traffic,
- dummy request and response traffic,
- rotating opaque mailbox ids,
- identical real/dummy outer packet format,
- simulated observer correlation metrics.

The strong mode is a simulator feature for the hackathon. Do not claim that the prototype ships a production anonymity network.

---

## 16. Money and Reputation — Pitch/Demo Only

Do not put this in the critical recovery path.

Pitch assumptions already defined:

- user pays roughly USD 10 equivalent per year into escrow,
- escrow slowly compensates storage guardians for continued service,
- escrow takes a small protocol fee,
- payments may later use privacy-preserving transfer mechanisms,
- guardian reputation is based on uptime and successful versus failed/lost recoveries,
- the simulator may show a fake reward tick/star score.

Do not implement staking, slashing, on-chain accounting, or hidden-payment infrastructure for the hackathon core.

---

## 17. Rust Architecture

Use a Cargo workspace:

```text
crates/
    gp-types
    gp-crypto
    gp-core
    gp-storage
    gp-wire
    gp-transport
    gp-sim
    gp-ipc
    gp-gui-sim
    gp-cli
```

### gp-types

Protocol data types only.

### gp-crypto

The only crate that directly touches cryptographic primitives.

- thin wrappers,
- no custom crypto implementations,
- deterministic test vectors where possible,
- zeroization of secret material where supported.

### gp-core

Pure deterministic state machines.

No:

- sockets,
- filesystem,
- system clock,
- environment reads,
- direct OS RNG calls.

All time, randomness, storage results, and network events are injected.

### gp-storage

Guardian, signer, config-store, and local client durable state.

### gp-wire

Canonical protocol encoding, framing, domain-separated signature transcripts, and length-prefixed fields.

Never sign arbitrary Rust serialization.

### gp-transport

Transport trait plus direct transport and simulated metadata-resistant transport adapters.

### gp-sim

Virtual network, virtual monotonic clocks, deterministic seeded randomness, participant registry, Byzantine toggles, cover traffic, and metadata modes.

### gp-ipc

Versioned local IPC shared by CLI, GUI, simulator, and test harness.

Unix Domain Sockets are acceptable for native Unix processes. A browser frontend must use a local backend/gateway; do not pretend a browser directly speaks UDS.

### gp-gui-sim

Backend for the visual simulator.

### gp-cli

CLI for setup, recovery, scripted demo, and deterministic replay.

---

## 18. Canonical Message Objects

Use explicit, canonical transcripts with protocol labels and length prefixes.

### RecoveryRequest

```text
RecoveryRequest {
    protocol_version,
    crypto_suite,
    config_id,
    config_version,
    request_id,
    recovery_recipient_key,
    requested_at,
    nonce,
    expiry
}
```

### SignerContribution

```text
SignerContribution {
    request,
    signer_id,
    signer_public_key,
    signer_signature,
    signer_membership_proof,
    encrypted_A_share_i
}
```

### BeginRecoveryCertificate

```text
BeginRecoveryCertificate {
    request,
    signer_contributions[]
}
```

### OwnerCancelCertificate

```text
OwnerCancelCertificate {
    protocol_version,
    config_id,
    config_version,
    request_id,
    request_digest,
    recovery_recipient_key,
    cancel_response_recipient_key,
    reason_code,
    nonce,
    issued_at,
    owner_cancel_public_key,
    owner_signature
}
```

### OwnerCancelAck

```text
OwnerCancelAck {
    protocol_version,
    config_id,
    config_version,
    request_id,
    request_digest,
    owner_cancel_transcript_digest,
    guardian_index,
    guardian_signature
}
```

### ReleaseVote / ReleaseCertificate

```text
ReleaseVote {
    protocol_version,
    config_id,
    config_version,
    request_id,
    request_digest,
    recovery_recipient_key,
    nonce,
    signer_id,
    signer_public_key,
    signer_membership_proof,
    signer_signature
}
```

A threshold-valid set forms the ReleaseCertificate.

### PendingRecovery

```text
PendingRecovery {
    request_id,
    config_id,
    config_version,
    recipient,
    started_at_monotonic,
    not_before,
    state
}
```

### GuardianContribution

```text
GuardianContribution {
    protocol_version,
    config_id,
    config_version,
    request_id,
    request_digest,
    guardian_index,
    ciphertext_fragment,
    encrypted_dek_share,
    merkle_path_proof,
    guardian_signature
}
```

`request_digest` is `SHA256("gp/recovery-request-digest/v1" || canonical_recovery_request)`.
It binds owner hard cancellation and guardian contributions to the complete immutable request,
including the exact recovery recipient, nonce, expiry, and crypto suite.

### RecoveryDescriptor

```text
RecoveryDescriptor {
    guardian opaque mailbox/routing handles,
    opaque slot ids,
    guardian indices,
    integrity roots,
    erasure parameters,
    recovery metadata
}
```

---

## 19. GUI / Simulator — Core Deliverable

Render:

- owner client,
- signers,
- mix nodes,
- storage guardians,
- recovery client,
- config store,
- wire observer.

Live controls:

- signer count and threshold,
- guardian count and threshold,
- owner hard-cancel test control,
- recovery delay multiplier,
- network latency,
- packet loss,
- packet duplication,
- guardian corrupts response,
- guardian goes offline,
- signer goes offline,
- mix drops packets,
- metadata mode OFF/BASIC/STRONG,
- cover traffic rate,
- deterministic replay seed.

Visualize protocol phases:

```text
SETUP
secret -> DEK -> ciphertext -> fragments -> guardians
A -> signer shares -> signers
DEK -> guardian shares -> A-derived encryption -> guardians

RECOVERY
fresh recovery recipient
-> signer approvals
-> A reconstruction
-> private guardian discovery
-> begin recovery
-> delay
-> owner hard cancel OR release certificate
-> guardian contributions
-> local DEK reconstruction
-> local payload reconstruction
-> secret
```

The simulator kernel may know which packets are real versus dummy for animation. Simulated protocol actors must not receive that privileged knowledge.

The passive-observer panel must show:

- packet sizes/buckets,
- timings,
- path-visible metadata,
- whether a packet can be classified as real/dummy from the observer's available data,
- remaining unavoidable leakage.

Do not show false claims such as "the observer learns nothing".

---

## 20. Minimal Security Tests

The hackathon test budget is intentionally small but must cover the corrected design.

### Crypto / Property Tests

- any s valid signer shares reconstruct A,
- fewer than s signer shares do not reconstruct A,
- any k valid DEK shares reconstruct DEK,
- fewer than k DEK shares do not reconstruct DEK,
- the correct A decrypts an encrypted DEK share E_i,
- the wrong A does not authenticate/decrypt E_i,
- changed config id/version/guardian index causes the A-derived share context to fail,
- any k valid ciphertext fragments reconstruct C,
- tampered fragment or encrypted DEK share fails integrity/authentication,
- changed recovery recipient invalidates the relevant signature transcript,
- stale request id/config version is rejected.

### Integration Tests

1. setup -> recovery -> success,
2. corrupt/offline guardian -> replacement contribution -> success,
3. begin -> owner hard cancel before release -> no honest release,
4. same simulation seed -> identical run.

Provide one `make test` or equivalent project command that executes the complete hackathon test suite.

---

## 21. Non-Goals

Explicitly out of scope:

- production/deployed mixnet,
- PIR/private information retrieval,
- anonymous ZK signer membership,
- on-chain reputation/slashing,
- production payment escrow,
- drand timelock security,
- formal verification artifacts,
- NIST-certification-grade audit,
- perfect anonymity,
- perfect size hiding,
- a claim of full post-quantum security while Ed25519 remains in the signer path.

If asked during Q&A:

> This is a working hackathon prototype. The secret-sharing, encryption, integrity, recovery-recipient binding, threshold recovery, cancellation state machine, and local reconstruction are real. The anonymity transport is simulated, and the prototype is post-quantum-skewed rather than fully post-quantum while signer signatures remain Ed25519.

---

## 22. Delivery Order

### Milestone 0

Workspace, types, gp-crypto wrappers, Shamir, Reed-Solomon, commitments/Merkle proofs, XChaCha20-Poly1305, verified transport hybrid or an explicit reported blocker. Unit tests green.

### Milestone 1

Local in-memory setup/recovery with owner, signers, guardians, Config Capsule, Recovery Card, A reconstruction, DEK-share wrapping, two-phase delay/release, and cancellation.

### Milestone 2

gp-sim with virtual network, monotonic virtual clocks, seeded replay, IPC, adversarial guardian behavior, and cancellation race.

### Milestone 3

GUI node canvas, state log, crypto-object visualization, metadata observer, and full replayable demo.

### Milestone 4

Metadata OFF/BASIC/STRONG modes, cover traffic visualization, rotating mailbox ids, epoch batching, README polish, and final demo script.

At every milestone:

- compile,
- run tests,
- run clippy,
- do not proceed while the current milestone's core path is broken.

No additional protocol features should be added unless they are already defined in this document.
