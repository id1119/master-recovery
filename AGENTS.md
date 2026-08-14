# AGENTS.md

## Purpose

This repository is a hackathon prototype of a metadata-resistant, post-quantum-skewed decentralized secret recovery protocol.

The authoritative design is `MASTER_PROMPT.md`.

Do not redesign the protocol while implementing it. If you find a contradiction, stop, explain it, and propose the smallest correction consistent with the existing documents.

## Source-of-Truth Order

1. `MASTER_PROMPT.md`
2. `PROTOCOL.md`
3. `SECURITY.md`
4. `ENVELOPE_SPEC.md` (owner-side artifact format — design draft, not implemented; protocol wins on any conflict)
5. `METADATA_RESISTANCE.md`
6. `ARCHITECTURE.md`
7. `DEMO.md`
8. `README.md`

If two files disagree, follow the higher file in this list and fix the lower file rather than inventing a third behavior.

## Non-Negotiable Protocol Rules

- No custom cryptographic primitives.
- No OTP layer.
- No drand security-critical timelock.
- No separate custody key G.
- Setup uses:
  - authorization key A,
  - data-encryption key DEK.
- A is Shamir-shared to signers.
- DEK is Shamir-shared to guardians.
- Guardian DEK shares are encrypted under per-guardian keys derived from A.
- The plaintext payload is encrypted with DEK before erasure coding.
- Guardians store encrypted DEK shares plus ciphertext fragments, not plaintext secrets.
- Recovery from a new device requires a fresh recovery-recipient KEM keypair.
- Signer approvals must bind to the exact recovery recipient and exact request transcript.
- Recovery uses Begin -> Delay -> ReleaseCertificate.
- Only the setup-time per-config owner cancellation private key can authorize cancellation.
- A valid owner hard cancellation permanently kills the request for honest nodes that observe it.
- Honest guardians fail closed on ambiguous state.
- Final reconstruction happens only on the recovery client.
- Config versions and request ids are replay-protected.
- The guardian roster is not public; it lives in the Recovery Descriptor sealed under A.
- The Recovery Card is non-confidential but privacy-sensitive.

## Metadata Rules

- Do not put real owner identity into guardian records.
- Do not create a public owner/config -> guardian mapping.
- Do not create a public plaintext recovery event log.
- Keep stable protocol identifiers out of outer transport headers whenever routing does not require them.
- STRONG simulator mode uses fixed-size/bucketed cells, epochs, cover traffic, dummy requests/responses, rotating opaque mailbox ids, and multi-hop routes.
- Real and dummy outer packet formats must be identical in STRONG mode.
- Do not claim information-theoretic anonymity or perfect metadata hiding.
- A participating signer necessarily knows it is approving some recovery request.
- A participating guardian necessarily knows one of its opaque slots is being accessed/released.
- The goal is to hide owner identity, public guardian-set mapping, and trivial traffic correlation from observers and curious individual nodes.

## Cryptography Rules

- All direct use of cryptographic libraries belongs in `gp-crypto`.
- Use maintained libraries only.
- Verify crate existence and compilation before relying on it.
- Never implement Shamir field arithmetic, Reed-Solomon math, XChaCha20-Poly1305, Ed25519, X25519, or ML-KEM manually.
- The X-Wing X25519 + ML-KEM-768 transport profile may be used only through an existing maintained implementation. Do not implement or modify its hybrid combiner.
- Signer signatures are Ed25519 for the hackathon and must be labeled classical/non-PQ.
- Use explicit domain separation for HKDF, commitments, and signed transcripts.
- Never sign arbitrary Rust serialization.
- Bind signatures and encrypted contributions to config id/version, request id, recipient, nonce, and the relevant actor index.
- Zeroize secret material where supported.

## Coding Rules

- Keep `gp-core` deterministic and I/O-free.
- No system time, filesystem, sockets, environment reads, or direct OS RNG inside `gp-core`.
- Inject time, entropy, storage results, and network events.
- The simulator and real processes must use the same state-machine logic.
- Prefer small modules and explicit state transitions.
- Avoid abstractions that are not exercised by the demo.
- Do not add blockchain integration, PIR, ZK membership, slashing, payment escrow, or a production mixnet.

## Required Recovery States

```text
Created
AwaitingApprovals
Authorized
DelayPending
Cancelled
Releasing
Completed
Expired
```

Do not create hidden alternate states that bypass this state machine.

## Required Tests

At minimum preserve tests for:

- s-of-m reconstruction of A,
- k-of-n reconstruction of DEK,
- failure with insufficient shares,
- failure under wrong A,
- fragment/share tamper detection,
- exact recovery-recipient binding,
- replay/stale-version rejection,
- end-to-end recovery,
- malicious/offline guardian replacement,
- owner hard cancellation before release,
- deterministic seeded replay.

## When You Must Stop Instead of Coding

Stop and report before implementing if:

- the requested hybrid KEM cannot be built without inventing a combiner,
- a crate is unmaintained or cannot compile,
- a proposed change would expose the guardian roster publicly,
- a proposed optimization causes a circular key dependency,
- a proposed shortcut would let guardians recover without signer-derived A,
- a proposed shortcut would let signers recover without guardian-held material,
- a message is not cryptographically bound to the exact recovery recipient,
- a metadata claim is stronger than the simulator can actually demonstrate.
