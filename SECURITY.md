# Security model

Master Recovery is an unaudited research prototype. This document states the
security goals, trust assumptions, and failure boundaries implemented by the
current code. It is not a production security claim.

For the protocol sequence, read [PROTOCOL.md](PROTOCOL.md). Guardian epoch
details are in [GUARDIAN_ROTATION.md](GUARDIAN_ROTATION.md).

## Security goals

### Plaintext confinement

The plaintext should exist only on the owner client during setup and on the
recovery client during final reconstruction. Signers, guardians, relays,
config stores, witnesses, and the ordinary rotation coordinator should not
receive it.

### Threshold authorization

Fewer than `s` valid signer shares must not reconstruct authorization key `A`.
Approvals must bind to the exact configuration, request, nonce, recipient, and
transcript.

### Threshold custody

Fewer than `k` valid guardian DEK shares must not reconstruct `DEK`. Guardian
records also contain Reed-Solomon fragments of ciphertext, not plaintext.

### Separation of duties

Signer material alone does not contain guardian records. Guardian material
alone does not contain `A`, which is needed to unwrap the stored DEK shares.
No single signer, guardian, relay, config store, or witness has the complete
recovery path.

### Integrity, freshness, and replay resistance

The client and nodes reject malformed shares, corrupted records, invalid
Merkle proofs, duplicate actors, stale configuration references, replayed
request ids, reused nonces, wrong recipients, and mismatched signed
transcripts.

### Private roster

The public Recovery Card and Config Capsule do not contain the guardian roster.
The roster lives in the Recovery Descriptor encrypted under `A`.

## Trust assumptions

The protocol assumes:

- fewer than the signer threshold are malicious when unauthorized recovery
  must be prevented;
- fewer than the guardian threshold expose usable custody material;
- honest guardians enforce delay, cancellation, freshness, and exact request
  binding;
- the owner retains the private cancellation key if cancellation is expected
  to remain available;
- protocol-v3 witness faults stay within the configured `f` bound, with `3f+1`
  pinned witnesses and `2f+1` quorums;
- endpoint private keys and node-local secret state are protected;
- secure erasure is effective enough for proactive guardian-epoch claims;
- the recovery client is trustworthy at the moment it reconstructs plaintext;
- authenticated private channels and the selected cryptographic libraries
  behave as specified.

An adversary that exceeds these assumptions may recover the secret, deny
service, expose metadata, or create ambiguous state that honest nodes refuse.

## Compromise cases

### Fewer than the signer threshold

These signers cannot reconstruct `A` or create a valid signer certificate.
They can refuse to participate and reduce availability.

### Signer threshold

A compromised signer threshold is serious. It can authorize a malicious
request, reconstruct `A`, and open the private Recovery Descriptor. It still
needs enough guardian contributions to recover `DEK` and ciphertext, but it
can initiate that process against a recipient it controls.

The guardian delay and owner cancellation path provide a reaction window.
They do not make signer-threshold compromise harmless.

### Fewer than the guardian threshold

These guardians cannot reconstruct `DEK`. Their stored DEK shares are also
encrypted under keys derived from `A`. They can withhold, corrupt, or expose
their own records and may reveal that their opaque slots were accessed.

### Guardian threshold

A guardian threshold can ignore its local delay policy and expose all of its
stored records. Without `A`, those records should not reveal `DEK` or the
plaintext. The compromise is still an availability and metadata failure and
becomes a recovery failure if the attacker also obtains sufficient
authorization material.

### Combined signer and guardian compromise

An attacker that obtains the signer threshold and enough guardian material can
complete recovery. The protocol separates authorization from custody; it does
not make compromise of both sides safe.

### Owner cancellation key

The owner key cannot authorize recovery, reconstruct `A`, open the Recovery
Descriptor, or decrypt the payload. Its compromise permits valid
request-specific cancellation and therefore denial of service. Losing it does
not reveal the secret, but removes the owner's cancellation ability.

### Relay, config store, and witness compromise

A relay can observe and manipulate delivery timing, sizes, adjacent endpoints,
and opaque mailbox use. End-to-end encryption and signatures prevent it from
reading payloads or making an altered message validate. It can always drop
traffic.

A protocol-v2 config store sees pseudonymous public capsules and access timing.
It has no plaintext descriptor or recovery key. A protocol-v3 witness sees
capsule hashes, epoch order, rotation timing, and owner rotation-veto events.
Within the stated `f` bound, witness quorums reject rollback and two finalized
children of one predecessor. An unavailable or conflicting quorum causes a
fresh client to fail closed.

## Recovery delay

Recovery uses two signer phases:

1. Begin starts a guardian-local monotonic delay.
2. Release authorizes contribution after the delay.

The default production policy requires at least 24 hours. Demo commands may
use a shorter delay when nodes explicitly allow insecure demo timing.

This is policy enforcement, not a trust-free cryptographic timelock. The
protocol does not use drand as a security-critical delay. Malicious guardians
can ignore their own clocks and software rules. A reboot that makes monotonic
time ambiguous causes an honest guardian to refuse release.

## Owner hard cancellation

Setup creates an independent per-config cancellation signing key. Guardians
pin its public key. The private key stays in the owner's control file.

A valid cancellation binds the exact request, canonical request digest,
recovery recipient, cancellation-response recipient, nonce, and owner key. An
honest guardian stores a permanent tombstone before returning its signed
acknowledgement. A cancellation that arrives before Begin still kills the
later reordered Begin.

The owner treats recovery cancellation as complete after valid
acknowledgements from `n - k + 1` distinct guardians. This leaves fewer than
`k` available for recovery. The guarantee assumes an acknowledging guardian
keeps its promise. A malicious guardian may sign and later violate policy.

Cancellation is not retroactive. A guardian records successful release before
sending its contribution and refuses to acknowledge a later cancellation. The
protocol cannot erase material that has already reached a recovery client.

Protocol-v3 rotation cancellation also needs a `2f+1` witness veto and enough
old-guardian tombstones to break the handoff quorum. Non-owner abort needs a
signer threshold; one signer cannot unlock or kill a rotation alone.

## Guardian rotation

Routine protocol-v3 rotation is not a recovery shortcut. It requires signer
Intent, Begin, Delay, Release, and Activate decisions for the exact plan. It
changes only the guardian epoch in the implemented one-for-one replacement
profile. `A`, `DEK`, payload generation, ciphertext, guardian count, and
threshold remain unchanged.

The coordinator reconstructs `A` and encrypted ciphertext `C`. This exposes
the private roster to that ephemeral client and lets it derive each guardian's
wrapping key. It does not receive plaintext DEK shares or the full successor
records. Each successor keeps its wrapped share locally and returns only a
commitment leaf. Otherwise the A-holding coordinator could unwrap a threshold
from its own transcript.

Each successor verifies its FROST share, the common public package, its exact
ciphertext fragment, index, and stable fragment proof. It stores the record as
`PREPARED`, then signs the assembled material root. Signers reject a Ready
certificate whose acknowledgements, root, descriptor, or successor capsule do
not agree. A witness quorum makes the cutover final.

The old epoch remains `ACTIVE` during preparation. After activation it drains
only requests that began before cutover. New requests must use the new epoch.
Failed preparation and valid pre-activation cancellation preserve the old
configuration.

### Historical shares

Refresh creates a new sharing of the same `DEK`. The protocol does not accept
old and new shares as one reconstruction set. Every recovery contribution
binds the exact `ConfigRef`, and the production wrapper rejects mixed epoch
labels before FROST reconstruction.

The proactive claim is conditional. An attacker must remain below the
provider's corruption threshold in each epoch and must not retain a complete
threshold. Honest nodes must erase old shares and ephemeral refresh state.
Rotation cannot revoke a `DEK`, old threshold, or plaintext that an attacker
already learned.

The current ephemeral coordinator preserves safe actor state if it crashes,
because the old epoch remains active until witness QC. It is not a replicated,
automatically resumed job service.

## Metadata leakage

The protocol hides message contents from relays and avoids publishing the
owner-to-guardian map. It does not provide perfect anonymity.

A participating signer knows it approved some recovery or rotation. A selected
guardian knows one of its opaque records was accessed. Relays see timing,
volume, adjacent endpoints, and mailbox handles. Witnesses see epoch activity.
A global observer can correlate timing and traffic volume.

OFF, BASIC, and STRONG metadata modes are simulator models. The live network
uses direct relay forwarding and does not implement STRONG cover traffic,
mixing, or dummy packets. See
[METADATA_RESISTANCE.md](METADATA_RESISTANCE.md).

## Availability

Thresholds tolerate some offline or corrupt actors. They do not guarantee
availability when too many signers, guardians, witnesses, relays, or stores are
unreachable. A network adversary that drops every route can stop recovery.
Cryptography cannot force packet delivery or honest approval.

Honest nodes fail closed on ambiguous state. That protects safety at the cost
of availability during partitions, clock ambiguity, conflicting witness views,
or incomplete certificates.

Merkle custody sampling detects a wrong sampled block. It is not a formal
proof of retrievability and does not prove that a guardian can return its whole
record later.

## Post-quantum scope

The project is post-quantum-skewed, not fully post-quantum.

- X-Wing combines ML-KEM-768 and X25519 for transport key establishment.
- Payload and share encryption use 256-bit symmetric keys.
- Shamir sharing and Reed-Solomon coding are not the classical public-key weak
  point.
- Ed25519 signatures and Ristretto255 FROST remain classical and are
  security-critical.

The X-Wing implementation and the exact FROST RTS plus refresh-DKG integration
still need external review for this use.

## Implementation limits

- The project has not received a professional protocol or code audit.
- Node JSON state relies on filesystem permissions and is not encrypted at
  rest in the demo runtime.
- Docker uses HTTP inside its bridge, automatic signer approval, and a short
  demo delay.
- Secret zeroization reduces ordinary memory lifetime but does not cover swap,
  crash dumps, allocator copies, backups, or compromised firmware.
- Secure physical deletion cannot be proven remotely.
- The simulator may inspect privileged state for visualization; protocol
  actors may not.
- Existing v3 artifacts from before the current capsule and acknowledgement
  fields must be recreated. There is no migration that invents missing signed
  data.

## Security invariants

1. Network nodes do not store the plaintext protected secret.
2. Fewer than `s` valid `A` shares do not reconstruct `A`.
3. Fewer than `k` valid DEK shares do not reconstruct `DEK`.
4. A wrong `A` fails to open guardian DEK shares.
5. Recovery binds the exact configuration, request, recipient, nonce, actor,
   and transcript.
6. An honest guardian releases only after valid Begin, elapsed local delay,
   valid Release, and an unambiguous non-cancelled state.
7. An observed valid owner cancellation permanently kills that request for an
   honest guardian.
8. Corrupted records and fragments fail integrity checks before
   reconstruction.
9. The public bootstrap data contains no plaintext guardian roster.
10. Protocol-v3 recovery rejects stale or mixed guardian epochs.
11. Routine rotation does not decrypt the payload or give the coordinator a
    DEK-share threshold.
12. Final plaintext reconstruction occurs only on the recovery client.

## Explicit non-claims

Master Recovery does not claim:

- bug-free or production-ready software;
- a professional security or cryptographic audit;
- perfect anonymity or information-theoretic metadata privacy;
- a production mixnet in the live runtime;
- an unconditional cryptographic timelock;
- availability against network-wide packet dropping;
- full post-quantum security;
- provable physical deletion or formal proof of retrievability;
- safety after a complete signer and guardian threshold compromise;
- healing after an attacker learns `DEK`, plaintext, or a complete old share
  threshold.

## Dependency audit

The 2026-08-16 `cargo audit` run found no known vulnerabilities and one allowed
unmaintained warning: RUSTSEC-2023-0089 for `atomic-polyfill 1.0.3`. It enters
the all-target graph through `frost-core 3.0.0 -> postcard 1.1.3 -> heapless
0.7.17` and is selected only by specific embedded targets, not the native demo
build. Those embedded targets are unsupported. A production release still
needs an upgraded provider chain or an external-review-approved disposition.
