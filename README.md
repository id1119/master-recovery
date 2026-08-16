# Master Recovery

Master Recovery is an experimental protocol for recovering a critical secret
without giving one person, company, or backup key sole control of recovery.

The project targets self-custody wallets, wallet infrastructure, institutional
signing keys, and other high-value secrets that may need to remain recoverable
for years. It is a protocol layer, not a wallet, hardware device, password
manager, or production custody service.

## Why

A normal encrypted backup still needs a recovery key. If one person or service
holds that key, recovery has a single point of failure and a single point of
compromise. Copying the plaintext to several places only creates more targets.

Master Recovery separates authorization from custody:

- signers decide whether a specific recovery request may proceed;
- guardians store encrypted DEK shares and fragments of the encrypted payload;
- a fresh recovery device combines both thresholds after a delay.

Neither group has the complete recovery path by itself. Plaintext
reconstruction happens only on the recovery device.

## How recovery works

```text
Owner protects a secret
          |
          v
  Encrypted recovery configuration
      /                       \
 Signers                    Guardians
 authorize an exact         hold encrypted shares
 recovery device            and ciphertext fragments
      \                       /
       signer threshold + delay
          + guardian threshold
                    |
                    v
       Fresh device reconstructs locally
```

At setup, the client creates an authorization key called `A` and a separate
data-encryption key called `DEK`. Signers receive threshold shares of `A`. The
payload is encrypted with `DEK`, then guardians receive encrypted DEK shares
and Reed-Solomon fragments of the ciphertext.

A new device creates a one-time recovery recipient key and an exact recovery
request. A signer threshold approves that request and sends its `A` shares only
to that device. The device reconstructs `A`, opens the private Recovery
Descriptor, and learns how to contact the guardians. Guardians start a local
delay when they accept the Begin certificate. After the delay, a fresh signer
threshold authorizes Release. A guardian threshold then returns the committed
material to the same recovery recipient. The device verifies it, reconstructs
`DEK` and the ciphertext, and decrypts the secret locally.

The owner can permanently cancel the exact request during the delay. This uses
a separate private cancellation key created at setup. Cancellation cannot
authorize recovery or decrypt anything.

See [HOW_IT_WORKS.md](HOW_IT_WORKS.md) for a concrete 2-of-3 signer,
5-of-8 guardian example.

## Actors

| Actor | Role | What it knows | What it cannot do alone |
|---|---|---|---|
| Owner | Creates the configuration and keeps cancellation control | The original secret, Recovery Card, and private owner-control file | Use the cancellation key as a recovery credential; cancellation does not decrypt the secret |
| Recovery client | Runs one exact recovery on a fresh device | The reconstructed secret after success | Skip signer approval, guardian delay, or guardian threshold |
| Signer | Performs an external identity check and contributes one `A` share | That it approved a pseudonymous request; its own share | Read guardian material or recover the payload alone |
| Guardian | Enforces delay and stores one encrypted DEK share plus one ciphertext fragment | Its own opaque record and requests for that record | Learn the owner, open its DEK share without `A`, or reconstruct the payload alone |
| Relay | Routes sealed messages through opaque mailboxes | Adjacent endpoints, timing, volume, and mailbox handles | Read protocol payloads or alter them without detection |
| Config store | Publishes a pseudonymous Config Capsule for protocol v2 | Public capsule fields and access timing | Read the private guardian roster or any recovery key |
| Witness | Tracks the active protocol-v3 guardian epoch | Capsule hashes, epoch order, and rotation timing | Read the guardian roster, shares, DEK, or plaintext |

## The Recovery Card

The Recovery Card is a locator, not a recovery key. A new device uses it to
find the public Config Capsule, signers, relays, and the witness set used by
protocol v3.

It contains no `A` share, DEK share, decryption key, plaintext, or guardian
roster. Possession of the card lets someone start contacting the recovery
system and reveals privacy-sensitive infrastructure metadata. It does not let
them complete recovery without the required approvals and guardian material.

The private `owner-control` file is different. It contains the per-config
cancellation private key and private operational data. Keep it secret. The
network setup commands write it with mode `0600`.

## Main properties

- Threshold authorization: the configured signer threshold must approve the
  exact request and fresh recipient.
- Threshold custody: the recovery client needs enough valid guardian records.
- Delayed release: guardians enforce Begin, a local monotonic delay, then
  Release.
- Owner hard cancellation: the setup-time owner key can permanently kill one
  exact request before material is released.
- Local reconstruction: network nodes do not reconstruct the plaintext.
- Integrity and replay checks: signed canonical transcripts, AEAD contexts,
  Merkle proofs, request identifiers, nonces, configuration references, and
  actor indices bind the flow.
- Guardian rotation: protocol v3 can replace a guardian and refresh the active
  DEK sharing without decrypting the payload.
- Conservative metadata goals: the public configuration does not expose the
  owner-to-guardian map. Stronger traffic-hiding behavior remains simulated.

## Guardian rotation

Guardians cannot be expected to stay online or trustworthy for the lifetime of
a recovery configuration. Protocol v3 organizes guardian custody into epochs.
A one-for-one replacement looks like this:

```text
Epoch 1: G1 G2 G3 G4 G5 G6 G7 G8
                         G4 leaves
Epoch 2: G1 G2 G3 G9 G5 G6 G7 G8
```

The old threshold uses the maintained Zcash Foundation FROST implementation to
repair the replacement participant, then the complete successor roster runs a
share refresh. The encrypted payload and `DEK` remain the same. The shares,
wrapping contexts, records, routes, and guardian epoch change.

Every successor verifies its new share and ciphertext fragment, stores its
record as `PREPARED`, and signs the exact material root. Signers and a pinned
witness quorum activate the new epoch only after every successor is ready. The
old epoch stays active until that cutover and drains requests that began before
activation.

Shares from different epochs are not accepted as one recovery set. Recovery
uses the witness-selected `ConfigRef`, and the wrapper rejects mixed epoch
labels before FROST reconstruction. Rotation still depends on secure erasure
and the stated per-epoch corruption bound; it cannot undo a DEK or plaintext
that an attacker already learned.

The full design and limits are in
[GUARDIAN_ROTATION.md](GUARDIAN_ROTATION.md).

## Cryptography

| Primitive | Use in the protocol |
|---|---|
| `blahaj` Shamir secret sharing | v2 `A` and `DEK` sharing; v3 `A` sharing |
| ZF `frost-ristretto255` | v3 DEK dealer sharing, guardian replacement, refresh, and recovery |
| XChaCha20-Poly1305 | Encrypts the payload, DEK shares, and private protocol state |
| Reed-Solomon | Splits encrypted payload bytes for guardian availability |
| SHA-256, HKDF, and Merkle commitments | Key separation, transcript digests, and integrity proofs |
| X-Wing (X25519 + ML-KEM-768) | Establishes recipient encryption keys for protocol messages |
| Ed25519 | Signs signer, guardian, owner, and witness transcripts |

The protocol is not fully post-quantum. X-Wing gives the transport a hybrid
classical and ML-KEM profile, but Ed25519 and Ristretto255 FROST remain
classical. The exact FROST rotation integration has not received an external
cryptographic audit.

## What exists today

### Implemented

- real encryption, sharing, signatures, commitments, erasure coding, and local
  reconstruction;
- deterministic recovery and rotation state machines shared by the simulator
  and network runtime;
- protocol-v2 setup, recovery, hard cancellation, relay and config-store
  failover, and full post-recovery configuration replacement;
- protocol-v3 setup, witness discovery, recovery, owner rotation
  cancellation, failed-guardian replacement, full-roster share refresh,
  atomic activation, draining, and repeated rotation;
- independent persistent signer, guardian, relay, config-store, and witness
  processes in the network demos;
- adversarial tests for corruption, replay, stale epochs, mixed shares,
  cancellation races, actor outages, persistence, and rollback.

### Simulated

The OFF, BASIC, and STRONG metadata modes live in `gp-sim`:

- OFF is direct encrypted transport with no anonymity claim.
- BASIC adds opaque mailboxes, randomized forwarding delay, and simulated
  multi-hop routes.
- STRONG adds fixed-size or bucketed cells, epochs, cover traffic, dummy
  requests and responses, rotating handles, and identical real/dummy outer
  formats.

The real network relay is a direct forwarding hop. It is not the STRONG
simulated mixnet. Timing, traffic volume, endpoints, and approximate message
sizes remain visible in the live runtime.

### Not production ready

This is a research and hackathon prototype. It has not received a professional
security audit. The Docker demo uses automatic signer approval and a short
delay. Node JSON state is not encrypted at rest, the coordinator is not a
replicated resumable service, and the live relay is not an anonymity network.

Read [SECURITY.md](SECURITY.md) before evaluating or deploying any part of the
system.

## Quick start

Rust 1.97 or later is recommended.

Run the test suite and deterministic simulator:

```sh
make test
make demo
```

Run the visual simulator, then open <http://127.0.0.1:8787>:

```sh
make gui
```

Run the live protocol-v3 smoke test with separate local processes:

```sh
make network-v3-smoke
```

Run the protocol-v2 Docker network and recovery demo:

```sh
make network-demo
```

The Docker command starts redundant relays and config stores, three signers,
and eight guardians. It needs Docker Compose. See
[NETWORK_GUIDE.md](NETWORK_GUIDE.md) for manual VM commands, APIs, failure
tests, and the full network model.

Useful simulator commands:

```sh
# Complete deterministic recovery with a corrupt guardian
cargo run -p gp-cli -- demo --seed 424242 --mode strong

# Replace offline or malicious guardians during recovery
cargo run -p gp-cli -- demo --corrupt-guardian 1 --offline-guardian 2

# Exercise setup-time owner cancellation
cargo run -p gp-cli -- cancel --seed 424242

# Run four protocol-v3 guardian rotations in the deterministic simulator
cargo run -p gp-cli -- rotate --seed 424242
```

## Repository map

```text
gp-types       protocol data, no crypto or I/O
gp-wire        canonical transcripts, contexts, and framing
gp-crypto      the only crate that calls cryptographic libraries directly
gp-core        deterministic, I/O-free protocol state machines
gp-storage     durable signer, guardian, witness, and replay state models
gp-transport   direct and simulated metadata transport adapters
gp-sim         seeded end-to-end recovery and rotation scenarios
gp-network     real multi-process actors and clients
gp-ipc         versioned CLI and browser command boundary
gp-gui-sim     local browser gateway and visual simulator
gp-cli         simulator and demo commands
```

`gp-core` reads no filesystem, socket, environment variable, wall clock, or OS
randomness. Callers inject time, entropy, storage outcomes, and network events.
The simulator and real runtime therefore exercise the same state transitions.

## Documentation

Suggested reading order:

1. [HOW_IT_WORKS.md](HOW_IT_WORKS.md): one recovery and rotation example in
   plain technical English.
2. [PROTOCOL.md](PROTOCOL.md): exact setup, request, delay, release, and
   reconstruction flow.
3. [SECURITY.md](SECURITY.md): trust assumptions and failure boundaries.
4. [GUARDIAN_ROTATION.md](GUARDIAN_ROTATION.md): authoritative protocol-v3
   rotation design and implementation evidence.

Other references:

- [ARCHITECTURE.md](ARCHITECTURE.md): crate boundaries and data flow.
- [SHAMIR_AUDIT.md](SHAMIR_AUDIT.md): threshold-sharing choices, tests, and
  benchmarks.
- [METADATA_RESISTANCE.md](METADATA_RESISTANCE.md): privacy goals and remaining
  leakage.
- [NETWORK_GUIDE.md](NETWORK_GUIDE.md): live topology, commands, APIs, and
  persistence behavior.
- [MASTER_PROMPT.md](MASTER_PROMPT.md): authoritative project requirements.
- [ENVELOPE_SPEC.md](ENVELOPE_SPEC.md): an unimplemented owner-side backup
  envelope design.
- [HUMAN_GUIDE_AND_DEFENSE.md](HUMAN_GUIDE_AND_DEFENSE.md): Serbian demo and
  project-defense notes.

## Security status

Master Recovery is experimental, unaudited, and not production ready. The
protocol has explicit threshold, delay, cancellation, metadata, availability,
secure-erasure, and classical-cryptography assumptions. See
[SECURITY.md](SECURITY.md) for the complete list.
