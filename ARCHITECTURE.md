# Architecture

Master Recovery keeps protocol decisions in a deterministic core and pushes
I/O to the edges. The simulator and the network runtime therefore drive the
same state machines instead of maintaining two versions of the protocol.

```text
                    injected events
                          |
                          v
crypto adapters -->   gp-core   --> actions to persist or send
                          ^
                          |
          simulator or network runtime

CLI / GUI --> local IPC or runtime --> storage and transport
```

The key boundary is `gp-core`: it may decide what should happen, but it cannot
read the clock, open a socket, inspect the environment, access a file, or draw
random bytes. Callers inject time, entropy, storage results, and network
events. This makes seeded runs reproducible and keeps real execution aligned
with the tested model.

For a plain-language protocol walkthrough, start with
[`HOW_IT_WORKS.md`](HOW_IT_WORKS.md). Exact messages and state transitions are
specified in [`PROTOCOL.md`](PROTOCOL.md), with the v3 rotation amendment in
[`GUARDIAN_ROTATION.md`](GUARDIAN_ROTATION.md).

## Workspace map

| Crate | Responsibility |
|---|---|
| `gp-types` | Protocol data types, with no cryptographic implementation or I/O |
| `gp-wire` | Canonical encodings, explicit signed transcripts, framing, domain labels, and size limits |
| `gp-crypto` | The only direct adapters to cryptographic libraries |
| `gp-core` | Deterministic recovery, cancellation, witness, draining, and rotation state machines |
| `gp-storage` | Durable signer, guardian, capsule, witness, replay, and cancellation state |
| `gp-transport` | Direct transport, mailbox abstractions, and simulated metadata modes |
| `gp-sim` | Seeded clock, virtual network, faults, cover traffic, and deterministic replay |
| `gp-ipc` | Versioned local interface shared by clients and the simulator UI |
| `gp-gui-sim` | Loopback-only visual simulator and observer views |
| `gp-cli` | Local setup, recovery, rotation, cancellation, and demo commands |
| `gp-network` | Multi-process HTTP runtime for local machines, Docker, or separate VMs |

## Cryptography boundary

All direct library use belongs in `gp-crypto`. It wraps:

- bounded `blahaj` threshold sharing for v2 keys and v3 authorization key `A`;
- Zcash Foundation FROST Ristretto255 sharing, RTS replacement, and refresh-DKG
  for the v3 `DEK`;
- Reed-Solomon coding for ciphertext fragments;
- XChaCha20-Poly1305, HKDF-SHA-256, Ed25519, X-Wing, commitments, and Merkle
  proofs.

The repository does not implement primitive arithmetic or a hybrid combiner.
Signed material is constructed by `gp-wire` from fixed fields with explicit
domain separation. Arbitrary Rust serialization is never signed.

See [`SHAMIR_AUDIT.md`](SHAMIR_AUDIT.md) for the threshold-sharing decisions
and their limits.

## Recovery path

```text
fresh recovery client
    |
    +--> signers: reconstruct A after exact-request approval
    |
    +--> config store: open the Recovery Descriptor with A
    |
    +--> guardians: Begin -> Delay -> ReleaseCertificate
    |
    +--> client: verify records, reconstruct DEK and ciphertext, decrypt
```

The final reconstruction step exists only in the recovery client. Signers do
not receive guardian-held material, and guardians do not receive enough signer
material to recover on their own.

The required recovery states are:

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

Storage and network actions emitted by these transitions execute outside
`gp-core` and return as new events.

## Rotation path

Protocol v3 adds a separate deterministic `RotationMachine`, an
`EpochWitnessMachine`, and epoch-bound recovery and draining logic.

```text
signer-approved successor plan
    |
    +--> old guardians: FROST RTS replacement contributions
    +--> successor roster: full refresh-DKG
    +--> ciphertext: reconstruct and re-encode without payload decryption
    +--> new guardians: durable PREPARED records
    +--> signers and witnesses: activate exactly one successor epoch
    +--> old epoch: drain accepted requests, then retire
```

Successor Guardian Records stay on their guardians. The coordinator handles
signed, encrypted provider messages, ciphertext fragments, commitment leaves,
and Merkle paths, but not payload plaintext or a reconstructable set of `DEK`
shares. It is still trusted for availability and orchestration.

## Storage boundary

`gp-storage` models atomic `ACTIVE`, `PREPARED`, and `DRAINING` guardian
records, zeroizing rotation journals, signer and witness locks, and durable
replay and cancellation tombstones. The network runtime persists JSON by
writing a temporary file, syncing it, renaming it, and syncing the containing
directory.

The prototype's storage format and coordinator lifecycle are not production
infrastructure. In particular, the ephemeral v3 coordinator is not a
replicated job that automatically resumes after any process crash.

## Transport and metadata boundary

`gp-transport` has two distinct roles:

- the simulator implements OFF, BASIC, and STRONG modes, including fixed-size
  cells, epochs, dummy traffic, rotating mailbox identifiers, and multi-hop
  routes;
- the live network runtime uses a direct single-hop relay with X-Wing-sealed
  endpoint payloads.

The live relay is not a mixnet and does not provide the STRONG simulator's
traffic-analysis resistance. The precise claims are in
[`METADATA_RESISTANCE.md`](METADATA_RESISTANCE.md).

## User-interface boundary

The UI does not manipulate state directly:

```text
UI action -> IPC command -> backend event -> core transition -> IPC update -> render
```

The visual simulator binds to loopback. Secrets are accepted only in
same-origin request bodies, response caching is disabled, and plaintext
secrets are never placed in query strings.

## Implementation status

The deterministic simulator, command-line tools, visual simulator, v2 network
flow, and v3 setup, discovery, recovery, cancellation, and repeated rotation
flow are implemented. The network runtime is suitable for demonstrations and
experiments, not deployment. It lacks an external cryptographic audit,
production operations, hardened identity and transport infrastructure, and a
real metadata-resistant network.

Operational commands and topology are documented in
[`NETWORK_GUIDE.md`](NETWORK_GUIDE.md). Security assumptions and non-claims
are documented in [`SECURITY.md`](SECURITY.md).
