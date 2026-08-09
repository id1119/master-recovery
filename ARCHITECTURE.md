# Rust Architecture

## Workspace

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
    gp-network
```

## gp-types

Contains protocol types only.

No cryptographic implementation and no I/O.

## gp-crypto

The only crate that directly depends on cryptographic primitive libraries.

Responsibilities:

- Shamir wrapper,
- Reed-Solomon wrapper,
- XChaCha20-Poly1305 wrapper,
- HKDF/SHA-256 wrapper,
- Ed25519 wrapper,
- maintained X-Wing (X25519 + ML-KEM-768) transport wrapper,
- Merkle/commitment helper,
- zeroization helpers.

Do not implement primitive math manually.

## gp-core

Deterministic state machines.

Input:

```text
Event
```

Output:

```text
State transition + Actions
```

No:

- sockets,
- filesystem,
- wall/system clock,
- environment access,
- direct OS RNG.

Inject:

- monotonic time,
- entropy,
- network events,
- storage results.

The real processes and simulator must use the same core state transitions.

## gp-storage

Durable state for:

- signer shares/state,
- guardian records,
- Config Capsules,
- client config/replay state.

Hackathon implementation may use simple local files/directories or another already-approved simple local store.

## gp-wire

Owns:

- canonical message encoding,
- explicit field ordering,
- length-prefixed transcripts,
- protocol domain labels,
- framing,
- maximum message lengths.

Never sign arbitrary Rust serialization.

## gp-transport

Owns:

- direct local/network transport,
- mailbox abstraction,
- multi-hop simulated transport adapter,
- metadata-mode selection.

It does not own protocol state.

## gp-sim

Owns:

- virtual monotonic clocks,
- virtual network,
- deterministic seeded randomness,
- packet latency/loss/duplication,
- offline/malicious actor toggles,
- OFF/BASIC/STRONG metadata modes,
- cover traffic generation,
- epoch batching,
- deterministic replay.

The simulator may have privileged knowledge for visualization. Protocol actors must not.

## gp-ipc

Versioned local IPC shared by:

- CLI,
- GUI,
- simulator,
- test harness.

Use Unix Domain Sockets for native Unix processes if appropriate.

A browser frontend must connect through a local backend/gateway rather than directly to UDS.

## gp-gui-sim

Visual simulator backend.

The local gateway binds to loopback, accepts secrets only in same-origin POST
bodies, disables response caching, and does not enable cross-origin reads. It
must never accept plaintext secrets in query strings.

It exposes:

- actor graph,
- packet animation,
- recovery state,
- observer view,
- "who knows what" matrix,
- deterministic replay controls.

## gp-cli

Commands for:

- setup,
- recovery,
- signer approval/release and owner hard-cancel,
- guardian simulation,
- scripted demo,
- deterministic replay.

## gp-network

Real multi-process network runtime for Docker or separate VMs.

- relay, config-store, signer, and guardian HTTP servers,
- persistent per-node state,
- X-Wing-encrypted provisioning and mailbox envelopes,
- actual wall-clock expiry and guardian-local monotonic delay enforcement,
- ephemeral setup and recovery clients,
- the same `gp-core` guardian state machine and `gp-crypto` primitives used by
  the simulator.

The network relay is a direct single-hop prototype, not the STRONG simulated
mixnet. See `NETWORK_GUIDE.md` for APIs, flows, Docker topology, and limits.

## State-Machine Boundary

The core recovery states are:

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

External actions such as network sends or disk writes are emitted by the core and executed outside it.

## IPC / UI Rule

The UI must not manipulate protocol state directly.

UI action -> IPC command -> backend/core event -> state transition -> IPC update -> UI render.
