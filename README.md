# Guardian Protocol

A working hackathon prototype of metadata-resistant, post-quantum-skewed,
decentralized secret recovery.

The implementation follows `MASTER_PROMPT.md`: an authorization key `A` is
Shamir-shared to signers, the payload is encrypted with a separate `DEK`, and
guardians receive Reed–Solomon ciphertext fragments plus DEK shares encrypted
under per-guardian keys derived from `A`. Recovery requires both thresholds,
the Begin → Delay → Release state machine, and a fresh recovery-recipient key.

The approved transport correction uses X-Wing (X25519 + ML-KEM-768) through
the maintained RustCrypto implementation. Ed25519 authorization and guardian
signatures remain classical, so the complete protocol is not fully
post-quantum. The X-Wing crate also states that its implementation has not been
independently audited; this repository is a hackathon prototype, not a
production cryptographic product.

## Quick start

Rust 1.97 or later is recommended.

```sh
make test
make demo
```

Launch the visual simulator:

```sh
make gui
```

Then open <http://127.0.0.1:8787>.

The browser opens with four stage-ready scenarios: standard recovery, guardian
failure/replacement, cancellation just before release, and a same-seed metadata
comparison. Pick a scenario and press **Run guided recovery**; the walkthrough
can then be played automatically or stepped backward and forward one verified
protocol event at a time.

The configuration sidebar accepts either text or a file up to 700 KiB and
exposes all simulator controls from the design: signer/guardian counts and
thresholds, cancellation threshold, offline/corrupt actors, delay, metadata
mode, latency, loss, duplication, mix drops, cover traffic, and replay seed.
Impossible combinations are rejected with a specific explanation before any
protocol execution. File plaintext is shown or downloaded only in the final
recovery-client panel.

Useful direct commands:

```sh
# Complete deterministic recovery with a corrupted guardian
cargo run -p gp-cli -- demo --seed 424242 --mode strong

# One corrupted and one offline guardian; replacement still succeeds
cargo run -p gp-cli -- demo --corrupt-guardian 1 --offline-guardian 2

# Threshold cancellation immediately before release
cargo run -p gp-cli -- cancel --seed 424242

# Compare observer views using the same protocol seed
cargo run -p gp-cli -- compare --seed 424242

# Machine-readable replay
cargo run -p gp-cli -- demo --json
```

Use `0` for a guardian/signer option to disable that adversarial toggle.

## What is real

- XChaCha20-Poly1305 payload encryption and guardian-share wrapping.
- Maintained Shamir secret sharing for `A` and `DEK`.
- Reed–Solomon erasure coding over encrypted payload bytes.
- SHA-256 commitments and Merkle membership proofs.
- Canonical length-prefixed signature transcripts with domain separation.
- Ed25519 signer and guardian signatures.
- X-Wing recipient encryption bound to request-specific AEAD context.
- Exact config version, request id, recipient, nonce, actor index, and request
  digest binding.
- Deterministic recovery and guardian state machines.
- Threshold-valid cancellation that permanently kills an observed request.
- Malicious/offline guardian replacement and final client-only reconstruction.
- Successful-recovery rotation to fresh version-2 keys, shares, fragments,
  commitments, and opaque slots.

## What is simulated

The anonymity transport is a deterministic visualization, not a deployed
mixnet. The simulator provides:

- OFF: direct encrypted transport baseline.
- BASIC: opaque mailboxes, randomized delay, and multi-hop routes.
- STRONG: fixed-size cells, epochs, rotating mailbox tags, multi-hop routes,
  dummy requests and responses, and continuous configured-rate cover traffic.

In STRONG mode, real and dummy packets have the same observer-visible outer
format. The simulation kernel retains the real/dummy bit for scoring, but the
observer packet object does not contain it. Timing, traffic volume, adjacent
hops, size buckets, and endpoint participation can still leak.

The GUI exposes thresholds, compressed delay, latency, loss, duplication, mix
drops, cover rate, actor failures, corruption, metadata mode, and replay seed.

## Workspace

```text
gp-types       protocol data only
gp-crypto      sole direct user of cryptographic libraries
gp-wire        canonical transcripts and contexts
gp-core        deterministic I/O-free state machines
gp-storage     in-memory signer/guardian/config stores
gp-transport   direct and metadata-mode adapters
gp-sim         seeded end-to-end protocol orchestration
gp-ipc         versioned CLI/browser command boundary
gp-gui-sim     local browser gateway and visual lab
gp-cli         demo, cancellation, comparison, and server commands
```

`gp-core` performs no filesystem, socket, environment, system-clock, or OS-RNG
access. Time and certificate validity are injected, and the same core machines
drive every simulator scenario.

## Security boundaries

The Recovery Card is non-confidential but privacy-sensitive. It contains the
config locator and opaque signer mailboxes, but no secret key material or
guardian roster. The roster exists only in the Recovery Descriptor sealed under
`A`.

A compromised signer threshold can authorize a malicious recovery. The delay
and cancellation path provide a reaction window; they do not make that
compromise harmless. Guardians enforce the delay as policy using an injected
monotonic clock—it is not a trust-free cryptographic timelock.

Do not claim perfect anonymity, full size hiding, unconditional availability,
or full post-quantum security.
