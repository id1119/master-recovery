# Shamir Secret-Sharing Compatibility Audit

Date: 2026-08-13

## Result

This repository now uses one deliberately bounded Shamir profile for both the
authorization key `A` and the data-encryption key `DEK`:

- maintained `blahaj` 0.6.0 over GF(256), with its unbiased coefficient sampling;
- exactly 32-byte protocol keys and 33-byte encoded shares;
- thresholds from 1 through 255 and unique nonzero share indices;
- deterministic, caller-injected CSPRNG seeds for simulator replay and externally
  generated random seeds in the network implementation;
- zeroizing generated, stored, decrypted, and reconstructed secret-share buffers;
- fail-closed validation before interpolation;
- AEAD, transcript binding, Merkle commitments, and replacement requests around
  the primitive for integrity and availability.

This is a merged **protocol profile**, not a new field-arithmetic implementation.
The field operations and interpolation remain entirely inside `blahaj`, as
required by `MASTER_PROMPT.md` and `AGENTS.md`.

There is no coherent primitive that simultaneously preserves every property of
every construction called an improvement to Shamir sharing. Several are mutually
exclusive policy or threat-model choices. For example, ramp sharing reduces share
size by allowing intermediate sets to learn partial information, while ordinary
Shamir sharing requires perfect privacy for every sub-threshold set. The word
"all" below therefore means all improvements compatible with this repository's
fixed threshold access structure, dealer-based setup, 32-byte `A`/`DEK` keys,
one-round storage, mandated `blahaj` dependency, and authoritative protocol.

## Repository branch audit

The Git remote exposes `main`, `animation`, and `docker`. Both topic heads are
ancestors of `main`, and `git branch --all --no-merged main` returns no branches.
The Shamir wrapper entered the repository in commit `18cf08c`; neither topic
branch contains an independent Shamir implementation. Consequently, there were
no source branches to merge mechanically. The meaningful merge was across the
compatible algorithm and systems-hardening lineages below.

## Direct Rust fork-lineage audit

The package lineage was checked separately from the repository branches so that
a renamed or external fork would not be missed:

| Package | Relevant change | Result |
|---|---|---|
| `sharks` 0.5.x | Original Rust implementation used by this project lineage | Rejected. Its nonzero-only polynomial coefficient sampling is RUSTSEC-2024-0398, and the advisory lists no patched release. |
| `blahaj` 0.6.0 | Forked `sharks` and restored uniform coefficient sampling, including zero | Retained. It is the implementation explicitly required by `MASTER_PROMPT.md`. |
| `shamirs` 0.7.0 | Forked `blahaj`; added duplicate-index rejection, a zeroizing recovery return, and a fixed-work field-multiplication rewrite intended to reduce cache-timing leakage | Partially incorporated at the wrapper boundary. Duplicate rejection and zeroizing recovery are present here. The field rewrite is not copied or substituted: doing either would violate the authoritative `blahaj` requirement or the prohibition on manually implementing Shamir field arithmetic. |

The `shamirs` source release was compiled locally: its 15 unit tests and 6
doctests passed. That establishes buildability, not an independent side-channel
audit. Adopting its arithmetic would require the smallest authoritative design
change: name a vetted maintained successor to `blahaj`, followed by migration
vectors and a fresh security/performance review. This implementation does not
silently make that protocol decision.

Direct-lineage sources: the [`shamirs` repository and changelog](https://github.com/voltzug/shamirs),
the [`blahaj` repository](https://github.com/str4d/blahaj), and the
[`sharks` advisory](https://rustsec.org/advisories/RUSTSEC-2024-0398.html).

## Improvement-family decision matrix

| Lineage | Benefit | Decision here | Reason / implementation |
|---|---|---|---|
| Shamir (1979) threshold sharing | Any `t` shares reconstruct; fewer reveal no information | Included | `blahaj` implements the maintained GF(256) primitive. The wrapper exhaustively tests the repository's 2-of-3 and 5-of-8 configurations. |
| Correct uniform coefficient sampling | Prevents information leakage when a secret is shared repeatedly | Included | `blahaj` fixes the `[1,255]` coefficient bias in `sharks` identified as RUSTSEC-2024-0398. A regression test demonstrates that zero coefficients remain reachable. |
| Krawczyk-style short sharing (1993) | Avoids applying perfect secret sharing to a large payload | Included at the composition layer | The payload is AEAD-encrypted under `DEK`, only `DEK` is Shamir-shared, and ciphertext is Reed-Solomon encoded. This was already the authoritative Krawczyk-Lite layout and remains intact. |
| Share authenticity / malicious contribution rejection | Detects substituted or corrupted stored material | Included at the composition layer | Guardian shares are AEAD-wrapped under per-index A-derived keys; signed contributions and Merkle leaves bind exact records and indices. Invalid contributions are treated as erasures and replacements are requested. The primitive does not falsely claim standalone robustness. |
| Strict parsing and duplicate rejection | Removes ambiguous or malformed reconstruction inputs | Included | Reconstruction rejects zero/oversized thresholds, more than 255 inputs, wrong-length encodings, index zero, duplicate indices, and wrong recovered length before returning secret material. |
| Secret-memory hygiene | Reduces residual copies of shares and reconstructed keys | Included | `blahaj`'s `zeroize_memory` feature is explicit. `SecretVec` is used through generation, signer storage, recipient decryption, guardian-share collection, and reconstruction. Signer debug output redacts its share and signing seed. |
| Deterministic testability | Reproducible vectors and simulator runs | Included | Entropy is injected at the wrapper boundary. Same-seed equality, different-seed separation, threshold ranges, maximum share count, and deterministic end-to-end replay are tested. Deterministic seeds are not a production entropy source. |
| Feldman VSS (1987) | Lets recipients verify dealer consistency | Excluded | Adds public group commitments, computational assumptions, and protocol objects. The repository has an honest local setup/dealer and forbids unspecified mechanisms. Feldman commitments can also expose a commitment to the secret, unlike the current private descriptor design. |
| Pedersen VSS (1991) | Hiding verifiable sharing | Excluded | Requires a second blinding polynomial/share, group parameters, verification rules, and a changed wire/storage format. It is a different sharing protocol, not a compatible parser or implementation hardening. |
| Publicly verifiable sharing / DKG | Removes trust in a dealer or permits public verification | Excluded | Requires participant interaction, broadcasts/proofs, new states, and usually new computational assumptions. There is no public share-verification or distributed-dealer requirement in the authoritative setup. |
| Proactive refresh (1995 onward) | Limits a mobile adversary to one compromise epoch | Excluded | Requires periodic interactive refresh, authenticated private channels, epoch agreement, secure erasure, recovery protocols, and new failure states. Existing successful-recovery rotation creates an entirely fresh configuration but is not proactive refresh. |
| Robust / cheater-identifiable reconstruction | Recovers despite forged shares or identifies cheaters | Excluded from the primitive; existing outer protections retained | Generic robust reconstruction needs additional redundancy, authentication data, or interaction and explicit corruption bounds. This protocol verifies guardian records before interpolation and replaces bad responses, so adding a second mechanism would change shares without improving the exercised path. |
| Ramp and packed/multi-secret schemes | Smaller amortized shares or batched MPC | Excluded | They change privacy thresholds or encode several field elements together. This system shares two independent 32-byte keys and requires no information from every sub-threshold set. |
| General, weighted, hierarchical, dynamic, or evolving access structures | Policies beyond `t`-of-`n` | Excluded | They replace the required signer and guardian threshold semantics rather than improve their implementation. |
| Share repair / redistribution | Rebuilds a lost share or changes participants without the dealer | Excluded | Requires inter-participant protocols and new authorization/state transitions. Authoritative rotation already creates fresh shares and invalidates the old configuration version. |
| Leakage-resilient or hardware-assisted sharing | Addresses continual side-channel leakage | Excluded | These constructions require a separate leakage model, extra encoding/hardware, or interaction. Memory zeroization is included, but no unimplemented leakage-resilience claim is made. |

References:

- Adi Shamir, [How to Share a Secret](https://doi.org/10.1145/359168.359176), 1979.
- Paul Feldman, [A Practical Scheme for Non-interactive Verifiable Secret Sharing](https://doi.org/10.1109/SFCS.1987.4), 1987.
- Torben Pedersen, [Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing](https://doi.org/10.1007/3-540-46766-1_9), 1991.
- Hugo Krawczyk, [Secret Sharing Made Short](https://doi.org/10.1007/3-540-48329-2_12), 1993.
- Amir Herzberg et al., [Proactive Secret Sharing](https://doi.org/10.1007/3-540-44750-4_27), 1995.
- Rosario Gennaro et al., [Secure Distributed Key Generation for Discrete-Log Based Cryptosystems](https://doi.org/10.1007/3-540-48910-X_21), 1999.
- Xuan Guang et al., [Repairable Threshold Secret Sharing Schemes](https://arxiv.org/abs/1410.7190), 2014.
- Avishek Adhikari et al., [Efficient Threshold Secret Sharing Schemes Secure against Rushing Cheaters](https://eprint.iacr.org/2015/1115), 2015.
- RustSec, [RUSTSEC-2024-0398: biased polynomial coefficients in `sharks`](https://rustsec.org/advisories/RUSTSEC-2024-0398.html).
- Ben David et al., [New Results in Share Conversion, with Applications to Evolving Access Structures](https://eprint.iacr.org/2024/1781), 2024/2025. Its non-convertibility results are further evidence that the various schemes do not form one stack with every upside preserved.

## Evidence and reproducibility

### Correctness and hardening

Run:

```sh
cargo test --workspace --all-targets
```

The suite contains 49 tests after this work, up from 40. New evidence includes:

- all 3 signer subsets in the default 2-of-3 policy;
- all 56 guardian subsets in the default 5-of-8 policy;
- every threshold/total pair through 12 participants over deterministic seeds;
- insufficient-share failure for every tested threshold greater than one;
- deterministic replay and seed separation;
- reachability of a zero degree-one coefficient (the `sharks` bias regression);
- malformed length, zero index, duplicate index, invalid threshold, and excess-share rejection;
- the maximum 255 distinct indices and 255-of-255 reconstruction;
- redaction of stored signer secret material from `Debug` output;
- unchanged serialization round-trips after moving stored shares into zeroizing buffers;
- the existing end-to-end, wrong-A, tamper, exact-recipient, replay, malicious/offline guardian, hard-cancel, and deterministic simulator tests.

### Performance

Run the same-process before/after comparison:

```sh
cargo bench -p gp-crypto --bench shamir -- --noplot
```

Criterion embeds the pre-hardening wrapper as a benchmark-only reference and
compares it with the production hardened wrapper under the same build and process.
An Apple M5 / arm64 run with Rust 1.97.1 produced:

| Operation | Pre-hardening reference | Hardened |
|---|---:|---:|
| split 2-of-3, 32 bytes | 1.2839–1.2879 us | 1.2593–1.2991 us |
| recover 2-of-3, 32 bytes | 425.58–426.42 ns | 425.33–426.31 ns |
| split 5-of-8, 32 bytes | 3.4888–3.7889 us | 3.4887–3.5072 us |
| recover 5-of-8, 32 bytes | 1.4599–1.4629 us | 1.4186–1.4206 us |

Microbenchmarks vary with host load, so these numbers prove retained practical
performance, not a universal speedup. The security improvement is concrete:
previously accepted ambiguous inputs now fail closed, secret-share copies remain
zeroizing, and nine additional regression/property tests pass. The benchmark
shows that those checks add no material cost in the actual configurations.

### Dependency audit

`cargo tree -p gp-crypto` resolves `blahaj 0.6.0`; `sharks` is absent. A current
`cargo audit --json` scan reports zero vulnerabilities. It separately reports an
allowed `unsound` warning for `lru 0.7.8`, transitively pinned by the latest
`reed-solomon-erasure 6.0.0`; that warning concerns panic safety in `LruCache::pop`
and is not in Shamir code. It is recorded here rather than hidden or "fixed" by
inventing Reed-Solomon math or swapping an authoritative primitive.

## Exact claims

The resulting profile improves misuse resistance and secret-memory handling while
retaining threshold correctness and practical performance. It does **not** claim
dealer verifiability, proactive security, public verifiability, robust standalone
interpolation, general access structures, constant-time field arithmetic,
side-channel immunity, or a universally optimal secret-sharing construction.
Adding any of those would require a new protocol version, threat model,
maintained implementation review, wire format, state-machine design, and
migration plan.
