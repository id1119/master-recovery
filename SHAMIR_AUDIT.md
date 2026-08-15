# Threshold Sharing Audit

Date: 2026-08-15

## Final result

Master Recovery has two deliberately separate, maintained-library threshold
profiles:

| Protocol material | Sharing implementation | Lifecycle |
|---|---|---|
| v2 authorization key `A` and v2 `DEK` | `blahaj` 0.6.0, GF(256), exactly 32-byte secrets and 33-byte encoded shares | dealer split and threshold reconstruction; a v2 rotation creates a completely fresh configuration |
| v3 authorization key `A` | the same bounded `blahaj` wrapper | dealer split and threshold reconstruction; routine guardian rotation does not change `A` |
| v3 `DEK` | `frost-ristretto255` 3.0.0 dealer sharing, repairable threshold sharing (RTS), and refresh-DKG | initial dealer split, threshold reconstruction on the recovery client, replacement repair, then a full successor-roster refresh every guardian epoch |

No Shamir, FROST, finite-field, polynomial, interpolation, RTS, refresh, or
combiner arithmetic is implemented locally. Direct library calls remain inside
`gp-crypto`. The v3 `DEK` is the provider's serialized 32-byte Ristretto scalar,
not an arbitrary uniformly sampled 256-bit string.

## Branch and implementation disposition

The final review inspected every remote head present on 2026-08-15:

- `origin/animation` and `origin/docker` were already ancestors of `main`;
- `origin/sss-hardening` contained five unmerged commits and was merged so its
  history and findings were not lost;
- the merged Python `sss/` prototype fixed several serious defects in its own
  earlier revisions, including a Pedersen trapdoor/public-digest leak, invalid
  batch verification, undersized-field and length-overflow cases, and missing
  commit-then-reveal/partial-verification checks;
- its 110 tests passed during review, but it remained a broad, hand-written,
  unaudited cryptographic implementation and was not used by the Rust runtime.
  Keeping it as a second apparent implementation would violate
  `MASTER_PROMPT.md` and `AGENTS.md`, so the final tree removes it. The branch
  history remains reachable through the merge and can be retired.

This is a compatibility and security decision, not a claim that useful
research ideas were ignored: only constructions that fit the fixed protocol
and have a maintained implementation are enabled.

## `blahaj` wrapper audit

`gp_crypto::split_secret` and `recover_secret` enforce:

- exactly 32 secret bytes, thresholds `1..=255`, total shares `1..=255`, and
  `threshold <= total`;
- deterministic caller-injected `ChaCha20Rng` seeds. The simulator injects a
  seeded stream for replay; the network obtains the seed from OS-backed `rand`;
- exactly 33 bytes per encoded share, a nonzero index, unique indices, bounded
  input count, sufficient shares, and exactly 32 recovered bytes;
- zeroizing generated shares and reconstructed secrets.

`blahaj` is the maintained fork that corrects the biased nonzero coefficient
sampling reported for `sharks` in RUSTSEC-2024-0398. `sharks` is absent from the
dependency graph. The wrapper does not claim verifiable or robust standalone
Shamir: integrity comes from the protocol's AEAD envelopes, signed exact-request
contributions, index binding, and Merkle record commitments. Invalid material is
rejected before interpolation and is treated as an erasure.

## FROST v3 `DEK` audit

The thin provider adapter enforces thresholds `2..=n`, `n <= 32`, bounded
serialized packages, unique participant identifiers, one common verifying key,
the declared minimum signer count, and share/public-package consistency.
Recovery uses `frost_recover_dek_for_epoch`: every contribution must carry the
exact expected `ConfigRef` before any provider reconstruction is attempted.

Routine rotation is:

1. a threshold of old participants uses the provider's RTS API to add a missing
   successor participant if needed;
2. the complete successor roster runs the provider's refresh-DKG;
3. every successor verifies its new share against the identical resulting
   public package and persists it as `PREPARED`. Its wrapped share and full
   record stay guardian-local because the A-holding coordinator knows the wrap
   key; only a commitment leaf crosses that boundary;
4. activation requires all successor preparation acknowledgements plus signer
   activation and witness quorum certificates;
5. recovery accepts only shares labelled with the witness-selected epoch.

Old and refreshed shares can be algebraically incompatible even though they
refer to the same underlying secret. The raw provider reconstruction API has no
epoch concept and is therefore not a protocol entry point. Regression tests
show that a mixed raw set does not recover the `DEK`, while the production
epoch-labelled wrapper rejects it before interpolation.

## Ciphertext-fragment compatibility across rotation

The encrypted payload and its Reed-Solomon parameters remain unchanged during
routine v3 guardian rotation. The setup capsule now commits to every raw
ciphertext fragment with a domain-separated Merkle root bound to `config_id`,
`payload_generation`, fragment index, total shard count, length, and bytes.

On every rotation the coordinator reconstructs ciphertext from threshold-valid
old records, deterministically re-encodes it, and must reproduce the stable
capsule root. Each successor receives its exact fragment and Merkle proof and
verifies both before producing a preparation acknowledgement. This closes the
case where a malicious coordinator could previously provision internally
committed but unusable successor fragments. It does not reveal plaintext and it
does not make sampled custody checks a proof of retrievability.

## Compatible and incompatible improvement families

| Family | Disposition |
|---|---|
| Uniform-coefficient Shamir, strict parsing, duplicate rejection, deterministic tests, zeroization | included in the bounded `blahaj` profile |
| Krawczyk-style short sharing | included: only `DEK` is shared; ciphertext is Reed-Solomon encoded |
| Share authenticity and cheater rejection | included at the composition layer with AEAD, signatures, epoch/index binding, provider verification, and Merkle proofs |
| Proactive refresh and participant replacement | included only for v3 `DEK`, through maintained ZF FROST RTS and refresh-DKG |
| Feldman/Pedersen VSS, arbitrary DKG, PVSS, weighted/hierarchical access, packed/ramp sharing | excluded because they change the protocol, assumptions, formats, or privacy semantics and have no selected maintained end-to-end provider here |
| Custom robust decoding, finite-field arithmetic, hybrid combiners, or share-conversion math | prohibited; no local implementation is retained |
| Dealer-free v2 setup or v3 `A` refresh | not implemented |

## Test evidence

The Rust tests cover:

- all signer subsets for 2-of-3 and all guardian subsets for 5-of-8 in the
  `blahaj` profile;
- parameter sweeps, insufficient shares, malformed length, zero and duplicate
  indices, maximum 255-share cases, deterministic seeds, and zeroization-facing
  wrapper behavior;
- FROST dealer reconstruction, provider share verification, corrupted shares,
  insufficient shares, maximum supported roster, RTS replacement, full-roster
  refresh, corrupted refresh messages, replay/reordering, and mixed historical
  epoch rejection;
- repeated guardian rotations, failed/offline guardians, owner cancellation,
  delay and stale-epoch rejection, atomic preparation/activation, recovery
  during drain, final recovery, deterministic replay, and zero plaintext
  decryptions during rotation;
- raw ciphertext-fragment corruption and index substitution, plus successor
  rejection of a bad fragment proof before durable preparation.

Reproduce correctness with:

```sh
cargo test --workspace --all-features
```

Reproduce threshold costs with:

```sh
cargo bench -p gp-crypto --bench shamir -- --noplot
```

The benchmark compares the pre-hardening and strict `blahaj` wrappers for
2-of-3 and 5-of-8 and separately measures FROST 5-of-8 dealer split,
reconstruction, and a complete eight-participant refresh. Host-specific results
from the final Apple arm64 run were:

| Operation | Time interval |
|---|---:|
| `blahaj` split 2-of-3, pre-hardening | 1.252–1.313 us |
| `blahaj` split 2-of-3, strict wrapper | 1.488–1.727 us |
| `blahaj` recover 2-of-3, pre-hardening | 457–477 ns |
| `blahaj` recover 2-of-3, strict wrapper | 483–547 ns |
| `blahaj` split 5-of-8, pre-hardening | 3.501–3.590 us |
| `blahaj` split 5-of-8, strict wrapper | 3.877–4.045 us |
| `blahaj` recover 5-of-8, pre-hardening | 1.345–1.421 us |
| `blahaj` recover 5-of-8, strict wrapper | 1.320–1.360 us |
| FROST dealer split 5-of-8 | 1.148–1.205 ms |
| FROST recover 5-of-8 | 169.2–172.3 us |
| FROST complete 8-participant refresh, 5-of-8 | 16.06–16.60 ms |

The stricter byte-Shamir wrapper adds measurable relative overhead in several
microbenchmarks, but at most hundreds of nanoseconds for the actual key sizes;
it is immaterial beside network and user-authorized delay costs. These numbers
demonstrate practicality, not a universal speedup or constant-time behavior.

## Exact non-claims

The implementation does not claim standalone robust Shamir interpolation,
dealer verifiability for `blahaj`, constant-time GF(256), side-channel immunity,
provable erasure, public verifiability, a general access structure, a
post-quantum FROST construction, or production readiness. Proactive security is
conditional on authenticated private channels, secure erasure, the provider's
corruption bounds, and no complete threshold compromise within an epoch. An
external review of the exact FROST integration remains a production gate.

Relevant primary references include Shamir (1979), Krawczyk (1993), Herzberg et
al. (1995), the Zcash Foundation FROST implementation and NCC review materials,
and [RUSTSEC-2024-0398](https://rustsec.org/advisories/RUSTSEC-2024-0398.html).
