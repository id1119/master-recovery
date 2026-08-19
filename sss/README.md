# SSS research prototype

This directory holds a pure-stdlib Python secret-sharing research package
(`shamir/`) together with its tests and design notes. It is a research track,
**not** part of the Master Recovery protocol: no Rust crate imports it, and
nothing here is on the path exercised by `cargo run -p gp-cli`.

## Status

The implementation was removed from the repository on 2026-08-15 as unused and
in tension with the project rule in [`../AGENTS.md`](../AGENTS.md) against
custom cryptographic primitives, then restored on request on 2026-08-19. The
rule still stands and this package does not satisfy it: it implements field
arithmetic, Pedersen commitments, Schnorr proofs and threshold signatures by
hand. Treat it as a study artifact, not as a candidate for production use.

The shipping threshold-sharing architecture, branch disposition, benchmarks and
non-claims are recorded in [`../SHAMIR_AUDIT.md`](../SHAMIR_AUDIT.md). Guardian
rotation in the Rust tree delegates its threshold work to `frost-ristretto255`
in `gp-crypto`, not to this package.

## Running it

```sh
cd sss
python tests/test_all.py        # 94 tests, about 19 seconds
```

## Known-fixed vulnerabilities

Four defects found by review were fixed here; each has a regression test:

| Defect | Effect before the fix |
|---|---|
| `h` derived as `g^{SHA-256(seed)}` | `log_g h` was a public constant, so any commitment opened to any value and every forged share verified |
| `digest = P(254)` published in the transcript | a free extra evaluation of the secret polynomial, so t holders reached t+1 points; at t=1 a single holder recovered the secret |
| `batch_verify` summed shares unweighted | two errors that cancel passed the batch check |
| 512-bit default field | prime-field DLP at that size is practical, so every computational claim failed |

Also fixed: `make_safe_prime` called the nonexistent `secrets.getrandbits`, and
`weighted_combine` fell back to `default_field()` and silently returned a wrong
secret across moduli.

## Known-unfixed weaknesses

Do not rely on these paths:

- `threshold_sign` is pre-FROST and breaks under concurrent signing sessions
  (ROS / Drijvers). Safe only for strictly serial signing.
- `deal_many` packs p secrets into the low coefficients of one degree-t
  polynomial, which leaks p-1 linear relations among them to a holder of t
  shares.
- `hybrid` bytes mode needs all n ciphertext chunks, so losing one holder
  destroys the secret; Krawczyk's construction needs only t+1.
- No formal proof of the composed scheme, no external audit, no constant-time
  engineering.

See [`SECURITY.md`](SECURITY.md) for the full claims register and
[`docs/unified_scheme.md`](docs/unified_scheme.md) for the design writeup,
including the auditor layer (`audit_challenge` / `prove_possession` /
`verify_possession` / `audit_holders`).
