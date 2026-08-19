# SSS research (documents only)

This directory holds design and security writeups from a secret-sharing
research track. **The implementation is not here.** It lived in `shamir/`
with its own test suite, and was removed from `main` on 2026-08-19.

Nothing in this directory is part of the Master Recovery protocol. No Rust
crate imported it, and it is on no path exercised by `cargo run -p gp-cli`.
Threshold work in the shipping system is delegated to `frost-ristretto255`
in `gp-crypto`; see [`../SHAMIR_AUDIT.md`](../SHAMIR_AUDIT.md).

## Why it was removed

It implemented field arithmetic, Pedersen commitments, Schnorr proofs and
threshold signatures by hand, which conflicts with the rule in
[`../AGENTS.md`](../AGENTS.md) against custom cryptographic primitives, and
it was unused. Keeping unreferenced hand-rolled cryptography in a custody
repository invites it to be mistaken for shipping code.

## Recovering it

The full implementation, tests and API contract are preserved under the
annotated tag `sss-research-v1`:

```sh
git show sss-research-v1                    # what it was and why it went
git checkout sss-research-v1 -- sss/        # restore the whole directory
```

## What the research produced

A review of the prototype found and fixed four real defects, each with a
regression test at the tag:

| Defect | Effect before the fix |
|---|---|
| `h` derived as `g^{SHA-256(seed)}` | `log_g h` was a public constant, so any commitment opened to any value and forged shares verified |
| `digest = P(254)` published in the transcript | a free extra evaluation of the secret polynomial, so t holders reached t+1 points; at t=1 one holder recovered the secret alone |
| `batch_verify` summed shares unweighted | two errors that cancel passed the batch check |
| 512-bit default field | prime-field DLP at that size is practical, so every computational claim failed |

It also produced an auditor layer (`audit_challenge`, `prove_possession`,
`verify_possession`, `audit_holders`): a challenge-bound, non-replayable
proof that a holder still has a valid share, revealing nothing about it.
That design is the part worth reading if an auditor node gets built, and it
is described in [`docs/unified_scheme.md`](docs/unified_scheme.md).

Weaknesses that were **not** fixed, and reasons not to reuse the code as is:
`threshold_sign` is pre-FROST and breaks under concurrent signing sessions;
`deal_many` leaks linear relations among packed secrets; the bytes mode
requires all n ciphertext chunks rather than t+1. There is no formal proof
of the composed scheme and no external audit.

[`SECURITY.md`](SECURITY.md) is the full claims register.
