# Security claims — honest register

This file states what the package provably provides, what it assumes, and what
it explicitly does **not** claim. It is a security *argument*, not a formal
proof and not an audit: no independent review has been performed. Every claim
below is tied to the construction in `shamir/unified.py` (and siblings) and
each item is tagged `[IT]` (information-theoretic, holds against unbounded
adversaries), `[COMP]` (computational, holds under a stated assumption), or
`[STANDARD]` (textbook result the integration relies on).

---

## 1. Threat model

- **Adversary classes**: (a) a malicious *dealer* at deal time; (b) malicious
  *share holders* (submit forged/corrupt shares); (c) an *external auditor*
  who sees transcript + shares/proofs; (d) a *combiner* who collects t+1
  shares; (e) a *mixer* who recombines material across sessions or fields.
- **Not in scope**: side-channel resistance, denial of service, key theft of
  the dealer's secret *before* dealing, physical compromise of all devices.

## 2. Provable properties

| Property | Tag | Statement / where |
|---|---|---|
| Secrecy of the secret | `[IT]` | With t of n shares at most, the secret is uniform given everything public. This requires that the transcript contain no evaluation of P; see the digest row below: the r-poly provides full entropy for every candidate secret (Pedersen masking). `gf.share_field()` = `GF(q)` makes shares live in Z_q, so the Z_q-uniform masking is exact, not approximate. |
| Share binding | `[COMP]` | A forged share that passes `verify_share` requires g^ds h^dr = 1 with (ds,dr) != 0, i.e. finding log_g h (DLP, 2048-bit safe prime). `h` is hashed *into* the subgroup by `gf.hash_to_subgroup`, so no party knows log_g h. Deriving it as g^{H(seed)} would publish the trapdoor and is the bug this replaced. |
| Batch verification | `[COMP]` | `batch_verify` uses the BGR small-exponents test with a fresh 128-bit weight per share. Unweighted summation is *not* sound: two errors that cancel in the sum pass. Forgery probability about 2^-128 on top of DLP. |
| Commitment binding (dealer) | `[COMP]` | Altering any committed coefficient after the deal breaks the transcript digest or a share check. DLP as above. |
| PoK soundness (dealer, coefficients) | `[STANDARD]` | Per-coefficient Schnorr sigma protocols in `_coeff_pok_entries`: special-sound (two transcripts with the same T and distinct c give za-za' = c-c' times the opening; q prime => invertible, extraction error 1/q), challenge domain-separated per (session, index) and bound to T (unified.py `_challenge_coeff`). |
| PoK soundness (share holdings) | `[STANDARD]` | `prove_share` proves knowledge of the Pedersen opening of C_x; `verify_share_proof` checks commitment = T*C_x^c; same extraction argument (challenge bound to session, x, T). |
| Zero knowledge (share proofs) | `[STANDARD]` | Honest-verifier zero knowledge: simulator picks c, za, zb uniform in Z_q and sets T = g^za h^zb * C_x^-c. Because shares and responses live in Z_q (**not** Z_p — `share_field` returns GF(q)), the simulated and real transcripts are *identically* distributed: exact, no statistical gap. Fiat-Shamir (non-interactive) adds the random-oracle assumption below. |
| Verifier hygiene | `[COMP]`-independent | Every commitment, every PoK T value, every proof R and Y is checked to lie in the order-q subgroup (`_check_subgroup`), so verification equations live entirely in the subgroup and the algebraic arguments above apply. |
| Corruption identification | `[IT]` for MACs, `[COMP]` public | Pairwise RBO MACs with dealer-epoch keys: forgery probability 1/q unconditional. Without keys, `audit_public` identifies exactly the shares failing the commitment check (computational binding). |
| Corruption correction | `[STANDARD]` | `combine` runs Berlekamp-Welch: corrects up to floor((n-t-1)/2) corrupt s-values among the collected shares; more failures raise. |
| Wrong-secret / cross-session detection | `[COMP]` | The reconstructed polynomial is checked coefficient by coefficient against the commitments (`_screen_against_commitments`). The transcript publishes **no** evaluation of the secret polynomial. Publishing (P(254), R(254)) previously gave any t holders a free (t+1)-th point, lowering the privacy threshold by one. |
| Sampled possession (auditor) | `[STANDARD]` | `audit_challenge` / `prove_possession` / `verify_possession`: Schnorr proof of the Pedersen opening whose Fiat-Shamir challenge binds an auditor nonce and epoch, so a stored proof cannot answer a later round. The auditor holds no key material and learns only which slots answered. |
| Dealer-free setup soundness | `[COMP]` | `distributed_run` = Pedersen DKG + per-dealer PoKs: any disqualified dealer (failed share check or PoK) is excluded from QUAL; the group secret is never materialized; the emergent transcript is a normal unified transcript. |
| Threshold signatures | `[STANDARD]` | `threshold_sign`: z = sum lambda_i (k_i + c x_i) over Lagrange weights => z = k + c x; verification g^z = R Y^c is the textbook Schnorr equation. Signing never reconstructs x or k. |

## 3. Assumption register (the honest "ifs")

**Forced — present in any scheme, not a defect:**

1. **Honest party exists.** Either an honest dealer at deal time, or an honest
   quorum during `distributed_run` (setup). A secret requires someone to hold
   it (or hold pieces and behave honestly). Unavoidable.
2. **Random oracle (Fiat-Shamir).** All non-interactive proofs use it. Every
   deployed Schnorr-style system (FROST, EdDSA, ECDSA) does too. Removing it
   requires going interactive.
3. **Computational binding.** Publicly verifiable commitments are
   computationally bound (DLP). Information-theoretic *binding* with public
   verification is known impossible.
4. **Cost rows.** ~2x share size and exponentiation-heavy verification are the
   deliberate price of public verifiability (the excluded attributes).

**Fixed in the hardening pass (each has a regression test):**

- `h` is hashed into the subgroup instead of computed as g^{SHA-256(seed)}.
  The old derivation published log_g h, so anyone could open a commitment to
  any value: `(s+delta, r-delta/c)` verified against the same commitments.
- The transcript no longer publishes `digest`/`digest_blinder`. It used to
  hand out P(254) and R(254) in the clear, so t colluding holders reached
  t+1 points and interpolated the secret; at threshold 1 one holder sufficed.
- `batch_verify` weights each share (BGR small exponents) instead of summing.
- The default field is 2048-bit, not 512-bit. `insecure_test_field()` keeps
  the old group for fast tests under an unmistakable name.
- `make_safe_prime` called `secrets.getrandbits`, which does not exist, so
  no alternative field could ever be generated.
- `weighted_combine` takes the field explicitly; it previously fell back to
  `default_field()` and silently returned a wrong secret across moduli.

**Removed or tightened in the earlier rewrite:**

- Response sampling is uniform over Z_q (share field == subgroup order), so
  HVZK holds *exactly*; no leftover statistical gap needs hand-waving.
- `T` values of every proof, and `R`/`Y` of every signature, are subgroup
  checked: equations never leave the group where the arguments hold.
- Bundles are field-locked: unsealing against a different safe prime is
  rejected structurally, not "usually fine".
- Setup can be dealer-free idiomatically (`distributed_run`), and signatures
  never reconstruct the key (`threshold_sign`).

## 4. Known limits — explicitly NOT claimed

- No formal theorem for the *composed* scheme (all layers at once). Each
  layer's property is standard and stated above; a composed security proof is
  not written.
- Nonce reuse defeats `threshold_sign` (z1 - z2 = (c1 - c2) x): fresh nonce
  sharing per message is a required protocol rule.
- Dealer-epoch MAC keys: after refresh/redistribution/linear composition the
  MAC layer is gone and authenticity rests on the (computational)
  commitments.
- No audit, no conformance tests against reference implementations, no
  formal verification of the implementation (constant-time, etc.).

*If any property in section 2 is load-bearing for your use, obtain a real
security review before production use.*