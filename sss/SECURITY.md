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
| Secrecy of the secret | `[IT]` | With t of n shares at most, the secret is uniform given everything public: the r-poly provides full entropy for every candidate secret (Pedersen masking). `gf.share_field()` = `GF(q)` makes shares live in Z_q, so the Z_q-uniform masking is exact, not approximate. |
| Share binding | `[COMP]` | A forged share that passes `verify_share` requires g^ds h^dr = 1 with (ds,dr) != 0, i.e. finding log_g h (DLP, safe-prime p). `batch_verify` (BGR-98) rests on the same assumption. |
| Commitment binding (dealer) | `[COMP]` | Altering any committed coefficient after the deal breaks the transcript digest or a share check. DLP as above. |
| PoK soundness (dealer, coefficients) | `[STANDARD]` | Per-coefficient Schnorr sigma protocols in `_coeff_pok_entries`: special-sound (two transcripts with the same T and distinct c give za-za' = c-c' times the opening; q prime => invertible, extraction error 1/q), challenge domain-separated per (session, index) and bound to T (unified.py `_challenge_coeff`). |
| PoK soundness (share holdings) | `[STANDARD]` | `prove_share` proves knowledge of the Pedersen opening of C_x; `verify_share_proof` checks commitment = T*C_x^c; same extraction argument (challenge bound to session, x, T). |
| Zero knowledge (share proofs) | `[STANDARD]` | Honest-verifier zero knowledge: simulator picks c, za, zb uniform in Z_q and sets T = g^za h^zb * C_x^-c. Because shares and responses live in Z_q (**not** Z_p — `share_field` returns GF(q)), the simulated and real transcripts are *identically* distributed: exact, no statistical gap. Fiat-Shamir (non-interactive) adds the random-oracle assumption below. |
| Verifier hygiene | `[COMP]`-independent | Every commitment, every PoK T value, every proof R and Y is checked to lie in the order-q subgroup (`_check_subgroup`), so verification equations live entirely in the subgroup and the algebraic arguments above apply. |
| Corruption identification | `[IT]` for MACs, `[COMP]` public | Pairwise RBO MACs with dealer-epoch keys: forgery probability 1/q unconditional. Without keys, `audit_public` identifies exactly the shares failing the commitment check (computational binding). |
| Corruption correction | `[STANDARD]` | `combine` runs Berlekamp-Welch: corrects up to floor((n-t-1)/2) corrupt s-values among the collected shares; more failures raise. |
| Wrong-secret / cross-session detection | `[COMP]` | SLIP-0039-style digest (P(254), R(254)) checked against commitments and re-checked at combine: mixing sessions/secrets is rejected. |
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

**Removed or tightened in the rewrite:**

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