# CONTEXT.md — session checkpoint

**Purpose**: preserve full context of the `sss` project work so a future
session (or the user) can resume without re-deriving anything. Written at the
end of the session that built: per-coefficient PoKs, `deal_weighted`,
`distributed_run`, `threshold_sign`, bundle field-locks, PoK hygiene
hardening, a fuzz battery, and `SECURITY.md`.

---

## 1. The project

`/home/aleksic/sss` — a pure-stdlib Python secret-sharing library (`shamir`
package) whose centerpiece is **the unified scheme** (`shamir/unified.py`):
one (t+1)-of-n construction over a 512-bit safe-prime field that merges the
whole Shamir-VSS lineage into a single transcript format, one share type
`(x, s_i, r_i)`, one field, and one end-to-end verification pipeline.

The meta-question the user cares about: **can one construction be "best in
every category" vs. all the SSS derivatives?** Honest answer (established this
session): yes on all but two *definitional* rows (receiver-privacy PVSS, and
the excluded cost rows speed/simplicity). Those two are kept as sibling
modules by design. `SECURITY.md` is the honest record of assumptions.

## 2. Package layout (`shamir/`)

- `gf.py` — safe-prime field; `share_field()` returns `GF(q)` (NOT p — the
  deliberate anti-Feldman-bug choice). `default_field()` = 512-bit safe prime
  p=2q+1, g=4, h derived deterministically.
- `core.py` — plain Shamir over Z_q, Lagrange, `interpolate_at`,
  `interpolate_polynomial`, `LagrangeCache`, `field_for`, bytes mode.
- `format.py` — session-bound, checksummed share blobs; `session_id()`.
- `vss.py` — Feldman + Pedersen (documents the p-vs-q interpolation bug).
- `robust.py` — Berlekamp-Welch correction, pairwise MAC helpers.
- `proactive.py` — refresh; `reshare.py` — redistribution;
  `multisecret.py` — YCH-2004 packing; `weighted.py`; `hierarchical.py`
  (Tassa Birkhoff derivatives, over GF(p)); `dkg.py` (Feldman DKG, no r-side);
  `pvss.py` (recipient-encrypted, Schoenmakers); `hybrid.py`; `gf256.py`;
  `hybrid.py`.
- `unified.py` — the big one, ~1700 lines.
- `tests/test_all.py` — self-contained test runner (no pytest): run
  `python tests/test_all.py`. 86/86 tests pass.
- `API_CONTRACT.md` — the API reference; `SECURITY.md` — honest claims/register.

## 3. Unified scheme architecture (the design map)

Transcript dict fields: `scheme, session (16B), threshold, n, secrets,
commitments (Pedersen list len threshold+1), digest/digest_blinder (P(254),
R(254)), proof (Schnorr PoK or None), mac_tags ({(i,j): tag})`.

Stack (each bullet = a merged paper; full list in module docstring):
Pedersen commitments ('91), per-coefficient Schnorr PoKs (this session),
RBO pairwise MACs ('89) + CFOR acceptance graph (Eurocrypt '12), Berlekamp-
Welch correction (McEliece-Sarwate '81), SLIP-0039 digest point at x=254,
refresh (Herzberg '95), redistribute (Desmedt-Jarecki '93), multi-secret
(YCH '04), bytes hybrid (Krawczyk '94), `audit`/`audit_public` cheater ID
(Tompa-Woll '88), linear layers / add / mul (BGW '88, Beaver '92),
`batch_verify` (BGR '98), `derive_share`, `recover_exponent` (Desmedt-
Frankel '89), threshold Schnorr (`threshold_sign`, this session), seal/unseal
(misuse-resistant bundles).

Key invariants: verification only against commitments (x in 1..253; 254 is
digest point); MAC layer + PoK are dealer-epoch only (refresh/redistribute/
linear/dkg drop them → proof=None, mac_tags={}); `combine` runs CFOR → BW →
digest screen; all functions honor `randfunc` for deterministic tests.

## 4. What THIS session added (all tested, 86/86 green)

1. **Per-coefficient PoKs (malicious-dealer binding)** — `_coeff_pok_entries`
   (unified.py): `_deal` now proves knowledge of the opening of EVERY
   commitment, not just C_0. New domain `_COEFF_POK_DOMAIN`, per-index
   challenge `_challenge_coeff`. `verify_transcript` verifies
   `proof["entries"]` (new style); legacy single-PoK proofs still verify
   (back-compat branch). Bundle wire format extended via
   `_proof_to_bundle`/`_proof_from_bundle`.
2. **`deal_weighted(secret, weights, quota, ...)`** — virtualization: one
   underlying deal with n=sum(weights); participant p holds weights[p]
   sub-shares; authorized iff covered ≥ quota+1; transcript carries
   `weights` which now survives the bundle round-trip (fixed dead-code bug in
   `_bundle_from` — it used to `return {}` before the weights block).
3. **`distributed_run(n, threshold, field, randfunc, corrupt=(), corrupt_r=())`**
   — Pedersen DKG for the unified scheme (dealer-free setup, has r-side so the
   output drops straight into the unified pipeline). Each dealer: s+r poly,
   commits, per-coefficient PoKs (per-dealer session = session+[dealer]),
   posts (P_i(254), R_i(254)). Recipients verify (s,r) pairs; complaints +
   PoK failures → disqualified from QUAL. Sums shares/commits/digest over
   QUAL; returns {shares, transcript, public_key (=recover_exponent),
   qual, commitments_all, poks, complaints, pok_failures, posted254}.
4. **`threshold_sign(message, transcript, shares, nonce_transcript,
   nonce_shares, signers, field)` / `verify_signature(...)`** — threshold
   Schnorr, never reconstructs the key. **Must use Lagrange weights**
   (`z = Σ λᵢ(kᵢ + c·xᵢ)`) — I initially summed unweighted shares (bug:
   Σ shares ≠ constant), fixed and tested. **Nonce reuse leaks the key** —
   fresh nonce sharing per message is a required protocol rule (documented).
   Verifier subgroup-checks R and Y.
5. **Field locks on bundles** — `_field_lock`/`_check_bundle_field`: every
   seal bundle embeds p,q,g,h; unseal/unseal_bytes reject a bundle sealed
   under a different safe prime. `_bundle_from` takes an explicit `field`
   arg now.
6. **PoK hygiene** — `verify_share_proof`, `_pok_entries_ok`, and the legacy
   single-PoK path now `_check_subgroup` the T values (previously only
   commitments were checked).
7. **`test_unified_property_fuzz`** — 40 randomized (secret, t, n) iterations
   per run: roundtrip, shuffled holders, cross-check s-values vs
   `core.interpolate_at` (GF(q)), redistribute→combine, all with real
   randomness.
8. **`SECURITY.md`** — honest claims register ([IT]/[COMP]/[STANDARD]),
   assumption register, explicit non-claims.

New tests (11 added): `test_unified_coeff_pok`, `test_unified_weighted`,
`test_unified_weighted_seal`, `test_unified_distributed_run`,
`test_unified_distributed_corruption`, `test_hierarchical_committed`,
`test_unified_threshold_sign`, `test_unified_threshold_sign_dealer_free`,
`test_unified_pok_hygiene`, `test_unified_bundle_field_lock`,
`test_unified_property_fuzz`.

## 5. Hierarchical additions

Plain `hierarchical_share`/`hierarchical_combine` stay over **GF(p)** (unchanged,
existing tests). New `hierarchical_deal_committed` + `hierarchical_verify` follow
the **vss.py convention over Z_q** — CRITICAL: derivative arithmetic in GF(p)
breaks commitment exponent reduction (g^v = Π C_j^coef fails); in Z_q it is
exact. Reconstruct committed entries with
`hierarchical_combine(entries, levels, GF(field.q))`.

## 6. Honest security picture (do not over-claim to the user)

Corrected this session: I earlier claimed a mod-p vs mod-q response bias in
the proof simulation — **it does not exist** because `share_field()` = GF(q),
so HVZK is exact. Attributes scorecard vs plain Shamir:
- More secure: on corruption/dealer axes; weaker in assumption hygiene
  (added DLP binding + random oracle).
- More decentralized: across the lifecycle; initial deal is still one dealer
  (or run distributed_run).
- More fault-proof: within the modeled faults (BW bound; CFOR; audit).
- More fool-proof: genuinely yes (seal/unseal, session discipline, field
  locks).
- More trustless: reduced, NOT zero (need honest dealer OR honest quorum,
  plus DLP).
- Knowledgeless: signature path now exists; formal ZK still rests on ROM +
  standard sigma-protocol arguments (written up in SECURITY.md, not an audit).
- Forced assumptions nobody can code away: honest party must exist, random
  oracle for NIZK, computational binding for public verification, the 2x-size/
  exponentiation cost rows.

## 7. Known bugs / open items

- **Composed-scheme theorem**: no formal proof for all layers at once —
  SECURITY.md §4 explicitly does not claim one.
- **threshold_sign**: not FROST's nonce re-randomization variant; Must-replay-
  protection/robustness (e.g. malicious signer submitting wrong partial) is
  NOT handled — currently honest-processor only, like `mul_shares`.
- **distributed_run**: 1-round PBS-style bias caveat (as documented in
  dkg.py for its sibling) applies; r-side vandal (`corrupt_r`) detected only
  via commitment check (which IS the mechanical guarantee).
- **External review**: none. Obtaining one is the big remaining step.
- No lint/typecheck tooling configured (pure `python -m py_compile` +
  `python tests/test_all.py`).

## 8. How to resume

1. `python tests/test_all.py` → expect `86/86 tests passed`.
2. Read `shamir/API_CONTRACT.md` (API) and `SECURITY.md` (claims) first.
3. Main entry point for new work is `shamir/unified.py`; sibling modules are
   the "deliberately not merged" rows.
4. Style: tabs, double quotes, semicolons, K&R braces, `const`-free Python
   with type hints sparse; docstrings reference the papers (see module header)
   — match that when extending.
