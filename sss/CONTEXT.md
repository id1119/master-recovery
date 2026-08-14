# CONTEXT.md — session checkpoint

**Purpose**: preserve full context of the `sss` project work so a future
session (or the user) can resume without re-deriving anything. Written at
the end of the session that built: per-coefficient PoKs, `deal_weighted`,
`distributed_run`, `threshold_sign`, bundle field-locks, PoK hygiene
hardening, a fuzz battery, and `SECURITY.md`; extended by the v4 session
(statement-binding challenges, `rejoin_share`, `change_threshold`, signer
attribution, audit fix — see §4b).

---

## 1. The project

`/home/aleksic/sss` — a pure-stdlib Python secret-sharing library (`shamir`
package) whose centerpiece is **the unified scheme** (`shamir/unified.py`):
one (t+1)-of-n construction over a 2048-bit safe-prime field that merges the
whole Shamir-VSS lineage into a single transcript format, one share type
`(x, s_i, r_i)`, one field, and one end-to-end verification pipeline.

The meta-question the user cares about: **can one construction be "best in
every category" vs. all the SSS derivatives?** Honest answer (established this
session): yes on all but two *definitional* rows (receiver-privacy PVSS, and
the excluded cost rows speed/simplicity). Those two are kept as sibling
modules by design. `SECURITY.md` is the honest record of assumptions.

## 2. Package layout (`shamir/`)

- `gf.py` — safe-prime field; `share_field()` returns `GF(q)` (NOT p — the
  deliberate anti-Feldman-bug choice). `default_field()` = 2048-bit safe prime
  p=2q+1, g=4, h hashed into the subgroup; `insecure_test_field()` = 512-bit
  for fast tests only.
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
- `unified.py` — the big one, ~2000 lines (scheme tag `unified-v4`).
- `tests/test_all.py` — self-contained test runner (no pytest): run
  `python tests/test_all.py`. 101/101 tests pass.
- `API_CONTRACT.md` — the API reference; `SECURITY.md` — honest claims/register.

## 3. Unified scheme architecture (the design map)

Transcript dict fields: `scheme, session (16B), threshold, n, secrets,
commitments (Pedersen list len threshold+1), proof (Schnorr PoK or None),
mac_tags ({(i,j): tag})`.  No polynomial evaluation is published (the old
digest/digest_blinder fields were removed — they handed observers a free
(t+1)-th point).

Stack (each bullet = a merged paper; full list in module docstring):
Pedersen commitments ('91), per-coefficient Schnorr PoKs (statement-bound
Fiat-Shamir challenges since v4), RBO pairwise MACs ('89) + CFOR acceptance
graph (Eurocrypt '12), Berlekamp-Welch correction (McEliece-Sarwate '81),
refresh (Herzberg '95), redistribute (Desmedt-Jarecki '93), multi-secret
(YCH '04), bytes hybrid (Krawczyk '94), `audit`/`audit_public` cheater ID
(Tompa-Woll '88), linear layers / add / mul (BGW '88, Beaver '92),
`batch_verify` (BGR '98), `derive_share`, `rejoin_share` (slot repair),
`change_threshold` (one-call migration), `recover_exponent` (Desmedt-
Frankel '89), threshold Schnorr (`threshold_sign`, verified signer shares),
seal/unseal (misuse-resistant bundles).

Key invariants: verification only against commitments (x in 1..253); MAC
layer + PoK are dealer-epoch only (refresh/redistribute/linear/dkg drop them
→ proof=None, mac_tags={}); `combine` runs CFOR → BW → commitment screen;
all functions honor `randfunc` for deterministic tests.

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

## 4b. What the v4 hardening session changed (101/101 tests green)

1. **Fiat-Shamir statement binding** — every PoK challenge now hashes the
   full commitment vector: `_challenge_coeff(session, j, commitments, T)`,
   `_challenge_share`, `_challenge_possession`. v3's `_challenge_coeff`
   bound only (session, index, T), so a per-coefficient proof re-verified
   against a different commitment vector with the same session/index/T — the
   Fiat-Shamir programmability argument needs the statement bound. This was
   the audit-flagged gap, most consequential in `distributed_run`'s rogue-
   key defense. Scheme AND bundle format moved to `unified-v4` (both counters
   together; old bundles are rejected as unknown format).
2. **`audit` collision fix** — malformed shares are keyed -1, -2, ... (was
   `len(statuses)`, which collided with a real holder index and silently
   overwrote a valid verdict).
3. **`rejoin_share(transcript, shares, x)`** — merged from
   `proactive.recover_share`: recompute the share at an OCCUPIED slot from
   t+1 verified shares, commitment-screened. This is the guardian
   replacement/repair primitive (lost slot rebuilt without dealer or
   secret) that `derive_share` deliberately refuses (new member = new
   coordinate).
4. **`change_threshold(shares, transcript, t', n')`** — merged from
   `reshare.change_threshold`: verify all old shares, reconstruct through
   the full pipeline, re-deal under new params; returns (shares, keys,
   transcript) like `deal`.
5. **`threshold_sign` signer attribution** — every signer's key and nonce
   share is verified against its transcript before use; invalid signers
   raise (naming them) or, with `drop_invalid=True`, are excluded and
   reported in `detail["rejected"]` (signature from survivors, needs
   threshold+1 clean). Matches the protocol's "accept only distinct valid
   contributions" rule (PROTOCOL.md 3.4).
6. **`weighted.weighted_combine` requires `field`** — the silent
   default_field() fallback returned a wrong secret across moduli
   (SECURITY.md claimed this was fixed; the sibling module still had the
   bug — now actually fixed, with a regression test).
7. **Doc drift cleaned** — `docs/unified_scheme.md`, `SECURITY.md`,
   `API_CONTRACT.md`, `CONTEXT.md` updated to the 2048-bit/v4 reality;
   stale "digest point" references in refresh/redistribute docstrings
   removed; `redistribute`'s docstring no longer promises a `posted` dict
   it never returns.

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

- **FIXED (v4-era)**: share blob header encoded `width` in one byte; a
  2048-bit field has width 256, so `seal`/`unseal` crashed on the production
  field (the 512-bit test field, width 64, masked it). Blob version bumped to
  0x02 with a 2-byte width field; regression test
  `test_unified_seal_on_production_field`.

- **Composed-scheme theorem**: no formal proof for all layers at once —
  SECURITY.md §4 explicitly does not claim one.
- **threshold_sign**: not FROST's nonce re-randomization variant. Signer
  share verification + attribution now exists (v4); must-replay protection
  (a live adversary intercepting/replaying a signer's partial) is still
  protocol-level, and a signer whose *share* is valid but who runs the
  protocol wrong locally is outside the honest-processor model.
- **distributed_run**: 1-round PBS-style bias caveat (as documented in
  dkg.py for its sibling) applies; r-side vandal (`corrupt_r`) detected only
  via commitment check (which IS the mechanical guarantee). A two-round
  commit-then-reveal variant would remove the last-dealer bias; not yet
  implemented.
- **CFOR at n = t+1**: the MAC acceptance graph is inert at the minimum
  deployment (t+1 certifying votes unreachable with t peers); reconstruction
  falls through to the commitment screen. Documented in SECURITY.md §4.
- **External review**: none. Obtaining one is the big remaining step.
- No lint/typecheck tooling configured (pure `python -m py_compile` +
  `python tests/test_all.py`).

## 8. How to resume

1. `python tests/test_all.py` → expect `101/101 tests passed`.
2. Read `shamir/API_CONTRACT.md` (API) and `SECURITY.md` (claims) first.
3. Main entry point for new work is `shamir/unified.py`; sibling modules are
   the "deliberately not merged" rows.
4. Style: tabs, double quotes, semicolons, K&R braces, `const`-free Python
   with type hints sparse; docstrings reference the papers (see module header)
   — match that when extending.
