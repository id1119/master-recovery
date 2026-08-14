# API Contract — merged SSS package (`shamir/`)

All feature modules import from `shamir.gf` / `shamir.gf256` / `shamir.core`.
Style: 4-space indent, stdlib only (hashlib, hmac, secrets), module + function
docstrings required, minimal inline comments. Every public function must be
deterministic-testable: accept an optional `randfunc` (callable returning an
int in field range) for reproducible tests.

## Field objects (shamir.gf)

`GF(p, q, g, h)`: ints mod p; methods add/sub/mul/div/inv/pow/neg/random,
`polynomial_eval(coeffs, x)`, `random_polynomial(degree, constant)`,
`commit(a) -> g^a`, `commit_double(a,b) -> g^a h^b`, `eval_commit(coeffs, x)`
(returns prod_j C_j^(x^j)), `_check_subgroup(x)`.
`default_field(with_subgroup=True)` -> 512-bit safe-prime field.
Constants: SHARE_INDEX_MIN=1, SHARE_INDEX_MAX=254.

## Byte field (shamir.gf256)

`GF256` singleton FIELD_256: same method names minus commit ops; add==sub==XOR.

## Core (shamir.core)

- `share(secret, threshold, n, field, randfunc, points) -> [(x, y)]`
- `combine(shares, field) -> secret`
- `interpolate_at(points, at, field)`, `interpolate_polynomial(points, degree, field)`
- `LagrangeCache(xs, field)` with `.coefficient(at)` and `.evaluate(ys, at)`
- `derive_share(shares, x, field)` (new share without the secret)
- `share_bytes(secret: bytes, threshold, n) -> [(x, bytes)]`,
  `combine_bytes(shares)`, `derive_share_bytes(shares, x)`

## Share format (shamir.format)

- `encode_share(index, value, session, width, byte_mode) -> bytes`
- `decode_share(blob, width, byte_mode) -> (index, value, session)` (raises ValueError)
- `encode_shares/decode_shares`, `session_id()`, `digest_for(secret_int, session, width)`,
  `check_digest(secret_int, session, tag)`, `DIGEST_POINT_X = 254`

---

# Feature module contracts

## shamir/vss.py — Feldman (1987) + Pedersen (1991)

```python
def feldman_deal(secret, threshold, n, field=None, randfunc=None) -> (shares, commitments)
    # commitments[j] = g^a_j for j=0..threshold; shares = [(x, y)]
def feldman_verify(share, commitments, field=None) -> bool    # share = (x, y)
def feldman_combine(shares, commitments, field=None) -> int   # verify-then-interpolate
def feldman_polynomial(shares, commitments, field=None) -> [coeffs]

def pedersen_deal(secret, threshold, n, field=None, randfunc=None) -> (pairs, commitments)
    # pairs = [(x, s_i, t_i)]; commitments[j] = g^a_j h^b_j
def pedersen_verify(pair, commitments, field=None) -> bool
def pedersen_combine(pairs, commitments, field=None) -> int   # uses s_i only
```
Rules: share index x in 1..n; verify g^y == prod C_j^(x^j) (Feldman),
g^s h^t == prod C_j^(x^j) (Pedersen); reject y=0 shares. Raise ValueError on
inconsistent sizes. No imports outside the shamir package + stdlib.

## shamir/pvss.py — Schoenmakers (1999)

```python
def pvss_keygen(field=None) -> (sk, pk)         # sk in Z_q, pk = g^sk
def pvss_deal(secret, threshold, recipient_pks, field=None, randfunc=None) -> transcript
    # transcript: dict with commitments, ciphertexts E_i=(W_i,V_i), fiat-shamir proof fields
def pvss_verify(transcript, field=None) -> bool   # fully public
def pvss_decrypt_share(transcript, sk, i, field=None) -> Y_i  # g^{f(i)}
def pvss_combine_exponent(Ys, indices, threshold, field=None) -> Y  # g^s
def pvss_recover_small_secret(Y, bound, field=None) -> int | None  # BSGS pullback
```
Rules: all public values in order-q subgroup; FS challenge c = H(transcript)
domain-separated; per-recipient randomness fresh. Returns None instead of
raising on invalid transcripts (verification result is data).

## shamir/robust.py — RS error correction + IT detection

```python
def berlekamp_welch(points, degree, field=None) -> [coeffs]  # raises ValueError if undecodable
def robust_combine(shares, threshold, field=None) -> int
    # error-corrects up to floor((n - t - 1)/2) corrupted shares, else raises
def verify_then_combine(shares, commitments, field=None) -> int  # VSS-committed robust

class PairwiseMACSharing:      # Rabin-Ben-Or (1989) information-theoretic detection
    def __init__(self, field=None)
    def deal(self, secret, threshold, n, randfunc=None) -> (shares, mac_keys, mac_tags)
    def check(self, share, index, mac_keys, mac_tags, min_ok=None) -> bool
    # mac_keys[(i,j)] = (a,b); mac_tags[(i,j)] = a*y_i + b; share i OK iff it
    # passes >= min_ok (default t+1) distinct j keys
```
Rules: field must be the 512-bit default (tags need q >= 2^128). Never reuse
keys. Berlekamp-Welch: solve linear system over GF(p) (use plain Gaussian
elimination, no numpy), verify deg(Q)-deg(E)==degree, monic E, and that Q/E
interpolates all-but-e points.

## shamir/proactive.py — Herzberg-Jarecki-Krawczyk-Yung (1995)

```python
def refresh(share, threshold, n, field=None, randfunc=None) -> (new_share, commitments, deltas)
    # dealer-free: each of n players deals δ_i degree-t, δ_i(0)=0, verifies via
    # commitments, sums. new_share at same index.
def refresh_verify(new_share, old_share, commitments_list, field=None) -> bool
def recover_share(index, contributor_shares, threshold, field=None) -> share
```
Rules: δ_i(0)=0 enforced; returns per-contributor commitments for external
verification; raise ValueError if any dealt polynomial is invalid.

## shamir/dkg.py — Pedersen DKG (1991) / JVRSS-FROST style

```python
def dkg_deal(index, threshold, n, field=None, randfunc=None) -> (share_polys, commitments, pok)
    # pok: Schnorr proof of knowledge of a_0 (prove + verify functions below)
def dkg_verify_share(dealer_commitments, recipient_index, received_share, field=None) -> bool
def dkg_pok_verify(pok, commitment_a0, index, field=None) -> bool
def dkg_combine(shares_by_recipient, qual, threshold, field=None) -> (final_share, public_key)
    # public_key = g^{sum a0} over qual (int mod p)
```
Rules: complaint model documented in docstring; the honest path returns the
sum polynomial; GJKR bias caveat documented. Keep it one-round (parallel
Feldman) + FROST-style PoK of a0.

## shamir/hybrid.py — Krawczyk (1994)

```python
def hybrid_share(secret: bytes, threshold, n, field=None, randfunc=None)
    -> (key_shares, ciphertext, chunk_map)
    # AES-256-GCM encrypt secret under fresh key; Shamir-share the key;
    # split ciphertext into n chunks (padded); chunk_map: chunk index -> (x, data)
def hybrid_combine(key_shares, chunk_map, threshold) -> bytes
```
Rules: use only hashlib/hmac/secrets — implement AES-GCM via
`cryptography`? NO external deps: implement with a well-known pure-stdlib
construction: use SHA-256-based stream (SHAKE256) XOR + HMAC tag. Document
that the reference construction is AES-GCM and the bundled one is an
AEAD built from SHAKE256 (computationally sound, auditable). chunk_map keys
are the share x-coordinates used for key shares.

## shamir/multisecret.py — Yang-Chang-Hwang (2004, sound p<=t case)

```python
def share_secrets(secrets: list[int], threshold, n, field=None, randfunc=None) -> shares
    # one degree-t polynomial h, first p=len(secrets) coefficients = secrets
def combine_secrets(shares, n_secrets, field=None) -> list[int]
```
Rules: require 1 <= p <= threshold; recover all p coefficients by
interpolation at x=0..p-1 (coefficient extraction).

## shamir/weighted.py + shamir/hierarchical.py

```python
# weighted.py — Shamir virtualization (distinct x per sub-share)
def weighted_share(secret, weights, quota, field=None, randfunc=None)
    -> {participant: [(x, y), ...]}   # sum(weights) sub-shares, threshold=quota
def weighted_combine(subshare_groups, quota, field) -> int
    # field is REQUIRED: interpolation over the wrong modulus silently
    # returns a different secret, so there is no default-field fallback

# hierarchical.py — Tassa (2007) Birkhoff derivative sharing
def hierarchical_share(secret, levels, ids, field=None, randfunc=None)
    -> {id: (level, share_value)}    # levels: list of cumulative thresholds k_i
def hierarchical_combine(entries, levels, field=None) -> int
    # entries: [(id, level, value)]; solve Birkhoff system over GF(p) by
    # Gaussian elimination; raises on singular systems
def hierarchical_deal_committed(secret, levels, ids, field=None, randfunc=None)
    -> (entries, commitments)        # committed variant over Z_q (vss.py
    # convention): shares/derivatives in Z_q so commitment exponents share
    # one modulus; commitments = [g^a_j]:
    #    hierarchical_combine(entries_list, levels, GF(field.q))
def hierarchical_verify(entry, commitments, levels, field=None) -> bool
    # Feldman check g^value == prod C_j^{falling(j,r)*id^(j-r)}, r =
    # k_{level-1}; returns bool, never raises
```
Rules: hierarchical — participant at level L gets P^(k_L-1)(id) (P degree
k_m-1); k_0=1..; ids must be distinct nonzero; solve with modular Gaussian
elimination; verify by construction that an authorized set (for every level i
at least k_i participants from levels <= i) yields a unique solution.

## shamir/reshare.py — Desmedt-Jarecki (1993) verifiable redistribution

```python
def redistribute(shares, old_commitments, new_threshold, new_n, field=None, randfunc=None)
    -> (new_shares, new_commitments)
    # each of t+1 holders deals h_i degree=new_threshold with h_i(0)=own share;
    # new share = sum over holders lambda_i * h_i(j); new commitments derived
def change_threshold(shares, old_commitments, new_threshold, new_n, field=None) -> (new_shares, new_commitments)
    # single-dealer variant (dealer knows secret): fresh share of same secret
```
Rules: verify old_commitments against old shares first; Lagrange over the
contributing holder set A must be the same for all recipients; raise on
degree mismatches.

## shamir/unified.py — unified scheme v2/v3 (one construction, merged lineage)

Everything below takes a 512-bit safe-prime `field` (default_field) with two
subgroup generators; shares are always (x, s_i, r_i) triples; transcripts are
dicts carrying scheme, session (16 B), threshold, n, secrets, commitments
(Pedersen), digest/digest_blinder (SLIP-0039 point x=254), proof (Schnorr PoK
or None), mac_tags ({(i,j): tag} or {}).

```python
# Dealing / recovery
def deal(secret, threshold, n, field=None, randfunc=None) -> (shares, mac_keys, transcript)
def deal_many(secrets: list[int], threshold, n, field=None, randfunc=None) -> (shares, keys, tr)  # YCH-2004: secrets packed in low coeffs
def deal_weighted(secret, weights: list[int], quota, field=None, randfunc=None)
    -> (groups, keys, tr)   # Shamir-1979 III virtualisation: participant p
    # holds weights[p] sub-shares; authorized iff covered sub-shares >=
    # quota + 1; one underlying deal with n = sum(weights); tr['weights']
    # kept through the bundle wire format
def distributed_run(n, threshold, field=None, randfunc=None, corrupt=(), corrupt_r=())
    -> {shares, transcript, public_key, qual, commitments_all, poks,
       complaints, pok_failures, posted254}
    # dealer-free unified setup (Pedersen DKG): every party deals a random
    # unified polynomial + per-coefficient PoK, posts its digest point
    # (P_i(254), R_i(254)); shares and digest sum over QUAL; nobody ever
    # sees the group secret; the transcript is a plain unified transcript
    # (proof=None, mac_tags={}) accepted by the whole pipeline
def combine(transcript, shares, mac_keys=None, field=None) -> int
def combine_many(transcript, shares, mac_keys=None, field=None) -> list[int]
def deal_bytes(secret: bytes, threshold, n, field=None, randfunc=None) -> (shares, keys, tr, chunk_map)  # Krawczyk-1994 hybrid
def combine_bytes(transcript, shares, chunk_map, mac_keys=None, field=None) -> bytes

# Verification & diagnosis (never raise; bool / tuple)
def verify_transcript(transcript, field=None) -> bool
def verify_share(share, transcript, field=None) -> bool   # x in 1..253
def batch_verify(shares, transcript, field=None) -> bool  # BGR-1998 aggregate, one multi-exp
def prove_share(share, transcript, field=None, randfunc=None) -> dict
    # FROST-style Schnorr ZK proof of holding a valid share of the deal;
    # proves knowledge of the Pedersen opening of C_x WITHOUT revealing
    # (s, r); carries only {x, T, c, za, zb}
def verify_share_proof(proof, transcript, field=None) -> bool
def audit(transcript, shares, mac_keys=None, field=None) -> (outcome, statuses, reason)
def audit_public(transcript, shares, field=None) -> (statuses, recoverable)
    # cheater identification WITHOUT reconstruction: auditor learns which
    # shares are corrupted but never the secret; recoverable is the
    # structural necessary-condition signal (digest screen only at
    # recovery)

# Epoch layers
def random_shares(threshold, n, field=None, randfunc=None) -> (secret, shares, keys, tr)
def refresh(share, transcript, field=None, randfunc=None, corrupt=()) -> (ns, ntr, info)
def redistribute(shares, transcript, new_threshold, new_n, field=None, randfunc=None) -> (ns, ntr, posted)
def derive_share(transcript, shares, y, field=None) -> (y, s_y, r_y)  # re-issue at a NEW coordinate, no dealer
def rejoin_share(transcript, shares, x, field=None) -> (x, s_x, r_x)
    # guardian slot repair: recompute the share at an OCCUPIED coordinate x
    # from any threshold+1 verified shares; result is commitment-screened;
    # the inverse of derive_share (which forbids occupied coordinates)
def change_threshold(shares, transcript, new_threshold, new_n, field=None,
                     randfunc=None) -> (shares, mac_keys, transcript)
    # single-dealer migration: verify every old share, reconstruct through
    # the full pipeline, re-deal under (t', n'); output drops into combine/
    # seal/audit like any deal

# Linear algebra over shares (BGW-1988: addition gates are free)
def mul_share(scalar, share, field=None) -> share
def add_shares(share_a, share_b, field=None) -> share
def linear_shares(coeffs, share_sets, field=None) -> list[share]   # holder-local sum
def linear_transcript(transcripts, coeffs=None, field=None) -> transcript  # exponent-only
def mul_shares(shares_a, shares_b, transcript_a, transcript_b, field=None, randfunc=None)
    -> (product_shares, product_transcript, info)
    # Beaver-1992 multiplication: requires equal threshold and n across the
    # two deals; opens d = x - a, e = y - b masks internally; output is a
    # valid sharing of x*y whose transcript derives in the exponent.
    # Honest-processor model: corrupt input shares surface via the usual
    # commitment/BW layers; per-party zero-knowledge of the openings is OOS.
def random_shares(threshold, n, field=None, randfunc=None)
    -> (secret, shares, keys, tr)   # preprocessing / Beaver-triple inputs

# Threshold exponentiation (Desmedt-Frankel 1989: g^s without s)
def recover_exponent(transcript, shares, field=None) -> int   # g^secret mod p
def threshold_sign(message: bytes, transcript, shares, nonce_transcript,
                   nonce_shares, signers, field=None,
                   drop_invalid=False) -> (R, z, Y, detail)
    # threshold Schnorr: sign WITHOUT reconstructing the key; key sharings
    # come from deal or distributed_run; one fresh nonce sharing per message
    # (reuse leaks the key); z = sum of Lagrange-weighted partials
    # lambda_i*(k_i + c*x_i).  Every signer's key and nonce share is verified
    # against its transcript before use: invalid signers raise (naming them)
    # by default, or are excluded with drop_invalid=True (reported in
    # detail["rejected"]) and the signature is produced from the survivors.
def verify_signature(message: bytes, R, z, Y, field=None) -> bool
    # public g^z == R * Y^c; checks R, Y in the order-q subgroup

# Portable bundles (misuse-resistant end-to-end)
def seal(secret, threshold, n, field=None, randfunc=None, keys=True) -> bundle
def unseal(bundle, blobs, mac_keys=None, field=None) -> int
def seal_bytes(secret: bytes, threshold, n, field=None, randfunc=None, keys=True) -> bundle
def unseal_bytes(bundle, blobs, mac_keys=None, field=None) -> bytes
```

Rules: verification of a share is against the transcript's Pedersen
commitments only (x range 1..253).  Deal proofs are per-coefficient Schnorr
PoK entries whose Fiat-Shamir challenges bind the full commitment vector
(the statement).  The MAC layer and PoK are dealer-epoch: refresh /
redistribute / linear_transcript / distributed_run drop them (empty
mac_tags, proof=None) and attest via the commitments.  combine
runs the CFOR acceptance graph (when mac_keys given), Berlekamp-Welch
correction, then the commitment screen (raises ValueError on cross-session or
wrong-secret mixing; no polynomial evaluation is published).  audit reports
malformed shares under negative keys -1, -2, ... so they never overwrite a
real holder's verdict.  seal bundles are JSON-serializable; share blobs are
session-bound + checksummed; unseal validates every layer and raises on any
tampering, including a bundle/field mismatch (every bundle carries a field
lock -- p, q, g, h -- and unseal rejects a different safe prime).  Every function honours an optional randfunc for reproducible
tests.  Access structures / DKG / PVSS / GF(2^8) / ramp remain sibling
modules and are intentionally not merged into this construction.

---

# Constraints for implementers

- stdlib only (hashlib, hmac, secrets, itertools, math). NO numpy/pytest.
- Every function docstring names the paper/improvement it implements.
- Do not modify gf.py, gf256.py, core.py, format.py.
- Add `from . import <sibling>` where needed via relative imports.
- Test your module by running python3 one-liners / scratch scripts in /tmp
  before returning; report the test output in your summary.
