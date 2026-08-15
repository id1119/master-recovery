# The Unified Scheme (U-SSS) — design, improvements, assumptions, implementation

> Historical research archive (2026-08-15): this proposed Python construction
> was not adopted and its implementation was removed. Master Recovery uses the
> maintained-library profiles documented in `../../SHAMIR_AUDIT.md`.

This document is the in-depth writeup of the project's centerpiece variation:
**the unified scheme v4** in `shamir/unified.py` (~2000 lines, pure stdlib).
It is one (t+1)-of-n secret-sharing construction over a 2048-bit safe-prime
field that absorbs the entire verifiable-secret-sharing lineage into a single
share format `(x, s_i, r_i)`, a single transcript format, and one end-to-end
verification pipeline.

The honest framing first: the scheme does **not** win every category. Two rows
of the SSS scorecard are *definitionally* excluded and live in sibling modules
on purpose — receiver-privacy PVSS (`shamir/pvss.py`) and the cost rows
(speed / simplicity). Everything else — verifiability, robustness, cheater
identification, proactivity, thresholds on *unreconstructed* values
(signatures, exponentials), dealer-free setup, misuse resistance — is merged
here. `SECURITY.md` is the companion claims register; `API_CONTRACT.md` the
API reference.

---

## 1. Identity

| | |
|---|---|
| Module | `shamir/unified.py` |
| Scheme tag | `"unified-v4"` (`_SCHEME`); the bundle *container* format is also `"unified-v4"` (`_BUNDLE_FORMAT`) — both counters moved together when the v4 Fiat-Shamir statement binding changed the challenge bytes (see §6.1) |
| Share | `(x, s_i, r_i)` — two field elements: the Shamir value *and* a Pedersen masking value |
| Transcript | public dict: scheme, 16-byte session, threshold, n, secrets, commitments, Schnorr PoK, MAC tags |
| Field | safe prime p = 2q+1, 2048-bit (512-bit group retained as `insecure_test_field()` for tests); share arithmetic in **Z_q** (deliberately), commitment arithmetic in the order-q subgroup of Z_p\* |
| Digest point | x = 254 (SLIP-0039 convention, `_DIGEST_INDEX`); no polynomial evaluation is ever published |
| Sibling modules (not merged) | `pvss.py` (recipient privacy), `gf256.py` (GF(2^8) field), `hierarchical.py` (Birkhoff-derivative hierarchies, plain and committed), `weighted.py` (standalone weighted scheme) |

The design goal, restated: a dealer deals once, publicly posts everything
needed to *verify* the deal and every share, and then the sharing lives out
its whole lifecycle — refresh, redistribution, joining, linear composition,
multiplication, signing, byte-secret recovery — with **no dealer and no
secret ever materialised outside the shares**, while every stage remains
publicly checkable against the commitments.

---

## 2. Design overview

### 2.1 The field (`shamir/gf.py`)

- Fixed 2048-bit safe prime `p = 2q + 1` (both prime, tested at import time in
  `default_field()`; the old 512-bit group is `insecure_test_field()`).
- `g = 2^2 = 4`: a quadratic residue, hence of exact order q in Z_p\*.
- `h = hash_to_subgroup(p, q, seed)`: the seed is hashed and squared *into*
  the order-q subgroup, so h is publicly recomputable but its discrete log
  base g is unknown to everyone, including whoever chose the seed. The
  earlier `h = g^{SHA-256(seed) mod q}` published log_g h as a derivable
  constant and therefore destroyed binding entirely: given any valid share
  `(s, r)` and any delta, `(s + delta, r - delta/c)` opened the same
  commitment and passed `verify_share`, `batch_verify` and `audit`.
- **The key anti-bug decision**: `GF.share_field()` returns `GF(q)`, not
  `GF(p)`. All secret/shares/coefficient arithmetic therefore lives in
  Z_q *exactly*, while commitment exponentiation lives in the order-q
  subgroup. This is the deliberate correction of the classic Feldman-style
  p-vs-q interpolation bug (documented in `vss.py`), and it is what makes the
  zero-knowledge claims *exact* rather than statistical (see §7).

### 2.2 Deal-time structure (`_deal`, unified.py:249)

The dealer picks two polynomials of degree ≤ t over Z_q:

```
P(x) = a_0 + a_1 x + ... + a_t x^t      (the secret polynomial; P(0) = secret)
R(x) = b_0 + b_1 x + ... + b_t x^t      (the masking polynomial, fully random)
```

- Shares: `s_i = P(i)`, `r_i = R(i)` at `x = 1..n`.
- Commitments (Pedersen 1991): `C_j = g^{a_j} h^{b_j}` for every coefficient.
  A share is publicly checkable because
  `g^{s_i} h^{r_i} == prod_j C_j^{x^j}` — but the secret is
  *information-theoretically* hidden by the random R polynomial (perfect
  masking, since R is uniform over Z_q; see §7).
- **No evaluation of the secret polynomial is published.** An earlier
  version put `digest = P(254)` and `digest_blinder = R(254)` in the public
  transcript, which handed every observer a free (t+1)-th point: t colluding
  holders interpolated the secret, and at t=1 a single holder did it alone.
  Reconstruction is instead screened coefficient by coefficient against the
  commitments, which checks all t+1 coefficients rather than one evaluation.
- **Per-coefficient Schnorr proofs of knowledge** (`_coeff_pok_entries`,
  unified.py:225): one sigma-protocol entry per coefficient, proving knowledge
  of the opening `(a_j, b_j)` of *every* commitment — not just C_0. This is
  the FROST/Schoenmakers-practice contribution (see §3.2).
- **Pairwise MACs** (Rabin-Ben-Or 1989): for every ordered pair (i,j), a fresh
  key `(a,b)` is drawn and the tag `t_{ij} = a·s_i + b` publicised. This gives
  the combiner, who holds the dealer's MAC keys, an *unconditional*
  per-share authentication layer (~forgery probability 1/q per tag).
- The whole deal is bound to a random 16-byte `session` id, and all
  Fiat-Shamir challenges are domain-separated with the session (see §6.2).

### 2.3 The transcript

```python
{
  "scheme": "unified-v4",
  "session": 16 random bytes,
  "threshold": t, "n": n, "secrets": p (number of packed secrets),
  "commitments": [C_0 .. C_t],
  "proof": {"T", "challenge", "za", "zb", "entries": [...]} or None,
  "mac_tags": {(i,j): tag},            # dealer-epoch only
  "weights": [...]                      # only for deal_weighted
}
```

Everything is public data. `verify_transcript` (unified.py:567) checks
structure, subgroup membership of every commitment, and (if present) every
PoK entry — the transcript is the *certificate* of the deal that any party
can re-check. No polynomial evaluation is published (the v2-era
`digest`/`digest_blinder` fields are gone; see §2.2).

---

## 3. Improvements over plain Shamir — the guarantee stack

Each layer merges a published construction. Plain Shamir gives you: a share
that is information-theoretically secret under ≤ t shares, and nothing else —
no public verification, no detection, no correction, no lifecycle.

### 3.1 Pedersen commitments — public verifiability with IT secrecy (CRYPTO '91)

Feldman's scheme makes shares publicly verifiable but leaks the secret's
order to the dealer-committed group element, and its verification is
*computationally* binding only. Pedersen's two-generator commitment restores
perfect hiding: the commitment `g^a h^b` carries no information about `a`
(one-time-pad by b), while `verify_share` still holds exactly for every valid
share. Share binding is computational (must know log_g h to forge).

### 3.2 Per-coefficient proofs of knowledge — malicious-dealer binding (FROST practice)

Where a single PoK of C_0 leaves the dealer free to *pick* the rest of the
polynomial adversarially and hash it into a transcript it never proved, the
per-coefficient entries (`_coeff_pok_entries`) bind the **whole** committed
polynomial to a dealer who knows its opening:

- one Schnorr entry per index `j` in 0..t: `T = g^{ua} h^{ub}`,
  `challenge = H(coeff-pok domain ‖ session ‖ j ‖ T)`,
  `za = ua + c·a_j`, `zb = ub + c·b_j` (all mod q);
- verified in `_pok_entries_ok` (unified.py:534) as
  `g^{za} h^{zb} == T · C_j^c`, with every T subgroup-checked;
- the Fiat-Shamir challenge is index-bound, so entries cannot be reordered or
  swapped across coefficients; the legacy single-PoK layout still verifies
  (backward-compatibility branch in `verify_transcript`).

`distributed_run` (the DKG, §5.3) reuses the same entries per-dealer, closing
the "dealer only knows what it hashed" gap at setup time too.

### 3.3 Pairwise MACs + CFOR acceptance graph — unconditional detection (STOC '89 / EUROCRYPT '12)

- The dealer-epoch keys give `_mac_ok` an exact per-share test: a forged tag
  succeeds with probability 1/q.
- `_acceptance_set` (unified.py:864) implements the Cevallos–Fehr–Ostrovsky–
  Rabani *iterative acceptance graph*: a share survives only if it is
  certified by t+1 *surviving* players; removing losers repeats until stable.
  This beats the naive majority rule against colluding cheaters (a coalition
  smaller than t+1 cannot keep its forged shares certified).

### 3.4 Berlekamp–Welch — correction, not just detection (McEliece–Sarwate '81)

`combine` (`_recover`, unified.py:920) runs the layered pipeline:

1. commitment-verify every submitted share (drop failures);
2. if MAC keys present, run the CFOR acceptance graph on the survivors;
3. decode with Berlekamp–Welch (corrects up to `floor((n-t-1)/2)` corrupt
   s-values) when some shares fail verification but ≥ t+1 pass;
4. plain Lagrange interpolation on the verified set as the cheap fallback;
5. **commitment screen**: `_screen_against_commitments` re-checks the
   recovered polynomial coefficient by coefficient against the Pedersen
   commitments — wrong secrets and cross-session mixes are rejected at
   combine, not silently returned. The transcript publishes *no* evaluation
   of the secret polynomial (v4 removed the old published digest point).

### 3.5 Session discipline (SLIP-0039 lineage)

- Every transcript carries a fresh random 16-byte session.
- Share *blobs* (seal bundles, §6.1) embed the session; `_decode_blob` rejects
  blobs from any other session, and every recovered polynomial is screened
  against the commitments at both verify and combine time, so a transcript
  from one deal cannot be mixed with shares from another.

### 3.6 What is deliberately NOT merged here

Receiver-private PVSS (each recipient's share encrypted to its public key)
stays in `shamir/pvss.py` — it changes the transcript fundamentally (per-
recipient ciphertexts, no open shares). Hierarchical access structures stay in
`shamir/hierarchical.py` (Birkhoff derivatives, important algorithmically
different sharing). GF(2^8) byte fields live in `shamir/gf256.py`. Speed and
simplicity are not chased inside the unified scheme; it is the
*exponentiation-heavy full-stack* variant by design.

---

## 4. Lifecycle layers — the sharing outlives the dealer

### 4.1 Refresh (`refresh`, unified.py:1749) — Herzberg et al. CRYPTO '95

Every player deals a **zero-constant** Pedersen delta pair (c-poly, m-poly).
Each recipient adds the others' evaluated deltas to its own share; the
commitments multiply coefficientwise for j ≥ 1 but the constant term is
untouched — the secret can't move. Corrupt dealers (nonzero constant) are
detected by checking the received delta `(d, m)` against the posted
commitments (`_eval_refresh_commit`) and the run raises naming the dealer.
Output is a new share with fresh randomness, an updated transcript (same
session), `mac_tags` cleared and `proof` dropped — the dealer-epoch layers
cannot survive a refresh, authenticity moving to the Pedersen (computational)
layer. This is the proactive-security primitive: an old share is useless
against the refreshed one.

### 4.2 Redistribution (`redistribute`, unified.py:1819) — Desmedt–Jarecki CRYPTO '93

Move the sharing to a different `(t', n')`. t+1 verified holders each deal a
new polynomial whose constant term is their own share value; recipients
combine the lambda-weighted evaluations. New commitments are derived *in the
exponent* (`prod C_{i,j}^{λ_i}`) — no secret, and no one learns anyone's
share. The new transcript carries the same session id, so the lineage is
traceable.

### 4.3 Share re-issuance (`derive_share`, unified.py:1173)

Interpolate a fresh, commitment-checkable `(y, s_y, r_y)` at any new
coordinate from t+1 verified shares — a new player joins with no dealer and
no secret exposure (Herzberg recovery adapted to triples).

---

## 5. Threshold crypto and dealer-free setup — never reconstruct

### 5.1 Threshold exponentiation (`recover_exponent`, unified.py:1266) — Desmedt–Frankel CRYPTO '89

`g^{s_i} = C_{x_i} / h^{r_i}` by the public r-binder, then Lagrange-combine in
the exponent. The int secret never appears in memory. This is the base for
the modular arithmetic that follows.

### 5.2 Threshold Schnorr signatures (`threshold_sign`, unified.py:1316)

Sign without reconstructing the key: `R = g^k` (nonce sharing, fresh per
message), `c = H(m ‖ R ‖ Y)`, and each signer contributes
`z_i = λ_i·(k_i + c·x_i)`; `z = Σ z_i = k + c·x` **only because the partials
are Lagrange-weighted — an unweighted sum of shares does not equal the
constant term** (a bug caught and fixed during development, with a
regression test). `verify_signature` is the textbook Schnorr check `g^z ==
R·Y^c` with subgroup checks on R and Y. Protocol rule, documented in code:
*never reuse a nonce sharing* — `z1 - z2 = (c1 - c2)·x` leaks the key.

Every partial is independently verified before it is summed: from the
transcripts, in the exponent only, the signer's public nonce commitment
`R_i = g^k_i` and public key share `Y_i = g^x_i` are recovered, and the
partial passes iff `g^z_i == R_i^λ_i · Y_i^(c·λ_i)`. A wrong partial — or a
replayed one from an earlier message, since `c` binds `(m, R, Y)` — is
computationally detected and attributed to its signer. Submitted partials
are bound to the signer set's challenge, so an invalid one aborts the run
(FROST restart discipline: replace the signer and re-run); `drop_invalid`
only ever drops signers whose *shares* fail transcript verification.

### 5.3 Dealer-free setup (`distributed_run`, unified.py) — Pedersen/GJKR-style DKG, two rounds

Every party deals a random unified polynomial (s + r sides). Round 1
(commit) posts the Pedersen commitments and per-coefficient PoKs (under a
per-dealer session `session + [dealer]`) — no shares yet. Round 2 (reveal)
posts the `(s, r)` share pair for each recipient; every recipient verifies
the pair against the round-1 commitments; complaints, PoK failures, and
reveals that do not match their own commit disqualify the dealer from QUAL.
The group generates:

- shares = sums over QUAL per recipient,
- transcript = summed commitments (a *plain* unified transcript),
- `public_key = recover_exponent(...)` = g^group-secret.

No party ever sees the group secret; the emergent transcript drops straight
into the entire pipeline (combine, refresh, seal, sign, ...). The two-round
commit-then-reveal structure removes the one-round PBS-style last-dealer
bias: a reveal is bound to its round-1 commit, so the last dealer cannot
swap in a polynomial chosen after seeing the other dealers' shares (the
`corrupt_switch` test hook simulates exactly that attempt and every
recipient catches it). An r-side vandal is caught by the commitment check
(the mechanical guarantee).

### 5.4 Linear algebra and multiplication (BGW '88 / Beaver '92)

- Share addition/scaling are free and local (`add_shares`, `mul_share`,
  `linear_shares`, unified.py:1013-1045).
- Transcripts combine in the exponent (`linear_transcript`, unified.py:1046):
  `C'_j = prod C_{t,j}^{c_t}`, digest = same linear combo; the MAC/PoK
  dealer-epoch layers are dropped, authenticity resting on the commitments —
  exactly the refresh discipline.
- `mul_shares` (unified.py:1110) implements Beaver degree-reduction with a
  random triple `([a],[b],[c=a·b])`: open `d = x − a`, `e = y − b`, then
  `[xy] = d[b] + e[a] + [c] + de`. Addition plus this multiplication closes
  arithmetic circuits over the sharing. Honesty framing (documented): the
  single-caller/honest-processor model; per-party ZK of the opened d_i, e_i
  is out of scope.

These are the pieces the composed sharing story is built from: a transcript
for a *linear combination of deals nobody dealt* is derived publicly.

---

## 6. Operational layers

### 6.1 Seal / unseal bundles — misuse resistance (unified.py:2089-2131)

`seal`/`seal_bytes` produce one JSON-serializable dict: the transcript
(hex), session-bound checksummed share blobs for every holder
(`SSSU` magic, version 0x02, 2-byte width, x, session, SHA-256 checksum),
optionally the MAC keys, and — new this session — the **field lock**
(§6.3). `unseal` runs
the whole validation pipeline on the way back: format, transcript public
verification, every blob's checksum + session binding, then the full combine
pipeline with MAC acceptance and the commitment screen. Cross-session mixing,
corrupted blobs and swapped transcripts fail loudly. `secret_kind` (int vs
bytes) is explicit so a bundle cannot be unsealed through the wrong path.

**Versioning note:** the scheme tag and the bundle format are versioned
together. The protocol is `"unified-v4"` (`_SCHEME`, checked by
`verify_transcript`), and the JSON bundle container is also `"unified-v4"`
(`_BUNDLE_FORMAT`, checked by `unseal`/`unseal_bytes`). v4 changed the
Fiat-Shamir challenges of the per-coefficient PoK, the share-holding proofs
and the possession proofs to bind the full commitment vector (the statement),
so both counters moved at once: a v3-era bundle is rejected as an unknown
format rather than failing a confusing proof check.

### 6.2 Domain separation (unified.py:119-124)

Six distinct Fiat-Shamir/derivation domains keep every hash binding to its
role: `pkt pok` (legacy dealer PoK), `coeff-pok` (per-coefficient),
`share-pok` (prove_share), `key` (AEAD key derivation), `aead` (keystream +
HMAC), `threshold-schnorr` (signatures). Every challenge binds the session,
and — since v4 — every PoK challenge also binds the full commitment vector
(the statement), with coefficient challenges additionally binding their
index and signature challenges binding (R, Y).

### 6.3 Field locks (unified.py:2017)

Every seal bundle embeds `p, q, g, h`; `unseal`/`unseal_bytes` reject a
bundle sealed under a different safe prime structurally (not "usually fine").
`_bundle_from` also restored the `weights` field round-trip (a dead-code bug:
an early `return {}` previously cut it).

### 6.4 Cheater identification (`audit` / `audit_public`, unified.py:1692-1723)

`_classify_shares` gives an exact per-share diagnosis (`ok / raw /
bad_index / out_of_range / duplicate / commit / mac`). `audit` additionally
reconstructs and reports the secret with a reason on failure; `audit_public`
never reconstructs — an external auditor pins exactly which shares are
corrupt *without learning the secret* (Tompa–Woll privacy side). And a holder
can prove authenticity of its share without surrendering it:
`prove_share`/`verify_share_proof` (unified.py:652-718) — a FROST-style
Schnorr proof of the Pedersen opening, special-sound and honest-verifier ZK.

### 6.5 Weighted/quota access (`deal_weighted`, unified.py:337)

Virtualisation: one underlying deal with n = Σweights; a participant of
weight w holds w sub-shares; a coalition is authorized iff covered ≥
quota+1. The whole guarantee stack applies unchanged and combine is plain
combine of quota+1 sub-shares. Transcript carries `weights` (which now
survives the bundle round-trip).

### 6.6 Data modes

- `deal_many`/`combine_many` (YCH-2004): p secrets packed into the low
  coefficients of one polynomial, same stack.
- `deal_bytes`/`combine_bytes` (Krawczyk CRYPTO '94 hybrid): a random session
  key K is unified-shared with the full stack; the bytes are encrypted
  (SHAKE256 stream XOR + HMAC tag — the pure-stdlib AEAD stand-in) and the
  ciphertext dispersed into n strided chunks keyed by the share
  x-coordinates. Reconstruction needs t+1 shares *and* all chunks.
- `batch_verify` (BGR '98): the *small exponents test*. Each share gets a
  fresh 128-bit weight d_i and the check is
  `g^{Σ d_i s_i} h^{Σ d_i r_i} == prod C_j^{Σ d_i x_i^j}`, O(n+t) work
  instead of O(nt). The weights are load-bearing: the unweighted sum is a
  checksum that accepts two errors which cancel.

---

## 7. Improvements vs plain Shamir — scorecard and honesty

**Wins (with the honest cost attached):**

| Axis | Plain Shamir | Unified scheme |
|---|---|---|
| Passive secrecy | IT, ≤ t shares | IT, ≤ t shares (Pedersen masking, Z_q-uniform — exact) |
| Share verification | none | public, computational (DLP) per share; batchable |
| Malicious dealer | undetectable | commitments + per-coefficient PoK + public transcript |
| Corrupt holders | silent garbage | detection: IT with MAC keys, computational without; correction: BW; identification: audit |
| Cross-session mixing | silent garbage | session binding + commitment screen rejects |
| Lifecycle | re-deal | refresh / redistribute / join, dealer-free |
| Setup | dealer needed | dealer-free DKG (`distributed_run`) |
| Use of the secret, secret kept private | reconstruct | exponentiate, sign, add, multiply shares — never materialise |
| Misuse resistance | none | field-locked, checksummed, session-bound bundles |
| Holder authentication | none | ZK proof of holding a valid share |
| Asset size | t+1 field elements | triples + commitments + transcript (2x+ share size) |

**Not claimed (definitional rows):** receiver privacy (PVSS sibling),
operation speed and implementation simplicity (this is the
exponentiation-heavy full-stack variant).

**Security-picture corrections made during development** (recorded for
posterity in CONTEXT.md/SECURITY.md): the simulation no longer suffers any
mod-p-vs-mod-q response bias — because `share_field()` is `GF(q)`, HVZK holds
*exactly*, identically distributed, no statistical gap.

The scorecard vs the full SSS derivative zoo admits: *more secure* on
corruption and dealer axes (weaker on assumption hygiene — DLP + ROM added);
*more decentralized* across the lifecycle (initial deal still needs one
dealer or a distributed run); *more fault-proof* within the modeled faults;
*fool-proof* genuinely improved; *trustless* reduced but **not zero** (honest
dealer or honest quorum, plus DLP).

---

## 8. Assumptions (the honest "ifs")

Tagged as in SECURITY.md: `[IT]` information-theoretic, `[COMP]`
computational, `[STANDARD]` textbook result.

**Forced — present in any scheme, not defects:**

1. **An honest party exists** — an honest dealer at deal time, or an honest
   quorum during `distributed_run`. A secret must be held honestly somewhere.
2. **Random oracle (Fiat-Shamir)** — every non-interactive proof uses it;
   same assumption as FROST/EdDSA/ECDSA. Removing it requires interactive
   protocols.
3. **Computational binding (DLP)** — public verification of commitments is
   computational; information-theoretic binding with public verification is
   impossible. All share/commitment binding rows are `[COMP]` on the
   2048-bit safe prime (log_g h unknown, h hashed into the subgroup).
4. **Cost rows** — 2x share size and exponentiation-heavy verification are
   the deliberate price.

**Removed or tightened during the rewrite:**

- Response sampling uniform over Z_q (share field == subgroup order) ⇒ HVZK
  exact, no leftover statistical gap;
- every proof T, every signature R/Y subgroup-checked ⇒ verification
  equations never leave the group where the arguments hold;
- bundles field-locked ⇒ wrong-modulus unseal rejected structurally;
- outing setup can be dealer-free, and signing never reconstructs the key.

**Explicit non-claims (SECURITY.md §4):** no formal theorem for the *composed*
scheme (each layer's property is standard; a joined proof is not written);
nonce reuse defeats `threshold_sign` (protocol rule instead); dealer-epoch
MACs do not survive refresh/redistribution/linear composition (authenticity
then rests on the computational commitments); no external audit, no
conformance tests, no constant-time engineering.

---

## 9. Implementation map (file:line in `shamir/unified.py`)

| Piece | Where |
|---|---|
| Deal core (s/r poly, commitments, PoK, MACs) | `_deal` :249 |
| Single / multi / weighted deal | :316 / :327 / :337 |
| Dealer-free DKG (two-round commit-then-reveal) | `_dkg_commit_round` :369 / `_dkg_reveal_round` :397 / `distributed_run` :483 |
| Per-coefficient PoK gen / verify | `_coeff_pok_entries` :225 / `_pok_entries_ok` :534 |
| Transcript / share public verification | :567 / :626 |
| Holder ZK proof | `prove_share` :652 / `verify_share_proof` :685 |
| Audit (challenge/holders) | `audit_challenge` :719 / `audit_holders` :828 / `audit` :1692 / `audit_public` :1723 |
| Combine pipeline (CFOR → BW → commitment screen) | `_recover` :920; CFOR filter `_acceptance_set` :864 |
| Linear layer + transcript-in-exponent | `mul_share` :989 / `linear_shares` :1013 / `linear_transcript` :1046; `mul_shares` :1110 |
| Re-issue / rejoin / exponent recovery | :1173 / :1210 / :1266 |
| Threshold Schnorr sign / verify | :1316 / :1471 |
| Batch verify (BGR) | `batch_verify` :1486 |
| Bytes mode (Krawczyk + stdlib AEAD) | `seal_bytes` :2133 / `unseal_bytes` :2156 |
| Refresh / redistribute | :1749 / :1819 |
| Bundle encode/decode, field lock | `_bundle_from` :2036 / `_field_lock` :2017 |
| Seal / unseal / bytes variants | :2089 / :2107 / :2133 |
| Field, safe prime, generators | `shamir/gf.py` (h-heavy) |

Status: `python tests/test_all.py` → 110/110 passing, including the property
fuzz (`test_unified_property_fuzz`), corruption tests, threshold-sign
regression tests (partial verification + replay rejection), the two-round
DKG commit/reveal tests, the protocol-shaped recovery lifecycle test,
multi-secret `change_threshold`, weighted-refresh weight preservation, the
seeded deterministic-replay test (pinning `session_id`: the session is the
only nondeterminism in the pipeline — everything else replays bit-for-bit
under a fixed seed), and production-field seal/unseal
(`test_unified_seal_on_production_field`). No lint/typecheck tooling
configured — verification is `py_compile` + the test runner.

---

## 10. Auditor layer (added for the Guardian Protocol auditor node)

`prove_share` is replayable by construction: its Fiat-Shamir challenge binds
only `(session, x, T)`, so a single proof answers every future audit and any
observer can replay it. `GUARDIAN_ROTATION_DESIGN.md` lists replayed
challenges as an explicit attack, so sampled possession gets its own
primitive:

| Call | Role |
|---|---|
| `audit_challenge(transcript, x, epoch)` | auditor mints a single-use 32-byte nonce bound to session, slot and epoch |
| `prove_possession(share, transcript, challenge)` | holder answers with a Schnorr proof of the Pedersen opening; the challenge hash binds the nonce and epoch |
| `verify_possession(proof, transcript, challenge)` | auditor checks it; a proof for any other nonce, epoch, slot or session fails |
| `audit_holders(transcript, challenges, responses)` | one sampling round, returning `held` / `invalid` / `missing` per slot |

Properties, matching R15 and the slashing boundary in the guardian design:

- **Trustless.** The auditor needs only the public transcript. It holds no
  share, no MAC key and no secret, and it cannot authorize anything.
- **Knowledgeless.** The proof is honest-verifier zero knowledge and exactly
  distributed (responses live in Z_q), so a full round teaches the auditor
  only which slots answered correctly.
- **Fresh.** A stored proof is useless against the next challenge, so a valid
  response is evidence of possession *at that challenge*, not in general.
- **Evidence semantics.** `invalid` means a response was given and failed to
  verify, which is an attributable cryptographic fault. `missing` is
  operational evidence only, because the network may be at fault; the
  guardian design is explicit that absence is not proof of loss.
