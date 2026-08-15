"""The unified scheme v4 (U-SSS): one construction absorbing the SSS lineage.

A single (t+1)-of-n construction over a safe-prime field that synthesizes the
independent improvements to plain Shamir (1979) secret sharing:

* Pedersen (CRYPTO 1991) commitments C_j = g^{a_j} h^{b_j}: shares are
  (x, s_i, r_i) pairs, every share is *publicly* verifiable via
  g^{s_i} h^{r_i} == prod_j C_j^{x^j}, and the secret stays
  information-theoretically hidden by the random masking polynomial R.
* Schnorr proofs of knowledge of the opening of EVERY commitment (FROST /
  Schoenmakers-PVSS practice): the deal is bound to a dealer who knows the
  whole committed polynomial -- commitments cannot be replayed or swapped
  in from another context, and an extractor can always open; verified
  publicly (per-coefficient entries; every Fiat-Shamir challenge binds the
  full statement, i.e. the commitment vector, so a proof minted against one
  transcript cannot verify against another).
* Rabin & Ben-Or (STOC 1989) pairwise MACs with the Cevallos-Fehr-Ostrovsky-
  Rabani (EUROCRYPT 2012) iterative acceptance-graph filter: when a combiner
  holds the dealer's keys, shares are accepted only if certified by t+1
  *accepted* holders, giving information-theoretic forgery detection that
  survives collusion better than the plain majority rule.
* McEliece & Sarwate (CACM 1981): reconstruction decodes the s-values with
  Berlekamp-Welch when not every share passes verification, correcting
  residual corruption instead of only detecting it.
* Reconstruction screen: the recovered polynomial is checked coefficient by
  coefficient against the commitments (g^{a_j} h^{b_j} == C_j), so a wrong
  secret or a cross-session mix is rejected at combine time.  No evaluation
  of the secret polynomial is ever published.
* Herzberg, Jarecki, Krawczyk & Yung (CRYPTO 1995): shares refresh in place
  with zero-constant Pedersen deltas and updated commitments, no
  dealer and no change to the secret.
* Desmedt & Jarecki (CRYPTO 1993): the sharing redistributes to a new
  (t', n') parameter set with new commitments derived in the exponent.
* Yang, Chang & Hwang (2004): several secrets are packed into the low
  coefficients of one polynomial (deal_many / combine_many).
* Krawczyk (CRYPTO 1994): byte / large secrets -- a random session key is
  unified-shared with the full guarantee stack, the secret is encrypted under
  it (SHAKE256 stream + HMAC tag, the pure-stdlib stand-in for AES-GCM) and
  the ciphertext scattered with an information dispersal scheme
  (deal_bytes / combine_bytes).
* Tompa & Woll (1988) / Pieprzyk & Zhang: `audit` identifies exactly which
  submitted shares are corrupted, using the commitments and, if keys are
  supplied, the pairwise MACs.
* Session discipline from shamir.format: every transcript carries a random
  16-byte session id; cross-session mixing is rejected by the screen.
* Ben-Or, Goldwasser & Wigderson (STOC 1988): Shamir sharing is linear --
  addition gates are free.  Holder i sums the counterpart shares of several
  deals locally (add_shares / mul_share / linear_shares) and the transcript
  of the combined secret is derived purely in the exponent
  (linear_transcript): no dealer, no secret ever materialised.  This is the
  linear algebra that underpins MPC-style composed sharing.
* Bellare, Garay & Rabin (EUROCRYPT 1998): batch_verify checks every share
  against the commitments in a single aggregate exponentiation
  (g^{sum s} h^{sum r} == prod_j C_j^{sum_i x_i^j}), O(n + t) work instead of
  O(n t), sound up to log_g h being unknown.
* Share re-issuance (Herzberg et al. 1995 recovery adapted): derive_share
  interpolates a fresh, commitment-verifiable (y, s_y, r_y) holding at a new
  coordinate from any threshold+1 verified shares -- a new player joins with
  no dealer and no secret exposure.
* seal / unseal (and seal_bytes / unseal_bytes): a portable, JSON-serializable
  bundle that carries the transcript, session-bound checksummed share blobs
  and (optionally) the MAC keys.  unseal runs the entire validation pipeline
  end-to-end, so mixed sessions, corrupted blobs or swapped transcripts fail
  loudly instead of silently.
* Desmedt & Frankel (CRYPTO 1989): recover_exponent computes g^{secret} from
  the verified shares themselves (g^{s_i} = C_{x_i}/h^{r_i}, then Lagrange
  combine in the exponent), never materialising the int secret -- the
  threshold-crypto building block for ElGamal / ECDSA / BLS style systems.
* Beaver (1992) / BGW (1988): mul_shares cancels a random sharing triple
  ([a], [b], [c=a*b]) to multiply two unified sharings with degree
  reduction, closing the arithmetic circuit: local addition (free) plus
  interactive multiplication over the same Pedersen-backed shares is
  enough to evaluate any arithmetic circuit on shared values.
* Schnorr-style zero-knowledge proofs of share holdings (FROST 2020
  practice, building on Schnorr 1991): prove_share / verify_share_proof let
  a holder prove knowledge of the Pedersen opening of its committed
  polynomial point -- "I hold a valid share of this deal" -- to an auditor
  or combiner who never learns (s, r).  Same sigma-protocol machinery as
  the dealer PoK, specialised to shares: special-sound and honest-verifier
  ZK, bound to the transcript session.
* audit_public: Tompa-Woll (1988) cheater identification that never
  reconstructs -- an external auditor pins exactly which shares are
  corrupted without ever learning the secret, the privacy side of the
  detection story (full audit additionally reports the recovered secret).
* Shamir (1979) III virtualisation: deal_weighted realizes weighted/quota
  threshold access structures with full-stack guarantees -- one underlying
  deal with n = sum(weights), a participant of weight w holding w
  sub-shares, authorized iff covered sub-shares >= quota + 1; nothing else
  in the pipeline changes.
* Pedersen (CRYPTO 1991) / GJKR-style dealer-free setup: distributed_run is
  DKG for the unified scheme -- every party deals a random unified
  polynomial and posts commitments + per-coefficient PoKs; verified
  shares and commitments sum over QUAL; no
  party ever sees the group secret, and the emergent transcript is a plain
  unified transcript that feeds the entire pipeline unchanged.

Costs (honest trade-offs): shares are triples (two field elements) plus a
dealer-held MAC table; the field must be a safe prime with two subgroup
generators g, h (shamir.gf.default_field); the MAC layer and the PoK are
dealer-epoch only -- after a refresh, redistribution, linear composition or
dealer-free distributed setup, authenticity rests on the Pedersen
commitments (computational binding).
Orthogonal axes of the literature are deliberately *not* merged into this one
variant, and are provided by sibling modules instead: hierarchy by Birkhoff
derivatives (shamir.hierarchical, now with Feldman commitments for public
share verification), general or ramp secrecy/efficiency trade-offs,
recipient-encrypted PVSS distribution (shamir.pvss), and the GF(2^8) byte
field (shamir.gf256).
"""

import hashlib
import hmac
import secrets

from . import core, robust
from .format import session_id

_SCHEME = "unified-v4"
_DIGEST_INDEX = 254  # same digest point as shamir.format.DIGEST_POINT_X
_POK_DOMAIN = b"sssx unified pok v1"
_COEFF_POK_DOMAIN = b"sssx unified coeff-pok v1"
_SHARE_POK_DOMAIN = b"sssx unified share-pok v1"
_KEY_DOMAIN = b"sssx unified key v1"
_AEAD_DOMAIN = b"sssx unified aead v1"
_AUDIT_DOMAIN = b"sssx unified audit-possession v1"
BATCH_WEIGHT_BITS = 128
AUDIT_NONCE_LEN = 32
_NONCE_LEN = 16
_TAG_LEN = 32
_KEY_LEN = 32
_BLOCK = 64
_BUNDLE_FORMAT = "unified-v4"
_BLOB_MAGIC = b"SSSU"
_BLOB_VERSION = 0x02
_BLOB_CHECKSUM_LEN = 8


def _arith(field):
    return core.field_for(field).share_field()


def _commit_field(field):
    f = core.field_for(field)
    if f.g is None or f.h is None or f.q is None:
        raise ValueError("unified scheme needs a field with generators g, h"
                         " and order q; use shamir.gf.default_field()")
    return f


def _group_width(field):
    return (field.p.bit_length() + 7) // 8


def _check_params(threshold, n):
    if not (1 <= threshold < n <= 253):
        raise ValueError("require 1 <= threshold < n <= 253 (254 is the"
                         " digest point)")


def _eval_refresh_commit(comm, x, cf):
    """prod_l C_l^{x^(l+1)} for refresh commitments [C_1..C_t].

    Refresh commitments omit the constant term (dealt as 1, since the delta
    has zero constant), so eval_commit's 0-based indexing does not apply.
    """
    acc = 1
    xpow = x % cf.q
    for c in comm:
        acc = (acc * pow(c, xpow, cf.p)) % cf.p
        xpow = (xpow * x) % cf.q
    return acc


def _monomial(points, field):
    """Monomial coefficients [a_0..a_m] of the poly through `points` (Newton)."""
    xs = [x for x, _ in points]
    ys = [y for _, y in points]
    m = len(xs) - 1
    table = list(ys)
    dds = [table[0]]
    for k in range(1, m + 1):
        for i in range(m, k - 1, -1):
            table[i] = field.div(field.sub(table[i], table[i - 1]),
                                 field.sub(xs[i], xs[i - k]))
        dds.append(table[k])
    poly = [dds[m]]
    for k in range(m - 1, -1, -1):
        out = [0] * (len(poly) + 1)
        for i, c in enumerate(poly):
            out[i] = field.sub(out[i], field.mul(c, xs[k]))
            out[i + 1] = field.add(out[i + 1], c)
        out[0] = field.add(out[0], dds[k])
        poly = out
    return poly


def _challenge_pok(session, n, threshold, commitments, t_val, cf):
    w = _group_width(cf)
    data = bytearray(_POK_DOMAIN + session)
    data += n.to_bytes(2, "big") + threshold.to_bytes(2, "big")
    for c in commitments:
        data += c.to_bytes(w, "big")
    data += t_val.to_bytes(w, "big")
    return int.from_bytes(hashlib.sha256(bytes(data)).digest(), "big") % cf.q


def _challenge_coeff(session, j, commitments, t_val, cf):
    """Challenge for the per-coefficient PoK of s_poly[j].

    Binds the full statement (all commitments) as well as the session, the
    coefficient index and the first message T.  Legacy `_challenge_pok`
    already bound the commitments; the per-coefficient variant did not, so a
    proof minted against one triple was re-verifiable against any other
    triple with the same session/index/T.  Fiat-Shamir challenges must bind
    the statement: this closes the concurrency-style transcript-swap gap.
    """
    w = _group_width(cf)
    data = bytearray(_COEFF_POK_DOMAIN + session + j.to_bytes(2, "big"))
    for c in commitments:
        data += c.to_bytes(w, "big")
    data += t_val.to_bytes(w, "big")
    return int.from_bytes(hashlib.sha256(bytes(data)).digest(), "big") % cf.q


def _coeff_pok_entries(s_poly, r_poly, commitments, session, draw, f, qf):
    """Schnorr proof of knowledge of the opening of every commitment.

    One entry per coefficient: proves knowledge of (s_poly[j], r_poly[j])
    opening C_j = g^a h^b, binding the dealer to a polynomial it provably
    knows rather than to constants it merely hashes (malicious-dealer
    binding; also closes the Fiat-Shamir extraction gap when the dealer is
    the only party who could ever compute with the secret).
    """
    entries = []
    for j, (a, b) in enumerate(zip(s_poly, r_poly)):
        ua, ub = draw(), draw()
        t_val = f.commit_double(ua, ub)
        ch = _challenge_coeff(session, j, commitments, t_val, f)
        entries.append({
            "index": j,
            "T": t_val,
            "challenge": ch,
            "za": (ua + ch * a) % qf.p,
            "zb": (ub + ch * b) % qf.p,
        })
    return entries


def _deal(coefficients, threshold, n, field=None, randfunc=None):
    """Shared core of deal / deal_many; `coefficients` are the low order
    coefficients of the share polynomial (1 <= len <= threshold)."""
    f = _commit_field(field)
    qf = _arith(field)
    _check_params(threshold, n)
    nsecrets = len(coefficients)
    if nsecrets < 1 or nsecrets > threshold:
        raise ValueError("need 1 <= len(coefficients) <= threshold, got %s"
                         % nsecrets)
    if not all(0 <= s < qf.p for s in coefficients):
        raise ValueError("secret outside [0, q)")
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))

    def _draw():
        return rand() % qf.p

    for _ in range(100):
        s_poly = ([s % qf.p for s in coefficients]
                  + [_draw() for _ in range(threshold + 1 - nsecrets)])
        r_poly = [_draw() for _ in range(threshold + 1)]
        shares = [(x, qf.polynomial_eval(s_poly, x),
                   qf.polynomial_eval(r_poly, x)) for x in range(1, n + 1)]
        if all(s != 0 and r != 0 for _, s, r in shares):
            break
    else:
        raise ValueError("could not draw polynomials with all-nonzero shares")

    commitments = [f.commit_double(a, b) for a, b in zip(s_poly, r_poly)]

    ua, ub = _draw(), _draw()
    t_val = f.commit_double(ua, ub)
    session = session_id()
    ch = _challenge_pok(session, n, threshold, commitments, t_val, f)
    proof = {
        "T": t_val,
        "challenge": ch,
        "za": (ua + ch * s_poly[0]) % qf.p,
        "zb": (ub + ch * r_poly[0]) % qf.p,
        "entries": _coeff_pok_entries(s_poly, r_poly, commitments, session,
                                      _draw, f, qf),
    }

    keys = {}
    tags = {}
    for i in range(1, n + 1):
        si = next(s for x, s, _ in shares if x == i)
        for j in range(1, n + 1):
            if i == j:
                continue
            a, b = _draw(), _draw()
            keys[(i, j)] = (a, b)
            tags[(i, j)] = qf.add(qf.mul(a, si), b)

    transcript = {
        "scheme": _SCHEME,
        "session": session,
        "threshold": threshold,
        "n": n,
        "secrets": nsecrets,
        "commitments": commitments,
        "proof": proof,
        "mac_tags": tags,
    }
    return shares, keys, transcript


def deal(secret, threshold, n, field=None, randfunc=None):
    """Deal the unified sharing of a single secret.

    Returns (shares, mac_keys, transcript): shares are [(x, s_i, r_i)] with
    P(0) == secret; mac_keys are the dealer-epoch Rabin-Ben-Or keys (the
    corresponding tags are public in transcript['mac_tags']); transcript is
    the publicly checkable deal (commitments, PoK, session).
    """
    return _deal([secret], threshold, n, field, randfunc)


def deal_many(secrets, threshold, n, field=None, randfunc=None):
    """Yang-Chang-Hwang (2004) merge: p = len(secrets) secrets in one deal.

    The secrets are packed into the low coefficients of the share polynomial;
    the full unified guarantee stack (commitments, MACs, digest, Poisson
    correction) applies unchanged.  combine_many recovers all of them.
    """
    return _deal(list(secrets), threshold, n, field, randfunc)


def deal_weighted(secret, weights, quota, field=None, randfunc=None):
    """Weighted unified sharing by virtualisation (Shamir 1979, III; quota
    systems equivalent to weighted threshold access structures).

    A participant of weight w holds w sub-shares at w distinct x coordinates
    assembled in one (x, s, r) group; a coalition is authorized iff the sum
    of its weights covers quota + 1 sub-shares.  Exactly one underlying deal
    with n = sum(weights) is produced, so the entire guarantee stack
    (commitments, per-coefficient PoK, MAC tags, digest screen, Poisson
    correction) applies unchanged and combine is plain unified combine of
    quota + 1 sub-shares.

    Returns (groups, mac_keys, transcript) with groups = {participant_index:
    [(x, s, r), ...]}, participant_index in 0..len(weights)-1.
    """
    weights = list(weights)
    if not weights or any(not isinstance(w, int) or w < 1 for w in weights):
        raise ValueError("weights must be positive ints")
    m = sum(weights)
    if m > 253:
        raise ValueError("total weight cannot exceed 253")
    shares, keys, transcript = _deal([secret], quota, m, field, randfunc)
    groups = {}
    start = 0
    for p, w in enumerate(weights):
        groups[p] = shares[start:start + w]
        start += w
    transcript = dict(transcript)
    transcript["weights"] = list(weights)
    return groups, keys, transcript


def _dkg_commit_round(n, threshold, session, f, qf, draw):
    """DKG round 1 (commit): every dealer posts commitments + PoKs.

    Returns (public, private).  `public` holds only public data -- the
    Pedersen commitments, the per-coefficient PoK (per-dealer session) --
    and is the round-1 broadcast; `private` holds each dealer's
    (s_poly, r_poly) for the reveal round.  Round-1 output must exist before
    any share does: the last dealer to speak has seen only hiding
    commitments, so it cannot bias the group secret (the one-round PBS
    last-dealer bias needs the other dealers' *shares*, which do not exist
    yet).
    """
    public = {}
    private = {}
    for dealer in range(1, n + 1):
        dealer_session = session + bytes([dealer])
        s_poly = [draw() for _ in range(threshold + 1)]
        r_poly = [draw() for _ in range(threshold + 1)]
        commitments = [f.commit_double(a, b) for a, b in
                       zip(s_poly, r_poly)]
        pok = {"entries": _coeff_pok_entries(s_poly, r_poly, commitments,
                                             dealer_session, draw, f, qf)}
        public[dealer] = {"commitments": commitments, "pok": pok,
                          "session": dealer_session}
        private[dealer] = (s_poly, r_poly)
    return public, private


def _dkg_reveal_round(public, private, threshold, n, session, f, qf, draw,
                      corrupt=(), corrupt_r=(), corrupt_switch=()):
    """DKG round 2 (reveal): dealers post share pairs, recipients verify.

    Every revealed (s, r) pair is checked against the *round-1* commitments
    (f.eval_commit): a dealer whose reveal does not match its commit is
    disqualified, with a complaint from every affected recipient.  The PoKs
    are re-verified against the round-1 broadcasts.

    corrupt:        dealer indices that hand a wrong s share to one
                    recipient (frameable, mirrors dkg_run)
    corrupt_r:      dealer indices that hand a wrong r value to one recipient
    corrupt_switch: dealer indices that commit a valid polynomial in round 1
                    but reveal a *different* one in round 2 -- the
                    late-adaptive swap the commit-binding check exists for;
                    caught on every recipient.
    """
    recipients = {r: {} for r in range(1, n + 1)}
    complaints = []
    for dealer, (s_poly, r_poly) in private.items():
        commitments = public[dealer]["commitments"]
        if dealer in corrupt_switch:
            s_poly = [draw() for _ in range(threshold + 1)]
            r_poly = [draw() for _ in range(threshold + 1)]
        for recipient in range(1, n + 1):
            s = qf.polynomial_eval(s_poly, recipient)
            r = qf.polynomial_eval(r_poly, recipient)
            if dealer in corrupt and recipient == (dealer % n) + 1:
                s = qf.add(s, 1)
            if dealer in corrupt_r and recipient == (dealer % n) + 1:
                r = qf.add(r, 1)
            recipients[recipient][dealer] = (s, r)
            if f.commit_double(s, r) != f.eval_commit(commitments, recipient):
                complaints.append((dealer, recipient))

    pok_failures = []
    for dealer, pub in public.items():
        if not _pok_entries_ok(pub["pok"]["entries"], pub["commitments"],
                               pub["session"], threshold, f):
            pok_failures.append(dealer)

    disqualified = {d for d, _ in complaints} | set(pok_failures)
    qual = sorted(set(range(1, n + 1)) - disqualified)

    shares = {}
    acc_s = [0] * (threshold + 1)
    acc_r = [0] * (threshold + 1)
    for dealer in qual:
        s_poly, r_poly = private[dealer]
        for j in range(threshold + 1):
            acc_s[j] = qf.add(acc_s[j], s_poly[j])
            acc_r[j] = qf.add(acc_r[j], r_poly[j])
    for recipient in range(1, n + 1):
        s = 0
        r = 0
        for dealer in qual:
            s = qf.add(s, recipients[recipient][dealer][0])
            r = qf.add(r, recipients[recipient][dealer][1])
        shares[recipient] = (s, r)

    commitments = [f.commit_double(acc_s[j], acc_r[j])
                   for j in range(threshold + 1)]
    transcript = {
        "scheme": _SCHEME,
        "session": session,
        "threshold": threshold,
        "n": n,
        "secrets": 1,
        "commitments": commitments,
        "proof": None,
        "mac_tags": {},
    }
    sample = [(r, s, rv) for r, (s, rv) in shares.items()][:threshold + 1]
    public_key = recover_exponent(transcript, sample, f)
    return {
        "shares": shares,
        "transcript": transcript,
        "public_key": public_key,
        "qual": qual,
        "commitments_all": {d: public[d]["commitments"] for d in public},
        "poks": {d: public[d]["pok"] for d in public},
        "complaints": complaints,
        "pok_failures": pok_failures,
    }


def distributed_run(n, threshold, field=None, randfunc=None, corrupt=(),
                    corrupt_r=(), corrupt_switch=()):
    """Dealer-free setup for the unified scheme: Pedersen DKG, two rounds.

    Round 1 (commit): every party i = 1..n deals a random unified polynomial
    (s-side and r-side masking) and broadcasts its Pedersen commitments
    together with a per-coefficient Schnorr proof of knowledge (per-dealer
    session) -- no shares yet.  Round 2 (reveal): every party posts the
    (s, r) share pair for each recipient; each recipient verifies the pair
    against the round-1 commitments (complaint on failure) and re-checks the
    PoKs.  Disqualified dealers -- any verified complaint or failed proof --
    leave QUAL.  The group polynomial is the SUM of the QUAL polynomials:
    the group secret P(0) is never materialised anywhere.

    The two-round structure removes the one-round PBS-style last-dealer
    bias: a dealer's reveal is bound to its round-1 commitments, so the
    last dealer to speak cannot substitute a polynomial chosen after seeing
    the other dealers' shares (`corrupt_switch` simulates exactly that
    attempt, and every recipient catches it).

    The returned transcript is a plain unified transcript (session-bound,
    commitments, proofs/mac_tags = None/{}) and drops
    straight into the whole pipeline: combine, batch_verify, recover_exponent,
    refresh, redistribute, seal, ...

    corrupt:        dealer indices that hand a wrong s share to one recipient
                    (frameable, mirrors dkg_run)
    corrupt_r:      dealer indices that hand a wrong r value to one recipient
    corrupt_switch: dealer indices that commit a valid polynomial in round 1
                    but reveal a different one in round 2 (caught on every
                    recipient by the commit-binding check)

    Returns a dict with keys: shares ({recipient_index: (s, r)}), transcript,
    public_key (g^group-secret, exponent-recovered from the transcript),
    qual, commitments_all ({dealer: commitments}), poks, complaints,
    pok_failures.
    """
    f = _commit_field(field)
    qf = _arith(field)
    _check_params(threshold, n)
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))

    def _draw():
        return rand() % qf.p

    session = session_id()
    public, private = _dkg_commit_round(n, threshold, session, f, qf, _draw)
    return _dkg_reveal_round(public, private, threshold, n, session, f, qf,
                             _draw, corrupt, corrupt_r, corrupt_switch)


def _pok_entries_ok(entries, commitments, session, threshold, f):
    """Verify a per-coefficient PoK entry list against the commitments.

    Every commitment and every T value is checked to lie in the order-q
    subgroup, so the verification equations live entirely in the subgroup
    where the sigma-protocol soundness argument applies.
    """
    if len(entries) != threshold + 1:
        return False
    for entry in entries:
        if entry["index"] < 0 or entry["index"] > threshold:
            return False
        t2 = entry["T"]
        try:
            f._check_subgroup(t2)
        except ValueError:
            return False
        c2 = _challenge_coeff(session, entry["index"], commitments, t2, f)
        if entry["challenge"] != c2:
            return False
        if f.commit_double(entry["za"], entry["zb"]) != \
                f.mul(t2, f.pow(commitments[entry["index"]], c2)):
            return False
    return True


def _verify_transcript_entries(proof, commitments, session, threshold, f):
    if "entries" in proof:
        return _pok_entries_ok(proof["entries"], commitments, session,
                               threshold, f)
    return None


def verify_transcript(transcript, field=None):
    """Publicly check the whole transcript; returns bool, never raises.

    Verifies structure, subgroup membership of every commitment, the
    digest pair against the commitments, and, when present, the Schnorr proof
    of knowledge of the opening of C_0.  Refreshed/redistributed transcripts
    carry proof=None and empty mac_tags (those layers are dealer-epoch only).
    """
    f = _commit_field(field)
    qf = _arith(field)
    try:
        if transcript["scheme"] != _SCHEME:
            return False
        threshold = transcript["threshold"]
        n = transcript["n"]
        nsecrets = transcript["secrets"]
        if not (1 <= threshold < n):
            return False
        if not (1 <= nsecrets <= threshold):
            return False
        commitments = transcript["commitments"]
        if len(commitments) != threshold + 1:
            return False
        for c in commitments:
            f._check_subgroup(c)
        proof = transcript["proof"]
        if proof is not None:
            session = transcript["session"]
            res = _verify_transcript_entries(proof, commitments, session,
                                             threshold, f)
            if res is True:
                pass
            elif res is False:
                return False
            else:
                try:
                    f._check_subgroup(proof["T"])
                except ValueError:
                    return False
                ch = _challenge_pok(session, n, threshold,
                                    commitments, proof["T"], f)
                if proof["challenge"] != ch:
                    return False
                if f.commit_double(proof["za"], proof["zb"]) != \
                        f.mul(proof["T"], f.pow(commitments[0], ch)):
                    return False
        tags = transcript["mac_tags"]
        if tags:
            expected = {(i, j) for i in range(1, n + 1)
                        for j in range(1, n + 1) if i != j}
            if set(tags) != expected:
                return False
            if not all(0 <= v < qf.p for v in tags.values()):
                return False
        return True
    except (ValueError, TypeError, KeyError):
        return False


def verify_share(share, transcript, field=None):
    """Public Pedersen check of one (x, s, r) share against the transcript."""
    f = _commit_field(field)
    qf = _arith(field)
    try:
        x, s, r = share
        if not (1 <= x <= 253):
            return False
        if not (0 <= s < qf.p and 0 <= r < qf.p):
            return False
        return f.commit_double(s, r) == f.eval_commit(
            transcript["commitments"], x)
    except (ValueError, TypeError, KeyError):
        return False


def _challenge_share(transcript, x, t_val, cf):
    w = _group_width(cf)
    data = bytearray(_SHARE_POK_DOMAIN + transcript["session"])
    data += x.to_bytes(2, "big")
    for c in transcript["commitments"]:
        data += c.to_bytes(w, "big")
    data += t_val.to_bytes(w, "big")
    return int.from_bytes(hashlib.sha256(bytes(data)).digest(), "big") % cf.q


def prove_share(share, transcript, field=None, randfunc=None):
    """Non-interactive (Fiat-Shamir) ZK proof that `share` opens to the
    committed polynomial at x -- without revealing (s, r).

    The relation proved is knowledge of (s, r) with g^s h^r ==
    eval_commit(commitments, x): the holder shows "I am a legitimate holder
    of a valid share of this deal" to an auditor or combiner who must NOT
    learn the share.  This is the FROST-style Schnorr proof of a Pedersen
    opening, bound to the transcript's session; it is special-sound
    (knowledge extraction) and honest-verifier zero knowledge.  Returns a
    small dict {x, T, c, za, zb}; the verifier checks it with
    verify_share_proof.  Nothing secret leaves this function.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    x, s, r = share
    if not (1 <= x <= 253):
        raise ValueError("share index must be in 1..253")
    if not (0 <= s < qf.p and 0 <= r < qf.p):
        raise ValueError("share outside Z_q")
    if not verify_share(share, transcript, f):
        raise ValueError("share does not match the transcript")
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))
    ua, ub = rand() % qf.p, rand() % qf.p
    t_val = f.commit_double(ua, ub)
    c_val = _challenge_share(transcript, x, t_val, f)
    return {"x": x, "T": t_val, "c": c_val,
            "za": (ua + c_val * s) % qf.p,
            "zb": (ub + c_val * r) % qf.p}


def verify_share_proof(proof, transcript, field=None):
    """Verify a prove_share proof against the transcript's committed poly.

    Recomputes C_x from the transcript and checks g^{za} h^{zb} == T * C_x^c
    using a freshly hashed (session-, x-, T-bound) challenge.  Returns bool,
    never raises.  Inverse of prove_share; exists so a share is provable
    without the holder surrendering it.
    """
    f = _commit_field(field)
    qf = _arith(field)
    try:
        if not verify_transcript(transcript, f):
            return False
        x = proof["x"]
        if not (1 <= x <= 253):
            return False
        t_val = proof["T"]
        f._check_subgroup(t_val)
        c_val = _challenge_share(transcript, x, t_val, f)
        if c_val != proof["c"]:
            return False
        za, zb = proof["za"], proof["zb"]
        if not (0 <= za < qf.p and 0 <= zb < qf.p):
            return False
        cx = f.eval_commit(transcript["commitments"], x)
        return f.commit_double(za, zb) == (t_val * pow(cx, c_val, f.p)) % f.p
    except (ValueError, TypeError, KeyError):
        return False


# --------------------------------------------------------------------------
# Auditor layer: sampled proof of possession, fresh per challenge
# --------------------------------------------------------------------------

def audit_challenge(transcript, x, epoch=0, randfunc=None):
    """Auditor side: mint a single-use challenge for the holder of slot x.

    `prove_share` is replayable by construction: its Fiat-Shamir challenge
    binds only (session, x, T), so one proof answers every future audit and
    anyone who observed it can replay it.  An auditor asking "do you hold
    this share *now*" needs freshness, so the possession proof binds an
    auditor-chosen nonce and an epoch as well.
    """
    if not (1 <= x <= 253):
        raise ValueError("share index must be in 1..253")
    if not (0 <= epoch < (1 << 64)):
        raise ValueError("epoch out of range")
    nonce = (_rand_bytes(randfunc, AUDIT_NONCE_LEN) if randfunc is not None
             else secrets.token_bytes(AUDIT_NONCE_LEN))
    return {"session": transcript["session"], "x": x, "epoch": epoch,
            "nonce": nonce}


def _challenge_possession(transcript, challenge, t_val, cf):
    w = _group_width(cf)
    data = bytearray(_AUDIT_DOMAIN + transcript["session"])
    data += challenge["x"].to_bytes(2, "big")
    data += challenge["epoch"].to_bytes(8, "big")
    data += bytes(challenge["nonce"])
    for c in transcript["commitments"]:
        data += c.to_bytes(w, "big")
    data += t_val.to_bytes(w, "big")
    return int.from_bytes(hashlib.sha256(bytes(data)).digest(), "big") % cf.q


def _challenge_wellformed(transcript, challenge, x=None):
    try:
        if challenge["session"] != transcript["session"]:
            return False
        if not isinstance(challenge["nonce"], (bytes, bytearray)):
            return False
        if len(challenge["nonce"]) < AUDIT_NONCE_LEN:
            return False
        if not (1 <= challenge["x"] <= 253):
            return False
        if not (0 <= challenge["epoch"] < (1 << 64)):
            return False
        return x is None or challenge["x"] == x
    except (KeyError, TypeError):
        return False


def prove_possession(share, transcript, challenge, field=None, randfunc=None):
    """Holder side: prove possession of a valid share against a fresh
    challenge, revealing nothing about (s, r).

    Same Schnorr proof of the Pedersen opening as `prove_share`, but the
    challenge hash also binds the auditor's nonce and epoch, so a proof is
    evidence of possession *at the time of that challenge* and cannot be
    replayed against a later one.  The auditor needs no secret material and
    learns only that slot x is held correctly.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    x, s, r = share
    if not _challenge_wellformed(transcript, challenge, x):
        raise ValueError("challenge does not match this transcript and slot")
    if not (0 <= s < qf.p and 0 <= r < qf.p):
        raise ValueError("share outside Z_q")
    if not verify_share(share, transcript, f):
        raise ValueError("share does not match the transcript")
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))
    ua, ub = rand() % qf.p, rand() % qf.p
    t_val = f.commit_double(ua, ub)
    c_val = _challenge_possession(transcript, challenge, t_val, f)
    return {"x": x, "epoch": challenge["epoch"], "T": t_val, "c": c_val,
            "za": (ua + c_val * s) % qf.p,
            "zb": (ub + c_val * r) % qf.p}


def verify_possession(proof, transcript, challenge, field=None):
    """Auditor side: check a possession proof against its own challenge.

    Returns bool and never raises.  A proof minted for a different nonce,
    epoch, slot or session fails, which is what makes a stored proof useless
    for answering the next audit.
    """
    f = _commit_field(field)
    qf = _arith(field)
    try:
        if not verify_transcript(transcript, f):
            return False
        x = proof["x"]
        if not _challenge_wellformed(transcript, challenge, x):
            return False
        if proof["epoch"] != challenge["epoch"]:
            return False
        t_val = proof["T"]
        f._check_subgroup(t_val)
        c_val = _challenge_possession(transcript, challenge, t_val, f)
        if c_val != proof["c"]:
            return False
        za, zb = proof["za"], proof["zb"]
        if not (0 <= za < qf.p and 0 <= zb < qf.p):
            return False
        cx = f.eval_commit(transcript["commitments"], x)
        return f.commit_double(za, zb) == (t_val * pow(cx, c_val, f.p)) % f.p
    except (ValueError, TypeError, KeyError):
        return False


def audit_holders(transcript, challenges, responses, field=None):
    """Auditor side: verdict per slot for one sampling round.

    `challenges` maps x -> challenge, `responses` maps x -> proof or None.
    Returns {x: verdict} with verdicts drawn from:

    * "held"     -- valid proof against this round's challenge;
    * "invalid"  -- a response was given and it does not verify: objective,
                    attributable cryptographic fault;
    * "missing"  -- no response: operational evidence only, since the network
                    may be at fault, so callers must not treat it as proof of
                    loss.

    The auditor holds no key material and no share, so a full round teaches
    it only which slots answered correctly.
    """
    f = _commit_field(field)
    verdicts = {}
    for x, challenge in challenges.items():
        proof = responses.get(x)
        if proof is None:
            verdicts[x] = "missing"
        elif verify_possession(proof, transcript, challenge, f):
            verdicts[x] = "held"
        else:
            verdicts[x] = "invalid"
    return verdicts


def _mac_ok(x, s, j, mac_keys, tags, qf):
    a, b = mac_keys.get((x, j), (None, None))
    if a is None:
        return False
    return qf.add(qf.mul(a, s), b) == tags.get((x, j))


def _acceptance_set(shares, mac_keys, tags, min_votes, qf):
    """Cevallos-Fehr-Ostrovsky-Rabani iterative acceptance-graph filter.

    A share is accepted only if it is certified by min_votes keys of players
    that are themselves still accepted; shares that lose the vote are removed
    and the process repeats.  This defeats the naive majority rule against
    colluding cheaters and is the efficient CFOR reconstruction front-end.
    """
    alive = sorted(set(x for x, _, _ in shares))
    s_by_x = {x: next(s for xx, s, _ in shares if xx == x) for x in alive}
    changed = True
    while changed and len(alive) >= min_votes:
        changed = False
        for x in list(alive):
            votes = sum(1 for j in alive
                        if j != x and _mac_ok(x, s_by_x[x], j, mac_keys,
                                              tags, qf))
            if votes < min_votes:
                alive.remove(x)
                changed = True
    return [sh for sh in shares if sh[0] in alive]


def _screen_against_commitments(coeffs, shares, transcript, f, qf):
    """Confirm the reconstructed polynomial really is the committed one.

    This replaces the old published digest point.  Publishing (P(254),
    R(254)) as plaintext handed every observer a free extra evaluation of the
    secret polynomial, so t colluding holders plus the public transcript
    reached t+1 points and interpolated the secret: the privacy threshold was
    one lower than advertised.  The commitments already pin the polynomial,
    so instead we rebuild the blinding polynomial from shares that agree with
    the candidate and check every commitment directly.  That is strictly
    stronger than a one-point screen (it checks all t+1 coefficients rather
    than a single evaluation) and it publishes nothing.
    """
    threshold = transcript["threshold"]
    commitments = transcript["commitments"]
    agree = [(x, sv, rv) for (x, sv, rv) in shares
             if qf.polynomial_eval(coeffs, x) == sv
             and verify_share((x, sv, rv), transcript, f)]
    if len(agree) < threshold + 1:
        raise ValueError("reconstruction is not backed by threshold + 1"
                         " commitment-verified shares (wrong secret or"
                         " cross-session mixing)")
    r_coeffs = _monomial([(x, rv) for x, _sv, rv in agree[:threshold + 1]], qf)
    for j, cj in enumerate(commitments):
        a = coeffs[j] if j < len(coeffs) else 0
        b = r_coeffs[j] if j < len(r_coeffs) else 0
        if f.commit_double(a, b) != cj:
            raise ValueError("reconstructed polynomial does not match the"
                             " commitments (wrong secret or cross-session"
                             " mixing)")
    return True


def _recover(transcript, shares, mac_keys, field):
    """Reconstruct the share polynomial coefficient list, with the full
    filtering pipeline; raises ValueError on unrecoverable input."""
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    threshold = transcript["threshold"]
    if len(shares) < threshold + 1:
        raise ValueError("need at least threshold + 1 (%d) shares, got %d"
                         % (threshold + 1, len(shares)))
    xs = [x for x, _, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")

    valid_c = [s for s in shares if verify_share(s, transcript, f)]
    coeffs = None
    if mac_keys is not None and transcript.get("mac_tags") \
            and len(valid_c) >= threshold + 1:
        survivors = _acceptance_set(valid_c, mac_keys, transcript["mac_tags"],
                                    threshold + 1, qf)
        if len(survivors) >= threshold + 1:
            try:
                coeffs = robust.berlekamp_welch(
                    [(x, s) for x, s, _ in survivors], threshold, qf)
            except ValueError:
                coeffs = None
    if coeffs is None and len(valid_c) >= threshold + 1:
        coeffs = _monomial([(x, s) for x, s, _ in valid_c], qf)
    if coeffs is None:
        coeffs = robust.berlekamp_welch(
            [(x, s) for x, s, _ in shares], threshold, qf)
    _screen_against_commitments(coeffs, shares, transcript, f, qf)
    return coeffs


def combine(transcript, shares, mac_keys=None, field=None):
    """Full single-secret reconstruction (see _recover for the pipeline).

    Asserts the transcript carries exactly one secret; returns the secret or
    raises ValueError.
    """
    if transcript["secrets"] != 1:
        raise ValueError("single-secret combine called on a multi-secret"
                         " transcript; use combine_many")
    coeffs = _recover(transcript, shares, mac_keys, field)
    return coeffs[0]


def combine_many(transcript, shares, mac_keys=None, field=None):
    """Yang-Chang-Hwang reconstruction: recover all packed secrets.

    Returns the list [s_0..s_{p-1}] of the p = transcript['secrets'] low
    coefficients of the share polynomial, with the full unified pipeline
    (commitments, MAC acceptance graph, BW, digest) applied.
    """
    coeffs = _recover(transcript, shares, mac_keys, field)
    return coeffs[:transcript["secrets"]]


# --------------------------------------------------------------------------
# Linear algebra over shares (BGW 1988: addition is free)
# --------------------------------------------------------------------------
# Shamir sharing over GF(q) is linear: s_i + s'_i is the share i of s + s',
# c * s_i the share of c * s.  The combined *transcript* -- commitments --
# is derived in the exponent without anyone ever seeing the
# intermediate secrets, so n holders can jointly obtain a sharing of a linear
# combination that no single player dealt.

def mul_share(scalar, share, field=None):
    """Locally scale one holder's share by `scalar` (share of c*s)."""
    f = _commit_field(field)
    qf = _arith(field)
    x, s, r = share
    c = scalar % qf.p
    return (x, qf.mul(s, c), qf.mul(r, c))


def add_shares(share_a, share_b, field=None):
    """Locally add two counterpart shares (share of s_a + s_b).

    `share_a` and `share_b` are the same holder's shares from two deals with
    the same n; x-coordinates must match.
    """
    f = _commit_field(field)
    qf = _arith(field)
    xa, s_a, ra = share_a
    xb, s_b, rb = share_b
    if xa != xb:
        raise ValueError("counterpart shares must share an x-coordinate")
    return (xa, qf.add(s_a, s_b), qf.add(ra, rb))


def linear_shares(coeffs, share_sets, field=None):
    """Locally combine counterpart shares: share of sum_t coeff[t]*s_t.

    `share_sets` is a list of share lists (one full list per deal, in the
    same order as coeffs); returns one combined share per position, i.e. the
    i-th holder's share of the linear combination.  Useful for complementing
    linear_transcript over whole deal bundles.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not share_sets:
        raise ValueError("no share sets given")
    if len(coeffs) != len(share_sets):
        raise ValueError("need one coefficient per share set")
    k = len(share_sets[0])
    for st in share_sets:
        if len(st) != k:
            raise ValueError("share sets must all hold shares for the same n")
    out = []
    for i in range(k):
        x = share_sets[0][i][0]
        s = 0
        r = 0
        for c, st in zip(coeffs, share_sets):
            xx, ss, rr = st[i]
            if xx != x:
                raise ValueError("counterpart shares must share x-coordinates")
            s = qf.add(s, qf.mul(ss, c % qf.p))
            r = qf.add(r, qf.mul(rr, c % qf.p))
        out.append((x, s, r))
    return out


def linear_transcript(transcripts, coeffs=None, field=None):
    """Transcript of a linear combination, derived purely in the exponent.

    Given the public transcripts of several single-secret deals all with the
    same n, returns the transcript of sum_t coeff[t]*s_t: commitments are
    merged (C_j = prod_t C_t,j^c_t), and the dealer-epoch layers (MAC tags,
    PoK) are dropped --
    authenticity rests on the (computationally binding) Pedersen commitments,
    exactly as for a refresh.  This lets n holders combine their locally
    summed shares against a publicly sound transcript with no dealer for the
    combination.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not transcripts:
        raise ValueError("need at least one transcript")
    coeffs = coeffs if coeffs is not None else [1] * len(transcripts)
    if len(coeffs) != len(transcripts):
        raise ValueError("need one coefficient per transcript")
    n = transcripts[0]["n"]
    for tr in transcripts:
        if not verify_transcript(tr, f):
            raise ValueError("transcript failed public verification")
        if tr["n"] != n:
            raise ValueError("all transcripts must share the same n")
        if tr["secrets"] != 1:
            raise ValueError("linear composition combines single-secret"
                             " transcripts only")
    tmax = max(tr["threshold"] for tr in transcripts)
    commitments = []
    for j in range(tmax + 1):
        acc = 1
        for tr, c in zip(transcripts, coeffs):
            if j < len(tr["commitments"]):
                acc = (acc * pow(tr["commitments"][j], c % f.q, f.p)) % f.p
        commitments.append(acc)
    return {
        "scheme": _SCHEME,
        "session": session_id(),
        "threshold": tmax,
        "n": n,
        "secrets": 1,
        "commitments": commitments,
        "proof": None,
        "mac_tags": {},
    }


def random_shares(threshold, n, field=None, randfunc=None):
    """Random unified sharing for MPC-style preprocessing.

    Draws a random secret in Z_q and deals it with the full stack; the dealer
    learns the secret (it is returned), which is exactly the honest
    preprocessing model -- the consumers only ever receive shares.
    Returns (secret, shares, mac_keys, transcript).
    """
    f = _commit_field(field)
    qf = _arith(field)
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))
    secret = rand() % qf.p
    shares, keys, transcript = _deal([secret], threshold, n, field, randfunc)
    return secret, shares, keys, transcript


def mul_shares(shares_a, shares_b, transcript_a, transcript_b, field=None,
               randfunc=None):
    """Beaver (1992) degree-reducing multiplication of two unified sharings.

    Closes the arithmetic circuit over the BGW addition layer: the caller
    clears a fresh random sharing triple ([a], [b], [c=a*b]) locally, opens
    the Beaver masks d = x - a and e = y - b from the *real* x-a / y-b
    sharings, then [x*y] = d*[b] + e*[a] + [c] + d*e is a valid
    (threshold+1)-of-n sharing whose transcript is derived in the exponent.

    Honesty framing: because d, e are opened inside this function from the
    honest combined shares, the output is always internally consistent, and
    corrupt *shares* fed in are handled by the usual commitment / MAC / BW
    layers.  A fully malicious *party* version additionally needs each party
    to prove its d_i, e_i open correctly (zero-knowledge); that layer is
    deliberately out of scope -- this is the honest-processor (single-caller)
    model.  See the shamir.dkg module for the FROST-style threat model.

    Returns (product_shares, product_transcript, info) with info =
    {d, e, triple: (a, b, c)}.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not (verify_transcript(transcript_a, f) and
            verify_transcript(transcript_b, f)):
        raise ValueError("transcript failed public verification")
    t = transcript_a["threshold"]
    n = transcript_a["n"]
    if t != transcript_b["threshold"]:
        raise ValueError("multiplication requires equal thresholds")
    if transcript_b["n"] != n:
        raise ValueError("multiplication requires equal n")
    if len(shares_a) != n or len(shares_b) != n:
        raise ValueError("share lists must hold one share per holder")

    a, sh_a, _k_a, t_a = random_shares(t, n, field, randfunc)
    b, sh_b, _k_b, t_b = random_shares(t, n, field, randfunc)
    c = qf.mul(a, b)
    shares_c, _keys_c, t_c = _deal([c], t, n, field, randfunc)

    d_shares = linear_shares([1, -1], [shares_a, sh_a], f)
    e_shares = linear_shares([1, -1], [shares_b, sh_b], f)
    d = combine(linear_transcript([transcript_a, t_a], [1, -1], field=f),
                d_shares[:t + 1], field=f)
    e = combine(linear_transcript([transcript_b, t_b], [1, -1], field=f),
                e_shares[:t + 1], field=f)
    de = qf.mul(d, e)

    base = linear_transcript([t_b, t_a, t_c], [d, e, 1], field=f)
    comms = list(base["commitments"])
    comms[0] = (comms[0] * pow(f.g, de, f.p)) % f.p
    product_tr = dict(base)
    product_tr["commitments"] = comms

    lin = linear_shares([d, e, 1], [sh_b, sh_a, shares_c], f)
    product_shares = [(x, qf.add(s, de), r) for x, s, r in lin]
    return product_shares, product_tr, {"d": d, "e": e, "triple": (a, b, c)}


# --------------------------------------------------------------------------
# Share re-issuance, threshold exponentiation, aggregate verification
# --------------------------------------------------------------------------

def derive_share(transcript, shares, y, field=None):
    """Re-issue a fresh verifiable share at a new coordinate (no dealer).

    Interpolates both the s-side and the r-side of the share polynomial at x
    = y from any threshold+1 shares that pass the Pedersen check, so a new
    player joins an existing sharing without the dealer or the secret ever
    appearing.  The derived (y, s_y, r_y) verifies against the transcript's
    commitments.  (Adapts the Herzberg et al. 1995 recovery primitive to the
    full unified triple.)
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    threshold = transcript["threshold"]
    if len(shares) < threshold + 1:
        raise ValueError("need at least threshold + 1 (%d) shares, got %d"
                         % (threshold + 1, len(shares)))
    xs = [x for x, _, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    for share in shares:
        if not verify_share(share, transcript, f):
            raise ValueError("share at index %d failed verification" % share[0])
    if not (1 <= y <= 253):
        raise ValueError("target index must be in 1..253 (share space)")
    if y in xs:
        raise ValueError("target index %d already in use" % y)
    cache = core.LagrangeCache(xs, qf)
    s_y = cache.evaluate([s for _, s, _ in shares], y)
    r_y = cache.evaluate([r for _, _, r in shares], y)
    derived = (y, s_y, r_y)
    if (s_y != 0 or r_y != 0) and not verify_share(derived, transcript, f):
        raise ValueError("derived share failed verification (internal error)")
    return derived


def rejoin_share(transcript, shares, x, field=None):
    """Rebuild the share at an OCCUPIED holder slot x (no dealer, no secret).

    Guardian repair: when the holder at coordinate x is lost, any threshold+1
    remaining holders can recompute the exact (x, s_x, r_x) triple -- the
    slot keeps its identity and its committed value, so a replacement
    guardian takes over an existing slot without re-dealing or revealing the
    secret.  The inverse of derive_share, which deliberately refuses an
    occupied coordinate (a new *member* must take a fresh index); rejoin is
    the same Herzberg et al. 1995 recovery primitive for the lost-slot case
    (mirrors shamir.proactive.recover_share, generalized to the unified
    triple and commitment-screened).

    `shares` must be at least threshold+1 verified shares of the transcript,
    not including x.  The recomputed share is verified against the
    transcript's commitments before it is returned (the committed polynomial
    is fixed, so a wrong rejoin is detected rather than distributed).
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    threshold = transcript["threshold"]
    if len(shares) < threshold + 1:
        raise ValueError("need at least threshold + 1 (%d) shares, got %d"
                         % (threshold + 1, len(shares)))
    xs = [xx for xx, _, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    if not (1 <= x <= 253):
        raise ValueError("target index must be in 1..253")
    if x in xs:
        raise ValueError("target index %d is among the input shares" % x)
    for share in shares:
        if not verify_share(share, transcript, f):
            raise ValueError("share at index %d failed verification" % share[0])
    cache = core.LagrangeCache(xs, qf)
    s_x = cache.evaluate([s for _, s, _ in shares], x)
    r_x = cache.evaluate([r for _, _, r in shares], x)
    rejoined = (x, s_x, r_x)
    if (s_x != 0 or r_x != 0) and not verify_share(rejoined, transcript, f):
        raise ValueError("rejoined share failed verification (internal error)")
    return rejoined


def _public_share_value(transcript, x, s, r, f):
    """g^s_x in the exponent from the transcript and a verified share.

    C_x = g^s_x * h^r_x, so g^s_x = C_x / h^r_x; C_x = prod_j C_j^{x^j} is
    the committed polynomial evaluated at x.  The share's s value never
    appears in memory (Desmedt-Frankel).
    """
    c = f.eval_commit(transcript["commitments"], x)
    return (c * pow(f.h, (f.q - r % f.q) % f.q, f.p)) % f.p


def recover_exponent(transcript, shares, field=None):
    """Threshold exponentiation: recover g^{secret} mod p, never the secret.

    Desmedt-Frankel (CRYPTO 1989) threshold-crypto practice.  From any
    threshold+1 commitment-verified shares each holder's contribution is
    g^{s_i} = C_{x_i} / h^{r_i} (the r-binder is public from the share), so
    g^s = prod_i (g^{s_i})^{lambda_i} -- the int secret never appears in
    memory.  The result is the canonical public key / ciphertext base for
    threshold ElGamal-, ECDSA- or BLS-style schemes building on this sharing.
    Shares failing the Pedersen check are discarded; at least threshold+1
    must survive.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    threshold = transcript["threshold"]
    if len(shares) < threshold + 1:
        raise ValueError("need at least threshold + 1 (%d) shares, got %d"
                         % (threshold + 1, len(shares)))
    xs = [x for x, _, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    verified = [s for s in shares if verify_share(s, transcript, f)]
    if len(verified) < threshold + 1:
        raise ValueError("fewer than threshold + 1 verified shares, cannot"
                         " recover the exponent")
    holders = verified[:threshold + 1]
    contributions = [_public_share_value(transcript, x, s, r, f)
                     for x, s, r in holders]
    lambdas = core.lagrange_coefficient([x for x, _, _ in holders], 0, qf)
    out = 1
    for gs, lam in zip(contributions, lambdas):
        out = (out * pow(gs, lam, f.p)) % f.p
    return out


_SIG_DOMAIN = b"sssx unified threshold-schnorr v1"


def _challenge_sig(message, r_val, y_val, f):
    w = _group_width(f)
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    data = bytearray(_SIG_DOMAIN)
    data += message
    data += r_val.to_bytes(w, "big") + y_val.to_bytes(w, "big")
    return int.from_bytes(hashlib.sha256(bytes(data)).digest(), "big") % f.q


def threshold_sign(message, transcript, shares, nonce_transcript, nonce_shares,
                   signers, field=None, drop_invalid=False, partials=None):
    """Threshold Schnorr signature over the unified sharing: sign WITHOUT
    ever reconstructing the key (the knowledgeless path).

    transcript/shares:    the sharing of the key x (a unified deal or a
                          distributed_run output).
    nonce_transcript/shares: a sharing of a fresh random nonce k -- one deal
                          per signature (dealer path), or a dealer-free
                          distributed_run (party path); must have the same
                          threshold as the key sharing, and every signer
                          index must hold a verified share of BOTH.
    signers:              list of holder indices, len >= threshold + 1.
    partials:             optional {i: z_i} of partial signatures *submitted*
                          by the signers, as in a real distributed signing
                          run.  When given, every submitted partial is
                          verified independently against the signer's public
                          nonce commitment R_i = g^k_i and public key share
                          Y_i = g^x_i (both derived from the transcripts in
                          the exponent -- no key material is ever exposed):
                          the partial passes iff g^z_i == R_i^{lambda_i} *
                          Y_i^{c*lambda_i}.  When None (default), each
                          partial is computed locally from the signer's
                          verified shares and then checked by the same
                          equation.

    Returns (R, z, Y, detail): R = g^k, z = k + c*x, Y = g^x the public key,
    detail = {"c": c, "partials": {i: z_i}, "publics": {i: (R_i, Y_i)},
    "rejected": [...]} (z = sum of the Lagrange-weighted partials z_i =
    lambda_i*(k_i + c*x_i)).  Verify publicly with verify_signature --
    nobody sees the key, the nonce k, or any individual share.  Honest
    caveat (documented, all threshold Schnorr schemes): never reuse a nonce
    sharing for two messages -- z1 - z2 = c1*x - c2*x leaks the key.

    Malicious-signer handling: every signer's key and nonce share is checked
    against its transcript *before* the challenge is fixed, so a corrupt or
    swapped share is attributed to its signer index rather than silently
    contaminating z (drop_invalid=True excludes such signers from the
    signing set).  Every partial is then checked against its signer's public
    (R_i, Y_i) under the challenge of the signing set -- a signer that runs
    the signing step wrongly, or a live adversary replaying a partial from
    an earlier message (the challenge c binds message, R and Y), is
    attributed to its index.  An invalid *submitted* partial always aborts
    the run (even with drop_invalid=True): the surviving partials are bound
    to the challenge of the original signer set, and silently continuing
    would emit a signature that fails public verification.  This is the
    FROST restart discipline: drop the failing signer, re-run the protocol
    with the smaller set and fresh partials (PROTOCOL.md 3.4).
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("key transcript failed public verification")
    if not verify_transcript(nonce_transcript, f):
        raise ValueError("nonce transcript failed public verification")
    if transcript["threshold"] != nonce_transcript["threshold"]:
        raise ValueError("key and nonce sharings must have the same threshold")
    threshold = transcript["threshold"]
    if len(signers) < threshold + 1:
        raise ValueError("need at least threshold + 1 (%d) signers, got %d"
                         % (threshold + 1, len(signers)))
    key_by_x = {x: (s, r) for x, s, r in shares}
    nonce_by_x = {x: (s, r) for x, s, r in nonce_shares}
    if len(key_by_x) != len(shares) or len(nonce_by_x) != len(nonce_shares):
        raise ValueError("duplicate share x-coordinates")
    if len(set(signers)) != len(signers):
        raise ValueError("duplicate signer indices in the signing set")
    if partials is not None and not isinstance(partials, dict):
        raise TypeError("partials must be a dict {signer_index: z_i}")
    rejected = []
    candidates = []
    for i in signers:
        if i not in key_by_x or i not in nonce_by_x:
            rejected.append(i)
            continue
        if not verify_share((i, key_by_x[i][0], key_by_x[i][1]),
                            transcript, f) or \
                not verify_share((i, nonce_by_x[i][0], nonce_by_x[i][1]),
                                 nonce_transcript, f):
            rejected.append(i)
            continue
        if partials is not None and i not in partials:
            rejected.append(i)
            continue
        candidates.append(i)
    if len(candidates) < threshold + 1:
        raise ValueError("signer set collapses below threshold + 1 after "
                         "rejecting %d invalid signer(s): %s"
                         % (len(rejected), sorted(rejected)))
    if rejected and not drop_invalid:
        raise ValueError("invalid signer contribution(s) from index(es) %s "
                         "(pass drop_invalid=True to sign with the remaining"
                         " signers)" % sorted(rejected))

    def _verify_partial(z_i, i, lam, c_val):
        """g^z_i == R_i^lam * Y_i^(c*lam); R_i, Y_i from the transcripts."""
        try:
            (sx, rx) = key_by_x[i]
            (sk, rk) = nonce_by_x[i]
            r_i = _public_share_value(nonce_transcript, i, sk, rk, f)
            y_i = _public_share_value(transcript, i, sx, rx, f)
            lhs = f.commit(z_i)
            rhs = (pow(r_i, lam, f.p) *
                   pow(y_i, qf.mul(c_val, lam), f.p)) % f.p
            return lhs == rhs, r_i, y_i
        except (ValueError, TypeError):
            return False, None, None

    r_val = recover_exponent(nonce_transcript,
                             [sh for sh in nonce_shares
                              if sh[0] in candidates], f)
    y_val = recover_exponent(transcript,
                             [sh for sh in shares
                              if sh[0] in candidates], f)
    if r_val == 1:
        raise ValueError("nonce k == 0: draw a fresh nonce sharing")
    if y_val == 1:
        raise ValueError("key x == 0: refuse to sign with a zero key")
    c_val = _challenge_sig(message, r_val, y_val, f)
    lambdas = core.lagrange_coefficient(candidates, 0, qf)
    accepted = []
    z_i_by_x = {}
    publics = {}
    partial_failures = []
    for lam, i in zip(lambdas, candidates):
        (sx, _rx) = key_by_x[i]
        (sk, _rk) = nonce_by_x[i]
        if partials is not None:
            z_i = partials[i]
        else:
            z_i = qf.mul(lam, qf.add(sk, qf.mul(c_val, sx)))
        ok, r_i, y_i = _verify_partial(z_i, i, lam, c_val)
        if not ok:
            partial_failures.append(i)
            rejected.append(i)
            continue
        accepted.append(i)
        z_i_by_x[i] = z_i
        publics[i] = (r_i, y_i)
    if partial_failures:
        raise ValueError("invalid partial signature(s) from index(es) %s: "
                         "partials are bound to the signer set's challenge; "
                         "replace the failing signer(s) and re-run the "
                         "protocol (FROST restart discipline)"
                         % sorted(set(partial_failures)))
    z = 0
    partials_out = {}
    for i in accepted:
        z = qf.add(z, z_i_by_x[i])
        partials_out[i] = z_i_by_x[i]
    detail = {"c": c_val, "partials": partials_out, "publics": publics,
              "rejected": list(rejected)}
    return r_val, z, y_val, detail


def verify_signature(message, r_val, z, y_val, field=None):
    """Public Schnorr check: g^z == R * Y^c.  Returns bool, never raises."""
    f = _commit_field(field)
    qf = _arith(field)
    try:
        f._check_subgroup(r_val)
        f._check_subgroup(y_val)
        if not (0 <= z < qf.p):
            return False
        c_val = _challenge_sig(message, r_val, y_val, f)
        return f.commit(z) == (r_val * pow(y_val, c_val, f.p)) % f.p
    except (ValueError, TypeError):
        return False


def batch_verify(shares, transcript, field=None, randfunc=None):
    """Aggregate Pedersen verification (Bellare-Garay-Rabin 1998 style).

    Checks every share against the commitments with one multi-exponentiation
    instead of n evaluations, using the BGR *small exponents test*: draw a
    fresh secret weight d_i per share and check

        g^{sum d_i s_i} h^{sum d_i r_i} == prod_j C_j^{sum_i d_i x_i^j}.

    The weights are load-bearing.  Summing the shares unweighted turns this
    into a checksum: an adversary adds delta to one share's s and subtracts
    delta from another, both errors cancel in the sum, and the batch passes
    with two corrupt shares.  With fresh random d_i the forged errors must
    satisfy sum d_i (ds_i, dr_i) = 0 for weights the adversary cannot
    predict, which happens with probability about 2^-BATCH_WEIGHT_BITS, on
    top of the discrete-log assumption that log_g h is unknown.

    Because the weights are random this returns a probabilistic accept; pass
    `randfunc` only for deterministic tests.  Use verify_share when a single
    corrupt share must be pinpointed.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        return False
    if not shares:
        return False
    if len(set(x for x, _, _ in shares)) != len(shares):
        return False
    draw = randfunc if randfunc is not None else (
        lambda: secrets.randbits(BATCH_WEIGHT_BITS))
    commitments = transcript["commitments"]
    S = 0
    R = 0
    exps = [0] * len(commitments)
    for share in shares:
        if not (isinstance(share, (tuple, list)) and len(share) == 3):
            return False
        x, s, r = share
        if not (1 <= x <= 253):
            return False
        if not (0 <= s < qf.p and 0 <= r < qf.p):
            return False
        weight = (draw() % ((1 << BATCH_WEIGHT_BITS) - 1)) + 1
        S = qf.add(S, qf.mul(s, weight))
        R = qf.add(R, qf.mul(r, weight))
        xr = x % f.q
        power = weight % f.q
        for j in range(len(exps)):
            exps[j] = (exps[j] + power) % f.q
            power = (power * xr) % f.q
    lhs = (pow(f.g, S, f.p) * pow(f.h, R, f.p)) % f.p
    rhs = 1
    for c, e in zip(commitments, exps):
        rhs = (rhs * pow(c, e, f.p)) % f.p
    return lhs == rhs


# --------------------------------------------------------------------------
# Byte / large-secret mode (Krawczyk 1994 merged into the unified deal)
# --------------------------------------------------------------------------

def _rand_bytes(randfunc, size):
    if randfunc is None:
        return secrets.token_bytes(size)
    return bytes(randfunc() % 256 for _ in range(size))


def _keystream(key, nonce, nbytes):
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        block = hashlib.shake_256(_AEAD_DOMAIN + key + nonce
                                  + counter.to_bytes(8, "big")).digest(_BLOCK)
        need = nbytes - len(out)
        out += block if need >= _BLOCK else block[:need]
        counter += 1
    return bytes(out)


def _encrypt(key, nonce, plaintext):
    ct = bytes(a ^ b for a, b in zip(plaintext,
                                     _keystream(key, nonce, len(plaintext))))
    tag = hmac.new(key, _AEAD_DOMAIN + nonce + ct, hashlib.sha256).digest()
    return nonce + ct + tag


def _decrypt(key, blob):
    if len(blob) < _NONCE_LEN + _TAG_LEN:
        raise ValueError("ciphertext too short")
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:-_TAG_LEN]
    tag = blob[-_TAG_LEN:]
    expected = hmac.new(key, _AEAD_DOMAIN + nonce + ct,
                        hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("invalid authentication tag")
    stream = _keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream))


def _split_chunks(blob, n):
    return [(i, len(blob[i::n]), blob[i::n]) for i in range(n)]


def _reassemble(chunk_map):
    entries = [(i, length, data) for i, length, data in chunk_map.values()]
    idx = [i for i, _len, _d in entries]
    if len(set(idx)) != len(idx) or set(idx) != set(range(len(entries))):
        raise ValueError("chunk_map must hold exactly chunks 0..n-1")
    m = sum(length for _i, length, _d in entries)
    out = bytearray(m)
    for i, length, data in entries:
        if len(data) != length:
            raise ValueError("chunk byte-length mismatch for chunk %d" % i)
        for k in range(length):
            out[i + k * len(entries)] = data[k]
    return bytes(out)


def deal_bytes(secret, threshold, n, field=None, randfunc=None):
    """Krawczyk (CRYPTO 1994) hybrid mode fused into the unified scheme.

    Draws a random session key K in Z_q, unifies it with the full guarantee
    stack (deal), derives an AEAD key from K (SHAKE256), encrypts `secret`
    under it (SHAKE256 stream XOR + HMAC tag), and scatters the ciphertext
    into n strided chunks keyed by the share x-coordinates.

    Returns (shares, mac_keys, transcript, chunk_map):
    * shares / mac_keys / transcript: the unified deal of K.
    * chunk_map: {x: (chunk_index, byte_length, data)} for x in 1..n.
    """
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    f = _commit_field(field)
    qf = _arith(field)
    _check_params(threshold, n)
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))
    k = rand() % qf.p
    shares, keys, transcript = _deal([k], threshold, n, field, randfunc)
    key = hashlib.shake_256(_KEY_DOMAIN + k.to_bytes(_group_width(f), "big")
                            ).digest(_KEY_LEN)
    nonce = _rand_bytes(randfunc, _NONCE_LEN)
    blob = _encrypt(key, nonce, secret)
    chunk_map = {}
    for i, length, data in _split_chunks(blob, n):
        chunk_map[i + 1] = (i, length, data)
    return shares, keys, transcript, chunk_map


def combine_bytes(transcript, shares, chunk_map, mac_keys=None, field=None):
    """Krawczyk reconstruction: recover the AEAD key via the full unified
    pipeline, reassemble the ciphertext from every chunk, authenticate and
    decrypt; returns the original bytes or raises ValueError."""
    if transcript["secrets"] != 1:
        raise ValueError("byte mode operates on single-secret transcripts")
    f = _commit_field(field)
    k = combine(transcript, shares, mac_keys, field)
    key = hashlib.shake_256(_KEY_DOMAIN + k.to_bytes(_group_width(f), "big")
                            ).digest(_KEY_LEN)
    blob = _reassemble(chunk_map)
    return _decrypt(key, blob)


def _classify_shares(transcript, shares, mac_keys, field):
    """Per-share diagnosis without any reconstruction (shared by audit and
    audit_public).  Returns a status map keyed by x for well-formed shares
    and by positional counter for malformed ones.  Diagnoses: 'ok', 'raw',
    'bad_index', 'out_of_range', 'duplicate', 'commit', 'mac'."""
    f = _commit_field(field)
    qf = _arith(field)
    statuses = {}
    n = transcript["n"] if isinstance(transcript, dict) else 0
    seen = set()

    def diagnose(share):
        if not isinstance(share, (tuple, list)) or len(share) != 3:
            return 'raw'
        x, s, r = share
        if not (1 <= x <= n):
            return 'bad_index'
        if not (0 <= s < qf.p and 0 <= r < qf.p):
            return 'out_of_range'
        if x in seen:
            return 'duplicate'
        if not verify_share(share, transcript, f):
            return 'commit'
        if mac_keys is not None and transcript.get('mac_tags'):
            votes = sum(1 for j in range(1, n + 1)
                        if j != x and _mac_ok(x, s, j, mac_keys,
                                              transcript['mac_tags'], qf))
            if votes < transcript['threshold'] + 1:
                return 'mac'
        return 'ok'

    for share in shares:
        st = diagnose(share)
        x = share[0] if isinstance(share, (tuple, list)) and len(share) == 3 \
            else None
        if x is not None and 1 <= x <= n:
            seen.add(x)
            statuses[x] = st
        else:
            statuses[-len(statuses) - 1] = st
    return statuses


def audit(transcript, shares, mac_keys=None, field=None):
    """Cheater identification (Tompa-Woll / Pieprzyk-Zhang / CFOR).

    Classifies every submitted share and reports exactly which are corrupted
    or malformed, plus the reconstruction outcome.  Returns
    (outcome, statuses, reason) where outcome is the recovered secret (list
    for multi-secret, int for single) or None, statuses maps each holder x
    to a diagnosis, malformed shares (bad shape, index or range) are keyed
    -1, -2, ... so they can never overwrite a real holder's verdict, and
    reason explains any failure:
      'ok', 'raw', 'bad_index', 'out_of_range', 'duplicate', 'commit',
      'mac', 'unrecoverable', 'digest'
    """
    f = _commit_field(field)
    statuses = _classify_shares(transcript, shares, mac_keys, f)
    try:
        coeffs = _recover(transcript, shares, mac_keys, f)
    except ValueError as exc:
        reason = str(exc)
        if 'digest' in reason:
            reason = 'digest'
        else:
            reason = 'unrecoverable'
        return None, statuses, reason
    if transcript['secrets'] == 1:
        outcome = coeffs[0]
    else:
        outcome = coeffs[:transcript['secrets']]
    return outcome, statuses, 'ok'


def audit_public(transcript, shares, field=None):
    """Cheater identification WITHOUT reconstruction (Tompa-Woll style).

    Same classification as audit, but never recovers the secret, so an
    external auditor can report exactly which shares are corrupted or
    malformed without ever learning the shared secret -- the privacy side of
    the ZK story made concrete.  Returns (statuses, recoverable):

    * statuses: per-share diagnosis, as in audit.
    * recoverable: whether the submitted set is structurally reconstructable
      (verified transcript, distinct x-coordinates, at least threshold+1
      'ok' shares).  The final digest screen can only be confirmed at actual
      recovery, so this is a necessary-condition signal, not a guarantee.
    """
    f = _commit_field(field)
    statuses = _classify_shares(transcript, shares, None, f)
    if not verify_transcript(transcript, f):
        return statuses, False
    ok_count = sum(1 for st in statuses.values() if st == 'ok')
    return statuses, ok_count >= transcript["threshold"] + 1


# --------------------------------------------------------------------------
# Refresh and redistribution (epoch-continuity layers)
# --------------------------------------------------------------------------

def refresh(share, transcript, field=None, randfunc=None, corrupt=()):
    """Herzberg et al. (1995) dealer-free refresh of one holder's share.

    Simulates the full period: every player deals zero-constant Pedersen
    deltas (s-side and masking side), broadcasts commitments, and each
    incoming delta is verified against its commitments before being added.
    Returns (new_share, new_transcript, info):

    * new_share:     (x, s', r') with the same secret and fresh randomness.
    * new_transcript: same session, updated commitments (constant term
                      unchanged), mac_tags cleared and proof dropped
                      (dealer-epoch layers).
    * info:          {received: [(dealer, d_s, d_r)], commitments_i:
                      {dealer: [C_1..C_t]}}.

    `corrupt` is a set of dealer indices dealing a nonzero-constant delta
    (to test detection); the refresh then raises ValueError naming the first
    corrupt dealer detected.
    """
    f = _commit_field(field)
    qf = _arith(field)
    threshold = transcript["threshold"]
    n = transcript["n"]
    x, s, r = share
    if not (1 <= x <= n):
        raise ValueError("share index must be a player id in 1..n")
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))

    def _draw():
        return rand() % qf.p

    commitments_i = {}
    received = []
    new_s, new_r = s, r
    for dealer in range(1, n + 1):
        if dealer in corrupt:
            c_poly = [_draw()] + [_draw() for _ in range(threshold)]
            m_poly = [_draw()] + [_draw() for _ in range(threshold)]
        else:
            c_poly = [0] + [_draw() for _ in range(threshold)]
            m_poly = [0] + [_draw() for _ in range(threshold)]
        comm = [f.commit_double(a, b) for a, b in zip(c_poly[1:], m_poly[1:])]
        commitments_i[dealer] = comm
        d = qf.polynomial_eval(c_poly, x)
        m = qf.polynomial_eval(m_poly, x)
        received.append((dealer, d, m))
        new_s = qf.add(new_s, d)
        new_r = qf.add(new_r, m)
        if dealer != x:
            expected = _eval_refresh_commit(comm, x, f)
            if f.commit_double(d, m) != expected:
                raise ValueError("refresh failed: dealer %d dealt a"
                                 " non-zero-constant polynomial" % dealer)

    new_transcript = dict(transcript)
    new_commitments = [transcript["commitments"][0]]
    for j in range(1, threshold + 1):
        acc = transcript["commitments"][j]
        for comm in commitments_i.values():
            acc = (acc * comm[j - 1]) % f.p
        new_commitments.append(acc)
    new_transcript["commitments"] = new_commitments
    new_transcript["mac_tags"] = {}
    new_transcript["proof"] = None
    info = {"received": received, "commitments_i": commitments_i}
    return (x, new_s, new_r), new_transcript, info


def redistribute(shares, transcript, new_threshold, new_n, field=None,
                 randfunc=None):
    """Desmedt-Jarecki (1993) redistribution to new (t', n') parameters.

    The first t+1 shares form the holder set; each holder deals a fresh
    Pedersen pair (h_i, m_i) with h_i(0) equal to its own s-value and
    m_i(0) to its own r-value; recipient j combines the lambda-weighted
    evaluations.  New commitments are derived in the exponent.

    Returns (new_shares, new_transcript, posted):
    * new_shares:     [(j, s''_j, r''_j)] for j in 1..new_n.
    * new_transcript: same session, new threshold/n, commitments,
                      mac_tags cleared and proof dropped.
    * posted:         {} (reserved; nothing is published during
                      redistribution -- no polynomial evaluation may leave
                      the protocol, see _screen_against_commitments).
    """
    f = _commit_field(field)
    qf = _arith(field)
    _check_params(new_threshold, new_n)
    threshold = transcript["threshold"]
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    if len(shares) < threshold + 1:
        raise ValueError("need at least t+1 (%d) old shares, got %d"
                         % (threshold + 1, len(shares)))
    holders = shares[:threshold + 1]
    if len(set(x for x, _, _ in holders)) != len(holders):
        raise ValueError("duplicate share x-coordinates among holders")
    for share in holders:
        if not verify_share(share, transcript, f):
            raise ValueError("old share at index %d failed verification"
                             % share[0])
    xs = [x for x, _, _ in holders]
    lambdas = core.lagrange_coefficient(xs, 0, qf)
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(qf.p))

    def _draw():
        return rand() % qf.p

    for _ in range(100):
        dealt = []
        dealt_commits = []
        for (x, s, r), _lam in zip(holders, lambdas):
            h_poly = [s % qf.p] + [_draw() for _ in range(new_threshold)]
            m_poly = [r % qf.p] + [_draw() for _ in range(new_threshold)]
            dealt.append((h_poly, m_poly))
            dealt_commits.append(
                [f.commit_double(a, b) for a, b in zip(h_poly, m_poly)])
        new_shares = []
        for j in range(1, new_n + 1):
            s_acc = 0
            r_acc = 0
            for (h_poly, m_poly), lam in zip(dealt, lambdas):
                s_acc = qf.add(s_acc, qf.mul(qf.polynomial_eval(h_poly, j), lam))
                r_acc = qf.add(r_acc, qf.mul(qf.polynomial_eval(m_poly, j), lam))
            new_shares.append((j, s_acc, r_acc))
        if all(s != 0 and r != 0 for _, s, r in new_shares):
            break
    else:
        raise ValueError("could not draw dealer polynomials with all-nonzero"
                         " shares")

    new_commitments = []
    for j in range(new_threshold + 1):
        acc = 1
        for cs, lam in zip(dealt_commits, lambdas):
            acc = (acc * pow(cs[j], lam, f.p)) % f.p
        new_commitments.append(acc)

    posted = {}
    new_transcript = dict(transcript)
    new_transcript["threshold"] = new_threshold
    new_transcript["n"] = new_n
    new_transcript["commitments"] = new_commitments
    new_transcript["mac_tags"] = {}
    new_transcript["proof"] = None
    return new_shares, new_transcript, posted


def change_threshold(shares, transcript, new_threshold, new_n, field=None,
                     randfunc=None):
    """Single-dealer threshold change: re-deal the same secret(s) under new
    (t', n') parameters.

    The dealer (single caller) verifies every old share against the old
    commitments, reconstructs the secret(s) through the full pipeline
    (CFOR/MAC, Berlekamp-Welch, commitment screen), and deals a fresh
    sharing under the new parameters -- same session, fresh commitments and
    a fresh dealer proof.  This is the one-call analogue of
    shamir.reshare.change_threshold for the unified scheme: configuration
    migration (a roster or threshold change) without touching the secret.

    Returns (new_shares, mac_keys, new_transcript) exactly like `deal`, so
    the output drops straight into the pipeline (combine, seal, audit, ...).
    Multi-secret transcripts are re-dealt through combine_many (output
    combines with combine_many).  Weighted transcripts are refused: a plain
    re-deal would silently flatten the access structure.
    """
    f = _commit_field(field)
    qf = _arith(field)
    if not verify_transcript(transcript, f):
        raise ValueError("transcript failed public verification")
    if transcript.get("weights") is not None:
        raise ValueError("change_threshold does not support weighted "
                         "transcripts (deal_weighted): a plain re-deal would "
                         "silently change the access structure -- re-deal "
                         "the weighted structure explicitly")
    _check_params(new_threshold, new_n)
    threshold = transcript["threshold"]
    if len(shares) < threshold + 1:
        raise ValueError("need at least threshold + 1 (%d) old shares, got %d"
                         % (threshold + 1, len(shares)))
    xs = [x for x, _, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    for share in shares:
        if not verify_share(share, transcript, f):
            raise ValueError("old share at index %d failed verification"
                             % share[0])
    if transcript["secrets"] == 1:
        secrets = [combine(transcript, shares, field=f)]
    else:
        secrets = combine_many(transcript, shares, field=f)
    new_shares, mac_keys, new_transcript = _deal(
        secrets, new_threshold, new_n, f, randfunc)
    return new_shares, mac_keys, new_transcript


# --------------------------------------------------------------------------
# Portable bundle: seal / unseal (misuse-resistant end-to-end pipeline)
# --------------------------------------------------------------------------
# A bundle is a JSON-serializable dict carrying the whole deal: the transcript
# (commitments in hex, PoK), session-bound checksummed share
# blobs for every holder, and optionally the dealer's MAC keys.  unseal
# validates every layer on the way back -- bundle format, transcript public
# verification, each blob's checksum and session id -- and then the
# commitment screen. Cross-session or cross-bundle mixing therefore fails
# loudly.

def _encode_blob(x, s, r, session, width):
    payload = s.to_bytes(width, "big") + r.to_bytes(width, "big")
    header = _BLOB_MAGIC + bytes([_BLOB_VERSION]) + width.to_bytes(2, "big") \
        + bytes([x]) + session
    tag = hashlib.sha256(header + payload).digest()[:_BLOB_CHECKSUM_LEN]
    return header + payload + tag


def _decode_blob(blob, session, width):
    fixed = 4 + 1 + 2 + 1 + 16
    if len(blob) != fixed + 2 * width + _BLOB_CHECKSUM_LEN:
        raise ValueError("share blob has wrong length")
    if blob[:4] != _BLOB_MAGIC:
        raise ValueError("bad share magic")
    if blob[4] != _BLOB_VERSION:
        raise ValueError("unsupported share blob version")
    if int.from_bytes(blob[5:7], "big") != width:
        raise ValueError("share blob width mismatch")
    x = blob[7]
    sess = blob[8:24]
    payload = blob[24:24 + 2 * width]
    given = blob[24 + 2 * width:]
    expected = hashlib.sha256(blob[:24] + payload).digest()[:_BLOB_CHECKSUM_LEN]
    if not hmac.compare_digest(given, expected):
        raise ValueError("share blob checksum mismatch (corrupted share)")
    if not hmac.compare_digest(sess, session):
        raise ValueError("share from a different session")
    if not (1 <= x <= 253):
        raise ValueError("share blob index out of range")
    s = int.from_bytes(payload[:width], "big")
    r = int.from_bytes(payload[width:], "big")
    return (x, s, r)


def _proof_to_bundle(proof):
    out = {"T": hex(proof["T"]), "challenge": hex(proof["challenge"]),
           "za": hex(proof["za"]), "zb": hex(proof["zb"])}
    if "entries" in proof:
        out["entries"] = [
            {"index": e["index"], "T": hex(e["T"]),
             "challenge": hex(e["challenge"]),
             "za": hex(e["za"]), "zb": hex(e["zb"])}
            for e in proof["entries"]]
    return out


def _proof_from_bundle(proof):
    out = {"T": int(proof["T"], 16), "challenge": int(proof["challenge"], 16),
           "za": int(proof["za"], 16), "zb": int(proof["zb"], 16)}
    if "entries" in proof:
        out["entries"] = [
            {"index": e["index"], "T": int(e["T"], 16),
             "challenge": int(e["challenge"], 16),
             "za": int(e["za"], 16), "zb": int(e["zb"], 16)}
            for e in proof["entries"]]
    return out


def _field_lock(f):
    """Field fingerprint embedded in every bundle (fool-proofing: a bundle
    cannot be silently unsealed against a different safe prime)."""
    return {
        "p": hex(f.p),
        "q": hex(f.q) if f.q is not None else None,
        "g": hex(f.g) if f.g is not None else None,
        "h": hex(f.h) if f.h is not None else None,
    }


def _check_bundle_field(bundle, f):
    lock = bundle.get("field")
    if lock is None or lock.get("p") is None:
        raise ValueError("bundle carries no field lock")
    if int(lock["p"], 16) != f.p:
        raise ValueError("bundle was sealed under a different field modulus")


def _bundle_from(transcript, shares, width, field=None):
    proof = transcript.get("proof")
    out = {
        "format": _BUNDLE_FORMAT,
        "field": _field_lock(_commit_field(field)),
        "session": transcript["session"].hex(),
        "threshold": transcript["threshold"],
        "n": transcript["n"],
        "secrets": transcript["secrets"],
        "commitments": [hex(c) for c in transcript["commitments"]],
        "proof": _proof_to_bundle(proof) if proof else None,
        "mac_tags": {("%d,%d" % (i, j)): hex(v)
                     for (i, j), v in transcript["mac_tags"].items()},
        "shares": [{"x": x, "blob": _encode_blob(
            x, s, r, transcript["session"], width).hex()}
            for x, s, r in shares],
    }
    if "weights" in transcript:
        out["weights"] = list(transcript["weights"])
    return out


def _transcript_from_bundle(bundle):
    out = {
        "scheme": _SCHEME,
        "session": bytes.fromhex(bundle["session"]),
        "threshold": bundle["threshold"],
        "n": bundle["n"],
        "secrets": bundle["secrets"],
        "commitments": [int(c, 16) for c in bundle["commitments"]],
        "proof": _proof_from_bundle(bundle["proof"]) if bundle.get("proof")
        else None,
        "mac_tags": {tuple(int(p) for p in k.split(",")): int(v, 16)
                     for k, v in bundle.get("mac_tags", {}).items()},
    }
    if "weights" in bundle:
        out["weights"] = list(bundle["weights"])
    return out


def _bundle_keys(bundle, mac_keys):
    if mac_keys is not None:
        return mac_keys
    if "keys" in bundle:
        return {(i, j): (a, b) for i, j, a, b in bundle["keys"]}
    return None


def _decode_blobs(bundle, blobs, width, session):
    return [_decode_blob(bytes.fromhex(b) if isinstance(b, str) else b,
                         session, width) for b in blobs]


def seal(secret, threshold, n, field=None, randfunc=None, keys=True):
    """Portable unified sharing of an int secret; returns a JSON-safe bundle.

    The bundle embeds the full transcript, a checksummed, session-bound blob
    for each of the n shares, and (keys=True) the dealer's MAC keys.  Hand out
    the per-holder blobs; combined with any threshold+1 of them, unseal
    recovers the secret.  Reproducible via randfunc.
    """
    f = _commit_field(field)
    shares, mac_keys, transcript = _deal([secret], threshold, n, field, randfunc)
    bundle = _bundle_from(transcript, shares, _group_width(f), f)
    bundle["secret_kind"] = "int"
    if keys:
        bundle["keys"] = [[i, j, a, b]
                          for (i, j), (a, b) in mac_keys.items()]
    return bundle


def unseal(bundle, blobs, mac_keys=None, field=None):
    """Recover an int secret from a seal bundle and its share blobs.

    Validates bundle format, public transcript verification, every blob's
    checksum and session binding, then reconstructs with the full pipeline
    (MAC acceptance graph if keys are available, error correction, digest
    screen).  Raises ValueError on any tampering, mixing or a malformed
    bundle.  `blobs` accept bytes or hex strings.
    """
    f = _commit_field(field)
    if bundle.get("format") != _BUNDLE_FORMAT:
        raise ValueError("unknown bundle format")
    if bundle.get("secret_kind") != "int":
        raise ValueError("bytes bundle; use unseal_bytes")
    if bundle.get("secrets") != 1:
        raise ValueError("multi-secret bundles are not supported by unseal"
                         "; use deal_many / combine_many")
    _check_bundle_field(bundle, f)
    width = _group_width(f)
    transcript = _transcript_from_bundle(bundle)
    if not verify_transcript(transcript, f):
        raise ValueError("bundle transcript failed public verification")
    shares = _decode_blobs(bundle, blobs, width, transcript["session"])
    return combine(transcript, shares, _bundle_keys(bundle, mac_keys), f)


def seal_bytes(secret, threshold, n, field=None, randfunc=None, keys=True):
    """Portable unified sharing of a bytes secret (Krawczyk hybrid mode).

    As seal, plus a chunk_map carrying the AEAD ciphertext: the bundle alone
    transports every share blob and every chunk, so the whole sharing is one
    serializable object.
    """
    f = _commit_field(field)
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    shares, mac_keys, transcript, chunk_map = deal_bytes(
        secret, threshold, n, field, randfunc)
    bundle = _bundle_from(transcript, shares, _group_width(f), f)
    bundle["secret_kind"] = "bytes"
    bundle["chunk_map"] = [
        [int(x), [i, length, data.hex()]]
        for x, (i, length, data) in chunk_map.items()]
    if keys:
        bundle["keys"] = [[i, j, a, b]
                          for (i, j), (a, b) in mac_keys.items()]
    return bundle


def unseal_bytes(bundle, blobs, mac_keys=None, field=None):
    """Recover a bytes secret from a seal_bytes bundle and its share blobs.

    Validates everything unseal does, then authenticates and decrypts the
    reassembled AEAD ciphertext.  Raises ValueError on tampering.
    """
    f = _commit_field(field)
    if bundle.get("format") != _BUNDLE_FORMAT:
        raise ValueError("unknown bundle format")
    if bundle.get("secret_kind") != "bytes":
        raise ValueError("int bundle; use unseal")
    _check_bundle_field(bundle, f)
    width = _group_width(f)
    transcript = _transcript_from_bundle(bundle)
    if not verify_transcript(transcript, f):
        raise ValueError("bundle transcript failed public verification")
    shares = _decode_blobs(bundle, blobs, width, transcript["session"])
    chunk_map = {int(x): (i, length, bytes.fromhex(data))
                 for x, (i, length, data) in bundle["chunk_map"]}
    return combine_bytes(transcript, shares, chunk_map,
                         _bundle_keys(bundle, mac_keys), f)
