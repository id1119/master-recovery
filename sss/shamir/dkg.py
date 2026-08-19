"""Dealer-free key generation: Pedersen DKG (1991) / JVRSS (FROST, RFC 9591).

Every party acts as a Feldman-dealer of a random polynomial; each recipient
verifies every received share against the broadcast commitments; a Schnorr
proof of knowledge of a0 (FROST's addition) stops rogue-key/key-race attacks;
disqualified dealers are excluded from the QUAL set; the group public key is
g^{sum of qualified a0}.  Shares sum to the group secret -- no party ever sees
it.

Caveat (documented per GJKR J. Cryptology 2007): this one-round parallel
Feldman DKG can in principle be biased by an adversary that disqualifies
dealers after seeing their commitments; the 3-round GIJKR New-DKG fixes that.
This module provides the practically standard 1-round + PoK variant used by
threshold-signature deployments.
"""

import hashlib
import secrets

from . import core
from .gf import default_field

_POK_DOMAIN = b"sssx dkg pok v1"


def _arith(field):
    return core.field_for(field).share_field()


def _commit_field(field):
    f = core.field_for(field)
    if f.g is None or f.q is None:
        raise ValueError("DKG needs a field with subgroup generator g and order"
                         " q; use shamir.gf.default_field()")
    return f


def _hash_pok(index, v, c0):
    h = hashlib.sha256(_POK_DOMAIN + index.to_bytes(2, "big")
                       + v.to_bytes(64, "big") + c0.to_bytes(64, "big")).digest()
    return int.from_bytes(h, "big")


def dkg_deal(index, threshold, n, field=None, randfunc=None):
    """Deal one party's contribution: (poly, commitments, pok).

    poly:       coefficients [a_0..a_t] in Z_q (secret z = a_0 mod q)
    commitments: [g^a_j] for j = 0..t
    pok:        Schnorr proof of knowledge of a_0
    """
    f = _arith(field)
    cf = _commit_field(field)
    if not (1 <= threshold < n):
        raise ValueError("require 1 <= threshold < n")
    rand = randfunc if randfunc is not None else (lambda: secrets.randbelow(f.p))
    poly = [rand() % f.p for _ in range(threshold + 1)]
    commitments = [cf.commit(c) for c in poly]
    v = rand() % f.p or 1
    big = cf.commit(v)
    c = _hash_pok(index, big, commitments[0]) % f.p
    z = (v + c * poly[0]) % f.p
    pok = {"V": big, "challenge": c, "response": z}
    return poly, commitments, pok


def dkg_verify_share(dealer_commitments, recipient_index, received_share,
                     field=None):
    """FROST share check: g^{share} == prod_j C_j^{recipient_index^j}."""
    cf = _commit_field(field)
    f = _arith(field)
    share = received_share % f.p
    return cf.commit(share) == cf.eval_commit(dealer_commitments, recipient_index)


def dkg_pok_verify(pok, commitment_a0, index, field=None):
    """Verify the Schnorr proof of knowledge of a0 (FROST)."""
    cf = _commit_field(field)
    f = _arith(field)
    try:
        cf._check_subgroup(pok["V"])
    except ValueError:
        return False
    c = _hash_pok(index, pok["V"], commitment_a0) % f.p
    return cf.commit(pok["response"]) == cf.mul(pok["V"],
                                                cf.pow(commitment_a0, c))


def dkg_combine(shares_by_recipient, qual, commitments0, threshold, field=None):
    """Final shares and public key over the QUAL set.

    shares_by_recipient: {recipient_index: [(dealer_index, value), ...]}
    qual:                sorted qualified dealer indices
    commitments0:        {dealer_index: g^a0} used for the public key
    Returns (final_shares, public_key).
    """
    f = _arith(field)
    cf = _commit_field(field)
    final = {}
    for recipient, entries in shares_by_recipient.items():
        acc = 0
        for dealer, value in entries:
            if dealer in qual:
                acc = f.add(acc, value % f.p)
        final[recipient] = acc
    pk = 1
    for dealer in qual:
        pk = cf.mul(pk, commitments0[dealer])
    return final, pk


def dkg_run(n, threshold, field=None, randfunc=None, corrupt=(), corrupt_pok=()):
    """End-to-end honest-path DKG with complaint handling.

    Every dealer deals a polynomial; every recipient verifies every received
    share (complaint on failure); every proof of knowledge is verified; failed
    dealers are excluded from QUAL; final shares + group public key emerge.

    corrupt:     dealer indices that hand a WRONG share to one recipient
    corrupt_pok: dealer indices whose PoK response is tampered (disqualified)

    Returns a dict with keys: shares, public_key, qual, commitments_all,
    poks, complaints, pok_failures, shares_by_recipient.
    """
    f = _arith(field)
    cf = _commit_field(field)
    if randfunc is not None:
        rand = lambda: randfunc() % f.p
    else:
        rand = lambda: secrets.randbelow(f.p)

    deals = {}
    for dealer in range(1, n + 1):
        poly, commitments, pok = dkg_deal(dealer, threshold, n, field, rand)
        deals[dealer] = (poly, commitments, pok)

    shares_by_recipient = {r: [] for r in range(1, n + 1)}
    complaints = []
    for dealer, (poly, _commitments, _pok) in deals.items():
        for recipient in range(1, n + 1):
            share = f.polynomial_eval(poly, recipient)
            if dealer in corrupt and recipient == (dealer % n) + 1:
                share = f.add(share, 1)
            shares_by_recipient[recipient].append((dealer, share))
            if not dkg_verify_share(deals[dealer][1], recipient, share, field):
                complaints.append((dealer, recipient))

    pok_failures = []
    for dealer, (_poly, commitments, pok) in deals.items():
        if dealer in corrupt_pok:
            pok = {"V": pok["V"], "challenge": pok["challenge"],
                   "response": f.add(pok["response"], 1)}
        if not dkg_pok_verify(pok, commitments[0], dealer, field):
            pok_failures.append(dealer)

    disqualified = {d for d, _ in complaints} | set(pok_failures)
    qual = sorted(set(range(1, n + 1)) - disqualified)
    commitments0 = {d: deals[d][1][0] for d in qual}
    final, pk = dkg_combine(shares_by_recipient, qual, commitments0, threshold,
                            field)
    return {
        "shares": final,
        "public_key": pk,
        "qual": qual,
        "commitments_all": {d: deals[d][1] for d in deals},
        "poks": {d: deals[d][2] for d in deals},
        "complaints": complaints,
        "pok_failures": pok_failures,
        "shares_by_recipient": shares_by_recipient,
    }