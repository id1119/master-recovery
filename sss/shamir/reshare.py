"""Desmedt-Jarecki (1993) verifiable redistribution of secret shares.

"Redistributing Secret Shares to New Participants" (CRYPTO '93): the t+1
holders of a degree-t polynomial P each deal a fresh degree-t' polynomial
h_i with h_i(0) equal to their own share; recipient j combines
sum_i lambda_i * h_i(j), where the lambda_i are the Lagrange coefficients
at 0 over the holder x-set.  The new polynomial P'(x) = sum_i lambda_i h_i(x)
satisfies P'(0) = P(0) and deg P' <= t'.  Feldman commitments of each h_i
let every recipient verify the dealt values, and the new commitments are
derived in the exponent: C'_j = prod_i C_{i,j}^{lambda_i}.

change_threshold is the single-dealer variant: the dealer verifies the old
shares against the old commitments, recovers the secret, and deals a fresh
sharing under the new threshold and participant count.

Secrets, coefficients and shares live in Z_q; commitments are exponents mod
p checked into the order-q subgroup (see gf.commit).
"""

from . import core
from . import vss
from .gf import GF, SHARE_INDEX_MAX


def _require_vss_field(field):
    if field.q is None or field.g is None:
        raise ValueError("reshare needs a field with subgroup order q and generator g;"
                         " use shamir.gf.default_field()")
    return field


def _qfield(field):
    return GF(field.q)


def _validate_shares(shares, old_commitments, field):
    if not old_commitments:
        raise ValueError("empty old commitments list")
    if len(shares) < len(old_commitments):
        raise ValueError("need at least t+1 (%s) old shares, got %s"
                         % (len(old_commitments), len(shares)))
    for share in shares:
        if not vss.feldman_verify(share, old_commitments, field):
            raise ValueError("old share at index %s failed verification" % (share[0],))
    holders = shares[:len(old_commitments)]
    if len(set(x for x, _ in holders)) != len(holders):
        raise ValueError("duplicate share x-coordinates among holders")


def _validate_new_params(new_threshold, new_n):
    if not (1 <= new_threshold < new_n):
        raise ValueError("require 1 <= new_threshold < new_n")
    if new_n > SHARE_INDEX_MAX - 1:
        raise ValueError("new_n must be <= 253 (share index space)")


def redistribute(shares, old_commitments, new_threshold, new_n, field=None, randfunc=None):
    """Desmedt-Jarecki (1993): verifiable redistribution to new participants.

    All old shares are verified against the Feldman commitments; the first
    t+1 form the holder set A.  Each holder deals a fresh degree-new_threshold
    polynomial h_i with h_i(0) = own share; recipient j combines
    sum_i lambda_i * h_i(j).  New commitments are derived in the exponent:
    C'_j = prod_i C_{i,j}^{lambda_i}.
    Returns ([(1, y'_1)..(new_n, y'_new_n)], [C'_0..C'_new_threshold]).
    """
    field = _require_vss_field(core.field_for(field))
    qfield = _qfield(field)
    _validate_new_params(new_threshold, new_n)
    _validate_shares(shares, old_commitments, field)
    holders = shares[:len(old_commitments)]
    xs = [x for x, _ in holders]
    lambdas = core.lagrange_coefficient(xs, 0, qfield)
    rand = randfunc if randfunc is not None else field.random
    for _ in range(100):
        dealt = []
        dealt_commits = []
        for (x, y), lam in zip(holders, lambdas):
            coeffs = [y % field.q] + [rand() % field.q for _ in range(new_threshold)]
            cs = [field.commit(c) for c in coeffs]
            vals = [qfield.polynomial_eval(coeffs, j) for j in range(1, new_n + 1)]
            for j, d in zip(range(1, new_n + 1), vals):
                if field.commit(d) != field.eval_commit(cs, j):
                    raise ValueError("holder %s dealt an unverifiable value" % x)
            dealt.append(vals)
            dealt_commits.append(cs)
        new_shares = []
        for j in range(1, new_n + 1):
            acc = 0
            for vals, lam in zip(dealt, lambdas):
                acc = qfield.add(acc, qfield.mul(vals[j - 1], lam))
            new_shares.append((j, acc))
        if all(y != 0 for _, y in new_shares):
            break
    else:
        raise ValueError("could not draw dealer polynomials with all-nonzero shares")
    new_commitments = []
    for j in range(new_threshold + 1):
        acc = 1
        for cs, lam in zip(dealt_commits, lambdas):
            acc = (acc * pow(cs[j], lam, field.p)) % field.p
        new_commitments.append(acc)
    return new_shares, new_commitments


def change_threshold(shares, old_commitments, new_threshold, new_n, field=None):
    """Single-dealer threshold change: re-deal the same secret under new params.

    The dealer verifies every old share against the Feldman commitments,
    recovers the secret by interpolation at 0 over Z_q, and deals a fresh
    (new_threshold+1)-of-new_n sharing with fresh commitments via
    vss.feldman_deal.
    """
    field = _require_vss_field(core.field_for(field))
    qfield = _qfield(field)
    _validate_new_params(new_threshold, new_n)
    _validate_shares(shares, old_commitments, field)
    holders = shares[:len(old_commitments)]
    secret = core.interpolate_at(holders, 0, qfield)
    return vss.feldman_deal(secret, new_threshold, new_n, field)
