"""Proactive secret sharing: Herzberg, Jarecki, Krawczyk, Yung (CRYPTO 1995).

Defends against mobile adversaries by periodically re-randomizing all shares:
every party deals a random degree-t polynomial with ZERO constant term
(a "refresh polynomial"), every recipient verifies the received delta against
broadcast Feldman commitments, and each party updates s'_j = s_j + sum_i
delta_i(j).  The secret is unchanged (sum of constants is 0) while the new
sharing polynomial is fresh and independent -- old shares are useless.

Secure erasure of pre-refresh state is the operator's responsibility; this
module enforces the zero-constant and verification discipline.
"""

import secrets

from . import core
from .gf import default_field


def _arith(field):
    return core.field_for(field).share_field()


def _commit_field(field):
    f = core.field_for(field)
    if f.g is None or f.q is None:
        raise ValueError("refresh needs a field with subgroup generator g and"
                         " order q; use shamir.gf.default_field()")
    return f


def _zero_poly(threshold, field, rand):
    return [0] + [rand() % field.p for _ in range(threshold)]


def _eval_refresh_commit(comm, x, cf):
    """prod_l C_l^{x^(l+1)} for refresh commitments [g^{a_1}..g^{a_t}].

    Refresh commitments deliberately omit C_0 (the constant term is committed
    as 0), so eval_commit's 0-based indexing does not apply.
    """
    acc = 1
    xpow = x % cf.q
    for c in comm:
        acc = (acc * pow(c, xpow, cf.p)) % cf.p
        xpow = (xpow * x) % cf.q
    return acc


def refresh(share, threshold, n, field=None, randfunc=None, corrupt=()):
    """Dealer-free refresh as seen by the holder of `share` (index = x).

    Simulates the full period: all n players deal delta_i (degree t, zero
    constant), commitments are broadcast, every incoming delta is verified
    against the commitments before being added (a delta with a nonzero
    constant term fails verification and raises ValueError).

    Returns (new_share, commitments, own_deltas, received_deltas):
    * commitments: {dealer_index: [C_1..C_t]} (constant term committed as 0)
    * own_deltas:  this player's delta evaluated at every recipient j in 1..n
    * received_deltas: [(dealer_index, delta_dealer(index_x))] for all dealers

    `corrupt` is a set of dealer indices that deliberately deal a polynomial
    with nonzero constant term (to test detection) -- the refresh then raises
    ValueError naming the first corrupt dealer detected.
    """
    f = _arith(field)
    cf = _commit_field(field)
    x, y = share
    if not (1 <= x <= n):
        raise ValueError("share index must be a player id in 1..n")
    if randfunc is not None:
        rand = lambda: randfunc() % f.p
    else:
        rand = lambda: secrets.randbelow(f.p)

    commitments = {}
    own_deltas = []
    received = []
    for dealer in range(1, n + 1):
        if dealer in corrupt:
            coeffs = [rand() % f.p] + [rand() % f.p for _ in range(threshold)]
        else:
            coeffs = _zero_poly(threshold, f, rand)
        comm = [cf.commit(c) for c in coeffs[1:]]
        commitments[dealer] = comm
        for recipient in range(1, n + 1):
            d = f.polynomial_eval(coeffs, recipient)
            if recipient == x:
                received.append((dealer, d))
            if dealer == x:
                own_deltas.append(d)
        if dealer != x:
            d = f.polynomial_eval(coeffs, x)
            expected = _eval_refresh_commit(comm, x, cf)
            if cf.commit(d) != expected:
                raise ValueError("refresh failed: dealer %d dealt an invalid"
                                 " (non-zero-constant) polynomial" % dealer)

    new_y = y
    for _, d in received:
        new_y = f.add(new_y, d)
    return (x, new_y), commitments, own_deltas, received


def refresh_verify(new_share, old_share, received_deltas, commitments, field=None):
    """Verify a refresh transcript: deltas match commitments, sum is the delta.

    Returns True iff every delta verifies against the dealer's commitments
    (proving zero constant term) and new_y == old_y + sum(deltas).
    """
    f = _arith(field)
    cf = _commit_field(field)
    if new_share[0] != old_share[0]:
        return False
    total = 0
    for dealer, d in received_deltas:
        comm = commitments.get(dealer)
        if comm is None:
            return False
        if cf.commit(d) != _eval_refresh_commit(comm, old_share[0], cf):
            return False
        total = f.add(total, d)
    return new_share[1] == f.add(old_share[1], total)


def recover_share(index, contributor_shares, threshold, field=None):
    """Reconstruct a lost share (index) from >= threshold+1 other players' shares.

    contributors: [(j, f(j))] with j != index.  Returns (index, f(index)).
    The player can be back up-to-date for the current period after adding the
    refresh deltas it missed (caller's job).
    """
    f = _arith(field)
    if len(contributor_shares) < threshold + 1:
        raise ValueError("need at least threshold + 1 contributor shares")
    cache = core.LagrangeCache([j for j, _ in contributor_shares], f)
    y = cache.evaluate([v for _, v in contributor_shares], index)
    return (index, y)
