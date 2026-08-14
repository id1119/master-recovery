"""Feldman VSS (1987) and Pedersen VSS (1991) over the order-q subgroup.

Feldman VSS (FOCS 1987, "A Practical Scheme for Non-interactive Verifiable
Secret Sharing") broadcasts commitments g^{a_j} so each shareholder verifies
its share non-interactively; hiding of the secret is only computational.
Pedersen VSS (CRYPTO 1991, "Non-Interactive and Information-Theoretic Secure
Verifiable Secret Sharing") adds a random masking polynomial so the secret is
hidden information-theoretically while binding stays computational.

Secrets, polynomial coefficients and shares live in Z_q (q the prime subgroup
order; the safe prime is p = 2q + 1); commitments are exponents mod p checked
to lie in the order-q subgroup via field.commit / field.commit_double.  The
classic bug this module avoids is interpolating shares over p instead of q.
"""

from . import core
from .gf import GF, SHARE_INDEX_MAX, SHARE_INDEX_MIN


def _require_vss_field(field):
    if field.q is None or field.g is None:
        raise ValueError("VSS needs a field with subgroup order q and generator g;"
                         " use shamir.gf.default_field()")
    return field


def _qfield(field):
    return GF(field.q)


def _validate_params(threshold, n):
    if not (1 <= threshold < n):
        raise ValueError("require 1 <= threshold < n")
    if n > SHARE_INDEX_MAX - 1:
        raise ValueError("n must be <= 253 (share index space)")


def _rand(randfunc, field):
    return randfunc if randfunc is not None else field.random


def _poly(secret, threshold, field, rand):
    return [secret % field.q] + [rand() % field.q for _ in range(threshold)]


def _check_index(x):
    if not (SHARE_INDEX_MIN <= x < SHARE_INDEX_MAX):
        raise ValueError("share index %s outside 1..253" % x)


def _check_feldman_share(share, field):
    if len(share) != 2:
        raise ValueError("Feldman share must be a (x, y) pair")
    x, y = share
    _check_index(x)
    if y % field.q == 0:
        raise ValueError("share value y == 0 (mod q) rejected")


def _check_pedersen_pair(pair, field):
    if len(pair) != 3:
        raise ValueError("Pedersen share must be a (x, s, t) triple")
    x, s, t = pair
    _check_index(x)
    if s % field.q == 0 or t % field.q == 0:
        raise ValueError("share with s == 0 or t == 0 (mod q) rejected")


def feldman_deal(secret, threshold, n, field=None, randfunc=None):
    """Feldman VSS (FOCS 1987): deal a (t+1)-out-of-n sharing, commitments g^{a_j}.

    Returns (shares, commitments) where shares = [(x, y)] with x in 1..n, y in
    Z_q, and commitments[j] = g^{a_j} mod p for the coefficients a_0 = s, ...
    """
    field = _require_vss_field(core.field_for(field))
    _validate_params(threshold, n)
    rand = _rand(randfunc, field)
    qfield = _qfield(field)
    for _ in range(100):
        coeffs = _poly(secret, threshold, field, rand)
        shares = [(x, qfield.polynomial_eval(coeffs, x)) for x in range(1, n + 1)]
        if all(y != 0 for _, y in shares):
            break
    else:
        raise ValueError("could not draw a polynomial with all-nonzero shares")
    commitments = [field.commit(c) for c in coeffs]
    return shares, commitments


def feldman_verify(share, commitments, field=None):
    """Feldman (1987) share check: g^y == prod_j C_j^{x^j} mod p.  Returns bool."""
    field = _require_vss_field(core.field_for(field))
    _check_feldman_share(share, field)
    if not commitments:
        raise ValueError("empty commitments list")
    x, y = share
    return field.commit(y) == field.eval_commit(commitments, x)


def feldman_combine(shares, commitments, field=None):
    """Feldman (1987) verify-then-interpolate (over Z_q); raises on any bad share."""
    field = _require_vss_field(core.field_for(field))
    if len(shares) < len(commitments):
        raise ValueError("need at least threshold + 1 (%s) shares, got %s"
                         % (len(commitments), len(shares)))
    valid = []
    for share in shares:
        if not feldman_verify(share, commitments, field):
            raise ValueError("share at index %s failed verification" % (share[0],))
        valid.append(share)
    return core.interpolate_at(valid[:len(commitments)], 0, _qfield(field))


def feldman_polynomial(shares, commitments, field=None):
    """Feldman (1987): interpolate the committed polynomial from verified shares.

    Every share is re-verified against the commitments, then
    core.interpolate_polynomial (over Z_q) recovers the polynomial values on
    the share points (used by higher layers, e.g. verifiable redistribution).
    """
    field = _require_vss_field(core.field_for(field))
    degree = len(commitments) - 1
    if len(shares) != degree + 1:
        raise ValueError("need degree + 1 (%s) shares, got %s" % (degree + 1, len(shares)))
    for share in shares:
        if not feldman_verify(share, commitments, field):
            raise ValueError("share at index %s failed verification" % (share[0],))
    return core.interpolate_polynomial(list(shares), degree, _qfield(field))


def pedersen_deal(secret, threshold, n, field=None, randfunc=None):
    """Pedersen VSS (CRYPTO 1991): share with a random masking polynomial.

    Returns (pairs, commitments) with pairs = [(x, s, t)], t_i = f'(i) a
    blinder, and commitments[j] = g^{a_j} h^{b_j}.  Hiding is
    information-theoretic because C_0 masks the secret with random b_0.
    """
    field = core.field_for(field)
    _validate_params(threshold, n)
    if field.g is None or field.h is None or field.q is None:
        raise ValueError("Pedersen VSS needs g, h and q; use shamir.gf.default_field()"
                         " (it configures h deterministically)")
    rand = _rand(randfunc, field)
    qfield = _qfield(field)
    for _ in range(100):
        f = _poly(secret, threshold, field, rand)
        fp = _poly(rand() % field.q, threshold, field, rand)  # b_0 uniform random
        pairs = [
            (x, qfield.polynomial_eval(f, x), qfield.polynomial_eval(fp, x))
            for x in range(1, n + 1)
        ]
        if all(s != 0 and t != 0 for _, s, t in pairs):
            break
    else:
        raise ValueError("could not draw polynomials with all-nonzero shares")
    commitments = [field.commit_double(a, b) for a, b in zip(f, fp)]
    return pairs, commitments


def pedersen_verify(pair, commitments, field=None):
    """Pedersen (CRYPTO 1991) pair check: g^s h^t == prod_j C_j^{x^j}.  Returns bool."""
    field = core.field_for(field)
    if field.g is None or field.h is None or field.q is None:
        raise ValueError("Pedersen VSS needs g, h and q; use shamir.gf.default_field()")
    _check_pedersen_pair(pair, field)
    if not commitments:
        raise ValueError("empty commitments list")
    x, s, t = pair
    return field.commit_double(s, t) == field.eval_commit(commitments, x)


def pedersen_combine(pairs, commitments, field=None):
    """Pedersen (1991) reconstruction: verify all pairs, interpolate s_i only.

    The t_i blinders are ignored for reconstruction (as per the paper).
    Interpolation happens over Z_q.
    """
    field = core.field_for(field)
    if field.g is None or field.h is None or field.q is None:
        raise ValueError("Pedersen VSS needs g, h and q; use shamir.gf.default_field()")
    if len(pairs) < len(commitments):
        raise ValueError("need at least threshold + 1 (%s) pairs, got %s"
                         % (len(commitments), len(pairs)))
    valid = []
    for pair in pairs:
        if not pedersen_verify(pair, commitments, field):
            raise ValueError("pair at index %s failed verification" % (pair[0],))
        valid.append(pair)
    points = [(x, s) for x, s, _ in valid[:len(commitments)]]
    return core.interpolate_at(points, 0, _qfield(field))