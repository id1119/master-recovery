"""Robust reconstruction of Shamir shares.

Two independent robustness improvements over plain Shamir:

* McEliece & Sarwate (CACM 1981): Shamir shares are the codewords of an
  [n, t+1, n-t] Reed-Solomon code, so Berlekamp-Welch decoding recovers the
  polynomial even when up to floor((n-t-1)/2) shares are corrupted.
* Rabin & Ben-Or (STOC 1989): information-theoretic pairwise MAC tags let
  holders detect substituted shares at reconstruction time with no
  number-theoretic assumptions.
"""

import secrets

from . import core
from .gf import default_field

_GF256_MAC_WARNING = "MAC fields must be >= 128 bits; use the default 512-bit safe-prime field"


def _arith(field):
    return core.field_for(field).share_field()


def _solve_linear(matrix, vec, field):
    """Gauss-Jordan over GF(p).  Returns a particular solution, or raises
    ValueError on an inconsistent system.  Rank-deficient (but consistent)
    systems return a solution with free variables set to zero."""
    n = len(vec)
    m = [row[:] + [vec[i]] for i, row in enumerate(matrix)]
    rows, cols = n, len(matrix[0])
    pivot_col = []
    r = 0
    for c in range(cols):
        pivot = next((rr for rr in range(r, rows) if m[rr][c] != 0), None)
        if pivot is None:
            continue
        m[r], m[pivot] = m[pivot], m[r]
        inv = field.inv(m[r][c])
        m[r] = [field.mul(v, inv) for v in m[r]]
        for rr in range(rows):
            if rr != r and m[rr][c] != 0:
                factor = m[rr][c]
                m[rr] = [field.sub(m[rr][k], field.mul(factor, m[r][k]))
                         for k in range(cols + 1)]
        pivot_col.append(c)
        r += 1
        if r == rows:
            break
    for rr in range(r, rows):
        if any(m[rr][k] != 0 for k in range(cols)):
            raise ValueError("inconsistent linear system (undecodable)")
    sol = [0] * cols
    for rr, c in enumerate(pivot_col):
        sol[c] = m[rr][cols]
    return sol


def _poly_divide(num, den, field):
    """Polynomial long division over GF(p); returns (quotient, remainder)."""
    num = list(num)
    den = [c % field.p for c in den]
    q = [0] * (len(num) + 1)
    while num:
        while num and num[-1] == 0:
            num.pop()
        if not num or len(num) < len(den):
            break
        shift = len(num) - len(den)
        factor = field.div(num[-1], den[-1])
        q[shift] = field.add(q[shift], factor)
        for i in range(len(den)):
            num[i + shift] = field.sub(num[i + shift], field.mul(factor, den[i]))
        num.pop()
    while q and q[-1] == 0:
        q.pop()
    return q, num


def _poly_eval(coeffs, x, field):
    acc = 0
    for c in reversed(coeffs):
        acc = field.add(field.mul(acc, x), c)
    return acc


def berlekamp_welch(points, degree, field=None):
    """Berlekamp-Welch unique decoding of Shamir shares (McEliece-Sarwate).

    Recovers the degree-`degree` polynomial through `points`, correcting up to
    floor((n - degree - 1)/2) errors.  Raises ValueError if the word is
    undecodable (too many errors).

    For error budget e, solve Q(x_i) = E(x_i) * y_i with deg Q = degree + e,
    E monic deg e, then f = Q / E.  The budget starts at 0 and grows; any
    solution of a consistent system satisfies Q = f*E on the true polynomial,
    and the fit check rejects words beyond the correction radius.
    """
    field = _arith(field)
    n = len(points)
    if n <= degree:
        raise ValueError("need more points than the degree")
    xs = [x for x, _ in points]
    ys = [y for _, y in points]
    if len(set(xs)) != n:
        raise ValueError("duplicate share x-coordinates")

    e_max = (n - degree - 1) // 2
    last_error = None
    for e in range(0, e_max + 1):
        q_deg = degree + e
        matrix = []
        vec = []
        for x, y in zip(xs, ys):
            row = []
            xpow = 1
            for _ in range(q_deg + 1):
                row.append(xpow)
                xpow = field.mul(xpow, x)
            xpow = 1
            for _ in range(e):
                row.append(field.neg(field.mul(y, xpow)))
                xpow = field.mul(xpow, x)
            matrix.append(row)
            vec.append(field.mul(y, xpow))  # y * x^e

        try:
            sol = _solve_linear(matrix, vec, field)
        except ValueError as exc:
            last_error = exc
            continue
        q = sol[:q_deg + 1]
        en = sol[q_deg + 1:] + [1]  # monic E(x) = x^e + e_{e-1} x^{e-1} + ... + e_0

        for x, y in zip(xs, ys):
            if _poly_eval(q, x, field) != field.mul(_poly_eval(en, x, field), y):
                last_error = ValueError("undecodable: Q/E does not fit received points")
                break
        else:
            q = [c for c in q]
            while len(q) > 1 and q[-1] == 0:
                q.pop()
            while len(en) > 1 and en[-1] == 0:
                en.pop()
            if not en or en[-1] != 1:
                last_error = ValueError("undecodable: E not monic")
                continue
            if len(en) - 1 > q_deg or len(q) - 1 < degree:
                last_error = ValueError("undecodable: degree mismatch")
                continue
            quotient, remainder = _poly_divide(q, en, field)
            if remainder:
                last_error = ValueError("undecodable: Q not divisible by E")
                continue
            coeffs = quotient + [0] * (degree + 1 - len(quotient))
            return coeffs[:degree + 1]
    raise last_error or ValueError("undecodable")


def robust_combine(shares, threshold, field=None):
    """Reconstruct despite up to floor((n - t - 1)/2) corrupted shares.

    Shamir shares are an RS codeword (McEliece-Sarwate 1981); the decoder
    either returns the unique consistent secret or raises ValueError.
    """
    field = _arith(field)
    n = len(shares)
    if n <= threshold:
        raise ValueError("need more shares than the threshold")
    coeffs = berlekamp_welch(shares, threshold, field)
    return coeffs[0]


def verify_then_combine(shares, commitments, field=None):
    """Robust reconstruction under Feldman commitments: verify, filter, interpolate."""
    from .vss import feldman_verify
    field = core.field_for(field)
    if len(shares) < len(commitments):
        raise ValueError("need at least threshold + 1 shares")
    valid = [s for s in shares if feldman_verify(s, commitments, field)]
    if len(valid) < len(commitments):
        raise ValueError("too few shares pass Feldman verification")
    return core.combine(valid[:len(commitments)], field)


class PairwiseMACSharing:
    """Rabin-Ben-Or (1989) information-theoretic share authentication.

    For every ordered pair (i, j) the dealer draws a fresh key k_ij in the
    share field and tags holder i's share under j's key.  A share submitted at
    reconstruction is accepted only if it passes the MAC check under at least
    (t+1) distinct other holders' keys; forgery probability is 1/|F| per key.
    """

    def __init__(self, field=None):
        self.field = core.field_for(field)
        if self.field.p.bit_length() < 128:
            raise ValueError(_GF256_MAC_WARNING)

    def deal(self, secret, threshold, n, randfunc=None):
        field = self.field
        if randfunc is not None:
            rand = lambda: randfunc() % field.p
        else:
            rand = lambda: secrets.randbelow(field.p)
        shares = core.share(secret, threshold, n, field, rand)
        keys = {}
        tags = {}
        for i in range(1, n + 1):
            for j in range(1, n + 1):
                if i == j:
                    continue
                keys[(i, j)] = (rand() % field.p, rand() % field.p)
        for i in range(1, n + 1):
            yi = next(y for x, y in shares if x == i)
            for j in range(1, n + 1):
                if i == j:
                    continue
                a, b = keys[(i, j)]
                tags[(i, j)] = field.add(field.mul(a, yi), b)
        return shares, keys, tags

    def check(self, share, index, mac_keys, mac_tags, min_ok=None):
        """True iff `share` passes >= min_ok (default: t+1) distinct MAC checks."""
        field = self.field
        x, y = share
        if x != index:
            return False
        ok = 0
        total = 0
        for (i, j) in mac_keys:
            if i != index:
                continue
            total += 1
            a, b = mac_keys[(i, j)]
            expected = mac_tags.get((index, j))
            if expected is not None and field.add(field.mul(a, y), b) == expected:
                ok += 1
        if min_ok is None:
            min_ok = total // 2 + 1
        return ok >= min_ok
