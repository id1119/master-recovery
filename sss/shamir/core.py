"""Base Shamir secret sharing (Shamir 1979) over any of the supported fields.

Plain (t+1)-out-of-n threshold sharing: the secret is the constant term of a
random degree-t polynomial, shares are evaluations at x in {1..n}.  Also
provides the generic interpolation primitives (whole polynomial, single point,
precomputed Lagrange coefficients) that every other layer in this package
builds on.
"""

import secrets

from .gf import GF, default_field
from .gf256 import FIELD_256, GF256


def field_for(field):
    """Resolve the configured field (GF(p) with optional subgroup params)."""
    return field if field is not None else default_field()


def _arith(field):
    """Resolve the arithmetic domain: GF(q) for safe-prime fields, else GF(p)."""
    return field_for(field).share_field()


def _points_ok(points):
    xs = [x for x, _ in points]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    return xs


def lagrange_coefficient(xs, at, field):
    """lambda = prod_{j != i} (at - xs[j]) / (xs[i] - xs[j]) for each i in xs."""
    out = []
    for i, xi in enumerate(xs):
        num = 1
        den = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = field.mul(num, field.sub(at, xj))
            den = field.mul(den, field.sub(xi, xj))
        out.append(field.div(num, den))
    return out


def interpolate_at(points, at, field=None):
    """Lagrange interpolation of the unique polynomial through `points` at x=at.

    Requires len(points) == degree+1 points (use interpolate_polynomial or a
    cache when many evaluations are needed).
    """
    field = _arith(field)
    xs = _points_ok(points)
    lambdas = lagrange_coefficient(xs, at, field)
    acc = 0
    for (_, y), lam in zip(points, lambdas):
        acc = field.add(acc, field.mul(y, lam))
    return acc


def interpolate_polynomial(points, degree, field=None):
    """Recover the coefficient list [a_0..a_degree] through `points` (degree+1 pts)."""
    field = _arith(field)
    n = len(points)
    if n != degree + 1:
        raise ValueError("need exactly degree+1 points for interpolation")
    xs = _points_ok(points)
    return [interpolate_at(points, x, field) for x in xs]


class LagrangeCache:
    """Precomputed Lagrange coefficients for a fixed x-set (dealer-side opt).

    Allows O(t) evaluation of the interpolated polynomial at new points, which
    is what makes verifiable redistribution and share re-issuance cheap.
    """

    def __init__(self, xs, field=None):
        self.field = _arith(field)
        self.xs = list(xs)
        self._denoms = []
        for i, xi in enumerate(self.xs):
            den = 1
            for j, xj in enumerate(self.xs):
                if i != j:
                    den = self.field.mul(den, self.field.sub(xi, xj))
            self._denoms.append(den)

    def coefficient(self, at):
        """lambda_i for each i, evaluating at x=at."""
        out = []
        for i, xi in enumerate(self.xs):
            num = 1
            for j, xj in enumerate(self.xs):
                if i != j:
                    num = self.field.mul(num, self.field.sub(at, xj))
            out.append(self.field.div(num, self._denoms[i]))
        return out

    def evaluate(self, ys, at):
        """The interpolated polynomial (through (xs, ys)) evaluated at x=at."""
        lam = self.coefficient(at)
        acc = 0
        for y, l in zip(ys, lam):
            acc = self.field.add(acc, self.field.mul(y, l))
        return acc


def share(secret, threshold, n, field=None, randfunc=None, points=None):
    """Shamir (threshold, n) sharing of an int secret over GF(p).

    Returns list of (x, y).  threshold is t (t+1 shares needed).
    """
    field = _arith(field)
    if not (1 <= threshold < n):
        raise ValueError("require 1 <= threshold < n")
    if points is None:
        points = list(range(1, n + 1))
    if len(points) != n or len(set(points)) != n:
        raise ValueError("need n distinct share points")
    rand = randfunc or secrets.randbelow
    poly = field.random_polynomial(threshold, constant=secret)
    return [(x, field.polynomial_eval(poly, x)) for x in points]


def combine(shares, field=None):
    """Reconstruct the secret from any threshold+1 shares (interpolate at 0)."""
    field = _arith(field)
    return interpolate_at(shares, 0, field)


def derive_share(shares, x, field=None):
    """Compute a new share at x from `threshold+1` existing shares (no secret).

    This is secrets.js-style `newShare` / re-issuance.
    """
    field = _arith(field)
    cache = LagrangeCache([s[0] for s in shares], field)
    y = cache.evaluate([s[1] for s in shares], x)
    return (x, y)


# --------------------------------------------------------------------------
# Byte-oriented mode over GF(2^8) (Vault/libgfshare-style)
# --------------------------------------------------------------------------

def share_bytes(secret, threshold, n, points=None):
    """Shamir sharing of a bytes secret over GF(2^8), one byte per share byte.

    Returns list of (x, bytes).  The x=0 index is forbidden (secret leak).
    """
    field = FIELD_256
    if not (1 <= threshold < n <= 254):
        raise ValueError("require 1 <= threshold < n <= 254")
    if points is None:
        points = list(range(1, n + 1))
    if len(points) != n or len(set(points)) != n:
        raise ValueError("need n distinct share points")
    polys = [field.random_polynomial(threshold, constant=b) for b in secret]
    out = []
    for x in points:
        y = bytes(field.polynomial_eval(poly, x) for poly in polys)
        out.append((x, y))
    return out


def combine_bytes(shares):
    """Reconstruct a bytes secret from threshold+1 GF(2^8) shares."""
    field = FIELD_256
    shares = [(x, bytes(y)) for x, y in shares]
    nbytes = len(shares[0][1])
    if any(len(y) != nbytes for _, y in shares):
        raise ValueError("share lengths differ")
    out = bytearray()
    for b in range(nbytes):
        pts = [(x, y[b]) for x, y in shares]
        out.append(interpolate_at(pts, 0, field))
    return bytes(out)


def derive_share_bytes(shares, x):
    """New GF(2^8) share at x from threshold+1 existing shares."""
    field = FIELD_256
    nbytes = len(shares[0][1])
    cache = LagrangeCache([s[0] for s in shares], field)
    y = bytes(cache.evaluate([s[1][b] for s in shares], x) for b in range(nbytes))
    return (x, y)
