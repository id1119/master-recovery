"""Yang, Chang and Hwang (2004) multi-secret sharing (the sound p <= t case).

A single degree-t polynomial h^ over GF(p) carries p <= t independent secrets
s_0..s_{p-1} as its lowest coefficients::

    h(x) = s_0 + s_1 x + ... + s_{p-1} x^{p-1} + a_p x^p + ... + a_t x^t

with the t - p higher coefficients chosen uniformly at random.  Shares are
ordinary Shamir evaluations h(x) at x in {1..n}; reconstruction interpolates
the degree-t polynomial from t+1 shares and reads off the lowest p
coefficients (Newton divided differences expanding into the monomial basis).
"""

from . import core


def _arith(field):
    """Resolve the configured arithmetic field (Z_q for safe-prime fields)."""
    return core.field_for(field).share_field()


def _newton_coefficients(points, field):
    """Monomial coefficients [a_0..a_degree] of the poly through `points`.

    Newton divided differences, then expansion of the Newton form into the
    standard monomial basis over GF(field.p).
    """
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


def share_secrets(secrets, threshold, n, field=None, randfunc=None):
    """Yang-Chang-Hwang (2004): share p = len(secrets) secrets in one (t, n) scheme.

    The first p coefficients of a degree-t polynomial are the secrets, the rest
    random; returns [(x, h(x))] for x in 1..n.  Requires 1 <= p <= threshold.
    """
    field = core.field_for(field)
    pcount = len(secrets)
    if pcount < 1 or pcount > threshold:
        raise ValueError("need 1 <= len(secrets) <= threshold, got %s" % pcount)
    if not (1 <= threshold < n):
        raise ValueError("require 1 <= threshold < n")
    for s in secrets:
        if s < 0 or s >= field.p:
            raise ValueError("secret %s outside field range [0, %s)" % (s, field.p))
    arith = _arith(field)
    rand = randfunc or arith.random
    coeffs = [arith.element(s) for s in secrets]
    coeffs += [rand() % arith.p for _ in range(threshold + 1 - pcount)]
    return [(x, arith.polynomial_eval(coeffs, x)) for x in range(1, n + 1)]


def combine_secrets(shares, n_secrets, field=None):
    """Recover the p = n_secrets lowest coefficients from threshold+1 shares.

    Interpolates the degree-(len(shares)-1) polynomial and extracts a_0..a_{p-1}
    (works whenever `shares` lie on a common degree-t polynomial).  Requires
    1 <= n_secrets <= len(shares) - 1; raises on duplicate x-coordinates.
    """
    field = _arith(field)
    if n_secrets < 1 or n_secrets > len(shares) - 1:
        raise ValueError("need 1 <= n_secrets <= len(shares)-1, got %s" % n_secrets)
    if any(len(share) != 2 for share in shares):
        raise ValueError("every share must be a (x, y) pair")
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share x-coordinates")
    coeffs = _newton_coefficients(shares, field)
    return coeffs[:n_secrets]