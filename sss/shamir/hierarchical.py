"""Hierarchical threshold secret sharing via Birkhoff interpolation (Tassa 2007).

Implements T. Tassa, "Hierarchical Threshold Secret Sharing", Journal of
Cryptology 20(2), 2007 (also CRYPTO 2005), which realizes the (k, n)
hierarchical threshold access structure of Definition 1.1 of the paper:
participants are partitioned into levels U_0 (highest) ... U_m (lowest),
thresholds 1 <= k_0 < k_1 < ... < k_m, and a coalition V is authorized iff

    |V cap (U_0 cup ... cup U_i)| >= k_i   for every i = 0..m.

The dealer picks a random polynomial P of degree k_m - 1 with P(0) = S and
hands participant u in level i the share P^(k_{i-1})(u), the (k_{i-1})-th
formal derivative of P at u, where k_{-1} = 0 (so the top level receives
plain values P(u), exactly like Shamir).  Reconstruction is Birkhoff
interpolation: an authorized minimal coalition of k_m participants yields a
square, nonsingular system; any unauthorized coalition yields a singular one
(the paper's main theorem).  This module solves the system by modular
Gaussian elimination over GF(p).

Level indexing follows the paper: 0 = highest level.  share values are ints
mod p; ids are distinct nonzero field elements.
"""

import secrets

from .gf import default_field, GF
from .core import field_for


def _falling_factorial(x, r, field):
    """x * (x-1) * ... * (x-r+1) mod p (integer multipliers, formal derivative)."""
    acc = 1
    for t in range(r):
        acc = field.mul(acc, (x - t) % field.p)
    return acc


def _derivative_eval(coeffs, order, x, field):
    """P^(order)(x) for P with coefficient list coeffs (degree = len-1)."""
    if order >= len(coeffs):
        return 0
    acc = 0
    for j in range(order, len(coeffs)):
        c = field.mul(coeffs[j], _falling_factorial(j, order, field))
        acc = field.add(acc, field.mul(c, field.pow(x % field.p, j - order)))
    return acc % field.p


def _check_levels(levels):
    if not isinstance(levels, (list, tuple)) or len(levels) < 2:
        raise ValueError("levels must be cumulative thresholds [k_0..k_m], m >= 1")
    if levels[0] < 1:
        raise ValueError("k_0 must be >= 1")
    if any(not isinstance(k, int) or k < 1 for k in levels):
        raise ValueError("thresholds must be positive ints")
    if any(levels[i] >= levels[i + 1] for i in range(len(levels) - 1)):
        raise ValueError("thresholds must be strictly increasing")


def hierarchical_deal_committed(secret, levels, ids, field=None, randfunc=None):
    """Tassa (2007) sharing with public Feldman commitments, over Z_q.

    Plain hierarchical_share keeps the polynomial in GF(p); this committed
    variant follows the VSS module convention (see vss.py) and does all
    share/derivative arithmetic in Z_q, the subgroup order -- so that
    commitment exponents and share values share one modulus and
    g^value == prod_j C_j^{coef_j} holds with the usual exponent reduction.
    The access structure is identical to hierarchical_share.

    Returns (entries, commitments): entries = {id: (level, value)} with
    values in Z_q; commitments = [g^{a_j}] mod p.  Reconstruct with
    hierarchical_combine(entries_list, levels, GF(field.q)).
    """
    field = field_for(field)
    cf = field_for(field)
    if cf.g is None or cf.q is None or cf.q != field.q:
        raise ValueError("committed hierarchical sharing needs a field with"
                         " subgroup generator g and order q; use"
                         " shamir.gf.default_field()")
    _check_levels(levels)
    k_m = levels[-1]
    if len(ids) < k_m:
        raise ValueError("need at least k_m = %d participants" % k_m)
    if len(set(i for i, _ in ids)) != len(ids):
        raise ValueError("participant ids must be distinct")
    for i, lv in ids:
        if i == 0:
            raise ValueError("participant ids must be nonzero")
        if not (0 <= lv <= len(levels) - 1):
            raise ValueError("level index out of range")
    if not (0 <= secret < field.q):
        raise ValueError("secret out of field range")

    qfield = GF(cf.q)
    if randfunc is not None:
        rand = lambda: randfunc() % cf.q
    else:
        rand = lambda: secrets.randbelow(cf.q)
    coeffs = [secret % cf.q] + [rand() for _ in range(k_m - 1)]
    commitments = [pow(cf.g, c, cf.p) for c in coeffs]

    orders = [0] + levels[:-1]
    out = {}
    for i, lv in ids:
        out[i] = (lv, _derivative_eval(coeffs, orders[lv], i, qfield))
    return out, commitments


def hierarchical_verify(entry, commitments, levels, field=None):
    """Public Feldman check of one committed hierarchical share.

    entry: (id, level_index, share_value); commitments: the list returned by
    hierarchical_deal_committed.  Checks g^value == prod_j
    C_j^{falling(j, r) * id^(j-r)} with r = k_{level_index-1} the derivative
    order (0 for the top level) and all exponents reduced mod q, so the check
    is a public deterministic function of the committed coefficients.
    Returns bool, never raises.
    """
    try:
        field = field_for(field)
        cf = field_for(field)
        if cf.g is None or cf.q is None:
            raise ValueError("need subgroup-capable field")
        _check_levels(levels)
        qfield = GF(cf.q)
        if len(commitments) != levels[-1]:
            return False
        u, lv, v = entry
        if u == 0:
            return False
        if not (0 <= lv <= len(levels) - 1):
            return False
        orders = [0] + levels[:-1]
        r = orders[lv]
        rhs = 1
        for j in range(r, levels[-1]):
            e = (_falling_factorial(j, r, qfield)
                 * pow(u % cf.q, j - r, cf.q)) % cf.q
            rhs = (rhs * pow(commitments[j], e, cf.p)) % cf.p
        return pow(cf.g, v % cf.q, cf.p) == rhs
    except (ValueError, TypeError, IndexError):
        return False


def hierarchical_share(secret, levels, ids, field=None, randfunc=None):
    """Tassa (2007) hierarchical sharing.

    levels: cumulative thresholds [k_0, k_1, ..., k_m], strictly increasing,
    k_0 >= 1; k_m is the top cumulative threshold (polynomial degree k_m - 1).
    ids: list of (id, level_index) pairs, level_index in 0..m with 0 the
    highest level.  ids must be distinct and nonzero; len(ids) >= k_m.

    Returns {id: (level_index, share_value)}: level i gets P^(k_{i-1})(id)
    with k_{-1} = 0 (top level gets P(id) itself).
    """
    field = field_for(field)
    _check_levels(levels)
    k_m = levels[-1]
    if not ids or len(ids) < k_m:
        raise ValueError("need at least k_m = %d participants" % k_m)
    if len(set(i for i, _ in ids)) != len(ids):
        raise ValueError("participant ids must be distinct")
    for i, lv in ids:
        if i == 0:
            raise ValueError("participant ids must be nonzero")
        if not (0 <= lv <= len(levels) - 1):
            raise ValueError("level index out of range")
    if not (0 <= secret < field.p):
        raise ValueError("secret out of field range")

    if randfunc is not None:
        rand = lambda: randfunc() % field.p
    else:
        rand = lambda: secrets.randbelow(field.p)
    coeffs = [secret % field.p] + [rand() for _ in range(k_m - 1)]

    # level i participants get derivative order k_{i-1} (k_{-1} = 0)
    orders = [0] + levels[:-1]
    out = {}
    for i, lv in ids:
        out[i] = (lv, _derivative_eval(coeffs, orders[lv], i, field))
    return out


def _augmented_rows(entries, levels, field):
    """Birkhoff coefficient matrix rows for each entry (id, level, value).

    Equation for derivative order r = k_{level-1}: sum_j a_j * j!/(j-r)! *
    u^(j-r) = value.  Returns (rows, k) where k = number of unknowns.
    """
    orders = [0] + levels[:-1]
    k = levels[-1]
    rows = []
    for u, lv, v in entries:
        r = orders[lv]
        row = [0] * (k + 1)
        for j in range(r, k):
            row[j] = field.mul(_falling_factorial(j, r, field),
                               field.pow(u % field.p, j - r))
        row[k] = v % field.p
        rows.append(row)
    return rows, k


def _solve_mod_p(rows, k, field):
    """Solve the square/overdetermined system by Gaussian elimination mod p.

    Returns the unique coefficient vector [a_0..a_{k-1}] if the rank is k and
    the system is consistent, else raises ValueError (unauthorized or
    corrupted entries).
    """
    r = 0
    col = 0
    while r < len(rows) and col < k:
        pivot = next((q for q in range(r, len(rows))
                      if rows[q][col] % field.p != 0), None)
        if pivot is None:
            col += 1
            continue
        rows[r], rows[pivot] = rows[pivot], rows[r]
        inv = field.inv(rows[r][col])
        rows[r] = [(v * inv) % field.p for v in rows[r]]
        for q in range(len(rows)):
            if q != r and rows[q][col] % field.p != 0:
                factor = rows[q][col]
                rows[q] = [(rows[q][t] - factor * rows[r][t]) % field.p
                           for t in range(k + 1)]
        r += 1
        col += 1
    if r != k:
        raise ValueError("unauthorized set (singular Birkhoff system)")
    for row in rows:
        if all(row[t] % field.p == 0 for t in range(k)) and row[k] % field.p != 0:
            raise ValueError("inconsistent entries (corrupted share values)")
    return [rows[i][k] for i in range(k)]


def hierarchical_combine(entries, levels, field=None):
    """Reconstruct the secret from hierarchical shares (Tassa 2007, Theorem 3.1).

    entries: list of (id, level_index, share_value) triples.  levels: the
    cumulative thresholds used at sharing time.  Solves the Birkhoff system
    over GF(p) by Gaussian elimination; raises ValueError on singular systems
    (unauthorized coalitions) or inconsistent data.
    """
    field = field_for(field)
    _check_levels(levels)
    if not entries:
        raise ValueError("no entries")
    seen = set()
    for u, lv, v in entries:
        if u in seen:
            raise ValueError("duplicate participant id")
        seen.add(u)
        if u == 0:
            raise ValueError("participant ids must be nonzero")
        if not (0 <= lv <= len(levels) - 1):
            raise ValueError("level index out of range")
    rows, k = _augmented_rows(entries, levels, field)
    coeffs = _solve_mod_p(rows, k, field)
    return coeffs[0] % field.p
