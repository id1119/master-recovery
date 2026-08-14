"""Weighted threshold secret sharing by Shamir virtualization (Shamir 1979).

A participant of weight w receives w sub-shares of a single (quota)-of-
sum(weights) Shamir sharing (degree quota-1 polynomial).  Sub-share
x-coordinates are distinct across all participants (consecutive integers
assigned in participant order), so forming a weighted coalition is exactly
collecting enough polynomial points: a coalition reconstructs the secret iff
its total weight is at least the quota, because it needs quota distinct
sub-share points to interpolate the degree quota-1 polynomial at 0.
"""

from .core import field_for, interpolate_at


def weighted_share(secret, weights, quota, field=None, randfunc=None):
    """Shamir-virtualized weighted sharing: participant i gets weights[i] sub-shares.

    Chooses one random degree-(quota-1) polynomial with constant term `secret`
    and hands every participant consecutive, globally distinct sub-share
    x-coordinates 1..sum(weights) in participant order.  Returns
    {participant: [(x, y), ...]}.
    """
    if not weights:
        raise ValueError("weights must be non-empty")
    if any(w <= 0 for w in weights):
        raise ValueError("weights must be positive integers")
    if quota < 1:
        raise ValueError("quota must be at least 1")
    n_total = sum(weights)
    if quota > n_total:
        raise ValueError("quota cannot exceed total weight")

    field = field_for(field).share_field()
    rand = randfunc or field.random
    coeffs = [secret % field.p] + [rand() % field.p for _ in range(quota - 1)]

    out = {}
    x = 1
    for participant, w in enumerate(weights):
        out[participant] = [(x + j, field.polynomial_eval(coeffs, x + j))
                            for j in range(w)]
        x += w
    return out


def weighted_combine(subshare_groups, quota, field=None):
    """Reconstruct the secret from weighted sub-shares (needs >= quota distinct points).

    subshare_groups is the dict {participant: [(x, y), ...]} returned by
    weighted_share; all sub-shares are pooled, duplicate x-coordinates are
    deduped, and the secret is recovered by Lagrange interpolation at 0 over
    the surviving points.  Raises ValueError if fewer than `quota` distinct
    points are supplied.
    """
    if quota < 1:
        raise ValueError("quota must be at least 1")
    points = {}
    for group in subshare_groups.values():
        for x, y in group:
            points[x] = y
    if len(points) < quota:
        raise ValueError("need at least %d distinct sub-shares to reconstruct"
                         % quota)
    return interpolate_at(list(points.items()), 0, field)