"""Prime finite field GF(p) with optional prime-order multiplicative subgroup.

The field object carries, in addition to the prime p, optional group parameters
used by the verifiable layers (Feldman VSS, Pedersen VSS, Schoenmakers PVSS):

* q   -- a prime divisor of p-1 (order of the subgroup used for commitments)
* g   -- generator of the order-q subgroup
* h   -- second generator with unknown discrete log relative to g (Pedersen)

All share arithmetic happens in GF(p) itself; commitment arithmetic happens in
the order-q subgroup.  Domain separation constants below are load-bearing:

* SHARE_INDEX_MIN/MAX -- valid share x-coordinates are 1..254 (index 0 is the
  secret itself; the SLIP-0039 x=0 attack).
* SAFE_PRIME_BITS -- default bit length for the built-in safe prime.
"""

import hashlib
import secrets

# Default modulus: a 512-bit safe prime p = 2*q + 1, q prime.
# Verified by repeated Miller-Rabin (64 rounds) at generation time.
_DEFAULT_P = 0xae26911128a55643af5a348e8f5a74db58d10595d7bdcf101879ab1883d739dffc267067eefabe377047d3509ba4cedea81cdef58b0a63e0ac55b562af381d83
_DEFAULT_Q = 0x571348889452ab21d7ad1a4747ad3a6dac6882caebdee7880c3cd58c41eb9ceffe133833f77d5f1bb823e9a84dd2676f540e6f7ac58531f0562adab1579c0ec1

DEFAULT_SAFE_PRIME = _DEFAULT_P
DEFAULT_SUBGROUP_Q = _DEFAULT_Q
# g = 4 is a quadratic residue (order exactly q) modulo the safe prime above.
DEFAULT_GENERATOR = pow(2, 2, DEFAULT_SAFE_PRIME)

SHARE_INDEX_MIN = 1
SHARE_INDEX_MAX = 254  # leaves room above for digest points (SLIP-0039 style)


class GF:
    """Elements are Python ints in [0, p)."""

    def __init__(self, p, q=None, g=None, h=None):
        if p < 3 or not _is_probable_prime(p):
            raise ValueError("p must be an odd prime")
        self.p = p
        self.q = q
        self.g = g % p if g is not None else None
        self.h = h % p if h is not None else None
        self._pow_inv_cache = {}
        self._share_field = None

    def share_field(self):
        """The GF used for secrets/shares/polynomial coefficients.

        When a subgroup is configured (safe prime p = 2q+1), coefficients live
        in Z_q -- interpolating shares over p instead of q is the classic
        Feldman-style bug this method exists to prevent.
        """
        if self.q is None:
            return self
        if self._share_field is None:
            self._share_field = GF(self.q)
        return self._share_field

    # --- basic arithmetic -------------------------------------------------
    def add(self, a, b):
        r = a + b
        return r - self.p if r >= self.p else r

    def sub(self, a, b):
        r = a - b
        return r + self.p if r < 0 else r

    def neg(self, a):
        return (-a) % self.p

    def mul(self, a, b):
        return (a * b) % self.p

    def div(self, a, b):
        if b == 0:
            raise ZeroDivisionError("division by zero in GF(p)")
        return (a * pow(b, self.p - 2, self.p)) % self.p

    def inv(self, a):
        if a == 0:
            raise ZeroDivisionError("inversion of zero in GF(p)")
        return pow(a, self.p - 2, self.p)

    def pow(self, a, e):
        return pow(a, e, self.p)

    def random(self):
        return secrets.randbelow(self.p)

    def random_nonzero(self):
        return 1 + secrets.randbelow(self.p - 1)

    def element(self, x):
        return x % self.p

    # --- subgroup (commitment) arithmetic ---------------------------------
    def subgroup_order(self):
        return self.q

    def commit(self, a):
        """C = g^a mod p, with subgroup membership validation."""
        if self.g is None:
            raise ValueError("no subgroup generator configured")
        c = pow(self.g, a, self.p)
        self._check_subgroup(c)
        return c

    def commit_double(self, a, b):
        """Pedersen-style C = g^a h^b mod p."""
        if self.g is None or self.h is None:
            raise ValueError("subgroup generators g, h not configured")
        c = (pow(self.g, a, self.p) * pow(self.h, b, self.p)) % self.p
        self._check_subgroup(c)
        return c

    def _check_subgroup(self, x):
        if x == 0 or x == 1:
            raise ValueError("invalid subgroup element (0 or 1)")
        if self.q is not None and pow(x, self.q, self.p) != 1:
            raise ValueError("element is not in the order-q subgroup")

    def eval_commit(self, coeffs, x):
        """Evaluate the committed polynomial in the exponent:
        prod_j C_j^(x^j) mod p.  x is an integer (reduced mod q for exponent)."""
        if self.q is not None:
            xr = x % self.q
        else:
            xr = x % (self.p - 1)
        acc = 1
        power = 1
        for c in coeffs:
            acc = (acc * pow(c, power, self.p)) % self.p
            power = (power * xr) % self.q if self.q is not None else power * xr
        return acc

    # --- helpers ------------------------------------------------------------
    def polynomial_eval(self, coeffs, x):
        """Horner evaluation of sum coeffs[j] * x^j."""
        acc = 0
        for c in reversed(coeffs):
            acc = (acc * x + c) % self.p
        return acc

    def random_polynomial(self, degree, constant=None):
        coeffs = [self.random() for _ in range(degree + 1)]
        if constant is not None:
            coeffs[0] = constant % self.p
        return coeffs

    def __repr__(self):
        return "GF(p=%d bits=%d, q=%s, subgroup=%s)" % (
            self.p, self.p.bit_length(),
            self.q.bit_length() if self.q else None,
            "on" if self.g is not None else "off")


def _is_probable_prime(n):
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(12):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def make_safe_prime(bits):
    """Generate a safe prime p (p, (p-1)/2 both prime), q = (p-1)/2."""
    while True:
        q = secrets.randbits(bits - 1)
        q |= (1 << (bits - 2)) | 1
        if _is_probable_prime(q):
            p = 2 * q + 1
            if _is_probable_prime(p):
                return p, q


H_SEED = b"sssx unified pedersen h seed v3"


def hash_to_subgroup(p, q, seed, domain=b"sssx-h2g-v1"):
    """Derive a subgroup element from a public seed with NO known discrete log.

    For a safe prime p = 2q+1 the quadratic residues are exactly the order-q
    subgroup, so squaring a hash output lands in the subgroup.  The point of
    this function is what it does *not* do: it never computes g^c for a
    derivable c.  Deriving h as g^{H(seed)} publishes log_g h, which destroys
    Pedersen binding, because anyone can recompute the exponent from the same
    public seed and then open any commitment to any value.  Hashing into the
    group instead leaves log_g h unknown to everyone, including whoever chose
    the seed.
    """
    need = (p.bit_length() + 128 + 7) // 8
    counter = 0
    while True:
        buf = b""
        block = 0
        while len(buf) < need:
            buf += hashlib.sha256(
                domain + seed + counter.to_bytes(4, "big")
                + block.to_bytes(4, "big")).digest()
            block += 1
        candidate = int.from_bytes(buf[:need], "big") % p
        counter += 1
        if candidate <= 1:
            continue
        h = pow(candidate, 2, p)          # square into the order-q subgroup
        if h in (0, 1, p - 1):
            continue
        if pow(h, q, p) != 1:
            continue
        return h


def default_field(with_subgroup=True):
    """The built-in GF for the unified scheme.

    h is derived by hashing a public seed *into* the subgroup, so log_g h is
    unknown to every party including the author of the seed.  Anyone can
    recompute h from the seed and check it, which is the nothing-up-my-sleeve
    property; nobody can recover its discrete log without solving DLP.
    """
    if with_subgroup:
        h = hash_to_subgroup(DEFAULT_SAFE_PRIME, DEFAULT_SUBGROUP_Q, H_SEED)
        return GF(DEFAULT_SAFE_PRIME, q=DEFAULT_SUBGROUP_Q,
                  g=DEFAULT_GENERATOR, h=h)
    return GF(DEFAULT_SAFE_PRIME)
