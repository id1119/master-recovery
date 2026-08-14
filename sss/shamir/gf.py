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

# Default modulus: a 2048-bit safe prime p = 2*q + 1, q prime.
# 512-bit prime-field DLP has been practical since Logjam (2015): about a week
# of per-prime precomputation, then individual logs in minutes.  Every
# computational claim here (commitment binding, PoK soundness, threshold
# signature unforgeability) rests on that DLP, so the default must be a size
# where it is not solvable.  The 512-bit group below is retained only for
# fast test runs and is explicitly named insecure.
_SECURE_P = 0xd666a686faf3fa8a9550cc356991d75ce23877c5aa76246cc6e3c2cca5babf8fec78fa60256e810cfd07061175ed2c14e5aa67a1bf5e594fe2fdab20a55d5515cb67d03189c84e2c50a314e9e1092008c937871b08e408ee7223696ca6c4444635a4a2e785cca4eec6dd31a36e1da50b6efd7888c694a7e5579cb63c4308109303a54f2d3b1b006aea65e2348e287ae2066e820f3d477868e20d454e4c7e9b5192f8a538c4b02390340a9626f49966bb3626040079f17ff5c3f4bc965e571dcc540e2aca9fa3d630d457ba3acf4e432f16661c343239cd23d692dce6a51489e27cdf8fed77fb9fd5105b8eda6d277d6adb062828125fe4f7c2454e0b56d98d47
_SECURE_Q = 0x6b3353437d79fd454aa8661ab4c8ebae711c3be2d53b12366371e16652dd5fc7f63c7d3012b740867e838308baf6960a72d533d0dfaf2ca7f17ed59052aeaa8ae5b3e818c4e4271628518a74f0849004649bc38d847204773911b4b6536222231ad25173c2e65277636e98d1b70ed285b77ebc44634a53f2abce5b1e2184084981d2a7969d8d80357532f11a47143d71033741079ea3bc347106a2a7263f4da8c97c529c625811c81a054b137a4cb35d9b1302003cf8bffae1fa5e4b2f2b8ee62a0715654fd1eb186a2bdd1d67a721978b330e1a191ce691eb496e73528a44f13e6fc7f6bbfdcfea882dc76d3693beb56d831414092ff27be122a705ab6cc6a3

# Legacy 512-bit safe prime. NOT SECURE: development and test use only.
_DEFAULT_P = 0xae26911128a55643af5a348e8f5a74db58d10595d7bdcf101879ab1883d739dffc267067eefabe377047d3509ba4cedea81cdef58b0a63e0ac55b562af381d83
_DEFAULT_Q = 0x571348889452ab21d7ad1a4747ad3a6dac6882caebdee7880c3cd58c41eb9ceffe133833f77d5f1bb823e9a84dd2676f540e6f7ac58531f0562adab1579c0ec1

DEFAULT_SAFE_PRIME = _SECURE_P
DEFAULT_SUBGROUP_Q = _SECURE_Q
INSECURE_SAFE_PRIME = _DEFAULT_P
INSECURE_SUBGROUP_Q = _DEFAULT_Q
# g = 4 is a quadratic residue, so it has order exactly q modulo a safe prime.
DEFAULT_GENERATOR = 4

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


def insecure_test_field(with_subgroup=True):
    """The legacy 512-bit group. NOT SECURE, for fast test runs only.

    Prime-field DLP at 512 bits is solvable, so every computational property
    of the scheme fails here.  Named loudly so it cannot be selected by
    accident: production callers want default_field().
    """
    if with_subgroup:
        h = hash_to_subgroup(INSECURE_SAFE_PRIME, INSECURE_SUBGROUP_Q, H_SEED)
        return GF(INSECURE_SAFE_PRIME, q=INSECURE_SUBGROUP_Q,
                  g=DEFAULT_GENERATOR, h=h)
    return GF(INSECURE_SAFE_PRIME)
