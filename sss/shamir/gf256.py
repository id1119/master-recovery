"""GF(2^8) arithmetic with log/exp tables (AES field, reduction 0x11B).

This is the fast binary-field layer used by the byte-oriented sharing mode
(Vault/libgfshare-style).  Multiplication is a table lookup; addition is XOR.
The primitive element is 0x03 (a generator of GF(2^8)*).
"""

_REDUCTION = 0x11B  # x^8 + x^4 + x^3 + x + 1

_GENERATOR = 0x03

_EXP = [0] * 512
_LOG = [0] * 256

_cur = 1
for _i in range(255):
    _EXP[_i] = _cur
    _LOG[_cur] = _i
    _cur ^= _cur << 1  # multiply by generator 0x03 (x+1); 0x02 has order 51 here
    if _cur & 0x100:
        _cur ^= _REDUCTION
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]
assert _EXP[255] == 1 and len(set(_EXP[:255])) == 255

SHARE_INDEX_MIN = 1
SHARE_INDEX_MAX = 254  # x=255 is reserved for the digest point (SLIP-0039)


class GF256:
    """Elements are ints in [0, 256)."""

    def add(self, a, b):
        return a ^ b

    def sub(self, a, b):
        return a ^ b

    def neg(self, a):
        return a

    def mul(self, a, b):
        if a == 0 or b == 0:
            return 0
        return _EXP[_LOG[a] + _LOG[b]]

    def div(self, a, b):
        if b == 0:
            raise ZeroDivisionError("division by zero in GF(2^8)")
        if a == 0:
            return 0
        return _EXP[(_LOG[a] - _LOG[b]) % 255]

    def inv(self, a):
        if a == 0:
            raise ZeroDivisionError("inversion of zero in GF(2^8)")
        return _EXP[255 - _LOG[a]]

    def pow(self, a, e):
        if a == 0:
            return 0
        return _EXP[(_LOG[a] * (e % 255)) % 255]

    def random(self):
        from secrets import randbelow
        return randbelow(256)

    def random_nonzero(self):
        from secrets import randbelow
        return 1 + randbelow(255)

    def element(self, x):
        return x & 0xFF

    def share_field(self):
        return self

    def polynomial_eval(self, coeffs, x):
        acc = 0
        for c in reversed(coeffs):
            acc = self.mul(acc, x) ^ c
        return acc

    def random_polynomial(self, degree, constant=None):
        coeffs = [self.random() for _ in range(degree + 1)]
        if constant is not None:
            coeffs[0] = constant & 0xFF
        return coeffs

    def __repr__(self):
        return "GF256 (AES field, reduction 0x11B, generator 0x03)"


# Singleton.
FIELD_256 = GF256()
