"""Krawczyk (1994) hybrid secret sharing for byte secrets.

Krawczyk, "Secret Sharing Made Short" (CRYPTO '94): instead of Shamir-sharing
a large secret (which costs n * |secret| bits of total storage), symmetrically
encrypt the secret under a fresh session key and Shamir-share only the small
key; the ciphertext is then split into n short chunks with Rabin-style
information dispersal.  Storage drops to roughly |secret| / n + |key| per
shareholder while the access structure stays (threshold, n): any threshold + 1
key shares recover the session key, and all n ciphertext chunks are needed to
reassemble the ciphertext.

The reference construction (as suggested in the paper) is AES-256-GCM.  This
package has no `cryptography` dependency, so the bundled AEAD is a pure-stdlib
equivalent: a SHAKE256 stream cipher, keystream = SHAKE256(key || nonce ||
counter) XOR-ed with the plaintext (256-bit key, 128-bit nonce), plus an
HMAC-SHA256 tag over (nonce || ciphertext).  It is computationally sound --
the keystream is indistinguishable from random given a 256-bit key to SHAKE256
and the tag is a secure PRF -- and fully auditable from first principles.
"""

import hashlib
import hmac
import secrets

from . import core

_AEAD_DOMAIN = b"sssx hybrid aead v1"
_NONCE_LEN = 16
_TAG_LEN = 32
_KEY_LEN = 32
_BLOCK = 64


def _rand_bytes(randfunc, size):
    """`size` random bytes: secrets.token_bytes, or deterministic via randfunc."""
    if randfunc is None:
        return secrets.token_bytes(size)
    return bytes(randfunc() % 256 for _ in range(size))


def _keystream(key, nonce, nbytes):
    """SHAKE256(_AEAD_DOMAIN || key || nonce || counter), _BLOCK bytes per step."""
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        block = hashlib.shake_256(_AEAD_DOMAIN + key + nonce
                                  + counter.to_bytes(8, "big")).digest(_BLOCK)
        need = nbytes - len(out)
        out += block if need >= _BLOCK else block[:need]
        counter += 1
    return bytes(out)


def _encrypt(key, nonce, plaintext):
    """XOR plaintext with the SHAKE256 stream; return nonce || ct || tag."""
    ct = bytes(a ^ b for a, b in zip(
        plaintext, _keystream(key, nonce, len(plaintext))))
    tag = hmac.new(key, _AEAD_DOMAIN + nonce + ct, hashlib.sha256).digest()
    return nonce + ct + tag


def _decrypt(key, blob):
    """Split blob, verify the HMAC tag, return plaintext; raises ValueError."""
    if len(blob) < _NONCE_LEN + _TAG_LEN:
        raise ValueError("ciphertext too short")
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:-_TAG_LEN]
    tag = blob[-_TAG_LEN:]
    expected = hmac.new(key, _AEAD_DOMAIN + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("invalid authentication tag")
    stream = _keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream))


def _split_chunks(blob, n):
    """Strided (IDA) split: chunk i = blob[i::n]; returns (i, length, data)."""
    return [(i, len(blob[i::n]), blob[i::n]) for i in range(n)]


def _reassemble(chunk_map):
    """Inverse of _split_chunks; raises on missing/duplicate/oversized chunks."""
    entries = [(i, length, data) for i, length, data in chunk_map.values()]
    n = len(entries)
    idx = [i for i, _length, _data in entries]
    if len(set(idx)) != n or set(idx) != set(range(n)):
        raise ValueError("chunk_map must hold exactly chunks 0..n-1")
    m = sum(length for _i, length, _d in entries)
    out = bytearray(m)
    for i, length, data in entries:
        if len(data) != length:
            raise ValueError("chunk byte-length mismatch for chunk %d" % i)
        for k in range(length):
            out[i + k * n] = data[k]
    return bytes(out)


def hybrid_share(secret, threshold, n, field=None, randfunc=None):
    """Krawczyk (CRYPTO '94) hybrid sharing: encrypt, Shamir-share key, split ct.

    Encrypts `secret` under a fresh 32-byte key (SHAKE256 stream XOR + HMAC
    tag, the pure-stdlib stand-in for the reference AES-256-GCM), Shamir-shares
    the key bytes over GF(2^8) via core.share_bytes with (threshold, n), and
    splits the ciphertext blob (nonce || ct || tag) into n strided chunks.

    Returns (key_shares, ciphertext, chunk_map):
      key_shares: [(x, bytes)] with x in 1..n, shareholder j's key material.
      ciphertext: the full blob (nonce || ct || tag) before chunking.
      chunk_map:  {x: (chunk_index, byte_length, data)}, keys sharing the
                  x-coordinates of the key shares; chunk i = blob[i::n] and
                  byte_length is what hybrid_combine needs to reassemble the
                  blob exactly.  `field` is accepted for API uniformity (the
                  key sharing runs over GF(2^8), Krawczyk's byte mode).
    """
    if not isinstance(secret, bytes):
        raise TypeError("secret must be bytes")
    if not (1 <= threshold < n):
        raise ValueError("require 1 <= threshold < n")
    key = _rand_bytes(randfunc, _KEY_LEN)
    nonce = _rand_bytes(randfunc, _NONCE_LEN)
    ciphertext = _encrypt(key, nonce, secret)
    key_shares, chunk_map = core.share_bytes(key, threshold, n), {}
    for i, length, data in _split_chunks(ciphertext, n):
        chunk_map[i + 1] = (i, length, data)
    return key_shares, ciphertext, chunk_map


def hybrid_combine(key_shares, chunk_map, threshold):
    """Krawczyk (CRYPTO '94) recovery: key from t+1 shares, blob from all chunks.

    Reconstructs the session key from any threshold + 1 key shares (shares past
    the first threshold + 1 are ignored), reassembles the ciphertext blob from
    every chunk in chunk_map, decrypts and authenticates it, and returns the
    original bytes.  Raises ValueError on an invalid authentication tag or on a
    missing / inconsistent chunk_map -- there is no way to authenticate a
    partial ciphertext, all n chunks are required.
    """
    if len(key_shares) < threshold + 1:
        raise ValueError("need at least threshold + 1 (%d) key shares, got %d"
                         % (threshold + 1, len(key_shares)))
    key = core.combine_bytes(list(key_shares)[:threshold + 1])
    blob = _reassemble(chunk_map)
    return _decrypt(key, blob)