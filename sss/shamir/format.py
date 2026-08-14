"""Share serialization: versioned, session-bound, checksummed shares.

Incorporates the practical-format improvements from production systems:

* session_id binds all shares of one sharing (prevents cross-sharing mixups)
* per-share checksum detects corruption/typos before interpolation
* index range 1..254 enforced (x=0 would be the secret itself; x=254 reserved
  for the digest point) -- the SLIP-0039 x=0 attack
* digest point (x=254, HMAC of the secret) detects wrong-secret
  reconstruction with failure probability 2^-32 (extendable)

Binary layout (little-endian where applicable):
  magic    4 bytes  "SSSX"
  version  1 byte   0x01
  flags    1 byte   bit0: 0 = GF(p) element, 1 = GF(2^8) share bytes
  width    1 byte   payload width in bytes
  index    1 byte   share x-coordinate
  session  16 bytes random session id
  payload  width bytes (big-endian GF(p) value, or raw share bytes)
  checksum 8 bytes  sha256(header+payload) truncated
"""

import hashlib
import hmac
import secrets

MAGIC = b"SSSX"
VERSION = 0x01
DIGEST_INDEX = 254  # SLIP-0039-style digest point x-coordinate

_HEADER_LEN = 4 + 1 + 1 + 1 + 1 + 16
_CHECKSUM_LEN = 8


def session_id():
    return secrets.token_bytes(16)


def _checksum(header, payload):
    return hashlib.sha256(header + payload).digest()[:_CHECKSUM_LEN]


def encode_share(index, value, session=None, width=None, byte_mode=False):
    """Serialize a share.

    index: x-coordinate (1..254)
    value: int (GF(p)) or bytes (GF(2^8) mode)
    """
    if not (1 <= index <= 253):
        raise ValueError("share index must be in 1..253 (254 reserved)")
    if byte_mode:
        if not isinstance(value, bytes):
            raise ValueError("byte mode requires bytes value")
        payload = value
        flags = 0x01
    else:
        if not isinstance(value, int):
            raise ValueError("GF(p) mode requires int value")
        if width is None:
            raise ValueError("width required for GF(p) mode")
        payload = value.to_bytes(width, "big")
        flags = 0x00
    if width is not None:
        if len(payload) != width:
            raise ValueError("value does not fit in width bytes")
    header = MAGIC + bytes([VERSION, flags, len(payload), index]) + session
    return header + payload + _checksum(header, payload)


def decode_share(blob, width=None, byte_mode=False):
    """Parse and checksum-verify a share.  Returns (index, value, session).

    Raises ValueError on malformed or corrupted shares.
    """
    if len(blob) < _HEADER_LEN + 1 + _CHECKSUM_LEN:
        raise ValueError("share too short")
    if blob[:4] != MAGIC:
        raise ValueError("bad magic")
    version = blob[4]
    if version != VERSION:
        raise ValueError("unsupported version %d" % version)
    flags = blob[5]
    payload_len = blob[6]
    index = blob[7]
    session = blob[8:24]
    payload = blob[24:24 + payload_len]
    if len(payload) != payload_len:
        raise ValueError("truncated payload")
    given = blob[24 + payload_len:24 + payload_len + _CHECKSUM_LEN]
    if len(given) != _CHECKSUM_LEN or not hmac.compare_digest(
            given, _checksum(blob[:24], payload)):
        raise ValueError("checksum mismatch (corrupted share)")
    if not (1 <= index <= 253):
        raise ValueError("share index out of range")
    if flags & 0x01:
        if not byte_mode:
            raise ValueError("share is byte-mode")
        if width is not None and payload_len != width:
            raise ValueError("share width mismatch")
        return index, payload, session
    else:
        if byte_mode:
            raise ValueError("share is GF(p) mode")
        if width is not None and payload_len != width:
            raise ValueError("share width mismatch")
        return index, int.from_bytes(payload, "big"), session


def encode_shares(shares, width=None, byte_mode=False, session=None):
    """Serialize a list of (index, value) shares sharing one session id."""
    sid = session or session_id()
    return [encode_share(i, v, sid, width, byte_mode) for i, v in shares]


def decode_shares(blobs, width=None, byte_mode=False):
    """Parse many shares, enforcing a single consistent session id."""
    parsed = [decode_share(b, width, byte_mode) for b in blobs]
    sids = {s for _, _, s in parsed}
    if len(sids) != 1:
        raise ValueError("shares from different sessions")
    return [(i, v) for i, v, _ in parsed], sids.pop()


# --------------------------------------------------------------------------
# Secret digest (SLIP-0039 wrong-secret detection)
# --------------------------------------------------------------------------

def digest_for(secret_int, session=None, width=8):
    """Dealer-side digest: HMAC-SHA256(session, secret) truncated to width."""
    sid = session or session_id()
    tag = hmac.new(sid, secret_int.to_bytes((secret_int.bit_length() + 7) // 8 or 1, "big"),
                   hashlib.sha256).digest()[:width]
    return sid, tag


def check_digest(secret_int, session, tag):
    """Verify a candidate secret against the dealer's digest."""
    expected = hmac.new(session,
                        secret_int.to_bytes((secret_int.bit_length() + 7) // 8 or 1, "big"),
                        hashlib.sha256).digest()[:len(tag)]
    return hmac.compare_digest(expected, tag)


# Alias used by the digest-point layer (x=254 polynomial evaluation).
DIGEST_POINT_X = DIGEST_INDEX
