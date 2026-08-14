"""Consolidated test suite for the shamir package (stdlib only).

Run from the repository root: python3 tests/test_all.py
"""

import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shamir import (core, dkg, format, gf, gf256, hierarchical, hybrid,
                    multisecret, proactive, pvss, reshare, robust, unified,
                    vss, weighted)
from shamir.gf import default_field
from shamir.gf256 import FIELD_256

_rng = random.Random(20260814)
_rand = lambda: _rng.randrange(1 << 520)
_rand_q = lambda b: _rng.randrange(b)


def raises(exc_type, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc_type:
        return
    except Exception as exc:
        raise AssertionError(
            'expected %s, got %s: %s' % (exc_type.__name__, type(exc).__name__, exc))
    raise AssertionError('expected %s, call succeeded' % exc_type.__name__)


def test_package_imports():
    import shamir
    assert shamir.__version__ == '0.1.0'
    for name in ('core', 'dkg', 'format', 'gf', 'gf256', 'hierarchical',
                 'hybrid', 'multisecret', 'proactive', 'pvss', 'reshare',
                 'robust', 'unified', 'vss'):
        assert hasattr(shamir, name), name


def test_core_shamir_roundtrip():
    f = default_field()
    shares = core.share(777, 2, 5, f)
    assert core.combine(shares[:3], f) == 777
    assert core.combine([shares[0], shares[2], shares[4]], f) == 777


def test_core_derive_share():
    f = default_field()
    shares = core.share(777, 2, 5, f)
    new = core.derive_share(shares[:3], 9, f)
    assert core.combine([new] + shares[:2], f) == 777


def test_core_lagrange_cache():
    f = default_field()
    qf = f.share_field()
    points = [(1, 11), (2, 22), (3, 33)]
    cache = core.LagrangeCache([1, 2, 3], qf)
    assert cache.evaluate([11, 22, 33], 0) == core.interpolate_at(points, 0, qf)


def test_core_bytes_mode():
    secret = b'attack at dawn!'
    shares = core.share_bytes(secret, 2, 5)
    assert core.combine_bytes(shares[:3]) == secret
    assert core.combine_bytes([shares[0], shares[2], shares[4]]) == secret
    new = core.derive_share_bytes(shares[:3], 9)
    assert core.combine_bytes([new] + shares[:2]) == secret


def test_gf256_arithmetic():
    assert FIELD_256.add(5, 3) == 6
    assert FIELD_256.sub(3, 5) == 6
    assert FIELD_256.mul(7, 1) == 7
    assert FIELD_256.mul(7, FIELD_256.inv(7)) == 1
    assert FIELD_256.polynomial_eval([1, 2], 3) == 7


def test_deterministic_randfunc():
    f = default_field()
    r1, r2 = random.Random(42), random.Random(42)
    a = vss.feldman_deal(777, 2, 5, f, lambda: r1.randrange(1 << 520))
    b = vss.feldman_deal(777, 2, 5, f, lambda: r2.randrange(1 << 520))
    assert a == b


def test_format_roundtrip():
    sid = format.session_id()
    blob = format.encode_share(5, 123456, session=sid, width=4)
    idx, value, sess = format.decode_share(blob, width=4)
    assert (idx, value, sess) == (5, 123456, sid)


def test_format_byte_mode():
    sid = b'\x00' * 16
    blob = format.encode_share(3, b'\xab\xcd', session=sid, byte_mode=True)
    idx, value, sess = format.decode_share(blob, byte_mode=True)
    assert (idx, value, sess) == (3, b'\xab\xcd', sid)


def test_format_corruption_detected():
    sid = b'\x11' * 16
    blob = bytearray(format.encode_share(5, 123456, session=sid, width=4))
    blob[24] ^= 0x01
    raises(ValueError, format.decode_share, bytes(blob), width=4)


def test_format_bad_magic():
    blob = format.encode_share(5, 123456, session=b'\x22' * 16, width=4)
    raises(ValueError, format.decode_share, b'XXXX' + blob[4:], width=4)


def test_format_reserved_index():
    raises(ValueError, format.encode_share, 254, 1,
           session=b'\x00' * 16, width=4)


def test_format_session_mixup():
    b1 = format.encode_share(1, 10, session=b'\x00' * 16, width=4)
    b2 = format.encode_share(2, 20, session=b'\x01' * 16, width=4)
    raises(ValueError, format.decode_shares, [b1, b2], width=4)


def test_format_digest():
    sid = format.session_id()
    sid2, tag = format.digest_for(424242, session=sid)
    assert sid2 == sid
    assert format.check_digest(424242, sid, tag)
    assert not format.check_digest(424243, sid, tag)


def test_vss_feldman():
    f = default_field()
    shares, commits = vss.feldman_deal(999, 2, 5, f)
    assert len(commits) == 3
    for s in shares:
        assert vss.feldman_verify(s, commits, f)
    assert vss.feldman_combine(shares[:3], commits, f) == 999
    tampered = (shares[0][0], shares[0][1] + 1)
    assert not vss.feldman_verify(tampered, commits, f)
    raises(ValueError, vss.feldman_combine, [tampered] + shares[1:3], commits, f)


def test_vss_feldman_polynomial():
    f = default_field()
    shares, commits = vss.feldman_deal(999, 2, 5, f)
    vals = vss.feldman_polynomial(shares[:3], commits, f)
    assert vals == [y for _, y in shares[:3]]


def test_vss_pedersen():
    f = default_field()
    pairs, commits = vss.pedersen_deal(1234, 2, 5, f)
    assert len(commits) == 3
    for p in pairs:
        assert vss.pedersen_verify(p, commits, f)
    assert vss.pedersen_combine(pairs[:3], commits, f) == 1234
    x, s, t = pairs[0]
    assert not vss.pedersen_verify((x, s + 1, t), commits, f)
    raises(ValueError, vss.pedersen_combine,
           [(x, s + 1, t)] + pairs[1:3], commits, f)


def test_robust_berlekamp_welch():
    f = default_field()
    shares = core.share(123, 3, 8, f)
    coeffs = robust.berlekamp_welch(shares, 3, f)
    assert coeffs[0] == 123


def test_robust_combine_corrects_errors():
    f = default_field()
    shares = core.share(123, 3, 8, f)
    bad = [(x, y + 1) for x, y in shares[:2]] + shares[2:]
    assert robust.robust_combine(bad, 3, f) == 123


def test_robust_combine_undecodable():
    f = default_field()
    shares = core.share(123, 3, 8, f)
    bad = [(x, y + 1) for x, y in shares[:4]] + shares[4:]
    raises(ValueError, robust.robust_combine, bad, 3, f)


def test_robust_verify_then_combine():
    f = default_field()
    shares, commits = vss.feldman_deal(123, 3, 8, f)
    assert robust.verify_then_combine(shares, commits, f) == 123
    tampered = [(x, y + 1) for x, y in shares[:5]] + shares[5:]
    raises(ValueError, robust.verify_then_combine, tampered, commits, f)


def test_robust_pairwise_mac():
    f = default_field()
    mac = robust.PairwiseMACSharing(f)
    shares, keys, tags = mac.deal(777, 2, 5)
    assert mac.check(shares[0], 1, keys, tags)
    tampered = (1, shares[0][1] + 1)
    assert not mac.check(tampered, 1, keys, tags)
    assert not mac.check(shares[1], 3, keys, tags)


def test_proactive_refresh():
    f = default_field()
    orig = core.share(777, 2, 5, f)
    fixed = lambda: 42424242
    new_shares = []
    for i in range(1, 6):
        old = (i, next(y for x, y in orig if x == i))
        ns, _commits, _own, _received = proactive.refresh(old, 2, 5, f, fixed)
        new_shares.append(ns)
    assert core.combine(new_shares[:3], f) == 777
    assert core.combine(new_shares[1:4], f) == 777


def test_proactive_verify_and_corrupt():
    f = default_field()
    orig = core.share(777, 2, 5, f)
    old = (1, next(y for x, y in orig if x == 1))
    ns, commits, own, received = proactive.refresh(old, 2, 5, f, _rand)
    assert proactive.refresh_verify(ns, old, received, commits, f)
    raises(ValueError, proactive.refresh, old, 2, 5, f, _rand, corrupt={2})


def test_proactive_recover():
    f = default_field()
    orig = core.share(777, 2, 5, f)
    rec = proactive.recover_share(3, [orig[0], orig[1], orig[3]], 2, f)
    assert rec == orig[2]


def test_dkg_honest():
    f = default_field()
    r = dkg.dkg_run(5, 2, f, _rand)
    assert r['qual'] == [1, 2, 3, 4, 5]
    assert r['complaints'] == []
    assert r['pok_failures'] == []
    s = r['shares']
    assert core.combine([(i, s[i]) for i in (1, 2, 3)], f) == \
        core.combine([(i, s[i]) for i in (3, 4, 5)], f)
    pk = 1
    for d in r['qual']:
        pk = f.mul(pk, r['commitments_all'][d][0])
    assert pk == r['public_key']


def test_dkg_corruption():
    f = default_field()
    r = dkg.dkg_run(5, 2, f, _rand, corrupt={2})
    assert r['complaints'] == [(2, 3)]
    assert 2 not in r['qual']
    r2 = dkg.dkg_run(5, 2, f, _rand, corrupt_pok={3})
    assert r2['pok_failures'] == [3]
    assert 3 not in r2['qual']


def test_dkg_pok_and_verify_share():
    f = default_field()
    qf = f.share_field()
    poly, commits, pok = dkg.dkg_deal(1, 2, 5, f, _rand)
    assert dkg.dkg_pok_verify(pok, commits[0], 1, f)
    bad = dict(pok)
    bad['response'] = pok['response'] + 1
    assert not dkg.dkg_pok_verify(bad, commits[0], 1, f)
    for x in range(1, 6):
        share = qf.polynomial_eval(poly, x)
        assert dkg.dkg_verify_share(commits, x, share, f)


def test_pvss_roundtrip():
    f = default_field()
    keys = [pvss.pvss_keygen(f) for _ in range(5)]
    pks = [pk for _, pk in keys]
    tr = pvss.pvss_deal(42, 2, pks, f, _rand_q)
    assert pvss.pvss_verify(tr, f)
    assert tr['secret_exponent'] == f.commit(42)
    Ys = [pvss.pvss_decrypt_share(tr, sk, i + 1, f)
          for i, (sk, _) in enumerate(keys)]
    Y = pvss.pvss_combine_exponent(Ys[:3], [1, 2, 3], 2, f)
    assert Y == tr['secret_exponent']
    assert pvss.pvss_recover_small_secret(Y, 100, f) == 42


def test_pvss_tamper_detection():
    f = default_field()
    keys = [pvss.pvss_keygen(f) for _ in range(5)]
    pks = [pk for _, pk in keys]
    tr = pvss.pvss_deal(42, 2, pks, f, _rand_q)
    tampered = dict(tr)
    tampered['ciphertexts'] = list(tr['ciphertexts'])
    w, v = tampered['ciphertexts'][0]
    tampered['ciphertexts'][0] = (w, (v * 2) % f.p)
    assert not pvss.pvss_verify(tampered, f)
    assert pvss.pvss_verify(tr, f)


def test_hybrid_roundtrip():
    secret = b'the eagle has landed'
    ks, ct, cmap = hybrid.hybrid_share(secret, 2, 5, None, _rand)
    assert hybrid.hybrid_combine(ks[:3], cmap, 2) == secret
    assert hybrid.hybrid_combine([ks[0], ks[2], ks[4]], cmap, 2) == secret


def test_hybrid_bad_key_share():
    secret = b'the eagle has landed'
    ks, ct, cmap = hybrid.hybrid_share(secret, 2, 5, None, _rand)
    bad = list(ks)
    x, y = bad[0]
    bad[0] = (x, y[:-1] + bytes([y[-1] ^ 1]))
    raises(ValueError, hybrid.hybrid_combine, bad[:3], cmap, 2)


def test_hybrid_bad_chunk():
    secret = b'the eagle has landed'
    ks, ct, cmap = hybrid.hybrid_share(secret, 2, 5, None, _rand)
    badmap = dict(cmap)
    i, length, data = badmap[1]
    badmap[1] = (i, length, bytes([d ^ 1 for d in data]))
    raises(ValueError, hybrid.hybrid_combine, ks[:3], badmap, 2)
    del badmap[2]
    raises(ValueError, hybrid.hybrid_combine, ks[:3], badmap, 2)


def test_multisecret_roundtrip():
    f = default_field()
    ms = multisecret.share_secrets([11, 22, 33], 5, 7, f, _rand)
    assert multisecret.combine_secrets(ms[:6], 3, f) == [11, 22, 33]


def test_multisecret_p_equals_threshold():
    f = default_field()
    ms = multisecret.share_secrets([1, 2], 2, 4, f, _rand)
    assert multisecret.combine_secrets(ms[:3], 2, f) == [1, 2]
    ms = multisecret.share_secrets([9], 2, 4, f, _rand)
    assert multisecret.combine_secrets(ms[:3], 1, f) == [9]


def test_multisecret_validation():
    f = default_field()
    raises(ValueError, multisecret.share_secrets, [1, 2, 3], 2, 5, f, _rand)
    ms = multisecret.share_secrets([1, 2], 2, 4, f, _rand)
    raises(ValueError, multisecret.combine_secrets, [ms[0], ms[0]], 2, f)
    raises(ValueError, multisecret.combine_secrets, ms[:3], 3, f)


def test_weighted_unequal_weights():
    f = default_field()
    w = weighted.weighted_share(777, [1, 2, 3], 3, f, _rand)
    assert [len(v) for v in w.values()] == [1, 2, 3]
    assert len({x for g in w.values() for x, _ in g}) == 6
    assert weighted.weighted_combine({2: w[2]}, 3) == 777
    assert weighted.weighted_combine({0: w[0], 1: w[1]}, 3) == 777
    raises(ValueError, weighted.weighted_combine, {1: w[1]}, 3)


def test_weighted_equal_weights():
    f = default_field()
    g = weighted.weighted_share(99, [1, 1, 1], 2, f, _rand)
    assert weighted.weighted_combine({0: g[0], 1: g[1]}, 2) == 99
    raises(ValueError, weighted.weighted_combine, {0: g[0]}, 2)


def test_hierarchical_two_levels():
    f = default_field()
    levels = [2, 3]
    ids = [(1, 0), (2, 0), (3, 1), (4, 1)]
    sh = hierarchical.hierarchical_share(777, levels, ids, f, _rand)
    assert sh[1][0] == 0 and sh[3][0] == 1
    entries = [(i, lv, v) for i, (lv, v) in sh.items()]
    assert hierarchical.hierarchical_combine(entries, levels, f) == 777
    auth = [e for e in entries if e[0] in (1, 2, 3)]
    assert hierarchical.hierarchical_combine(auth, levels, f) == 777
    top2 = [e for e in entries if e[0] in (1, 2)]
    raises(ValueError, hierarchical.hierarchical_combine, top2, levels, f)
    mixed = [e for e in entries if e[0] in (1, 3, 4)]
    raises(ValueError, hierarchical.hierarchical_combine, mixed, levels, f)


def test_hierarchical_three_levels():
    f = default_field()
    levels = [1, 2, 4]
    ids = [(1, 0), (2, 1), (3, 1), (4, 2), (5, 2), (6, 2)]
    sh = hierarchical.hierarchical_share(99, levels, ids, f, _rand)
    entries = [(i, lv, v) for i, (lv, v) in sh.items()]
    boss = [e for e in entries if e[0] == 1]
    raises(ValueError, hierarchical.hierarchical_combine, boss, levels, f)
    mids = [e for e in entries if e[0] in (2, 3)]
    raises(ValueError, hierarchical.hierarchical_combine, mids, levels, f)
    auth = [e for e in entries if e[0] in (1, 2, 4, 5)]
    assert hierarchical.hierarchical_combine(auth, levels, f) == 99


def test_hierarchical_paper_example():
    f = default_field()
    levels = [2, 4, 7]
    ids = [(1, 0), (2, 0), (3, 1), (4, 1), (5, 2), (6, 2), (7, 2)]
    sh = hierarchical.hierarchical_share(1234, levels, ids, f, _rand)
    entries = [(i, lv, v) for i, (lv, v) in sh.items()]
    assert hierarchical.hierarchical_combine(entries, levels, f) == 1234
    partial = [e for e in entries if e[0] in (1, 2, 3, 4)]
    raises(ValueError, hierarchical.hierarchical_combine, partial, levels, f)
    topless = [e for e in entries if e[1] != 0]
    raises(ValueError, hierarchical.hierarchical_combine, topless, levels, f)


def test_hierarchical_tamper_detection():
    f = default_field()
    levels = [2, 3]
    ids = [(1, 0), (2, 0), (3, 1), (4, 1)]
    sh = hierarchical.hierarchical_share(777, levels, ids, f, _rand)
    entries = [(i, lv, v) for i, (lv, v) in sh.items()]
    entries[2] = (entries[2][0], entries[2][1], entries[2][2] + 1)
    raises(ValueError, hierarchical.hierarchical_combine, entries, levels, f)


def test_reshare_redistribute():
    f = default_field()
    qf = f.share_field()
    shares, commits = vss.feldman_deal(999, 2, 5, f)
    ns, ncom = reshare.redistribute(shares, commits, 3, 7, f, _rand)
    assert len(ns) == 7 and len(ncom) == 4
    for s in ns:
        assert vss.feldman_verify(s, ncom, f)
    assert core.interpolate_at(ns[:4], 0, qf) == 999


def test_reshare_change_threshold():
    f = default_field()
    qf = f.share_field()
    shares, commits = vss.feldman_deal(999, 2, 5, f)
    ns, ncom = reshare.change_threshold(shares, commits, 4, 6, f)
    assert len(ns) == 6 and len(ncom) == 5
    for s in ns:
        assert vss.feldman_verify(s, ncom, f)
    assert core.interpolate_at(ns[:5], 0, qf) == 999


def test_unified_roundtrip():
    f = default_field()
    shares, keys, tr = unified.deal(777, 2, 5, f, _rand)
    assert unified.combine(tr, shares[:3], field=f) == 777
    assert unified.combine(tr, [shares[0], shares[2], shares[4]],
                           field=f) == 777
    assert unified.combine(tr, shares[:3], mac_keys=keys, field=f) == 777


def test_unified_public_verification():
    f = default_field()
    shares, keys, tr = unified.deal(777, 2, 5, f, _rand)
    assert unified.verify_transcript(tr, f)
    for share in shares:
        assert unified.verify_share(share, tr, f)
    x, s, r = shares[0]
    assert not unified.verify_share((x, s + 1, r), tr, f)
    assert not unified.verify_share((x, s, r + 1), tr, f)
    assert not unified.verify_share((x + 5, s, r), tr, f)
    bad = dict(tr)
    bad['commitments'] = [(tr['commitments'][0] * 2) % f.p]         + list(tr['commitments'][1:])
    assert not unified.verify_transcript(bad, f)


def test_unified_corruption_recovery():
    f = default_field()
    shares, keys, tr = unified.deal(777, 2, 5, f, _rand)
    s_tampered = [(x, s + 1, r) for x, s, r in shares[:1]] + shares[1:]
    assert unified.combine(tr, s_tampered, field=f) == 777
    r_tampered = [(x, s, r + 1) for x, s, r in shares[:1]] + shares[1:]
    assert unified.combine(tr, r_tampered, field=f) == 777
    fried = [(x, s + 1, r) for x, s, r in shares[:4]] + shares[4:]
    raises(ValueError, lambda: unified.combine(tr, fried, field=f))


def test_unified_cross_session_detected():
    f = default_field()
    shares_a, keys_a, tr_a = unified.deal(777, 2, 5, f, _rand)
    shares_b, keys_b, tr_b = unified.deal(888, 2, 5, f, _rand)
    raises(ValueError, lambda: unified.combine(tr_a, shares_b[:3], field=f))
    bad_tr = dict(tr_a)
    bad_tr['commitments'] = list(tr_a['commitments'][:-1])         + [tr_b['commitments'][-1]]
    raises(ValueError, lambda: unified.combine(bad_tr, shares_a[:3], field=f))


def test_unified_refresh():
    f = default_field()
    shares, keys, tr = unified.deal(777, 2, 5, f, _rand)
    fixed = lambda: 42424242
    new_shares = []
    new_tr = None
    for i in range(1, 6):
        share = next(sh for sh in shares if sh[0] == i)
        ns, ntr, info = unified.refresh(share, tr, f, fixed)
        new_shares.append(ns)
        new_tr = ntr
    assert unified.verify_transcript(new_tr, f)
    assert new_tr['mac_tags'] == {}
    for share in new_shares:
        assert unified.verify_share(share, new_tr, f)
    assert unified.combine(new_tr, new_shares[:3], field=f) == 777
    share1 = next(sh for sh in shares if sh[0] == 1)
    raises(ValueError, unified.refresh, share1, tr, f, fixed, corrupt={2})


def test_unified_redistribute():
    f = default_field()
    shares, keys, tr = unified.deal(999, 2, 5, f, _rand)
    ns, ntr, posted = unified.redistribute(shares, tr, 3, 7, f, _rand)
    assert unified.verify_transcript(ntr, f)
    assert len(ns) == 7
    for share in ns:
        assert unified.verify_share(share, ntr, f)
    assert unified.combine(ntr, ns[:4], field=f) == 999


def test_unified_deal_many_roundtrip():
    f = default_field()
    secrets = [11, 22, 33]
    shares, keys, tr = unified.deal_many(secrets, 3, 5, f, _rand)
    assert tr['secrets'] == 3
    assert unified.verify_transcript(tr, f)
    for share in shares:
        assert unified.verify_share(share, tr, f)
    assert unified.combine_many(tr, shares[:4], field=f) == secrets
    assert unified.combine_many(tr, shares[1:], field=f) == secrets
    assert unified.combine_many(tr, shares[:4], mac_keys=keys, field=f) == secrets


def test_unified_combine_many_validation():
    f = default_field()
    shares, _keys, tr = unified.deal_many([11, 22, 33], 3, 5, f, _rand)
    raises(ValueError, unified.combine, tr, shares[:4], field=f)
    single_sh, _k, single_tr = unified.deal(5, 2, 4, f, _rand)
    assert unified.combine_many(single_tr, single_sh[:3], field=f) == [5]
    raises(ValueError, unified.deal_many, [], 2, 4, f, _rand)
    raises(ValueError, unified.deal_many, [1, 2, 3], 2, 4, f, _rand)


def test_unified_deal_many_corruption():
    f = default_field()
    secrets = [7, 8, 9, 10]
    shares, _keys, tr = unified.deal_many(secrets, 4, 7, f, _rand)
    tampered = [(x, s + 1, r) for x, s, r in shares[:2]] + shares[2:]
    assert unified.combine_many(tr, tampered, field=f) == secrets


def test_unified_deal_bytes_roundtrip():
    f = default_field()
    secret = b'the eagle has landed -- twice'
    shares, keys, tr, cmap = unified.deal_bytes(secret, 2, 5, f, _rand)
    assert unified.verify_transcript(tr, f)
    for share in shares:
        assert unified.verify_share(share, tr, f)
    assert unified.combine_bytes(tr, shares[:3], cmap, field=f) == secret
    assert unified.combine_bytes(tr, [shares[0], shares[2], shares[4]], cmap,
                                 field=f) == secret
    assert unified.combine_bytes(tr, shares[:3], cmap, mac_keys=keys,
                                 field=f) == secret


def test_unified_deal_bytes_tamper():
    f = default_field()
    secret = b'attack at dawn!'
    shares, _keys, tr, cmap = unified.deal_bytes(secret, 2, 5, f, _rand)
    bad_shares = [(x, s + 1, r) for x, s, r in shares[:1]] + shares[1:]
    assert unified.combine_bytes(tr, bad_shares, cmap, field=f) == secret
    badmap = dict(cmap)
    i, length, data = badmap[1]
    badmap[1] = (i, length, bytes([d ^ 0xFF for d in data]))
    raises(ValueError, unified.combine_bytes, tr, shares[:3], badmap, field=f)
    dropped = dict(cmap)
    del dropped[2]
    raises(ValueError, unified.combine_bytes, tr, shares[:3], dropped, field=f)


def test_unified_deal_bytes_validation():
    f = default_field()
    raises(TypeError, unified.deal_bytes, 'not bytes', 2, 5, f, _rand)


def test_unified_audit_honest_and_corrupt():
    f = default_field()
    shares, keys, tr = unified.deal(777, 2, 5, f, _rand)
    outcome, statuses, reason = unified.audit(tr, shares, mac_keys=keys,
                                              field=f)
    assert outcome == 777 and reason == 'ok'
    for x in range(1, 6):
        assert statuses[x] == 'ok'
    tampered = [(1, shares[0][1] + 1, shares[0][2])] + shares[1:]
    outcome, statuses, reason = unified.audit(tr, tampered, mac_keys=keys,
                                              field=f)
    assert outcome == 777 and reason == 'ok'
    assert statuses[1] == 'commit'
    for x in range(2, 6):
        assert statuses[x] == 'ok'


def test_unified_audit_malformed():
    f = default_field()
    shares, _keys, tr = unified.deal(777, 2, 5, f, _rand)
    mixed = [(1, 5), shares[1], shares[2], shares[3], shares[4]]
    outcome, statuses, reason = unified.audit(tr, mixed, field=f)
    assert outcome is None and reason == 'unrecoverable'
    assert statuses[0] == 'raw'
    bad_x = [(0, shares[0][1], shares[0][2])] + shares[1:]
    _o, statuses, _r = unified.audit(tr, bad_x, field=f)
    assert statuses[0] == 'bad_index'
    oob = [(1, -1, 0)] + shares[2:]
    _o, statuses, _r = unified.audit(tr, oob, field=f)
    assert statuses[1] == 'out_of_range'
    dup = [shares[0], shares[0], shares[2], shares[3], shares[4]]
    _o, statuses, _r = unified.audit(tr, dup, field=f)
    assert statuses[1] == 'duplicate'


def test_unified_audit_multi():
    f = default_field()
    secrets = [3, 4, 5]
    shares, _keys, tr = unified.deal_many(secrets, 3, 5, f, _rand)
    outcome, statuses, reason = unified.audit(tr, shares, field=f)
    assert outcome == secrets and reason == 'ok'
    assert all(st == 'ok' for st in statuses.values())


def test_unified_add_shares_homomorphic():
    f = default_field()
    s1, s2 = 777, 555
    sh1, _k1, tr1 = unified.deal(s1, 2, 5, f, _rand)
    sh2, _k2, tr2 = unified.deal(s2, 2, 5, f, _rand)
    summed = unified.linear_shares([1, 1], [sh1, sh2], f)
    assert unified.verify_transcript(
        unified.linear_transcript([tr1, tr2], field=f), f)
    assert unified.combine(
        unified.linear_transcript([tr1, tr2], field=f),
        summed[:3], field=f) == s1 + s2
    scaled = unified.linear_shares([3], [sh1], f)
    assert unified.combine(
        unified.linear_transcript([tr1], coeffs=[3], field=f),
        scaled[:3], field=f) == 3 * s1
    diff = unified.linear_shares([1, -1], [sh1, sh2], f)
    assert unified.combine(
        unified.linear_transcript([tr1, tr2], coeffs=[1, -1], field=f),
        diff[:3], field=f) == s1 - s2
    assert unified.mul_share(2, sh1[0], f) == \
        unified.linear_shares([2], [sh1], f)[0]


def test_unified_linear_shares_verified():
    f = default_field()
    sh1, _k1, tr1 = unified.deal(111, 2, 5, f, _rand)
    sh2, _k2, tr2 = unified.deal(222, 2, 5, f, _rand)
    sh3, _k3, tr3 = unified.deal(333, 2, 5, f, _rand)
    combined = unified.linear_shares([1, 1, 1], [sh1, sh2, sh3], f)
    ctr = unified.linear_transcript([tr1, tr2, tr3], field=f)
    assert unified.verify_transcript(ctr, f)
    for share in combined:
        assert unified.verify_share(share, ctr, f)
    assert unified.batch_verify(combined, ctr, f)
    assert unified.combine(ctr, [combined[0], combined[2], combined[4]],
                           field=f) == 666


def test_unified_linear_mixed_n_rejected():
    f = default_field()
    _s1, _k1, tr1 = unified.deal(1, 2, 5, f, _rand)
    _s2, _k2, tr2 = unified.deal(2, 2, 6, f, _rand)
    raises(ValueError, unified.linear_transcript, [tr1, tr2], None, f)


def test_unified_random_shares():
    f = default_field()
    secret, shares, keys, tr = unified.random_shares(2, 5, f, _rand)
    assert 0 <= secret < f.share_field().p
    assert unified.verify_transcript(tr, f)
    assert unified.combine(tr, shares[:3], field=f) == secret
    assert unified.combine(tr, shares[:3], mac_keys=keys, field=f) == secret


def test_unified_derive_share():
    f = default_field()
    shares, _keys, tr = unified.deal(999, 2, 5, f, _rand)
    derived = unified.derive_share(tr, shares[:3], 9, f)
    assert unified.verify_share(derived, tr, f)
    assert unified.combine(tr, [derived] + shares[1:3], field=f) == 999
    raises(ValueError, unified.derive_share, tr, shares[:3], 1, f)
    raises(ValueError, unified.derive_share, tr, shares[:3], 254, f)
    raises(ValueError, unified.derive_share, tr, shares[:2], 9, f)


def test_unified_batch_verify():
    f = default_field()
    shares, _keys, tr = unified.deal(4242, 3, 8, f, _rand)
    assert unified.batch_verify(shares, tr, f)
    assert unified.batch_verify(shares[:4], tr, f)
    for i, share in enumerate(shares):
        assert unified.verify_share(share, tr, f) == \
            unified.batch_verify([share], tr, f)
    tampered = [(x, s + 1, r) for x, s, r in shares]
    assert not unified.batch_verify(tampered, tr, f)
    malformed = shares[:2] + [(0, 1, 1)] + shares[3:]
    assert not unified.batch_verify(malformed, tr, f)
    assert not unified.batch_verify([], tr, f)


def test_unified_seal_unseal():
    f = default_field()
    bundle = unified.seal(31337, 2, 5, f, _rand)
    assert bundle['format'] == 'unified-v3'
    assert bundle['secret_kind'] == 'int'
    blobs = [b['blob'] for b in bundle['shares']]
    assert unified.unseal(bundle, blobs[:3], field=f) == 31337
    assert unified.unseal(bundle, [blobs[0], blobs[2], blobs[4]], field=f) == \
        31337
    out = unified.unseal(bundle, blobs[:3], mac_keys=None, field=f)
    assert out == 31337


def test_unified_seal_tamper_detection():
    f = default_field()
    bundle = unified.seal(31337, 2, 5, f, _rand)
    blobs = [b['blob'] for b in bundle['shares']]
    raw = bytearray(bytes.fromhex(blobs[0]))
    raw[30] ^= 0x01
    bad_blobs = [raw.hex()] + blobs[1:]
    raises(ValueError, unified.unseal, bundle, bad_blobs, field=f)
    other = unified.seal(999, 2, 5, f, _rand)
    other_blob = other['shares'][0]['blob']
    raises(ValueError, unified.unseal, bundle, [other_blob] + blobs[1:],
           field=f)
    bad_bundle = dict(bundle)
    bad_bundle['commitments'] = [hex((int(bundle['commitments'][0], 16) * 2)
                                     % f.p)] + list(bundle['commitments'][1:])
    raises(ValueError, unified.unseal, bad_bundle, blobs[:3], field=f)


def test_unified_seal_no_keys_and_kind_guard():
    f = default_field()
    bundle = unified.seal(7, 1, 3, f, _rand, keys=False)
    assert 'keys' not in bundle
    blobs = [b['blob'] for b in bundle['shares']]
    assert unified.unseal(bundle, blobs[:2], field=f) == 7
    with_keys = unified.seal(7, 1, 3, f, _rand, keys=True)
    assert 'keys' in with_keys
    wblobs = [b['blob'] for b in with_keys['shares']]
    assert unified.unseal(with_keys, wblobs[:2], field=f) == 7


def test_unified_seal_bytes():
    f = default_field()
    secret = b'portable bytes secret -- 2560'
    bundle = unified.seal_bytes(secret, 2, 5, f, _rand)
    assert bundle['secret_kind'] == 'bytes'
    blobs = [b['blob'] for b in bundle['shares']]
    assert unified.unseal_bytes(bundle, blobs[:3], field=f) == secret
    raw = bytearray(bytes.fromhex(blobs[0]))
    bad_blobs = [bytes(raw[:24] + bytes([raw[24] ^ 1]) + raw[25:]).hex()] \
        + blobs[1:]
    raises(ValueError, unified.unseal_bytes, bundle, bad_blobs, field=f)
    bad_cmap = dict(bundle)
    x, (i, length, data) = bundle['chunk_map'][0]
    bad_cmap['chunk_map'] = [(z, [j, ln, hex(int(dt, 16) ^ 1)])
                             for z, (j, ln, dt) in bundle['chunk_map']]
    raises(ValueError, unified.unseal_bytes, bad_cmap, blobs[:3], field=f)
    raises(ValueError, unified.unseal, bundle, blobs[:3], field=f)


def test_unified_mul_shares():
    f = default_field()
    qf = f.share_field()
    x, y = 12, 34
    sh_x, _kx, tr_x = unified.deal(x, 2, 5, f, _rand)
    sh_y, _ky, tr_y = unified.deal(y, 2, 5, f, _rand)
    prod, ptr, info = unified.mul_shares(sh_x, sh_y, tr_x, tr_y, f, _rand)
    a, b, c = info['triple']
    assert c == (a * b) % qf.p
    assert unified.verify_transcript(ptr, f)
    for share in prod:
        assert unified.verify_share(share, ptr, f)
    assert unified.batch_verify(prod, ptr, f)
    want = (x * y) % qf.p
    assert unified.combine(ptr, prod[:3], field=f) == want
    assert unified.combine(ptr, [prod[0], prod[2], prod[4]], field=f) == want


def test_unified_mul_closure():
    f = default_field()
    qf = f.share_field()
    x, y, z = 5, 6, 7
    sh_x, _k, tr_x = unified.deal(x, 2, 5, f, _rand)
    sh_y, _k, tr_y = unified.deal(y, 2, 5, f, _rand)
    sh_z, _k, tr_z = unified.deal(z, 2, 5, f, _rand)
    xy, tr_xy, _i = unified.mul_shares(sh_x, sh_y, tr_x, tr_y, f, _rand)
    xyz, tr_xyz, _i = unified.mul_shares(xy, sh_z, tr_xy, tr_z, f, _rand)
    assert unified.verify_transcript(tr_xyz, f)
    assert unified.combine(tr_xyz, xyz[:3], field=f) == (x * y * z) % qf.p


def test_unified_mul_requires_equal_params():
    f = default_field()
    sh_x, _k, tr_x = unified.deal(2, 2, 5, f, _rand)
    sh_y, _k, tr_y = unified.deal(3, 3, 5, f, _rand)
    raises(ValueError, unified.mul_shares, sh_x, sh_y, tr_x, tr_y, f, _rand)
    _, _sh, tr_y2 = unified.deal(3, 2, 6, f, _rand)
    raises(ValueError, unified.mul_shares, sh_x, _sh, tr_x, tr_y2, f, _rand)


def test_unified_recover_exponent():
    f = default_field()
    shares, _keys, tr = unified.deal(777, 2, 5, f, _rand)
    want = pow(f.g, 777, f.p)
    assert unified.recover_exponent(tr, shares[:3], f) == want
    assert unified.recover_exponent(
        tr, [shares[0], shares[2], shares[4]], f) == want
    tampered = [(1, shares[0][1] + 1, shares[0][2])] + shares[1:]
    assert unified.recover_exponent(tr, tampered, f) == want
    fried = [(x, s + 1, r) for x, s, r in shares[:4]] + shares[4:]
    raises(ValueError, unified.recover_exponent, tr, fried, f)


def test_unified_prove_share():
    f = default_field()
    shares, _keys, tr = unified.deal(8888, 2, 5, f, _rand)
    for share in shares:
        p = unified.prove_share(share, tr, f, _rand)
        assert set(p) == {'x', 'T', 'c', 'za', 'zb'}
        assert unified.verify_share_proof(p, tr, f)
    p = unified.prove_share(shares[0], tr, f, _rand)
    bad = dict(p)
    bad['za'] = p['za'] + 1
    assert not unified.verify_share_proof(bad, tr, f)
    moved = dict(p)
    moved['x'] = 2
    assert not unified.verify_share_proof(moved, tr, f)
    sh2, _k, tr2 = unified.deal(9999, 2, 5, f, _rand)
    p2 = unified.prove_share(sh2[0], tr2, f, _rand)
    assert not unified.verify_share_proof(p2, tr, f)
    assert all(k not in p for k in ('s', 'r'))
    rng1, rng2 = random.Random(5), random.Random(5)
    a = unified.prove_share(shares[0], tr, f, lambda: rng1.randrange(1 << 520))
    b = unified.prove_share(shares[0], tr, f, lambda: rng2.randrange(1 << 520))
    assert a == b


def test_unified_audit_public():
    f = default_field()
    shares, keys, tr = unified.deal(777, 2, 5, f, _rand)
    statuses, rec = unified.audit_public(tr, shares, f)
    assert rec is True
    assert all(st == 'ok' for st in statuses.values())
    tampered = [(1, shares[0][1] + 1, shares[0][2])] + shares[1:]
    statuses, rec = unified.audit_public(tr, tampered, f)
    assert rec is True
    assert statuses[1] == 'commit'
    too_few = shares[:2]
    _st, rec = unified.audit_public(tr, too_few, f)
    assert rec is False
    o, st_full, _r = unified.audit(tr, tampered, mac_keys=keys, field=f)
    assert o == 777
    assert st_full == statuses
    no_secret = unified.audit_public(tr, shares, f)
    assert all(st == 'ok' for st in no_secret[0].values())


def test_unified_coeff_pok():
    f = default_field()
    shares, keys, tr = unified.deal(777, 2, 5, f, _rand)
    assert unified.verify_transcript(tr, f)
    assert len(tr['proof']['entries']) == 3
    bad = dict(tr)
    entries = [dict(e) for e in tr['proof']['entries']]
    entries[2]['za'] = (entries[2]['za'] + 1) % f.p
    bad['proof'] = dict(tr['proof'])
    bad['proof']['entries'] = entries
    assert not unified.verify_transcript(bad, f)
    entries = [dict(e) for e in tr['proof']['entries']]
    entries[2]['index'] = 0
    bad['proof'] = dict(tr['proof'])
    bad['proof']['entries'] = entries
    assert not unified.verify_transcript(bad, f)
    legacy = dict(tr)
    legacy['proof'] = {k: tr['proof'][k] for k in
                       ('T', 'challenge', 'za', 'zb')}
    assert unified.verify_transcript(legacy, f)


def test_unified_weighted():
    f = default_field()
    groups, keys, tr = unified.deal_weighted(777, [1, 2, 3], 3, f, _rand)
    assert tr['weights'] == [1, 2, 3]
    assert len(tr['commitments']) == 4
    assert unified.verify_transcript(tr, f)
    all_sh = [sh for p in groups for sh in groups[p]]
    assert len(all_sh) == 6
    for sh in all_sh:
        assert unified.verify_share(sh, tr, f)
    heavy = groups[2]
    raises(ValueError, lambda: unified.combine(tr, heavy, field=f))
    coalition = groups[1] + groups[2]
    assert unified.combine(tr, coalition[:4], field=f) == 777
    assert unified.combine(tr, coalition, mac_keys=keys, field=f) == 777
    tampered = [(1, coalition[0][1] + 1, coalition[0][2])] + coalition[1:]
    assert unified.combine(tr, tampered, field=f) == 777


def test_unified_weighted_seal():
    f = default_field()
    groups, keys, tr = unified.deal_weighted(777, [2, 3, 1], 3, f, _rand)
    all_sh = [sh for p in groups for sh in groups[p]]
    width = unified._group_width(f)
    b = unified._bundle_from(tr, all_sh, width)
    tr2, sh2 = unified._transcript_from_bundle(b), all_sh
    assert tr2['weights'] == [2, 3, 1]
    assert unified.verify_transcript(tr2, f)
    for sh in sh2:
        assert unified.verify_share(sh, tr2, f)
    assert unified.combine(tr2, sh2[:4], field=f) == 777


def test_unified_distributed_run():
    f = default_field()
    res = unified.distributed_run(5, 2, f, _rand)
    tr = res['transcript']
    assert unified.verify_transcript(tr, f)
    shares = res['shares']
    for r in range(1, 6):
        assert unified.verify_share((r, shares[r][0], shares[r][1]), tr, f)
    sample = [(r, s, rv) for r, (s, rv) in shares.items()][:3]
    secret = unified.combine(tr, sample, field=f)
    assert pow(f.g, secret, f.p) == res['public_key']
    assert res['qual'] == [1, 2, 3, 4, 5]
    assert res['complaints'] == []
    assert res['pok_failures'] == []
    assert unified.batch_verify([(r, s, rv) for r, (s, rv)
                                 in shares.items()], tr, field=f)


def test_unified_distributed_corruption():
    f = default_field()
    res = unified.distributed_run(5, 2, f, _rand, corrupt={2}, corrupt_r={4})
    assert (2, 3) in res['complaints']
    assert (4, 5) in res['complaints']
    assert 2 not in res['qual']
    assert 4 not in res['qual']
    tr = res['transcript']
    honest_recipients = res['qual']
    triples = [(r, res['shares'][r][0], res['shares'][r][1])
               for r in honest_recipients]
    assert unified.combine(tr, triples[:3], field=f)
    assert pow(f.g, unified.combine(tr, triples[:3], field=f),
               f.p) == res['public_key']
    bad_share = next(sh for r, sh in res['shares'].items() if r == 2)
    assert not unified.verify_share((2, bad_share[0] + 1, bad_share[1]), tr, f)


def test_hierarchical_committed():
    f = default_field()
    levels = [1, 2, 3]
    ids = [(1, 0), (2, 0), (3, 1), (4, 1), (5, 2), (6, 2)]
    entries, commits = hierarchical.hierarchical_deal_committed(
        42, levels, ids, f, _rand)
    qfield = gf.GF(f.q)
    assert hierarchical.hierarchical_combine(
        [(i, lv, v) for i, (lv, v) in entries.items()], levels, qfield) == 42
    for i, (lv, v) in entries.items():
        assert hierarchical.hierarchical_verify((i, lv, v), commits, levels, f)
    lv, v = entries[3]
    assert not hierarchical.hierarchical_verify(
        (3, lv, v + 1), commits, levels, f)
    assert not hierarchical.hierarchical_verify(
        (999, 0, 1), commits, levels, f)
    assert not hierarchical.hierarchical_verify(
        (3, lv, v), commits[:-1], levels, f)


def test_unified_threshold_sign():
    f = default_field()
    msg = b"commitment to the release"
    x_shares, _xk, xtr = unified.deal(987, 2, 5, f, _rand)
    k_shares, _kk, ktr = unified.deal(12345, 2, 5, f, _rand)
    R, z, Y, detail = unified.threshold_sign(
        msg, xtr, x_shares, ktr, k_shares, [1, 2, 3], f)
    assert z == sum(detail["partials"].values()) % f.q
    assert unified.verify_signature(msg, R, z, Y, f)
    assert not unified.verify_signature(b"other message", R, z, Y, f)
    assert not unified.verify_signature(msg, R, (z + 1) % f.q, Y, f)
    R2, z2, _Y, _d = unified.threshold_sign(
        msg, xtr, x_shares, ktr, k_shares, [2, 3, 4], f)
    assert unified.verify_signature(msg, R2, z2, Y, f)
    raises(ValueError, unified.threshold_sign,
           msg, xtr, x_shares, ktr, k_shares, [1, 2], f)
    raises(ValueError, lambda: unified.threshold_sign(
        msg, xtr, x_shares, ktr, k_shares[:3], [1, 2, 4], f))


def test_unified_threshold_sign_dealer_free():
    f = default_field()
    msg = b"party path"
    key = unified.distributed_run(5, 2, f, _rand)
    nonce = unified.distributed_run(5, 2, f, _rand)
    ks = [key["shares"][i] for i in range(1, 4)]
    ns = [nonce["shares"][i] for i in range(1, 4)]
    xtr = key["transcript"]
    ktr = nonce["transcript"]
    ktriples = [(i, *nonce["shares"][i]) for i in range(1, 4)]
    xtriples = [(i, *key["shares"][i]) for i in range(1, 4)]
    R, z, Y, _d = unified.threshold_sign(msg, xtr, xtriples, ktr, ktriples,
                                         [1, 2, 3], f)
    assert Y == key['public_key']
    assert unified.verify_signature(msg, R, z, Y, f)


def test_unified_pok_hygiene():
    f = default_field()
    shares, keys, tr = unified.deal(424242, 1, 3, f, _rand)
    x, s, r = shares[0]
    proof = unified.prove_share((x, s, r), tr, f, _rand)
    from shamir.gf import GF
    assert unified.verify_share_proof(proof, tr, f)
    bad = dict(proof)
    bad['T'] = f.p - 1
    assert not unified.verify_share_proof(bad, tr, f)
    bad2 = dict(proof)
    bad2['za'] = (proof['za'] + 1) % f.p
    assert not unified.verify_share_proof(bad2, tr, f)


def test_unified_bundle_field_lock():
    f = default_field()
    bundle = unified.seal(777, 2, 5, f, _rand)
    blobs = [b['blob'] for b in bundle['shares']]
    assert unified.unseal(bundle, blobs[:3], field=f) == 777
    assert int(bundle['field']['p'], 16) == f.p
    forged = dict(bundle)
    forged['field'] = {'p': hex(f.p + 2), 'q': None, 'g': None, 'h': None}
    raises(ValueError, lambda: unified.unseal(forged, blobs[:3], field=f))


def test_unified_property_fuzz():
    f = default_field()
    import os
    rng = random.Random(20260814)
    for _ in range(40):
        secret = rng.randrange(f.q)
        threshold = rng.randrange(1, 5)
        n = rng.randrange(threshold + 1, 9)
        shares, keys, tr = unified.deal(secret, threshold, n, f)
        assert unified.verify_transcript(tr, f)
        assert unified.combine(tr, shares[:threshold + 1], field=f) == secret
        assert unified.combine(tr, shuffled := random.sample(
            shares, threshold + 1), field=f) == secret
        for sh in shares:
            assert unified.verify_share(sh, tr, f)
        s_values = [(x, s) for x, s, _ in shares]
        assert core.interpolate_at(s_values[:threshold + 1], 0,
                                   f.share_field()) == secret
        if threshold >= 2:
            proto = random.sample(shares, threshold + 1)
            fos, ntr, _posted = unified.redistribute(
                proto, tr, threshold, n, f, _rand)
            assert unified.verify_transcript(ntr, f)
            assert unified.combine(ntr, fos[:threshold + 1], field=f) == secret


def main():
    tests = sorted((name, fn) for name, fn in globals().items()
                   if name.startswith('test_') and callable(fn))
    passed = 0
    failed = []
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failed.append(name)
            print('FAIL  %s -- %s' % (name, exc))
        except Exception as exc:
            failed.append(name)
            print('FAIL  %s -- %s: %s' % (name, type(exc).__name__, exc))
        else:
            passed += 1
            print('ok    %s' % name)
    print('\n%d/%d tests passed' % (passed, len(tests)))
    if failed:
        sys.exit(1)


if __name__ == '__main__':
    main()
