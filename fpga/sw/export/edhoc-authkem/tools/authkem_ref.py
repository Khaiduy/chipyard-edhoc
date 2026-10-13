#!/usr/bin/env python3
"""Independent reference model of draft-ietf-lake-authkem-edhoc-01 with the
draft-ietf-lake-pqsuites-01 cipher suites TBD1 (AES-CCM-16-128-128, SHAKE256,
MAC 16, ML-KEM-512, ML-DSA-44, AES-CCM-16-64-128, SHA-256), TBD2 (A256GCM,
SHAKE256, MAC 16, ML-KEM-512, ML-DSA-44, A256GCM, SHA-256) and TBD3 (A256GCM,
SHA-384, MAC 16, ML-KEM-1024, ML-DSA-87, A256GCM, SHA-384). The suite is read
from message_1.

Written from the draft text, not from the C code. Given a transcript logged by
tests/test_loopback.c (message_1..message_5_KEM, the Initiator's ephemeral
secret key and its PRK_out) and the static test keys, it recomputes every
transcript hash, PRK, keystream, AEAD and MAC from the bytes on the wire and
checks them, then compares PRK_out.

    python3 tools/authkem_ref.py build/loopback.txt

Needs: kyber-py (ML-KEM), pycryptodome (cSHAKE256), cryptography (AES-GCM).
"""
import hashlib
import hmac
import re
import sys
from pathlib import Path

from Crypto.Hash import cSHAKE256
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_1024

MAC_LEN = 16
ROOT = Path(__file__).resolve().parent.parent

# Per-suite parameters, keyed by the suite label in message_1 (private-use
# placeholders until IANA assigns TBD2/TBD3; see AUTHKEM_SUITE_TBD2/3).
SUITES = {
    -22: dict(name='TBD1', hash='shake256', hash_len=64, kem=ML_KEM_512,
              ct_len=768, pk_len=800, keys='src/mlkem512_test_keys.h',
              build='build-tbd1', aead='ccm', key=16, iv=13, app_key=16,
              app_iv=13),
    -24: dict(name='TBD2', hash='shake256', hash_len=64, kem=ML_KEM_512,
              ct_len=768, pk_len=800, keys='src/mlkem512_test_keys.h',
              build='build', aead='gcm', key=32, iv=12, app_key=32,
              app_iv=12),
    -23: dict(name='TBD3', hash='sha384', hash_len=48, kem=ML_KEM_1024,
              ct_len=1568, pk_len=1568, keys='src/mlkem1024_test_keys.h',
              build='build-tbd3', aead='gcm', key=32, iv=12, app_key=32,
              app_iv=12),
}
S = None   # selected suite, set in main()

# ---- RFC 9528 primitives (Sections 4.1, 5) ----------------------------------
# EDHOC hash SHAKE256: H = SHAKE256-512, Extract/Expand = KMAC256.
# EDHOC hash SHA-384:  H = SHA-384, Extract/Expand = HKDF-SHA-384 (RFC 5869).

def H(x):
    if S['hash'] == 'sha384':
        return hashlib.sha384(x).digest()
    return hashlib.shake_256(x).digest(S['hash_len'])

def _be(x):
    return x.to_bytes(max(1, (x.bit_length() + 7) // 8), 'big')

def kmac256(key, data, n):
    """SP 800-185 KMAC256(K, X, 8n, "") built on cSHAKE256(.., "KMAC", "")."""
    enc_k = bytes([len(_be(8 * len(key)))]) + _be(8 * len(key)) + key
    z = bytes([len(_be(136))]) + _be(136) + enc_k
    z += b'\0' * (-len(z) % 136)
    x = z + data + _be(8 * n) + bytes([len(_be(8 * n))])
    return cSHAKE256._new(x, b'', b'KMAC').read(n)

def hkdf_expand(prk, info, n):
    out, t, i = b'', b'', 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), 'sha384').digest()
        out += t
        i += 1
    return out[:n]

def extract(salt, ikm):
    if S['hash'] == 'sha384':
        return hmac.new(salt, ikm, 'sha384').digest()
    return kmac256(salt, ikm, S['hash_len'])

def cbor_head(mt, v):
    if v < 24:
        return bytes([mt << 5 | v])
    for n, ai in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if v < 1 << (8 * n):
            return bytes([mt << 5 | ai]) + v.to_bytes(n, 'big')

def cbor_int(v):
    return cbor_head(0, v) if v >= 0 else cbor_head(1, -1 - v)

def bstr(b):
    return cbor_head(2, len(b)) + b

def kdf(prk, label, context, n):
    """EDHOC_KDF: info = (label : int, context : bstr, length : uint)."""
    info = cbor_int(label) + bstr(context) + cbor_int(n)
    if S['hash'] == 'sha384':
        return hkdf_expand(prk, info, n)
    return kmac256(prk, info, n)

def aead_decrypt(key, iv, ct, aad):
    """The suite's EDHOC AEAD (16-byte tag): AES-CCM-16-128-128 or A256GCM."""
    if S['aead'] == 'ccm':
        return AESCCM(key, tag_length=16).decrypt(iv, ct, aad)
    return AESGCM(key).decrypt(iv, ct, aad)

def enc_structure(th):
    """COSE Enc_structure ["Encrypt0", h'', TH] (RFC 9052 Section 5.3)."""
    return b'\x83' + b'\x68Encrypt0' + b'\x40' + bstr(th)

# ---- minimal CBOR item splitter ---------------------------------------------

def _arg(b, i):
    ai = b[i] & 31
    if ai < 24:
        return ai, 1
    n = {24: 1, 25: 2, 26: 4, 27: 8}[ai]
    return int.from_bytes(b[i + 1:i + 1 + n], 'big'), 1 + n

def item_len(b, i=0):
    """Length of the CBOR data item at b[i] (definite lengths only)."""
    mt = b[i] >> 5
    v, h = _arg(b, i)
    if mt in (0, 1, 7):
        return h
    if mt in (2, 3):
        return h + v
    j = i + h
    for _ in range(v * (2 if mt == 5 else 1)):
        j += item_len(b, j)
    return j - i

def split_seq(b):
    out, i = [], 0
    while i < len(b):
        n = item_len(b, i)
        out.append(b[i:i + n])
        i += n
    return out

def bstr_value(item):
    assert item[0] >> 5 == 2, item.hex()
    v, h = _arg(item, 0)
    assert h + v == len(item)
    return item[h:]

def id_cred_from_plaintext(item):
    """RFC 9528 3.5.3.2: a bare kid in a PLAINTEXT stands for {4: kid}, kid
    a byte string; a one-byte int stands for the kid that is its encoding."""
    if item[0] >> 5 in (0, 1):
        assert len(item) == 1, 'compact int kid must be one byte'
        return b'\xa1\x04\x41' + item
    return b'\xa1\x04' + item if item[0] >> 5 == 2 else item

# ---- key material -----------------------------------------------------------

def c_array(path, name):
    src = Path(path).read_text()
    m = re.search(r'%s\s*\[[^\]]*\]\s*=\s*\{([^}]*)\}' % name, src)
    return bytes(int(t, 0) for t in re.findall(r'0x[0-9a-fA-F]+|\d+', m.group(1)))

def main(log):
    global S
    m = {k: bytes.fromhex(v) for k, v in
         (l.strip().split('=', 1) for l in open(log) if '=' in l)}
    m1 = split_seq(m['msg1'])
    suite = m1[1]   # SUITES_I: a single int when one suite is offered
    label = -1 - _arg(suite, 0)[0] if suite[0] >> 5 == 1 else _arg(suite, 0)[0]
    S = SUITES[label]
    HASH_LEN, CT_LEN, KEM = S['hash_len'], S['ct_len'], S['kem']
    KEY_LEN, IV_LEN = S['key'], S['iv']
    print('suite %s (%d)' % (S['name'], label))
    keys = ROOT / S['keys']
    creds = ROOT / S['build'] / 'gen/authkem_creds.h'
    init_sk, resp_sk = c_array(keys, 'INIT_SK'), c_array(keys, 'RESP_SK')
    cred_i, cred_r = c_array(creds, 'CRED_I_CCS'), c_array(creds, 'CRED_R_CCS')
    ok = True

    def check(what, cond):
        nonlocal ok
        print(('  ok   ' if cond else '  FAIL ') + what)
        ok &= bool(cond)

    # message_1 = (METHOD, SUITES_I, pk_eph, C_I, ?EAD_1)
    check('message_1 METHOD = 5', m1[0] == cbor_int(5))
    # dk = dk_PKE || ek || H(ek) || z (FIPS 203 Algorithm 16)
    pk_off = len(m['sk_eph']) - S['pk_len'] - 64
    check('pk_eph is the public key inside sk_eph',
          bstr_value(m1[2]) == m['sk_eph'][pk_off:pk_off + S['pk_len']])

    # message_2 = ( ct_eph_CIPHERTEXT_2 : bstr )
    (b2,) = split_seq(m['msg2'])
    b2 = bstr_value(b2)
    ct_eph, ct2 = b2[:CT_LEN], b2[CT_LEN:]
    ss_eph = KEM.decaps(m['sk_eph'], ct_eph)
    th2 = H(bstr(H(m['msg1'])) + bstr(ct_eph))       # TH_2 = H(H(message_1), ct_eph)
    prk_2e = extract(th2, ss_eph)
    ks2 = kdf(prk_2e, 0, th2, len(ct2))
    pt2 = bytes(a ^ b for a, b in zip(ct2, ks2))
    p2 = split_seq(pt2)                              # (C_R, ID_CRED_R, ?EAD_2)
    check('PLAINTEXT_2 decodes to (C_R, ID_CRED_R, ?EAD_2)', len(p2) >= 2)
    c_r, id_cred_r = p2[0], id_cred_from_plaintext(p2[1])

    # message_3 = ( ct_R_CIPHERTEXT_3 : bstr )
    (b3,) = split_seq(m['msg3'])
    b3 = bstr_value(b3)
    ct_r, ct3 = b3[:CT_LEN], b3[CT_LEN:]
    ss_r = KEM.decaps(resp_sk, ct_r)
    th3 = H(bstr(th2) + pt2 + cred_r + bstr(ct_r))   # TH_3 = H(TH_2, PT_2, CRED_R, ct_R)
    salt_3e2m = kdf(prk_2e, 1, th3, HASH_LEN)        # TH_3: -01 Section 4.1.2, Figure 3
    prk_3e2m = extract(salt_3e2m, ss_r)
    k3, iv3 = kdf(prk_3e2m, 3, th3, KEY_LEN), kdf(prk_3e2m, 4, th3, IV_LEN)
    pt3 = aead_decrypt(k3, iv3, ct3, enc_structure(th3))
    p3 = split_seq(pt3)                              # (C_I, ID_CRED_I, ?EAD_3)
    check('CIPHERTEXT_3 decrypts under K_3/IV_3 with external_aad TH_3', len(p3) >= 2)
    c_i, id_cred_i = p3[0], id_cred_from_plaintext(p3[1])

    # message_4_KEM = ( ct_I_CIPHERTEXT_4 : bstr )
    (b4,) = split_seq(m['msg4'])
    b4 = bstr_value(b4)
    ct_i, ct4 = b4[:CT_LEN], b4[CT_LEN:]
    ss_i = KEM.decaps(init_sk, ct_i)
    th4 = H(bstr(th3) + pt3 + cred_i + bstr(ct_i))   # TH_4 = H(TH_3, PT_3, CRED_I, ct_I)
    salt_4e3m = kdf(prk_3e2m, 5, th4, HASH_LEN)
    prk_4e3m = extract(salt_4e3m, ss_i)
    k4, iv4 = kdf(prk_4e3m, 8, th4, KEY_LEN), kdf(prk_4e3m, 9, th4, IV_LEN)
    pt4 = aead_decrypt(k4, iv4, ct4, enc_structure(th4))
    p4 = split_seq(pt4)                              # (MAC_2, ?EAD_4)
    context_2 = c_r + id_cred_r + bstr(th4) + cred_r + b''.join(p4[1:])
    check('MAC_2 = EDHOC_KDF(PRK_3e2m, 2, context_2, 16)',
          bstr_value(p4[0]) == kdf(prk_3e2m, 2, context_2, MAC_LEN))

    # message_5_KEM = ( CIPHERTEXT_5 : bstr )
    th5 = H(bstr(th4) + pt4)                         # TH_5 = H(TH_4, PLAINTEXT_4)
    (b5,) = split_seq(m['msg5'])
    k5, iv5 = kdf(prk_4e3m, 11, th5, KEY_LEN), kdf(prk_4e3m, 12, th5, IV_LEN)
    pt5 = aead_decrypt(k5, iv5, bstr_value(b5), enc_structure(th5))
    p5 = split_seq(pt5)                              # (MAC_3, ?EAD_5)
    check('CIPHERTEXT_5 decrypts under K_5/IV_5 (labels 11/12, TH_5)', len(p5) >= 1)
    context_3 = c_i + id_cred_i + bstr(th5) + cred_i + b''.join(p5[1:])
    check('MAC_3 = EDHOC_KDF(PRK_4e3m, 6, context_3, 16)',
          bstr_value(p5[0]) == kdf(prk_4e3m, 6, context_3, MAC_LEN))

    prk_out = kdf(prk_4e3m, 7, th5, HASH_LEN)        # PRK_out from TH_5
    check('PRK_out = EDHOC_KDF(PRK_4e3m, 7, TH_5, %d) equals the firmware\'s' % HASH_LEN,
          prk_out == m['prk_out'])
    # Application channel (src/edhoc_app_data.c): EDHOC_Exporter, RFC 9528
    # Section 4.2.1, labels 32768 / 32769, empty context, application AEAD
    # key and nonce sizes of the suite.
    if 'app_key' in m:
        prk_exporter = kdf(prk_out, 10, b'', HASH_LEN)
        check('app key = EDHOC_Exporter(32768, h\'\', %d)' % S['app_key'],
              m['app_key'] == kdf(prk_exporter, 32768, b'', S['app_key']))
        check('app IV  = EDHOC_Exporter(32769, h\'\', %d)' % S['app_iv'],
              m['app_iv'] == kdf(prk_exporter, 32769, b'', S['app_iv']))
    print('REFERENCE MODEL:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1

if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
