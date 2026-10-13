#!/usr/bin/env python3
"""Generate a DEMO ML-KEM (FIPS 203) static key header for the AuthKEM apps.

    python3 tools/gen_mlkem_test_keys.py 1024 > src/mlkem1024_test_keys.h

Keys come from ML-KEM.KeyGen_internal(d, z) with d, z derived from fixed
labels (SHAKE256("authkem-demo-<role>-<level>"), 64 bytes -> d || z), so the
header is reproducible. They are public demo keys: never use them in a real
device. Needs kyber-py (pip install kyber-py).
"""
import hashlib
import sys

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

LEVELS = {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}


def c_array(name, data):
    rows = [', '.join('0x%02x' % b for b in data[i:i + 16])
            for i in range(0, len(data), 16)]
    return ('static const uint8_t %s[%d] = {\n    ' % (name, len(data)) +
            ',\n    '.join(rows) + '\n};\n')


def main(level):
    kem = LEVELS[level]
    out = ['/* ML-KEM-%d test vectors (tools/gen_mlkem_test_keys.py %d) '
           '-- DO NOT USE IN PRODUCTION */\n' % (level, level),
           '#ifdef EDHOC_PROFILE_PRODUCTION\n'
           '#error "mlkem%d_test_keys.h contains shared DEMO private keys and '
           'must never be built into a production image. Provide device keys '
           'via PROVISION_DIR / PROVISION_SRC (see include/authkem_provision.h)."\n'
           '#endif\n' % level]
    for role, prefix in (('init', 'INIT'), ('resp', 'RESP')):
        seed = hashlib.shake_256(b'authkem-demo-%s-%d' % (role.encode(), level)).digest(64)
        ek, dk = kem._keygen_internal(seed[:32], seed[32:])
        out.append('\n' + c_array(prefix + '_SK', dk))
        out.append('\n' + c_array(prefix + '_PK', ek))
    sys.stdout.write(''.join(out))


if __name__ == '__main__':
    main(int(sys.argv[1]))
