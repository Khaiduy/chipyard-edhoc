# EDHOC AuthKEM on RV64 — post-quantum, ML-KEM-512 / ML-KEM-1024

Bare-metal firmware for the five-message EDHOC AuthKEM handshake
([draft-ietf-lake-authkem-edhoc-01](https://datatracker.ietf.org/doc/draft-ietf-lake-authkem-edhoc/),
Method 5) with the cipher suites of
[draft-ietf-lake-pqsuites-01](https://datatracker.ietf.org/doc/draft-ietf-lake-pqsuites/).
Both parties authenticate with static ML-KEM keys; no signatures, no
Diffie-Hellman. Target: the 64-bit Rocket of `EdhocRocket6475MHzArty100TConfig`
(Arty A7-100T, 75 MHz, 64 KiB scratchpad).

| `SUITE=` | EDHOC AEAD | Hash / KDF | KEM | App AEAD | Wire label |
|----------|-----------|------------|-----|----------|-----------:|
| TBD1 | AES-CCM-16-128-128 | SHAKE256 / KMAC256 | ML-KEM-512 | AES-CCM-16-64-128 | -22 |
| TBD2 (default) | A256GCM | SHAKE256 / KMAC256 | ML-KEM-512 | A256GCM | -24 |
| TBD3 | A256GCM | SHA-384 / HKDF | ML-KEM-1024 | A256GCM | -23 |

TBD3 (AES-256 + ML-KEM-1024) is the strongest option configured here. The pqsuites
code points are not assigned yet, so suites travel as RFC 9528 private-use
labels; `AUTHKEM/AUTHKEM_SPEC_DECISIONS.md` records how each draft ambiguity
was resolved.

ML-KEM is [mlkem-native](https://github.com/pq-code-package/mlkem-native)
(FIPS 203), with a local `MLK_CONFIG_LOW_RAM` option that cuts the ML-KEM-1024
decapsulation stack from 34 kB to 19 kB so TBD3 fits. AES, SHA-2, HMAC/HKDF and
KMAC come from `../common/crypto`, shared with edhoc-wolfssl.

## Build

Needs `riscv64-unknown-elf-gcc` with an `rv64imac`/`lp64` multilib, a host
`cc`, and the sibling `../common/` directory.

```bash
make edhoc_authkem_initiator SUITE=TBD3
make edhoc_authkem_responder SUITE=TBD3
```

Output: `build/` for TBD2, `build-tbd1/`, `build-tbd3/` for the others. Options
as in edhoc-wolfssl: `TRANSPORT=rf|uart` (default rf, MRF24J40 on PMOD JC),
`DEBUG=1`, `TIMING=1` (compute time of each of the 5 message steps, as in edhoc-wolfssl), `APP_FILE_BYTES=<n>`, `EXTRA_CFLAGS=-DAPP_SD_XFER`
(SD card to SD card file transfer, `SEND.BIN` -> `RECV.BIN`), and
`PROFILE=production PROVISION_DIR=<dir> PROVISION_SRC=<files>`, which refuses the
shared demo keys in `src/mlkem*_test_keys.h` (see `include/authkem_provision.h`).

The demo credentials (CCS, identified by kid) are generated at build time by
`tools/gen_ccs.c` into `build*/gen/authkem_creds.h`. Each holds an AKP
COSE_Key (draft-ietf-jose-pqc-kem-06); the ML-KEM-512 / ML-KEM-1024 `alg`
values are still unassigned, so COSE private-use values -65537 / -65539 stand
in. ID_CRED is `{4: h'01'}` / `{4: h'02'}` (kid is a byte string), sent in
compact form; see `AUTHKEM/AUTHKEM_SPEC_DECISIONS.md` for the encodings the
receiver refuses.

## Host tests

```bash
make unit-test SUITE=TBD2        # suite gate, KEM, CBOR codecs, error messages
make loopback-test SUITE=TBD2    # full handshake, two threads, PRK_out compared
make loopback-test LOOPBACK_LOG=build/loopback.txt
python3 tools/authkem_ref.py build/loopback.txt   # independent model of the draft
```

`authkem_ref.py` re-derives every transcript hash, key, MAC and `PRK_out` from
the logged wire bytes (needs kyber-py, pycryptodome, cryptography).

## Running on two boards

```bash
../common/board/load_both.sh build-tbd3/edhoc_authkem_initiator.elf \
                             build-tbd3/edhoc_authkem_responder.elf
```

Watch both consoles at 57600 baud: each prints `EDHOC OK!`, `PERF` lines and its
peak stack, then runs the encrypted application-data echo and prints
`APP DATA OK`.

`../common/board/run_pair.sh <name> <initiator.elf> <responder.elf>` does the
same and prints one PASS/FAIL line; it also compares the `PRK_out` both sides
print (`prk=match`). `VERBOSE=1` in front shows both consoles live, and a
`DEBUG=1` build adds the intermediate values (message_1, TH_2, salt, MAC_2
computed and received, ...).

## Layout

```
Makefile         includes mk/config.mk, ../common/mk/rules.mk, mk/targets.mk
mk/config.mk     suite selection, profile, stack reservation, sources
mk/targets.mk    initiator / responder targets, credential generation
src/             initiator / responder mains, demo ML-KEM key pairs
include/         CCS credential layout, provisioning interface
AUTHKEM/         AuthKEM protocol library (messages, key schedule, suites)
tests/           host unit and loopback tests
tools/           gen_ccs.c, authkem_ref.py, gen_mlkem_test_keys.py
```
