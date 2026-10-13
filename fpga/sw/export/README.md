# EDHOC on RV64 — firmware packages

EDHOC firmware for the 64-bit Rocket core of `EdhocRocket6475MHzArty100TConfig`
(Arty A7-100T, 75 MHz, 64 KiB scratchpad), run board to board over an
MRF24J40 802.15.4 radio. `cd` into a package, read its README, `make`.

| Directory | What it is | Crypto |
|-----------|-----------|--------|
| [`edhoc-wolfssl/`](edhoc-wolfssl/) | EDHOC Methods 0–3, all 9 RFC 9528 suites (0–6, 24, 25) | wolfCrypt (P-256/384, X448, Ed448), Monocypher, curve25519-donna, `common/crypto` |
| [`edhoc-authkem/`](edhoc-authkem/) | EDHOC AuthKEM (draft-ietf-lake-authkem-edhoc-01), post-quantum, pqsuites TBD1 / TBD2 / TBD3 | ML-KEM-512/1024 (mlkem-native, FIPS 203), `common/crypto` |
| [`tests/`](tests/) | Crypto known-answer tests (SHA-2, HMAC, HKDF, AES-CCM/GCM, X25519, ML-KEM-512/768/1024) and GPIO / UART / SPI / JTAG peripheral tests | as the firmware |
| `common/` | Shared by all three: platform headers, startup, linker script, radio and UART links, CBOR, EDHOC core, symmetric crypto, application-data channel, SD card + FAT32 file transfer, build fragments (`mk/`), board scripts (`board/`) | |
| `tools/` | `mksd.sh`: prepares an SD card once (boot partition + FAT32 for `SEND.BIN` / `RECV.BIN`) | |

Everything is pure software (`rv64imac`/`lp64`) and needs only a bare-metal
RISC-V GCC (`riscv64-unknown-elf-gcc`). Every dependency is vendored: no
submodules, nothing to fetch. The packages share `common/`, so ship `export/`
as a whole (`make clean` in each package first, or just skip the `build*/`
directories).

Note: `edhoc-wolfssl/wolfssl/` contains a vendored wolfCrypt subset under
**GPLv2** (`COPYING`). If you cannot ship GPLv2, either replace it with a
wolfSSL commercial-license copy or hand recipients wolfSSL v5.9.1 separately.
