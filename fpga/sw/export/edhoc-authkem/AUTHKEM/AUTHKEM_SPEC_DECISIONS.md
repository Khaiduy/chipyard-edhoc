# authkem-01 + pqsuites TBD1/TBD2/TBD3 — current implementation (2026-10)

Target: `draft-ietf-lake-authkem-edhoc-01` (28 Sep 2026) with the cipher
suites of `draft-ietf-lake-pqsuites-01` (Table 3), one per image (`SUITE=`):

| Suite | EDHOC AEAD | Hash | KEM | App AEAD |
|-------|-----------|------|-----|----------|
| TBD1 | AES-CCM-16-128-128 | SHAKE256 | ML-KEM-512 | AES-CCM-16-64-128 |
| TBD2 (default) | A256GCM | SHAKE256 | ML-KEM-512 | A256GCM |
| TBD3 | A256GCM | SHA-384 | ML-KEM-1024 | A256GCM |

-01 drops the -00 suite-7 proposal and refers to pqsuites for suites.
Everything below the line further down is the -00 history. The SHAKE256 notes
below apply to TBD1/TBD2; TBD3 uses SHA-384 with HKDF as in RFC 9528.

Changes from -00, all implemented:

| | -00 (old code) | -01 (now) |
|---|---|---|
| TH_2 | `H(pk_eph, H(m1))` | `H(H(message_1), ct_eph)` |
| TH_3 | `H(ct_R, TH_2, PT_2, CRED_R)` | `H(TH_2, PT_2, CRED_R, ct_R)` |
| TH_4 | `H(ct_I, TH_3, PT_3, CRED_I)` | `H(TH_3, PT_3, CRED_I, ct_I)` |
| message_3 / _4 | two bstrs | one bstr `ct ‖ CIPHERTEXT` (like message_2) |
| SALT_3e2m context | TH_2 | TH_3 (see below) |
| message_5 key | K_4 / IV_4 | K_5 / IV_5, labels 11 / 12, context TH_5 |
| PRK_out context | TH_4 | TH_5 |

-01 settled the -00 figure-vs-prose conflict in favour of the figure.

Suite TBD2 per RFC 9528 Sections 4.1.1 / 4.1.2 with an EDHOC hash of SHAKE256:
H = SHAKE256 with 512-bit output (hash_length 64), EDHOC_Extract =
KMAC256(salt, IKM, 512, ""), EDHOC_Expand = KMAC256(PRK, info, 8L, "").
EDHOC_Exporter runs on the EDHOC hash too (the application channel used the
application hash before; same thing for suite 7, wrong for TBD2).

**Remaining ambiguities in -01, and what this code does:**

* SALT_3e2m: the KDF table in Section 4.1.2 still shows `TH_2`, and the
  Responder's processing steps compute PRK_3e2m before TH_3. The new text in
  the same section ("SALT_3e2m and SALT_4e3m are derived using the latest
  available transcript hash ..., which are TH_3 and TH_4") and the redrawn
  Figure 3 (`L=1 ctx=TH_3`) say TH_3. **TH_3 is used.** The table row is
  unchanged from -00 while the SALT_4e3m row next to it was edited, so it reads
  as a leftover. Not yet raised on github.com/lake-wg/authkem.
* Section 5.3.2 (Initiator composition of message_3) still writes
  `TH_3 = H(ct_R, TH_2, PLAINTEXT_2, CRED_R)`; Section 5.3.3 and Figure 3 have
  the new order. **The new order is used** (both sides must agree, and 5.3.3
  is the one that changed).
* The PRK_out formula in Section 4.1.3 still reads
  `EDHOC_KDF(PRK_4e3m, TH_4, hash_length)` (no label); the table and the
  "changes" list say label 7 with TH_5. **Label 7, TH_5.**

**Unassigned code points:** the suites travel as RFC 9528 private-use suite
labels, TBD2 **-24**, TBD3 **-23**, TBD1 **-22** (`AUTHKEM_SUITE_TBD*` in
`inc/edhoc/suites.h`, overridable with `-DAUTHKEM_SUITE_TBD2=<n>` etc. once
IANA assigns them). Suite bytes are stored
signed. Method 5 is still "suggested". The ML-KEM-512 COSE value (TBD1 in
draft-ietf-jose-pqc-kem-06) never reaches the wire.

**ML-DSA-44** only names the suite's signature slot (verifying X.509
credentials). Credentials here are CCS by kid, so no ML-DSA is linked.

**Verification:** no published test vectors exist for -01. `make loopback-test
LOOPBACK_LOG=build/loopback.txt` runs both roles on the host and
`tools/authkem_ref.py` re-derives every transcript hash, PRK, keystream, AEAD,
MAC, PRK_out and the application key/IV from the logged wire bytes. It is an
independent model written from the draft text (kyber-py, pycryptodome,
cryptography). Swapping in the TH_2 reading of SALT_3e2m makes it fail at the
message_3 AEAD tag. SHAKE256/KMAC256 and A256GCM were also checked against
hashlib, pycryptodome, `cryptography` and the McGrew–Viega GCM test case 16.

---

# authkem-00 — spec decisions and implementation plan (history)

Target: `EDHOC_doc/draft-ietf-lake-authkem-edhoc-00.txt` (5-message, KEM-only,
Method 5). Body is technically identical to `draft-pocero-lake-authkem-edhoc-00`
— the diff is the WG-adoption rename, dates, and one reflowed table.

This tree was derived from an earlier 3-message IKR implementation
(`draft-pocero-authkem-ikr-edhoc-03`), which is not shipped in this export.
The IKR and current five-message AuthKEM protocols both use METHOD 5, but they
are **not** configurations of one state machine: their key schedules, KDF label
spaces, and transcript-hash chains are disjoint.

## Ruling on figure-vs-prose conflicts

Figure 2 (§3, key schedule) contradicts the §4 prose on every transcript hash.
**Decision: the prose is normative; the figure is treated as informational and
wrong.** Applied uniformly, no case-by-case judgement.

| TH | Figure 2 | §4 prose (adopted) | Prose sites |
|----|----------|--------------------|-------------|
| TH_2 | `H(H(msg1), ct_eph)` | **`H(pk_eph, H(message_1))`** | §4.2.2 :981, §4.2.3 :1037 |
| TH_3 | `H(TH_2, PLAINTEXT_2, CRED_R, ct_R)` | **`H(ct_R, TH_2, PLAINTEXT_2, CRED_R)`** | §4.3.2 :1099, §4.3.3 :1160 |
| TH_4 | `H(TH_3, PLAINTEXT_3, CRED_I, ct_I)` | **`H(ct_I, TH_3, PLAINTEXT_3, CRED_I)`** | §4.4.2 :1206 |
| TH_5 | — | **`H(TH_4, PLAINTEXT_4)`** | §4.5.2 :1261, §4.5.3 :1323 |

TH_2 is the substantive one: the figure hashes `ct_eph`, the prose hashes
`pk_eph`. Not a reordering — different input material. Both prose sites agree
and both roles derive it identically, so the prose is self-consistent.

TH_3 and TH_4 differ only in where the ciphertext sits; the prose puts it first.

## Other draft defects found

- §4.4.1 and §4.5.1 both name their CDDL rule `message_3 = (` inside the
  *Message 4* and *Message 5* sections. Copy-paste; read as `message_4` and
  `message_5`.
- §4.3.2 bullet 3 says "the Responder is not yet able to authenticate itself,
  so MAC_3 is not computed" inside *Initiator* composition of msg3. Should read
  Initiator / MAC_3.
- §5.2 suite 8's algorithm array (`10, -16, 8, 1, -55, -49, -16`) does not match
  its own description (A256GCM, SHA-384, 16, ML-KEM-1024, ML-DSA-65, A256GCM,
  SHA-384): `10` is AES-CCM-16-64-128, not A256GCM. Suite 8 is not implemented
  here, so this is recorded, not resolved. Suite 7 (ML-KEM-512) is unaffected
  and is already wired in `src/edhoc/suites.c`.
- §3.1.2 notes K_5/IV_5 "can be derived" but does not define them; msg5 reuses
  K_4/IV_4 (§4.5.2). Adopted as written.

## Protocol to implement

```
I -> R  msg1 = (METHOD, SUITES_I, pk_eph, C_I, ?EAD_1)      -- plaintext
I <- R  msg2 = (ct_eph | CIPHERTEXT_2)                      -- XOR keystream
I -> R  msg3 = (ct_R, CIPHERTEXT_3)                         -- AEAD, aad TH_3
I <- R  msg4 = (ct_I, CIPHERTEXT_4)                         -- AEAD, aad TH_4
I -> R  msg5 = (CIPHERTEXT_5)                               -- AEAD, aad TH_5
```

`PLAINTEXT_2 = (C_R, ID_CRED_R, ?EAD_2)`, `PLAINTEXT_3 = (C_I, ID_CRED_I, ?EAD_3)`.
Initiator derives `PRK_out` after msg4, Responder after msg5.

### Key schedule (§3.1.2 Fig 3) — labels 0..10

```
KEYSTREAM_2  = EDHOC_KDF(PRK_2e,   0, TH_2,      plaintext_length)
SALT_3e2m    = EDHOC_KDF(PRK_2e,   1, TH_2,      hash_length)
MAC_2        = EDHOC_KDF(PRK_3e2m, 2, context_2, mac_length_2)
K_3          = EDHOC_KDF(PRK_3e2m, 3, TH_3,      key_length)
IV_3         = EDHOC_KDF(PRK_3e2m, 4, TH_3,      iv_length)
SALT_4e3m    = EDHOC_KDF(PRK_3e2m, 5, TH_4,      hash_length)
MAC_3        = EDHOC_KDF(PRK_4e3m, 6, context_3, mac_length_3)
PRK_out      = EDHOC_KDF(PRK_4e3m, 7, TH_4,      hash_length)
K_4          = EDHOC_KDF(PRK_4e3m, 8, TH_4,      key_length)
IV_4         = EDHOC_KDF(PRK_4e3m, 9, TH_4,      iv_length)
PRK_exporter = EDHOC_KDF(PRK_out, 10, h'',       hash_length)

PRK_2e   = EDHOC_Extract(TH_2,      ss_eph)
PRK_3e2m = EDHOC_Extract(SALT_3e2m, ss_R)
PRK_4e3m = EDHOC_Extract(SALT_4e3m, ss_I)
```

MAC contexts carry the *latest* transcript hash, not the one matching the MAC
index — worth stating because it reads like a typo, but §4.4.2 and §4.5.2 both
say so explicitly:

```
context_2 = << C_R, ID_CRED_R, TH_4, CRED_R, ?EAD_4 >>
context_3 = << C_I, ID_CRED_I, TH_5, CRED_I, ?EAD_5 >>
```

## Tree layout

The KEM backend vendors `mlkem-native` commit
`9cd4c6df08e428f63e47a0dfa59c02c79e647c71` under
`externals/mlkem-native/`. This replaces the inherited round-3 Kyber/PQClean
code with FIPS 203 ML-KEM-512, including the required encapsulation public-key
modulus check and decapsulation secret-key hash check. TinyCrypt and zcbor
remain the symmetric/CBOR dependencies.

Removed from the imported IKR code (not part of this export):
`src/edhoc/ikr_{initiator,responder,messages,plaintext}.c`,
`inc/edhoc/ikr_{messages,plaintext}.h`.

Renamed: `crypto_wrapper_ikr.c` -> `crypto_wrapper_kem.c`, guard
`EDHOC_IKR_ONLY` -> `EDHOC_KEM_ONLY`, make switch `IKR_ONLY` -> `KEM_ONLY`. The
wrapper body is unchanged and directly reusable — ML-KEM plus TinyCrypt
AEAD/SHA-256/HKDF, sign/verify stubbed.

The legacy `enum ikr_info_label` remains in `inc/edhoc/hkdf_info.h` only for
source compatibility. Nothing in this tree calls it.

## What is implemented

Full five-message state machine, host-validated and building for RV32.

| File | Contents |
|------|----------|
| `src/edhoc/authkem_initiator.c` | initiator: msg1 gen, msg2/msg4 process, msg3/msg5 gen |
| `src/edhoc/authkem_responder.c` | responder: msg1/msg3/msg5 process, msg2/msg4 gen |
| `src/edhoc/authkem_messages.c` | CBOR for all five messages |
| `src/edhoc/authkem_plaintext.c` | PLAINTEXT_2/3/4/5 and context_2/context_3 |
| `src/edhoc/th.c` | `authkem_th2_calculate`, `authkem_th_calculate` |
| `src/edhoc/prk.c` | `authkem_prk_extract` |

The KDF label enum needed no new definitions: authkem-00 reuses the RFC 9528
label space exactly, so the existing `enum info_label` (0..10) is used as-is.
CIPHERTEXT_2's XOR keystream is applied inline in the two state machines.

### Crypto backend seam

`src/common/crypto_wrapper.c` keeps the same filename and role it has in
upstream uoscore-uedhoc. It is trimmed to the Method-5 primitives rather than carrying the
multi-method dispatch, but it is the same seam.

The contract is the 14 functions declared in `inc/common/crypto_wrapper.h`:

```
KEM        ephemeral_kem_key_gen, kem_encapsulate, kem_decapsulate
AEAD       aead
Hash       hash
HKDF       hkdf_extract, hkdf_expand, hkdf_sha_256
ECDH       shared_secret_derive, ephemeral_dh_key_gen
Signature  sign_signature, sign_verify, sign_edhoc, verify_edhoc
```

All 14 are `WEAK`, so an application can accelerate a single primitive with a
hardware core by defining a strong symbol of the same signature — the library
is not touched. Replacing the whole backend means writing another file against
the same header and swapping this one out of the build.

The three KEM primitives used to be declared in `edhoc.h`, and
`kem_encapsulate` / `kem_decapsulate` were not `WEAK` — so the very primitives
an ML-KEM core would accelerate could not be overridden. They now sit in
`crypto_wrapper.h` with the rest of the contract.

Note this is the per-primitive offload path. The other hardware model in this
repo — whole-handshake offload, as in `../src/edhoc_m3_initiator_hw.c` driving
`../driver/edhoc_m3` over MMIO — bypasses the library entirely and does not use
this seam.

### Standard layout kept

The tree carries the full standard uoscore-uedhoc file set plus the AuthKEM
state machines; upstream has no AuthKEM flow. The RFC 9528 four-message flow (`initiator.c`,
`responder.c`, `plaintext_{encode,decode}.c`, `ciphertext.c`,
`signature_or_mac_msg.c`, `cert.c`), the OSCORE layer, and the standard
`th2_calculate` / `th34_calculate` / `prk_derive` are all present and building.

`th.c` and `prk.c` hold both key schedules side by side, the RFC 9528 functions
and the authkem ones, each labelled.

An earlier revision of this tree deleted those files to shrink the build. That
was unnecessary: `-ffunction-sections -fdata-sections` with `-Wl,--gc-sections`
already drops everything the authkem path never calls, so restoring them left
both RV32 binaries **byte-identical** (29641 B and 28781 B). Deleting sources is
not how this build gets small; the linker is.

The one exception is the certificate credential path, which *is* reachable --
`retrieve_cred()` dispatches into it -- so it is excluded by the
`EDHOC_NO_CERT_CRED` build flag rather than by garbage collection. The code
stays in the tree; only the branches compile out.

`KEM_ONLY=1` similarly stops `makefile_config.mk` adding `-DFALCON_LEVEL_1`, so
the Falcon backend is not compiled even though nothing would link it.

Verified with `nm` on both ELFs: zero symbols matching
`falcon|sign_|verify_edhoc|dilithium|cert|x509|asn1|oscore`.

## Bug found in the inherited code

`AAD_SIZE` was 45. The COSE `Enc_structure` `["Encrypt0", h'', h'TH']` with a
32-byte transcript hash encodes to **46** bytes, measured directly against
`cbor_encode_edhoc_enc_structure` (45 and below fail, 46 succeeds). With 45 the
generated encoder returned `unexpected_result_from_ext_lib`, so every AEAD in
messages 3, 4 and 5 failed. Corrected to 46 in `inc/edhoc/buffer_sizes.h`.

This was latent upstream rather than new: the other user of `AAD_SIZE` is the
RFC 9528 `ciphertext.c`, which the AuthKEM state machine does not exercise.
AuthKEM is the first active path here that constructs this Enc_structure.

## Credential encoding

The board applications use an RFC 8392/RFC 8747 CCS containing an AKP
COSE_Key, as authkem-edhoc-01 3.1.3 and draft-ietf-jose-pqc-kem-06 Section 8
specify: `{8: {1: {1: 7, 3: alg, -1: pk}}}` (`cnf` → `COSE_Key` → key). AKP
(`kty` 7, `pub` label -1) follows `draft-ietf-cose-dilithium`. The ML-KEM
algorithm values are TBD1 (ML-KEM-512) and TBD3 (ML-KEM-1024) in
jose-pqc-kem-06 and unassigned, so COSE private-use values stand in:
-65537 for ML-KEM-512 (TBD1, TBD2) and -65539 for ML-KEM-1024 (TBD3)
(`include/authkem_cred.h`). Earlier builds used -54 (the authkem-00
provisional value) for both parameter sets.

ID_CRED is `{4: h'01'}` / `{4: h'02'}`: kid is a byte string (COSE). In
PLAINTEXT_2/3 it travels compact as the int 1 / 2 (RFC 9528 3.5.3.2); a
received compact int expands to the byte-string kid it encodes, and the
non-canonical forms (a bstr holding a one-byte int encoding, a full `{4:
kid}` map, a multi-byte int) are refused, as are such forms of C_I/C_R
(RFC 9528 3.3.2).

## Status

- `make host-test` — **PASS**: FIPS 203 keygen/encapsulation/decapsulation,
  invalid-public-key rejection, multi-suite message_1, compact byte-string
  `kid`, encoded connection IDs, EAD sequence round trips, and all three RFC
  9528 error-message forms.
- RV32 with `TIMING=1`: `make edhoc_authkem_initiator` 36447 B text / 7864 B
  bss; `make edhoc_authkem_responder` 35807 B text / 5424 B bss.
- **Not yet run on hardware.** A two-board end-to-end run is still required.
- `DEMO_RNG=1` is the explicit default for the board demo and is not suitable
  for production. A production build must use `DEMO_RNG=0` and provide the
  platform `edhoc_platform_entropy()` hook from a TRNG-backed implementation;
  otherwise randomness fails closed.
