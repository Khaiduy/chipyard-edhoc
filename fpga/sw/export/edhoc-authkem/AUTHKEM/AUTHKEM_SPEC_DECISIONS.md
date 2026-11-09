# authkem-01 + pqsuites TBD1/TBD2/TBD3 — current implementation (2026-10)

Target: `draft-ietf-lake-authkem-edhoc-01` (28 Sep 2026) with the cipher
suites of `draft-ietf-lake-pqsuites-01` (Table 3), one per image (`SUITE=`):

| Suite | EDHOC AEAD | Hash | KEM | App AEAD |
|-------|-----------|------|-----|----------|
| TBD1 | AES-CCM-16-128-128 | SHAKE256 | ML-KEM-512 | AES-CCM-16-64-128 |
| TBD2 (default) | A256GCM | SHAKE256 | ML-KEM-512 | A256GCM |
| TBD3 | A256GCM | SHA-384 | ML-KEM-1024 | A256GCM |

-01 drops the -00 suite-7 proposal and refers to pqsuites for suites. The
SHAKE256 notes below apply to TBD1/TBD2; TBD3 uses SHA-384 with HKDF as in
RFC 9528.

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
EDHOC_Exporter runs on the EDHOC hash too.

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

## Credential encoding

The board applications use an RFC 8392/RFC 8747 CCS containing an AKP
COSE_Key, as authkem-edhoc-01 3.1.3 and draft-ietf-jose-pqc-kem-06 Section 8
specify: `{8: {1: {1: 7, 3: alg, -1: pk}}}` (`cnf` → `COSE_Key` → key). AKP
(`kty` 7, `pub` label -1) follows `draft-ietf-cose-dilithium`. The ML-KEM
algorithm values are TBD1 (ML-KEM-512) and TBD3 (ML-KEM-1024) in
jose-pqc-kem-06 and unassigned, so COSE private-use values stand in:
-65537 for ML-KEM-512 (TBD1, TBD2) and -65539 for ML-KEM-1024 (TBD3)
(`include/authkem_cred.h`).

ID_CRED is `{4: h'01'}` / `{4: h'02'}`: kid is a byte string (COSE). In
PLAINTEXT_2/3 it travels compact as the int 1 / 2 (RFC 9528 3.5.3.2); a
received compact int expands to the byte-string kid it encodes, and the
non-canonical forms (a bstr holding a one-byte int encoding, a full `{4:
kid}` map, a multi-byte int) are refused, as are such forms of C_I/C_R
(RFC 9528 3.3.2).
