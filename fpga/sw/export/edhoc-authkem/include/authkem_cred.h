#ifndef AUTHKEM_CRED_H
#define AUTHKEM_CRED_H

#include <stdint.h>
#include <string.h>

/* RFC 8392 CCS containing an AKP COSE_Key (draft-ietf-jose-pqc-kem-06 8):
 * { 8: { 1: { 1: 7, 3: alg, -1: h'...' } } }
 * kty AKP (7) and pub (-1) follow draft-ietf-cose-dilithium. alg names the
 * key's parameter set; ML-KEM-512 and ML-KEM-1024 are TBD1 and TBD3 in
 * draft-ietf-jose-pqc-kem-06, still unassigned, so values from the COSE
 * private-use range (< -65536) stand in until IANA assigns them, as the
 * cipher suites use RFC 9528's private-use labels. */
#if MLK_CONFIG_PARAMETER_SET == 1024
#define AUTHKEM_COSE_ALG_LOW 0x02   /* -65539: ML-KEM-1024 */
#else
#define AUTHKEM_COSE_ALG_LOW 0x00   /* -65537: ML-KEM-512 */
#endif
#define AUTHKEM_CRED_OVERHEAD 17u
#define AUTHKEM_CRED_SIZE(pk_len) (AUTHKEM_CRED_OVERHEAD + (pk_len))

static inline uint32_t authkem_build_ccs(uint8_t *out, uint32_t capacity,
					 const uint8_t *pk, uint32_t pk_len)
{
	if (pk_len > 0xffffu || capacity < AUTHKEM_CRED_SIZE(pk_len))
		return 0;
	uint8_t prefix[] = {
		0xa1, 0x08,       /* CCS: { cnf(8): ... } */
		0xa1, 0x01,       /* cnf: { COSE_Key(1): ... } */
		0xa3,             /* COSE_Key with three members */
		0x01, 0x07,       /* kty: AKP(7) */
		0x03, 0x3a, 0x00, 0x01, 0x00, AUTHKEM_COSE_ALG_LOW, /* alg */
		0x20, 0x59,       /* pub(-1): bstr(16-bit length) */
		(uint8_t)(pk_len >> 8), (uint8_t)pk_len
	};
	memcpy(out, prefix, sizeof(prefix));
	memcpy(out + sizeof(prefix), pk, pk_len);
	return (uint32_t)sizeof(prefix) + pk_len;
}

#endif
