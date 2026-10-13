/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef PLAINTEXT_H
#define PLAINTEXT_H

#include <stdbool.h>
#include <stdint.h>

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "cbor.h"

/* RFC 9528 3.3.2: true if the byte string c_x is the one-byte CBOR encoding
 * of an int in -24..23, and so travels as that int, never as a bstr. */
bool c_x_is_encoded_int(const struct byte_array *c_x);

/* true if item is one well-formed C_x: a one-byte int, or a bstr that is
 * not the encoding of such an int (C_x = bstr / -24..23). */
bool c_x_item_valid(const uint8_t *item, uint32_t n);

/* Read ID_CRED_x from a plaintext into its map form (RFC 9528 3.5.3.2). */
enum err id_cred_read(struct cbor_r *r, struct byte_array *id_cred);

/**
 * @brief                       Decodes id_cred to kid.
 * 
 * @param[in] id_cred           ID_CRED_x
 * @param[out] kid              The result.
 * @retval                      Ok or error code.
 */
enum err id_cred2kid(const struct byte_array *id_cred, struct byte_array *kid);

/**
 * @brief                       Splits the plaintext of message 2. 
 *
 * @param[in] ptxt              Pointer to the plaintext.
 * @param[out] c_r              Connection identifier of the responder. 
 *                              This MUST be NULL when used plaintext 3 
 * @param[out] id_cred_x        ID_CRED_x.
 * @param[out] sign_or_mac      Signature or mac.
 * @param[out] ead              External Authorization Data.
 * @retval                      Ok or error code.
 */
enum err plaintext_split(struct byte_array *ptxt, struct byte_array *c_r,
			 struct byte_array *id_cred_x,
			 struct byte_array *sign_or_mac, struct byte_array *ad);

#endif
