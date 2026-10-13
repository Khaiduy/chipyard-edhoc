/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef INT_ENCODE_DECODE_H
#define INT_ENCODE_DECODE_H

#include <stdint.h>
#include "common/oscore_edhoc_error.h"

/**
 * @brief 			Encodes an int in CBOR.
 * 
 * @param[in] in		The input int.
 * @param in_len 		The length of the int.
 * @param[out] out		The result.
 * @return 			Ok or error code. 
 */
enum err encode_int(const int32_t *in, uint32_t in_len, struct byte_array *out);

#endif
