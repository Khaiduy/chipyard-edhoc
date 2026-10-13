#ifndef TRY_CLEANUP_H
#define TRY_CLEANUP_H

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

/* Error handling that routes every exit through a cleanup label.
 *
 * The library's TRY() returns directly on failure. That is fine for control
 * flow and wrong for key material: a function that wipes its shared secrets
 * just before `return ok` leaves them in the frame on every error path, which
 * is exactly the path an attacker who can induce failures gets to choose.
 *
 * These variants behave identically to TRY()/BYTE_ARRAY_NEW() -- same error
 * codes, same handle_runtime_error() call, same buffers -- except that they
 * jump to `cleanup` instead of returning. A function using them must declare
 *
 *     enum err r = ok;
 *
 * and end with
 *
 *     cleanup:
 *         <wipes>
 *         return r;
 *
 * Wipes must address the NAME##_buf array and sizeof, never the byte_array
 * struct: a jump taken before the struct is initialised would otherwise read
 * an uninitialised .ptr/.len. The underlying array is a fixed-size object
 * whose storage exists for the whole function, so it is always safe to wipe.
 */

#define TRY_CLEANUP(x)                                                         \
	do {                                                                   \
		enum err _tc_retval = (x);                                     \
		if (ok != _tc_retval) {                                        \
			handle_runtime_error(_tc_retval, __FILE__, __LINE__);   \
			r = _tc_retval;                                        \
			goto cleanup;                                          \
		}                                                              \
	} while (0)

/* Fail to `cleanup` with an explicit error code. */
#define FAIL_CLEANUP(err_code)                                                 \
	do {                                                                   \
		r = (err_code);                                                \
		goto cleanup;                                                  \
	} while (0)

/* BYTE_ARRAY_NEW that fails to `cleanup` rather than returning. Mirrors the
 * non-VLA definition in byte_array.h. */
#define BYTE_ARRAY_NEW_C(NAME, BUF_SIZE, SIZE)                                 \
	TRY_CLEANUP(check_buffer_size(BUF_SIZE, SIZE));                        \
	struct byte_array NAME;                                                \
	uint8_t NAME##_buf[BUF_SIZE];                                          \
	if ((SIZE) == 0) {                                                     \
		NAME = NULL_ARRAY;                                             \
	} else {                                                               \
		NAME.ptr = NAME##_buf;                                         \
		NAME.len = (SIZE);                                             \
	};

#endif /* TRY_CLEANUP_H */
