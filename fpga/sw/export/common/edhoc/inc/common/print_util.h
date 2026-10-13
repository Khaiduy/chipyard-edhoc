/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef PRINT_UTIL_H
#define PRINT_UTIL_H

#include <stdint.h>

/* Debug output of the EDHOC library, on the console UART via kprintf. All of
 * it compiles away unless DEBUG_PRINT is defined (make DEBUG=1). */

void kprintf(const char *, ...);

/**
 * @brief		Prints a labelled hex dump, 16 bytes per line.
 */
void print_array(const char *label, const uint8_t *in_data, uint32_t in_len);

/**
 * @brief		Called by TRY / TRY_EXPECT with the location of a failed
 *			call; prints it in DEBUG_PRINT builds.
 */
void handle_runtime_error(int error_code, const char *file_name,
			  const int line);
void handle_external_runtime_error(int error_code, const char *file_name,
				   const int line);

#ifdef DEBUG_PRINT
#define PRINT_ARRAY(msg, a, a_len) print_array((msg), (a), (a_len))
#define PRINT_MSG(msg) kprintf("%s", (msg))
#define PRINTF(...) kprintf(__VA_ARGS__)
#else
#define PRINT_ARRAY(msg, a, a_len)                                             \
	do {                                                                   \
	} while (0)
#define PRINT_MSG(msg)                                                         \
	do {                                                                   \
	} while (0)
#define PRINTF(...)                                                            \
	do {                                                                   \
	} while (0)
#endif

#endif /* PRINT_UTIL_H */
