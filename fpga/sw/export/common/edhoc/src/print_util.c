/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "common/print_util.h"

void print_array(const char *label, const uint8_t *in_data, uint32_t in_len)
{
	kprintf("%s (size %u):", label, (unsigned)in_len);
	for (uint32_t i = 0; i < in_len; i++)
		kprintf(i % 16 ? "%02X " : "\n  %02X ", in_data[i]);
	kprintf("\n");
}

void handle_runtime_error(int error_code, const char *file_name,
			  const int line)
{
	(void)error_code;
	(void)file_name;
	(void)line;
	PRINTF("Runtime error: code %d at %s:%d\n", error_code, file_name, line);
}

void handle_external_runtime_error(int error_code, const char *file_name,
				   const int line)
{
	(void)error_code;
	(void)file_name;
	(void)line;
	PRINTF("External library error: code %d at %s:%d\n", error_code,
	       file_name, line);
}
