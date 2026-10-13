#ifndef EDHOC_EAD_H
#define EDHOC_EAD_H

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/* Validate EAD = 1* (ead_label:int, ? ead_value:bstr). Empty is accepted for
 * the optional EAD field. The bytes remain opaque to the EDHOC layer. */
enum err ead_validate(const struct byte_array *ead);

#endif
