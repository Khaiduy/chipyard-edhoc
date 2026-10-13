#include "secure_wipe.h"

void edhoc_wipe(void *p, size_t n)
{
	volatile uint8_t *vp = (volatile uint8_t *)p;

	while (n--)
		*vp++ = 0;
}
