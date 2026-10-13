/* DEMO static key pairs for the suite this image is built for: ML-KEM-512
 * (pqsuites TBD2, default) or ML-KEM-1024 (TBD3, SUITE=TBD3). */
#if AUTHKEM_PQ_SUITE == 3
#include "mlkem1024_test_keys.h"
#else
#include "mlkem512_test_keys.h"
#endif
