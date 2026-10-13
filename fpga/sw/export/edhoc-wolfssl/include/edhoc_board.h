/* edhoc_board.h - board-side helpers shared by src/edhoc_initiator.c and
 * src/edhoc_responder.c (console, link start-up, reports, app channel). */
#ifndef EDHOC_BOARD_H
#define EDHOC_BOARD_H

#include <stdint.h>
#include "common/byte_array.h"

void board_init(int is_responder);
void board_report(uint64_t t0, uint64_t t1);
void board_app_data(struct byte_array *prk_out, int is_initiator);

#endif /* EDHOC_BOARD_H */
