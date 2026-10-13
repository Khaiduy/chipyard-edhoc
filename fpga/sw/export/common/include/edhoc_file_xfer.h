/*
 * edhoc_file_xfer.h — send a file from one board's SD card to the other's
 * over the EDHOC-derived channel (EXTRA_CFLAGS=-DAPP_SD_XFER).
 *
 * The initiator reads SEND.BIN from the FAT32 partition of its card; the
 * responder writes it as RECV.BIN on its own card. Copy the file on with any
 * PC; tools/mksd.sh prepares a card once.
 *
 * Composition, not new crypto: fat32.c streams bytes off and onto the cards
 * and edhoc_app_data.c protects each chunk under the key EDHOC derived.
 * Neither side holds more than one chunk and one sector, so RAM is flat in
 * the file size.
 *
 * Wire format, each record independently AEAD-protected:
 *
 *   record 0   : 4-byte length (BE); 0xFFFFFFFF = sender has no SEND.BIN
 *   record 1..n: the file, APP_PT_MAX bytes each, last one short
 *   record n+1 : 4-byte CRC-32 (BE) of the file
 *
 * The AEAD tag on every record is the security mechanism. The CRC-32 is an
 * end-to-end check that the bytes read off one card are the bytes written to
 * the other; RECV.BIN is only committed when length and CRC both match.
 */
#ifndef EDHOC_FILE_XFER_H
#define EDHOC_FILE_XFER_H

#include "edhoc_app_data.h"

/** @brief Sends SEND.BIN from the local card to the peer. */
enum err file_xfer_send(struct app_chan *ch, app_tx_fn tx, void *sock);

/**
 * @brief	Receives a file sent by file_xfer_send() and stores it as
 *		RECV.BIN. Without a usable card the stream is still received
 *		and checked, just not stored, so both sides stay in step.
 */
enum err file_xfer_recv(struct app_chan *ch, app_rx_fn rx, void *sock);

#endif /* EDHOC_FILE_XFER_H */
