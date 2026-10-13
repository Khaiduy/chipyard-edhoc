/*
 * sd_card.h — microSD card on SPI0 (PMOD JA), SPI mode, 512-byte blocks.
 *
 * Block access only; the file system on top is fat32.c. The command sequence
 * is adapted from the bootloader's sdboot/sd.c, which drives the same slot.
 */
#ifndef EDHOC_SD_CARD_H
#define EDHOC_SD_CARD_H

#include <stdint.h>

#define SD_SECTOR_SIZE 512u

/**
 * @brief	Brings SPI0 up and takes the card through SPI-mode init
 *		(CMD0/CMD8/ACMD41/CMD58/CMD16).
 * @param pbus_hz	Peripheral bus clock in Hz; sets the SPI divider.
 * @return	0, or -1 if no card completed init.
 */
int sd_init(uint32_t pbus_hz);

/** @brief Card capacity in 512-byte sectors from the CSD; 0 if unknown
 *	   (SDSC cards, CSD v1, are not handled). */
uint32_t sd_sectors(void);

/** @brief Reads block @p lba into @p buf (CRC-16 checked). 0 or -1. */
int sd_read(uint32_t lba, uint8_t *buf);

/** @brief Writes @p buf to block @p lba and waits until programmed. 0 or -1. */
int sd_write(uint32_t lba, const uint8_t *buf);

#endif /* EDHOC_SD_CARD_H */
