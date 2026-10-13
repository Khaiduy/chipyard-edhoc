/* sd_format.h — see src/sd_format.c */
#ifndef SD_FORMAT_H
#define SD_FORMAT_H

#include <stdint.h>

enum { SD_FMT_OK = 0, SD_FMT_EIO = -1, SD_FMT_SMALL = -2 };

/** @brief Writes the mksd.sh layout (MBR, boot partition, FAT32) onto a
 *	   card of @p total sectors. Erases everything but partition 1. */
int sd_format(uint32_t total);

#endif /* SD_FORMAT_H */
