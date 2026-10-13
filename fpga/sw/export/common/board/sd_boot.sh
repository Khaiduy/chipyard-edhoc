#!/bin/bash
# sd_boot.sh — write a firmware .bin raw to the SD card's boot partition; the
# bootrom (sdboot) copies it from LBA 2048 into the scratchpad at power-on.
#
#   sudo ./sd_boot.sh <file.bin> <partition>     e.g. sdc1
#
# The partition must start at LBA 2048 (the usual first partition).
BIN=${1:?usage: sudo $0 <file.bin> <partition, e.g. sdc1>}
DEV=/dev/${2:?usage: sudo $0 <file.bin> <partition, e.g. sdc1>}
[ -f "$BIN" ] || { echo "not found: $BIN"; exit 1; }
[ -b "$DEV" ] || { echo "no block device $DEV. Available:"; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT; exit 1; }
START=$(cat /sys/class/block/$(basename "$DEV")/start 2>/dev/null)
[ "$START" = 2048 ] || { echo "$DEV starts at LBA ${START:-?}, not 2048: sdboot would not find it"; exit 1; }
echo "Write $BIN ($(stat -c%s "$BIN") B) to $DEV?"
read -p "[y/N] " -n 1 -r; echo
[[ $REPLY =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }
dd if="$BIN" of="$DEV" bs=1M conv=fsync status=progress
