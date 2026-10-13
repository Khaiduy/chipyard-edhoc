#!/usr/bin/env bash
#
# mksd.sh — prepare a microSD card once for the board: MBR with
#   partition 1  LBA 2048, 32 MiB, raw: the SD boot image (common/board/sd_boot.sh)
#   partition 2  the rest, FAT32: SEND.BIN / RECV.BIN for the file transfer
#
#   sudo ./mksd.sh /dev/sdX [boot.bin]
#
# Afterwards copy the file to send onto partition 2 as SEND.BIN with any PC;
# the receiving board writes RECV.BIN there. ERASES THE WHOLE CARD.
set -euo pipefail

DEV=${1:?usage: sudo $0 /dev/sdX [boot.bin]}
BOOT=${2:-}
[ -b "$DEV" ] || { echo "$DEV is not a block device"; exit 1; }
[ "$(lsblk -dno TYPE "$DEV")" = disk ] || { echo "$DEV is not a whole disk"; exit 1; }
[ "$(lsblk -dno RM "$DEV" | tr -d ' ')" = 1 ] || { echo "$DEV is not removable; refusing"; exit 1; }
[ -z "$BOOT" ] || [ -f "$BOOT" ] || { echo "not found: $BOOT"; exit 1; }

lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINT "$DEV"
read -p "Erase all of $DEV? [y/N] " -n 1 -r; echo
[[ $REPLY =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }

umount "$DEV"?* 2>/dev/null || true
printf 'label: dos\n2048,65536,da\n67584,,c\n' | sfdisk -q "$DEV"
partprobe "$DEV" 2>/dev/null || true
sleep 1
P=$DEV; case $DEV in *[0-9]) P=${DEV}p ;; esac
mkfs.vfat -F 32 -n EDHOC "${P}2" >/dev/null
[ -z "$BOOT" ] || dd if="$BOOT" of="${P}1" bs=1M conv=fsync status=none
sync
echo "done: ${P}1 boot (raw), ${P}2 FAT32 'EDHOC'. Copy SEND.BIN onto ${P}2."
