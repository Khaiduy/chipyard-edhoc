#!/bin/bash
# run_one.sh — load one ELF into one board over its C232HM JTAG cable, resume
# it, and print what its console says.
#
#   ./run_one.sh <file.elf> [seconds]
#
# Env overrides:
#   BOARD=initiator|responder  which board/cable (default initiator)
#   TTY=/dev/ttyUSBn           that board's USB-UART console (default: found
#                              by the board's serial in boards.env)
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/boards.env"
ELF=${1:?usage: $0 <file.elf> [seconds]}
SECS=${2:-30}
BOARD=${BOARD:-initiator}
if [ -z "$TTY" ]; then
	CONSOLE=$( [ "$BOARD" = responder ] && echo $RESPONDER_CONSOLE || echo $INITIATOR_CONSOLE )
	for d in /sys/bus/usb/devices/*; do
		[ "$(cat $d/serial 2>/dev/null)" = "$CONSOLE" ] &&
			TTY=/dev/$(ls $d/$(basename $d):1.1 | grep -m1 tty)
	done
	[ -n "$TTY" ] || { echo "console $CONSOLE not found: check boards.env (list_boards.sh)"; exit 1; }
fi
[ -f "$ELF" ] || { echo "not found: $ELF"; exit 1; }

stty -F "$TTY" 57600 raw -echo clocal -crtscts
LOG=$(mktemp)
cat "$TTY" > "$LOG" &
CAT=$!
trap 'kill $CAT 2>/dev/null; rm -f "$LOG"' EXIT

SERIAL=$( [ "$BOARD" = responder ] && echo $RESPONDER_SERIAL || echo $INITIATOR_SERIAL )
openocd -c "adapter serial $SERIAL" -f "$HERE/c232hm.cfg" -c "poll off" -c "halt" \
	-c "reg mstatus 0x0" -c "reg mie 0x0" -c "reg mtvec 0x80000000" \
	-c "load_image $ELF" -c "resume 0x80000000" -c "shutdown" >/dev/null 2>&1

sleep "$SECS"
tr -d '\r' < "$LOG" | tr -cd '\11\12\40-\176'
