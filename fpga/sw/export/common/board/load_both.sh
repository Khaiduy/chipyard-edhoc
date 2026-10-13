#!/bin/bash
# load_both.sh — load firmware into BOTH boards over their C232HM JTAG cables
# (responder first: it boots and waits for message_1), resume them, and exit.
#
#   ./load_both.sh <initiator.elf> <responder.elf>
#
# Watch the run on the two USB-UART consoles (57600 baud), e.g.
#   screen /dev/ttyUSB3 57600     # initiator
#   screen /dev/ttyUSB4 57600     # responder
#
# The cables are told apart by FTDI serial (boards.env).
# Each board is loaded by a one-shot OpenOCD that exits after 'resume': two
# long-lived C232HM OpenOCD instances collide on the USB path and wedge a
# debug module (dmstatus=0x0). 'halt', not 'reset halt': ndmreset stalls the
# core clock on this bitstream. load_image overwrites any stale image.
set -e
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/boards.env"
INI=${1:?usage: $0 <initiator.elf> <responder.elf>}
RES=${2:?usage: $0 <initiator.elf> <responder.elf>}

load() {
	echo "  $1: $2"
	serial=$( [ "$1" = initiator ] && echo $INITIATOR_SERIAL || echo $RESPONDER_SERIAL )
	openocd -c "adapter serial $serial" -f "$HERE/c232hm.cfg" -c "poll off" -c "halt" \
		-c "reg mstatus 0x0" -c "reg mie 0x0" -c "reg mtvec 0x80000000" \
		-c "load_image $2" -c "resume 0x80000000" -c "shutdown"
}

for f in "$INI" "$RES"; do [ -f "$f" ] || { echo "not found: $f"; exit 1; }; done
load responder "$RES"
sleep 0.5
load initiator "$INI"
echo "Both boards running from 0x80000000."
