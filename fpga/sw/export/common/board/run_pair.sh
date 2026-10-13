#!/bin/bash
# run_pair.sh — run one EDHOC pair on the two boards and judge it.
#
#   ./run_pair.sh <name> <initiator.elf> <responder.elf> [timeout_s]
#
# Loads both boards (load_both.sh), captures both consoles until each prints
# APP DATA OK or a FAIL, saves them as $LOGDIR/<name>.ini.log / .res.log and
# prints one line, also appended to $RESULTS:
#   <name> PASS|FAIL hs=<initiator handshake s> stack_i=<B> stack_r=<B> prk=<p> <s>[ why]
# PASS = both sides EDHOC OK and APP DATA OK, no OVERRAN-RESERVE, and the two
# PRK_out dumps equal when both consoles print one (prk=match|DIFFER|-).
#
# VERBOSE=1 ./run_pair.sh ... also shows both consoles live (I| initiator,
# R| responder). Build with DEBUG=1 to add the intermediate values (TH_2,
# PRK_2e, K_3, MAC_2, ...); with TIMING=1 the steps include that printing.
# The consoles are found by the boards' Digilent serials (boards.env), since
# ttyUSB numbers move whenever Vivado or OpenOCD opens a port.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/boards.env"
NAME=${1:?usage: $0 <name> <initiator.elf> <responder.elf> [timeout_s]}
INI=${2:?}; RES=${3:?}; TMO=${4:-300}
OUT=${LOGDIR:-boardlogs}; mkdir -p "$OUT"
RESULTS=${RESULTS:-$OUT/results.txt}
LI=$OUT/$NAME.ini.log; LR=$OUT/$NAME.res.log

tty_of() { for d in /sys/bus/usb/devices/*; do
	[ "$(cat $d/serial 2>/dev/null)" = "$1" ] && ls $d/$(basename $d):1.1 | grep -m1 tty; done; }
TI=/dev/$(tty_of $INITIATOR_CONSOLE); TR=/dev/$(tty_of $RESPONDER_CONSOLE)
for t in $TI $TR; do stty -F $t 57600 raw -echo clocal -crtscts || exit 1; done
cat $TI > $LI.raw & C1=$!
cat $TR > $LR.raw & C2=$!
trap 'kill $C1 $C2 2>/dev/null' EXIT
if [ "${VERBOSE:-0}" = 1 ]; then
	tail --pid=$C1 -n +1 -f $LI.raw | LC_ALL=C sed -u 's/[^[:print:]\t]//g;s/^/I| /' & T1=$!
	tail --pid=$C2 -n +1 -f $LR.raw | LC_ALL=C sed -u 's/[^[:print:]\t]//g;s/^/R| /' & T2=$!
fi

"$HERE/load_both.sh" "$INI" "$RES" > $OUT/$NAME.load.log 2>&1 ||
	{ echo "$NAME LOADFAIL" | tee -a $RESULTS; exit 1; }
T0=$(date +%s)
done_() { grep -qa "APP DATA OK\|FAIL" "$1"; }
while ! { done_ $LI.raw && done_ $LR.raw; }; do
	sleep 1; [ $(( $(date +%s) - T0 )) -ge $TMO ] && break
done
sleep 1; kill $C1 $C2 2>/dev/null; [ -n "$T1" ] && wait $T1 $T2
for f in $LI $LR; do tr -d '\r' < $f.raw | tr -cd '\11\12\40-\176' > $f; rm -f $f.raw; done

ok=1; why=""
for f in $LI $LR; do
	grep -q "EDHOC OK!" $f || { ok=0; why="$why no-EDHOC-OK($(basename $f))"; }
	grep -q "APP DATA OK" $f || { ok=0; why="$why no-APP-OK($(basename $f))"; }
	grep -q "OVERRAN-RESERVE" $f && { ok=0; why="$why OVERRAN($(basename $f))"; }
done
# PRK_out: a label line, then lines of hex bytes (authkem app or DEBUG=1 dump)
prk_of() { awk '/PRK_out/ { if (got) exit; f = 1; next }
	f && /^ *([0-9A-F][0-9A-F] *)+$/ { got = got $0; next } { f = 0 }
	END { gsub(/ /, "", got); print got }' "$1"; }
pi=$(prk_of $LI); pr=$(prk_of $LR); prk=-
[ -n "$pi" ] && [ -n "$pr" ] && { [ "$pi" = "$pr" ] && prk=match ||
	{ prk=DIFFER; ok=0; why="$why PRK_out-differs"; }; }
hs=$(grep -m1 "handshake_total" $LI | awk '{print $5}')
si=$(grep -m1 "STACK peak" $LI | awk '{print $3}'); sr=$(grep -m1 "STACK peak" $LR | awk '{print $3}')
[ $ok = 1 ] && v=PASS || v=FAIL
echo "$NAME $v hs=${hs}s stack_i=$si stack_r=$sr prk=$prk $(( $(date +%s) - T0 ))s$why" | tee -a $RESULTS
[ $ok = 1 ]
