#!/bin/bash
# list_boards.sh — print the serial of every Arty (Digilent FT2232, console
# tty) and every C232HM JTAG cable plugged in, for filling in boards.env.
# Plug the boards in one at a time to tell which serial belongs to which.
for d in /sys/bus/usb/devices/*; do
	s=$(cat "$d/serial" 2>/dev/null) || continue
	p=$(cat "$d/product" 2>/dev/null)
	case "$p" in
	Digilent*) echo "Arty console  $s  /dev/$(ls "$d/$(basename "$d"):1.1" 2>/dev/null | grep -m1 tty)" ;;
	C232HM*)   echo "C232HM JTAG   $s  ($p)" ;;
	esac
done
