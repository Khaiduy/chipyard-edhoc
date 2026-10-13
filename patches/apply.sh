#!/bin/bash
# apply.sh — apply this fork's changes to two Chipyard submodules. Run once from
# the repository root after ./build-setup.sh (or git submodule update --init):
#   fpga-shells.patch         Vivado opt/place/route flow used to close 75 MHz
#   rocket-chip-blocks.patch  GPIO tie-offs for the EDHOC SoC's 8-pin GPIO
set -e
cd "$(dirname "$0")/.."
git -C fpga/fpga-shells apply "$PWD/patches/fpga-shells.patch"
git -C generators/rocket-chip-blocks apply "$PWD/patches/rocket-chip-blocks.patch"
echo "patches applied"
