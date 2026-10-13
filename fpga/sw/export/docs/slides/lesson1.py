#!/usr/bin/env python3
"""lesson1.py — Lesson 1 of 5: EDHOC SoC on Arty A7-100T.

    python3 lesson1.py           -> 01_EDHOC_SoC_on_Arty_A7-100T.pptx

Course plan: 1 hardware SoC · 2 software environment & tests · 3 EDHOC on two
boards · 4 post-quantum EDHOC · 5 secure file transfer & results.

Numbers come from the real build and boards (Vivado reports of
EdhocRocket6475MHzArty100TConfig, ELF sizes, console output of tests/).
[Bracketed] text and PHOTO boxes are placeholders still to be filled.
"""
import os

from pptx.dml.color import RGBColor

from slidekit import Deck, GRAY, GREEN, RED, HEAD_BG

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                   "01_EDHOC_SoC_on_Arty_A7-100T.pptx")
SOC = RGBColor(0xDA, 0xE8, 0xFC)
PMOD = RGBColor(0xFF, 0xF2, 0xCC)
EXT = RGBColor(0xE2, 0xF0, 0xD9)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)

d = Deck()
d.sections = ["Start Here", "Requirements → Hardware", "SoC Configuration",
              "FPGA Pins & Harness", "Build & Timing Closure", "Programming & Bring-up",
              "Practice"]

# ---------------------------------------------------------------- opening
d.title("「 Lesson 1 」 EDHOC SoC on Arty A7-100T")
d.purpose("Today’s lecture purpose:", [
    "Turn the EDHOC hardware requirement into a Chipyard SoC: 64-bit Rocket, "
    "8 KiB caches, 64 KiB on-chip RAM, GPIO / UART / JTAG / SPI.",
    "Set up your PC and boards from a fresh clone, then map the SoC onto two Arty "
    "A7-100T boards: SD card, radio, UART and JTAG on the four PMOD ports.",
    "Build the bitstream, close timing at 75 MHz, program both boards and "
    "check every peripheral with a test program.",
], footer="Repository: github.com/Khaiduy/chipyard-edhoc (private: ask the author for "
          "access)   ·   paths are relative to its root")
d.outline()

# ---------------------------------------------------------------- 1. start here
S0 = "1. Start Here"
d.outline(0)

s = d.content(S0, "(1/7) The learning path")
path = [("Clone", "L1"), ("Prepare\nhardware", "L1, L2"), ("Run a\nhandshake", "L3, L4"),
        ("Understand\nthe bytes", "L3, L4"), ("Transfer\na file", "L5"),
        ("Measure", "L3–L5"), ("Diagnose\nfailures", "L2–L5")]
for i, (step, les) in enumerate(path):
    x = 0.35 + i * 1.84
    d.box(s, step, x, 1.0, 1.55, 1.0, fill=SOC if i < 2 else EXT, size=14, bold=True)
    d.text(s, [("", les)], x, 2.05, 1.55, 0.4, size=14, bullets=False, color=GRAY)
    if i:
        d.arrow(s, x - 0.29, 1.5, x, 1.5)
d.text(s, [
    "At the end of the course you can, with only these slides and the repository:",
    (1, "configure **your own** two boards (cables, consoles, wiring);"),
    (1, "run one classical (RFC 9528) and one post-quantum (AuthKEM) handshake and "
        "explain the important output lines;"),
    (1, "send a file from one SD card to the other and prove it arrived intact;"),
    (1, "find the cause of a deliberately broken build or link, and restore it."),
], 0.4, 2.7, 12.5, 3.0, size=18)
d.text(s, [("", "Lesson map: 1 hardware SoC · 2 software and first runs · 3 EDHOC · "
            "4 post-quantum EDHOC · 5 file transfer, performance, diagnosis.")],
       0.4, 6.1, 12.5, 0.8, size=16, bullets=False, color=GRAY)

s = d.content(S0, "(2/7) Equipment")
d.table(s, [
    ["Item", "Qty", "Notes"],
    ["Digilent Arty A7-100T", "2", "one board per party (initiator A, responder B)"],
    ["micro-USB cable", "2", "power, FPGA programming and the console of each Arty"],
    ["FTDI C232HM-DDHSL-0 USB–JTAG cable (3.3 V)", "2",
     "core debug on PMOD JD; leave its red VCC wire unconnected"],
    ["microSD PMOD adapter (PmodSD) + microSD card", "2",
     "PMOD JA; any SDHC / SDXC card — it gets erased"],
    ["MRF24J40MA 802.15.4 module on a PMOD adapter", "2", "PMOD JC; adapter: [part no.]"],
    ["SD card reader (optional)", "1", "copy your own files; without one, sd_prep does "
                                      "it over JTAG"],
    ["3 jumper wires (optional)", "–", "wired UART1 link on PMOD JB instead of the radio"],
], 0.4, 0.95, 12.5, 4.6, size=15, col_w=[5.2, 0.8, 6.5])
d.text(s, [("", "Wiring of every PMOD, pin by pin: section 4 (2/8).")], 0.4, 5.8, 12.5,
       0.6, size=16, bullets=False, color=GRAY)

s = d.content(S0, "(3/7) Software")
d.table(s, [
    ["Software", "Tested version", "Needed for"],
    ["Ubuntu (x86-64)", "24.04 LTS", "host PC"],
    ["Vivado ML Standard (free) or Vivado Lab", "2024.2", "building (route A) and "
                                                         "programming the FPGAs"],
    ["Chipyard and its conda environment", "1.11.0 + this fork", "route A only"],
    ["riscv64-unknown-elf-gcc, rv64imac / lp64 multilib", "15.1.0", "all firmware"],
    ["OpenOCD with RISC-V and FTDI support", "0.12.0+dev", "loading firmware over JTAG"],
    ["Python 3", "3.11", "host tests, timing tables, these slides (python-pptx)"],
    ["pip: pyfatfs pycryptodome cryptography kyber-py", "–",
     "FAT32 host test, AuthKEM reference model"],
    ["dosfstools (mkfs.vfat, fsck.fat)", "4.2", "FAT32 host test, mksd.sh"],
], 0.4, 0.95, 12.5, 4.6, size=15, col_w=[5.6, 2.4, 4.5])
d.text(s, [
    "USB access without sudo: install Vivado's cable drivers (Digilent) and "
    "OpenOCD's *60-openocd.rules* (C232HM), and be in the *dialout* / *plugdev* "
    "groups for the consoles.",
    "Other versions may work; these are the ones every result in the course came from.",
], 0.4, 5.75, 12.5, 1.3, size=16)

s = d.content(S0, "(4/7) Get the code — two routes")
b = d.code(s, """git clone git@github.com:Khaiduy/chipyard-edhoc.git chipyard
cd chipyard
git checkout edhoc-course-v1     # the revision these slides describe""",
           0.4, 0.95, 12.5, 1.2, size=15, title="Run this — on your PC")
d.table(s, [
    ["Route", "Your goal", "Setup", "Then"],
    ["A — full hardware build", "learn how the SoC is generated and placed on the FPGA",
     "./build-setup.sh riscv-tools; source env.sh; ./scripts/init-fpga.sh; "
     "./patches/apply.sh",
     "Lesson 1 from section 2"],
    ["B — firmware only", "run and study the protocols on boards that already hold "
                          "the EDHOC bitstream", "cd fpga/sw/export; toolchain + OpenOCD "
                                                 "(Lesson 2, section 1)",
     "Lesson 1, section 6, then Lesson 2"],
], 0.4, d.below(b, 0.3), 12.5, 2.3, size=15, col_w=[2.6, 3.9, 3.9, 2.1])
d.text(s, [
    "The repository is **private**: ask the author to add your GitHub account, then "
    "clone with your own SSH key.",
    "No prebuilt bitstream ships with the course: route B needs a bitstream built "
    "from the **same revision** (route A), e.g. by your lab, written to the boards' "
    "flash or kept as a *.bit*.",
    "The firmware tree *fpga/sw/export/* is self-contained (all code vendored) and "
    "needs only the toolchain, OpenOCD and Python — not Chipyard.",
], 0.4, 4.6, 12.5, 2.3, size=17)

s = d.content(S0, "(5/7) Readiness check")
b = d.code(s, """vivado -version | head -1                      # Vivado v2024.2 ...
riscv64-unknown-elf-gcc --version | head -1    # ... 15.1.0
openocd --version 2>&1 | head -1               # Open On-Chip Debugger 0.12.0 ...
cd fpga/sw/export && ./common/board/list_boards.sh""",
           0.4, 0.95, 12.5, 1.6, size=15, title="Run this — from the repository root")
b = d.console(s, """C232HM JTAG   FTA6GPSN  (C232HM-DDHSL-0)
Arty console  210319B4A439  /dev/ttyUSB4
C232HM JTAG   FTA6JVAK  (C232HM-DDHSL-0)
Arty console  210319B269F6  /dev/ttyUSB1""", 0.4, d.below(b, 0.25), 7.5, 1.6, size=14,
              title="Example output — our lab (your serials differ)")
d.text(s, [
    "Expect **two** Arty lines, each with a tty, and **two** C232HM lines.",
], 8.1, d.below(b, -1.5), 5.0, 1.4, size=16)
d.table(s, [
    ["If", "Check first"],
    ["an Arty is missing", "USB cable, board power switch, Vivado cable drivers"],
    ["an Arty has no tty", "dialout / plugdev group (log out and in), Vivado holding the port"],
    ["a C232HM is missing", "USB plug, OpenOCD udev rules (0403:6014)"],
], 0.4, d.below(b, 0.3), 12.5, 1.7, size=15, col_w=[3.3, 9.2])

s = d.content(S0, "(6/7) How to read the practical slides")
d.code(s, """make gpio_test""", 0.4, 0.95, 6.0, 0.6, size=15,
       title="Run this — from fpga/sw/export/tests")
d.console(s, """GPIO TEST: PASS (0 failures)""", 6.8, 0.95, 6.3, 0.6, size=14,
          title="Example output — board A")
d.code(s, """while (busy) ...   /* shortened: not runnable */""", 0.4, 2.0, 6.0, 0.6,
       size=15, title="Simplified — common/src/sd_card.c")
d.text(s, [
    "**Run this** boxes are complete commands, in order, with the directory they "
    "start from. **Example output** boxes are real console text. **Simplified** "
    "boxes shorten source code with “...” — read them, do not paste them.",
    "Every lab follows the same steps: **objective → starting state → commands → "
    "expected output → what it proves → if it fails**.",
    "Serial numbers, tty names and times in examples come from our lab; yours "
    "differ. Lesson 2 shows how to set up your own.",
], 0.4, 3.0, 12.5, 4.0, size=18)

s = d.content(S0, "(7/7) Words used in this course")
d.table(s, [
    ["Term", "Meaning", "Term", "Meaning"],
    ["EDHOC", "Ephemeral Diffie-Hellman Over COSE (RFC 9528)", "AEAD",
     "encryption + integrity tag (AES-CCM, AES-GCM, ChaCha20/Poly1305)"],
    ["initiator / responder", "board A / board B: who sends message_1 / who answers",
     "KEM", "key encapsulation: (ct, ss) = Encaps(pk); ss = Decaps(sk, ct)"],
    ["suite", "set of algorithms (curve or KEM, hash, AEAD)", "ML-KEM",
     "the NIST post-quantum KEM (FIPS 203)"],
    ["method", "how each side proves itself: signature or static DH", "AuthKEM",
     "post-quantum EDHOC, method 5 (IETF draft)"],
    ["CBOR / COSE", "compact binary encoding / its security formats", "PRK_out",
     "the shared secret EDHOC ends with"],
    ["CRED / ID_CRED / kid", "a public-key credential / a short reference to it / key id",
     "TH_n", "transcript hash: everything sent so far"],
    ["PMOD", "Digilent 12-pin expansion socket", "PERF / STACK",
     "console lines with timing / stack use"],
], 0.4, 0.95, 12.5, 5.0, size=14, col_w=[2.4, 4.0, 1.8, 4.3])
d.text(s, [("", "Every later lesson uses these words without repeating them; come back "
            "here when one is unclear.")], 0.4, 6.15, 12.5, 0.7, size=16, bullets=False,
       color=GRAY)

# ------------------------------------------------- 2. requirements -> hardware
S1 = "2. Requirements → Hardware"
d.outline(1)

s = d.content(S1, "(1/4) What the design asks for, and what we chose")
d.table(s, [
    ["Item", "Asked for", "Built", "Why"],
    ["Core", "Rocket, 64-bit", "Rocket RV64IMAC (small core)", ""],
    ["L1 caches", "8 KiB I$ + 8 KiB D$", "8 KiB I$ + 8 KiB D$", ""],
    ["RAM", "32 KiB minimum", "64 KiB on-chip scratchpad", "**code + stack, next slide**"],
    ["Peripherals", "GPIO, UART, JTAG, SPI", "8 GPIO, 2 UART, 3 SPI, JTAG debug", ""],
    ["Clock", "100 MHz", "75 MHz", "**timing result, (3/4)**"],
    ["FPGA", "Artix-7 100T", "Arty A7-100T (xc7a100tcsg324-1)", ""],
], 0.5, 1.0, 12.3, 4.2, size=18, col_w=[2.0, 3.3, 4.9, 2.1])
d.text(s, ["Two items differ from what was asked; the next two slides show why, and how to check it yourself.",
           "Board-to-board traffic goes over an MRF24J40 802.15.4 radio; files come "
           "from a microSD card."], 0.5, 5.5, 12.3, 1.3, size=18)

s = d.content(S1, "(2/4) Why 64 KiB of RAM")
cats = ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s24", "s25", "TBD1", "TBD2", "TBD3"]
img = [42291, 42291, 43739, 43739, 41653, 43365, 46361, 47391, 47913, 32712, 32876, 37637]
stk = [5376, 5376, 8448, 8448, 5376, 8448, 8448, 11008, 12544, 22016, 22016, 23808]
d.bar_chart(s, cats, [("Image (code + data)", img), ("Stack reserve", stk)],
            0.3, 0.85, 8.2, 6.1)
d.text(s, [
    "Largest build of each cipher suite (EDHOC suites 0–25, post-quantum TBD1–3), "
    "in bytes.",
    "Everything fits **64 KiB = 65,536 B**; largest: suite 25 = 60,457 B, "
    "TBD3 = 61,445 B.",
    "Smallest build (suite 4, method 3) needs ≈ 32.3 KB with its stack: only method 3 "
    "of suites 0 / 1 / 4 fits 32 KiB, and barely.",
    "Check any build yourself: Lesson 2, “Will my build fit?”.",
    "The requirement says “minimum 32 KiB”, so 64 KiB is within it.",
], 8.7, 1.0, 4.4, 6.0, size=17)

s = d.content(S1, "(3/4) Why 75 MHz instead of 100 MHz")
d.table(s, [
    ["Target clock", "Worst slack (WNS)", "Failing endpoints", "Result"],
    ["100 MHz", "−3.191 ns", "4,372 of 24,321", "Fmax ≈ 1 / 13.19 ns = 75.8 MHz"],
    ["75 MHz", "0.000 ns (met)", "0 of 24,148", "**Used**"],
], 0.5, 1.0, 12.3, 1.7, size=18, col_w=[2.2, 3.0, 3.0, 4.1])
d.text(s, [
    "The critical path is inside the Rocket core, not in our peripherals:",
    (1, "fetch queue → RVC expander → decoder → hazard check → EX operand register"),
    (1, "13 LUT levels, 83 % of the delay is routing"),
    "Result of **this** implementation (Vivado 2024.2, this config and flow, speed "
    "grade -1): 100 MHz failed timing, 75 MHz closes. A different flow, constraints "
    "or core configuration can change that — re-check after any change.",
    "The clock is set in one place, `WithTinyArty100TTweaks(75)` (section 3); the "
    "check is *report/timing.txt* (section 5).",
], 0.5, 3.0, 12.3, 3.9, size=19)

s = d.content(S1, "(4/4) The two-board system")
for bx, name in ((0.4, "Board A — Initiator"), (7.0, "Board B — Responder")):
    d.box(s, f"**{name}**\nArty A7-100T", bx, 1.0, 5.9, 0.75, fill=EXT, size=16)
    d.box(s, "Rocket RV64 · 75 MHz\n64 KiB scratchpad · 8 KiB I$/D$", bx + 1.4, 2.0, 3.1, 1.0,
          fill=SOC, size=14)
    d.box(s, "JA\nmicroSD", bx, 3.4, 1.35, 0.95, fill=PMOD, size=14)
    d.box(s, "JB\nUART1", bx + 1.5, 3.4, 1.35, 0.95, fill=PMOD, size=14)
    d.box(s, "JC\nMRF24J40", bx + 3.0, 3.4, 1.35, 0.95, fill=PMOD, size=14)
    d.box(s, "JD\nJTAG", bx + 4.5, 3.4, 1.35, 0.95, fill=PMOD, size=14)
    d.box(s, "PC: OpenOCD + C232HM\nUSB-UART console", bx + 3.2, 4.85, 2.7, 0.85,
          fill=RGBColor(0xEE, 0xEE, 0xEE), size=13)
    d.arrow(s, bx + 5.17, 4.35, bx + 5.17, 4.85, both=True)
# radio link: between the SoC boxes and the PMOD row, JC of A <-> JC of B
d.arrow(s, 4.075, 3.18, 4.075, 3.4, color=GREEN, width=3)
d.arrow(s, 10.675, 3.18, 10.675, 3.4, color=GREEN, width=3)
c = d.arrow(s, 4.075, 3.18, 10.675, 3.18, color=GREEN, width=3)
c.line._get_or_add_ln().remove(c.line._get_or_add_ln()[-1])   # plain line
d.text(s, [("", "**2.4 GHz IEEE 802.15.4 radio**"), ("", "EDHOC handshake + encrypted file")],
       4.95, 2.05, 3.4, 0.9, size=14, bullets=False, color=GREEN)
d.text(s, ["Same bitstream on both boards; the firmware decides the role.",
           "SD card on JA holds SEND.BIN (board A) and RECV.BIN (board B)."],
       0.4, 5.9, 6.3, 1.2, size=16)
d.photo(s, "both boards wired: JA SD, JC radio, JD JTAG cable", 7.0, 5.85, 5.9, 1.2)

# ---------------------------------------------------------- 2. SoC configuration
S2 = "3. SoC Configuration"
d.outline(2)

s = d.content(S2, "(1/7) One config class builds the SoC")
d.text(s, ["The bitstream is built from **EdhocRocket6475MHzArty100TConfig** in "
           "*fpga/src/main/scala/arty100t/Configs.scala*:"], 0.4, 0.85, 12.5, 0.8, size=19,
       bullets=False)
b = d.code(s, """class EdhocRocket6475MHzArty100TConfig extends Config(
  new WithArtyJCRadio ++                  // board-to-board link: MRF24J40 on PMOD JC (SPI1)
  new WithTinyArty100TTweaks(75) ++       // Arty shell, peripherals, all bus clocks = 75 MHz
  new chipyard.config.WithBroadcastManager ++   // coherence without an L2 cache
  new chipyard.EdhocRocket64Config        // the SoC itself (next slide)
)""", 0.4, 1.7, 12.5, 2.0, size=14)
d.text(s, [
    "Chipyard configs are a chain of fragments joined with `++`; a fragment on the "
    "**left overrides** the ones on its right.",
    "Read it bottom-up: the SoC → how memory coherence works → the board shell and "
    "clock → the radio pin variant.",
    "Same pattern as the Chipyard lecture (04: *MyRocketConfig* on Arty 35T), on the 100T board.",
], 0.4, d.below(b, 0.3), 12.5, 3.0, size=19)

s = d.content(S2, "(2/7) EdhocRocket64Config: the SoC")
d.text(s, [("", "*generators/chipyard/src/main/scala/config/EdhocConfigs.scala*")],
       0.4, 0.8, 12.5, 0.5, size=17, bullets=False)
d.code(s, """class EdhocRocket64Config extends Config(
  new freechips.rocketchip.subsystem.WithL1ICacheSets(128) ++     // 8 KiB I-cache
    new freechips.rocketchip.subsystem.WithL1DCacheSets(128) ++   // 8 KiB D-cache
    new chipyard.harness.WithDontTouchChipTopPorts(false) ++
    new testchipip.soc.WithMbusScratchpad(base = 0x80000000L,
                                          size = BigInt(64 << 10)) ++  // 64 KiB on-chip SRAM
    new freechips.rocketchip.subsystem.WithNoMemPort ++           // no DDR / off-chip memory
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++      // one small Rocket, RV64
    new freechips.rocketchip.subsystem.WithoutTLMonitors ++
    new chipyard.config.AbstractConfig)""", 0.4, 1.3, 7.6, 3.6, size=12)
d.table(s, [
    ["Fragment", "Effect"],
    ["WithNSmallCores(1)", "1 Rocket tile, RV64IMAC, no FPU"],
    ["WithL1I/DCacheSets(128)", "128 sets → 8 KiB caches"],
    ["WithMbusScratchpad", "64 KiB SRAM at 0x8000_0000 (BRAM)"],
    ["WithNoMemPort", "no DDR: all code + data on chip"],
    ["WithoutTLMonitors", "smaller, faster (no protocol checkers)"],
], 8.2, 1.3, 4.9, 3.6, size=14, col_w=[2.3, 2.6])
d.text(s, ["Everything the firmware uses — code, data, stack — lives in the 64 KiB "
           "scratchpad. There is no external RAM on this SoC.",
           "The Arty’s 256 MB DDR3 is left unused: the requirement asks for on-chip "
           "RAM, and the whole firmware fits on chip."],
       0.4, 5.1, 12.5, 1.9, size=18)

s = d.content(S2, "(3/7) Cache size and fragment order")
d.box(s, "128 sets", 0.6, 1.2, 2.0, 0.8, size=20, bold=True)
d.text(s, [("", "×")], 2.65, 1.3, 0.4, 0.6, size=26, bullets=False)
d.box(s, "1 way", 3.1, 1.2, 2.0, 0.8, size=20, bold=True)
d.text(s, [("", "×")], 5.15, 1.3, 0.4, 0.6, size=26, bullets=False)
d.box(s, "64 B / line", 5.6, 1.2, 2.0, 0.8, size=20, bold=True)
d.text(s, [("", "=")], 7.65, 1.3, 0.4, 0.6, size=26, bullets=False)
d.box(s, "8 KiB per cache", 8.1, 1.2, 2.6, 0.8, size=20, bold=True, fill=HEAD_BG)
d.text(s, [
    "`WithNSmallCores(1)` creates the tile with small default caches; "
    "`WithL1ICacheSets` / `WithL1DCacheSets` **rewrite** those tile parameters.",
    "A rewrite only sees tiles that already exist, so the cache fragments must stay "
    "**to the left** of `WithNSmallCores` in the chain.",
    "Wrong order builds without error but gives the default cache size — check the "
    "generated *.dts* / *.json* or the utilization report after a change.",
    "Small core = RV64IMAC: integer, multiply/divide, atomics, compressed; "
    "no floating point (the firmware is integer-only).",
], 0.5, 2.4, 12.3, 4.6, size=19)

s = d.content(S2, "(4/7) Memory map")
d.table(s, [
    ["Address", "Size", "Device", "Used for"],
    ["0x0000_0000", "4 KiB", "Debug module", "JTAG debugging / program loading"],
    ["0x0001_0000", "8 KiB", "Boot ROM (sdboot)", "copies the firmware from the SD card at reset"],
    ["0x0200_0000", "64 KiB", "CLINT", "timer, software interrupts"],
    ["0x0C00_0000", "64 MiB", "PLIC", "external interrupts (unused by the firmware)"],
    ["0x6400_0000", "4 KiB", "UART0", "USB-UART console, 57600 baud"],
    ["0x6400_1000", "4 KiB", "SPI0", "microSD card (PMOD JA)"],
    ["0x6400_2000", "4 KiB", "GPIO, 8 pins", "4 LEDs, RGB LED, radio ~RST / INT"],
    ["0x6400_3000", "4 KiB", "UART1", "PMOD JB (optional wired link)"],
    ["0x6400_5000", "4 KiB", "SPI2", "spare"],
    ["0x6400_6000", "4 KiB", "SPI1", "MRF24J40 radio (PMOD JC)"],
    ["0x8000_0000", "64 KiB", "Scratchpad SRAM", "code, data and stack"],
], 0.5, 0.95, 12.3, 5.4, size=15, col_w=[2.0, 1.2, 2.8, 6.3])
d.text(s, [("", "The firmware’s *common/include/platform.h* uses the same addresses.")],
       0.5, 6.5, 12.3, 0.5, size=16, bullets=False, color=GRAY)

s = d.content(S2, "(5/7) Peripherals and their addresses")
b = d.code(s, """class WithDefaultPeripherals extends Config((site, here, up) => {
  case PeripheryUARTKey => List(
    UARTParams(address = BigInt(0x64000000L)),  // UART0 - USB UART
    UARTParams(address = BigInt(0x64003000L)))  // UART1 - PMOD JB (with the radio)
  case PeripherySPIKey => List(
    SPIParams(rAddress = BigInt(0x64001000L)),  // SPI0 - SD card
    SPIParams(rAddress = BigInt(0x64006000L)),  // SPI1 - radio
    SPIParams(rAddress = BigInt(0x64005000L)))  // SPI2
  case PeripheryGPIOKey => List(GPIOParams(address = BigInt(0x64002000L), width = 8))
})""", 0.4, 0.95, 12.5, 3.3, size=13,
       title="fpga/src/main/scala/arty100t/Configs.scala")
d.text(s, [
    "The UART, SPI and GPIO blocks are SiFive’s open-source peripherals "
    "(*sifive-blocks*), the same as in the Chipyard lecture (04).",
    "Each list entry is one controller instance; the list index is the port number "
    "used by the overlays in section 3 (SPI0 → JA, SPI1 → JC).",
    "Addresses are free to choose inside the peripheral bus window; keep them in "
    "step with the firmware headers.",
], 0.4, d.below(b, 0.3), 12.5, 2.5, size=19)

s = d.content(S2, "(6/7) One clock for the whole SoC")
b = d.code(s, """class WithTinyArty100TTweaks(freqMHz: Double = 50) extends Config(
  new chipyard.harness.WithHarnessBinderClockFreqMHz(freqMHz) ++
  new chipyard.config.WithMemoryBusFrequency(freqMHz) ++
  new chipyard.config.WithFrontBusFrequency(freqMHz) ++
  new chipyard.config.WithSystemBusFrequency(freqMHz) ++
  new chipyard.config.WithPeripheryBusFrequency(freqMHz) ++
  new chipyard.config.WithControlBusFrequency(freqMHz) ++
  new chipyard.config.WithOffchipBusFrequency(freqMHz) ++
  new chipyard.clocking.WithPassthroughClockGenerator ++
  new WithArty100TUARTHarnessBinder ++ new WithArty100TSPISDCardHarnessBinder ++
  new WithArty100TJTAGHarnessBinder ++ new WithArty100TGPIOHarnessBinder ++
  ...
  new WithDefaultPeripherals ++ new WithSystemModifications ++ ...)""",
       0.4, 0.95, 8.0, 4.6, size=12, title="fpga/src/main/scala/arty100t/Configs.scala")
d.text(s, [
    "`(75)` sets all seven bus clocks at once.",
    "Chipyard 1.11 added front / control / off-chip bus clocks that default to "
    "500 MHz; every bus in the clock group must ask for the same frequency.",
    "The board’s 100 MHz oscillator (pin E3) feeds a PLL that makes 75 MHz.",
], 8.6, 1.0, 4.5, 5.0, size=17)
d.text(s, [("", "Firmware must know the clock too: `PERF_CPU_HZ` / `F_CPU` = 75000000 "
            "(UART divider, SPI dividers, timing reports).")], 0.4, d.below(b, 0.3), 12.5, 1.0,
       size=17, bullets=False, color=GRAY)

s = d.content(S2, "(7/7) Boot ROM rebuilt for RV64")
b = d.code(s, """class WithSystemModifications extends Config((site, here, up) => {
  case BootROMLocated(x) => up(BootROMLocated(x), site).map{ p =>
    val freqMHz = (site(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toLong
    val make = s"make -C fpga/src/main/resources/arty35t/sdboot " +
               s"XLEN=${site(XLen)} PBUS_CLK=${freqMHz}"
    require (make.! == 0, "Failed to build bootrom")
    p.copy(hang = 0x10000, size = 0x2000,
           contentFileName = s"./fpga/src/main/resources/arty35t/sdboot/build/sdboot.bin")
  }
  ...""", 0.4, 0.95, 12.5, 3.1, size=13, title="fpga/src/main/scala/arty100t/Configs.scala")
d.text(s, [
    "Every bitstream build recompiles the boot ROM for the core width (`XLEN=64`) "
    "and the bus clock (`PBUS_CLK=75`).",
    "At reset the boot ROM copies the firmware from the SD card (LBA 2048) into the "
    "scratchpad and jumps to 0x8000_0000.",
    "During development we skip it: firmware is loaded over JTAG in seconds "
    "(section 5).",
], 0.4, d.below(b, 0.3), 12.5, 2.7, size=19)

# ---------------------------------------------------------- 3. pins & harness
S3 = "4. FPGA Pins & Harness"
d.outline(3)

s = d.content(S3, "(1/8) PMOD map")
d.table(s, [
    ["PMOD", "Module", "Controller", "Pins (PMOD pin: FPGA pin)"],
    ["JA", "microSD (PmodSD)", "SPI0 @0x6400_1000", "1 CS: G13 · 2 MOSI: B11 · 3 MISO: A11 · 4 SCK: D12"],
    ["JB", "UART1", "UART1 @0x6400_3000", "1 RX: E15 · 2 TX: E16"],
    ["JC", "MRF24J40 radio", "SPI1 @0x6400_6000 + GPIO 5 / 7",
     "1 CS: U12 · 2 MOSI: V12 · 3 MISO: V10 · 4 SCK: V11 · 7 INT: U14 · 8 ~RST: V14"],
    ["JD", "JTAG (C232HM cable)", "Debug module",
     "1 TDI: D4 · 2 TMS: D3 · 3 TCK: F4 · 4 TDO: F3"],
], 0.4, 0.95, 12.5, 3.3, size=15, col_w=[0.9, 2.6, 2.7, 6.3])
d.photo(s, "Arty A7-100T top view, PMOD JA–JD labelled", 0.4, 4.45, 6.1, 2.6)
d.text(s, [
    "Same wiring on both boards.",
    "JC used to carry UART1; it moved to JB to free JC for the radio.",
    "The USB-UART console (UART0) uses the on-board FTDI chip, no PMOD.",
], 6.7, 4.5, 6.2, 2.5, size=17)

s = d.content(S3, "(2/8) Wiring: pin numbers, direction, power")
for r, pins in enumerate((("1", "2", "3", "4", "5 GND", "6 3.3V"),
                          ("7", "8", "9", "10", "11 GND", "12 3.3V"))):
    for c, p in enumerate(pins):
        d.box(s, p, 0.5 + c * 1.0, 1.05 + r * 0.6, 0.9, 0.5,
              fill=PMOD if c < 4 else WHITE, size=12)
d.text(s, [
    "Every PMOD is a 2 × 6 socket: top row 1–6, bottom row 7–12. Pins 5 / 11 are GND, "
    "6 / 12 are 3.3 V. Pin 1 is marked on the board's silkscreen.",
], 6.7, 1.0, 6.4, 1.3, size=16)
d.table(s, [
    ["PMOD", "FPGA → module (outputs)", "module → FPGA (inputs)", "Power"],
    ["JA  SD", "1 CS, 2 MOSI, 4 SCK", "3 MISO", "5 GND, 6 3.3 V"],
    ["JB  UART1", "2 TX", "1 RX", "5 GND; to the other board: TX → RX, RX ← TX, GND"],
    ["JC  radio", "1 CS, 2 MOSI, 4 SCK, 8 ~RST", "3 MISO, 7 INT", "5 / 11 GND, 6 / 12 3.3 V"],
    ["JD  JTAG", "4 TDO", "1 TDI, 2 TMS, 3 TCK", "5 GND (black wire); red VCC unconnected"],
], 0.4, 2.45, 12.5, 2.9, size=15, col_w=[1.6, 3.6, 3.0, 4.3])
d.text(s, [
    "Same wiring on both boards. The SD and radio modules take 3.3 V from the PMOD; "
    "the C232HM only shares ground.",
    "Check before power-on: every module's GND on pin 5 (and 11), no 5 V anywhere.",
], 0.4, 5.55, 12.5, 1.4, size=17)

s = d.content(S3, "(3/8) From SoC port to FPGA pin")
y = 1.25
for i, (name, what, f) in enumerate([
        ("DigitalTop", "SoC: UART, SPI,\nGPIO, JTAG ports", SOC),
        ("IOBinder", "port → IO cell\n(ChipTop)", PMOD),
        ("HarnessBinder", "IO cell → shell port\n(Arty100TWithoutDDRHarness)", PMOD),
        ("Shell overlay", "shell port → package\npin + IO standard (XDC)", EXT)]):
    x = 0.4 + i * 3.2
    d.box(s, f"**{name}**\n{what}", x, y, 2.8, 1.3, fill=f, size=15)
    if i:
        d.arrow(s, x - 0.4, y + 0.65, x, y + 0.65)
d.table(s, [
    ["File (fpga/src/main/scala/arty100t/)", "What we changed"],
    ["Configs.scala", "EDHOC configs, peripherals, clock tweak, radio switch"],
    ["IOBinders.scala", "SPI / GPIO punch-through ports (WithArtySPIIOPunchthrough)"],
    ["HarnessBinders.scala", "UART, SPI-SD, JTAG (PMOD JD), GPIO binders"],
    ["CustomShell.scala", "shell with 3 SPI overlays, 2 UARTs, JTAG, GPIO"],
    ["CustomOverlay.scala", "package pins of every overlay (next slides)"],
], 0.4, 2.9, 12.5, 3.2, size=15, col_w=[4.4, 8.1])
d.text(s, [("", "Same three levels as in the Chipyard lecture (04): DigitalTop → ChipTop → ChipHarness.")],
       0.4, 6.3, 12.5, 0.6, size=17, bullets=False, color=GRAY)

s = d.content(S3, "(4/8) SD card on PMOD JA (SPI0)")
b = d.code(s, """case 0 => Seq(("D12", IOPin(io.spi_clk)),    // SPI0 - PMOD JA (SD card)
              ("B11", IOPin(io.spi_cs)),
              ("A11", IOPin(io.spi_dat(0))),
              ("D13", IOPin(io.spi_dat(1))),
              ("B18", IOPin(io.spi_dat(2))),
              ("G13", IOPin(io.spi_dat(3))))""", 0.4, 0.95, 7.0, 2.4, size=13,
       title="CustomOverlay.scala — SDIOArtyPlacedOverlay")
d.table(s, [
    ["Overlay pin", "Carries", "PMOD pin", "PmodSD"],
    ["G13  spi_dat(3)", "chip select", "JA1", "CS"],
    ["B11  spi_cs", "MOSI (command)", "JA2", "MOSI"],
    ["A11  spi_dat(0)", "MISO (data 0)", "JA3", "MISO"],
    ["D12  spi_clk", "clock", "JA4", "SCK"],
], 0.4, d.below(b), 7.0, 2.4, size=14, col_w=[2.2, 2.2, 1.2, 1.4])
d.text(s, [
    "The SDIO overlay uses **SD-card pin names**: the pin called *spi_cs* carries "
    "MOSI, and CS goes out on *dat(3)*.",
    "Pull-ups on CS, MOSI and MISO.",
    "Same pins as upstream Chipyard’s Arty 100T SD slot.",
    "Card init at ~150 kHz, data at ~2.3 MHz (SPI mode).",
], 7.6, 1.0, 5.4, 5.0, size=17)
d.photo(s, "PmodSD with microSD card on JA", 0.4, 6.15, 7.0, 0.85)

s = d.content(S3, "(5/8) MRF24J40 radio on PMOD JC (SPI1 + GPIO)")
b = d.code(s, """case 1 if shell.p(ArtyJCRadioKey) =>
  Seq(("V11", IOPin(io.spi_clk)),    // JC4 SCK
      ("V12", IOPin(io.spi_cs)),     // JC2 MOSI
      ("V10", IOPin(io.spi_dat(0))), // JC3 MISO
      ("F6",  IOPin(io.spi_dat(1))), // unused (freed RGB LED pin)
      ("G4",  IOPin(io.spi_dat(2))), // unused (freed RGB LED pin)
      ("U12", IOPin(io.spi_dat(3)))) // JC1 CS""", 0.4, 0.95, 6.6, 2.7, size=13,
       title="CustomOverlay.scala — SPI1 with the radio")
b = d.code(s, """val gpioLocations = List("H5", "J5", "T9", "T10",  // 4 LEDs
                         "E1",                     // RGB LED
                         if (radio) "V14" else "F6", // JC8 ~RST
                         "G6",
                         if (radio) "U14" else "G4") // JC7 INT""",
       0.4, d.below(b), 6.6, 1.9, size=13, title="CustomOverlay.scala — GPIO")
d.text(s, [
    "`WithArtyJCRadio` sets `ArtyJCRadioKey = true`; the overlays then pick the "
    "radio pinout.",
    "MRF24J40MA: IEEE 802.15.4, 2.4 GHz, 250 kbit/s; SPI at 4.7 MHz.",
    "GPIO 5 drives the radio’s reset, GPIO 7 reads its interrupt line (polled).",
    "Two RGB-LED pins are given up for this.",
], 7.2, 1.0, 5.8, 4.8, size=17)
d.photo(s, "MRF24J40MA module on PMOD JC", 0.4, d.below(b), 6.6, 1.05)

s = d.content(S3, "(6/8) UART0 console and UART1 on PMOD JB")
b = d.code(s, """// UART0: USB UART (A9=RX, D10=TX)
// UART1: PMOD C (U12=RX, V12=TX), or PMOD B (E15=RX, E16=TX) with the radio
val packagePinsWithPackageIOs = shellInput.index match {
  case 0 => Seq(("A9",  IOPin(io.rxd)),    // USB UART RX
                ("D10", IOPin(io.txd)))    // USB UART TX
  case 1 if shell.p(ArtyJCRadioKey) => Seq(
                ("E15", IOPin(io.rxd)),    // PMOD B JB1 - RX
                ("E16", IOPin(io.txd)))    // PMOD B JB2 - TX
  case 1 => Seq(("U12", IOPin(io.rxd)),    // PMOD C JC1 - RX
                ("V12", IOPin(io.txd)))    // PMOD C JC2 - TX
}""", 0.4, 0.95, 8.4, 3.9, size=13, title="CustomOverlay.scala — UARTArtyPlacedOverlay")
d.text(s, [
    "UART0 = console through the board’s USB port, 57600 baud, 8N1.",
    "UART1 = optional wired link between the boards (TRANSPORT=uart).",
    "With the radio, UART1 moves from JC to JB.",
], 9.0, 1.0, 4.1, 4.0, size=17)
d.text(s, ["Each board shows up as two ttyUSB devices; the console is interface 1 of the "
           "Digilent FTDI. Find it by serial number, because ttyUSB numbers change when "
           "Vivado or OpenOCD opens a port (section 5)."], 0.4, d.below(b, 0.3), 12.5, 1.8, size=17)

s = d.content(S3, "(7/8) JTAG on PMOD JD with a C232HM cable")
d.table(s, [
    ["C232HM wire", "FTDI pin", "Signal", "PMOD JD", "FPGA pin"],
    ["Orange", "ADBUS0", "TCK", "JD3", "F4"],
    ["Yellow", "ADBUS1", "TDI", "JD1", "D4"],
    ["Green", "ADBUS2", "TDO", "JD4", "F3"],
    ["Brown", "ADBUS3", "TMS", "JD2", "D3"],
    ["Black", "GND", "GND", "JD5 (GND)", "–"],
], 0.4, 0.95, 7.3, 3.1, size=15)
d.code(s, """source [find interface/ftdi/c232hm.cfg]
transport select jtag
adapter speed 1000
# RISC-V debug DTM: 5-bit IR
jtag newtap riscv tap -irlen 5 -ignore-version
target create riscv.cpu riscv -chain-position riscv.tap""",
       0.4, 4.25, 7.3, 2.1, size=13, title="fpga/sw/export/common/board/c232hm.cfg")
d.text(s, [
    "The core’s debug module is wired to PMOD JD, not to the board’s USB JTAG "
    "(that one programs the FPGA).",
    "One C232HM per board; scripts pick the cable by its FTDI serial "
    "(*common/board/boards.env*).",
    "JTAG clock 1 MHz (`adapter speed 1000`).",
], 7.9, 1.0, 5.2, 4.2, size=17)
d.photo(s, "C232HM cable on PMOD JD", 7.9, 5.3, 5.2, 1.7)

s = d.content(S3, "(8/8) Makefile entry")
b = d.code(s, """ifeq ($(SUB_PROJECT),arty100t)
	SBT_PROJECT       ?= fpga_platforms
	MODEL             ?= Arty100TWithoutDDRHarness   # was Arty100THarness
	VLOG_MODEL        ?= Arty100TWithoutDDRHarness
	MODEL_PACKAGE     ?= chipyard.fpga.arty100t
	CONFIG            ?= SmallRocket32Arty100TConfig  # default; override on the command line
	CONFIG_PACKAGE    ?= chipyard.fpga.arty100t
	GENERATOR_PACKAGE ?= chipyard
	...""", 0.4, 0.95, 12.5, 3.0, size=14, title="fpga/Makefile")
d.text(s, [
    "`SUB_PROJECT ?= arty100t` is now the default sub-project (upstream: vcu118).",
    "**Arty100TWithoutDDRHarness**: our harness without the DDR3 controller "
    "(the SoC has no memory port).",
    "The EDHOC config is chosen at build time: "
    "`CONFIG=EdhocRocket6475MHzArty100TConfig` (next section).",
], 0.4, d.below(b, 0.3), 12.5, 2.8, size=19)

# ---------------------------------------------------------- 4. build & timing
S4 = "5. Build & Timing Closure"
d.outline(4)

s = d.content(S4, "(1/5) Build the bitstream")
b = d.code(s, """cd chipyard                # repository root, route A set up (section 1)
source env.sh
cd fpga
make SUB_PROJECT=arty100t CONFIG=EdhocRocket6475MHzArty100TConfig bitstream
echo $?                    # 0 = done; 2 = timing failed (a .bit is still written)""",
       0.4, 1.0, 12.5, 1.9, size=16, title="Run this — about 1 h on a recent PC")
d.text(s, [
    "Output folder: *fpga/generated-src/chipyard.fpga.arty100t.Arty100TWithoutDDRHarness."
    "EdhocRocket6475MHzArty100TConfig/obj/*",
    (1, "*Arty100TWithoutDDRHarness.bit* — the bitstream"),
    (1, "*report/timing.txt*, *report/utilization.txt* — check these after every build"),
    (1, "*post_opt.dcp*, *post_route.dcp* — checkpoints for timing closure"),
    "**Careful:** if timing fails, make stops with exit code 2 but still writes the "
    "*.bit* file. Always read *timing.txt* before using a new bitstream.",
], 0.4, d.below(b, 0.3), 12.5, 4.1, size=18)

s = d.content(S4, "(2/5) Resources used")
d.table(s, [
    ["Resource", "Used", "Available (XC7A100T)", "Use"],
    ["Slice LUTs", "14,672", "63,400", "23.1 %"],
    ["Flip-flops", "6,716", "126,800", "5.3 %"],
    ["Block RAM (36 Kb)", "34 + 10 half", "135", "28.9 %"],
    ["DSP slices", "10", "240", "4.2 %"],
], 0.4, 1.0, 8.0, 2.8, size=17, col_w=[2.6, 1.8, 2.3, 1.3])
d.text(s, [
    "16 of the 34 block RAMs are the 64 KiB scratchpad (16 × 4 KiB).",
    "The rest: caches, boot ROM, peripheral FIFOs.",
    "Plenty of room left: in this build, timing, not area, was the constraint.",
], 8.6, 1.0, 4.5, 3.4, size=17)
d.text(s, [("", "From *report/utilization.txt* (`report_utilization -hierarchical`):")],
       0.4, 4.2, 12.5, 0.5, size=16, bullets=False, color=GRAY)
d.console(s, """| Instance                  | Module         | Total LUTs |  FFs | RAMB36 | RAMB18 | DSP |
| Arty100TWithoutDDRHarness |          (top) |      14672 | 6716 |     34 |     10 |  10 |
|   chiptop0                | ChipTop        |      14666 | 6630 |     34 |     10 |  10 |
|     system                | DigitalTop     |      14663 | 6624 |     34 |     10 |  10 |
|       bank                | ScratchpadBank |         67 |  109 |     16 |      0 |   0 |""",
          0.4, 4.7, 12.5, 2.2, size=12)

s = d.content(S4, "(3/5) Reading the timing report")
d.text(s, [("", "*report/timing.txt* — Design Timing Summary, 75 MHz build:")],
       0.4, 0.9, 12.5, 0.5, size=17, bullets=False)
b = d.console(s, """    WNS(ns)  TNS(ns)  TNS Failing Endpoints  TNS Total Endpoints   WHS(ns)  THS(ns)  THS Failing Endpoints
      0.000    0.000                      0                24148     0.000    0.000                      0
Clock                      WNS(ns)  TNS(ns)  TNS Failing  TNS Total   WHS(ns)
  clk_out1_harnessSysPLL     0.000    0.000            0      23458     0.000
JTCK                        41.206    0.000            0        548     0.140""",
          0.4, 1.4, 12.5, 1.9, size=12)
b = d.text(s, [("", "Same report for the 100 MHz attempt (EdhocRocket64100MHzArty100TConfig):")],
       0.4, d.below(b), 12.5, 0.5, size=17, bullets=False)
b = d.console(s, """    WNS(ns)    TNS(ns)  TNS Failing Endpoints  TNS Total Endpoints   WHS(ns)
     -3.191  -5498.651                   4372                24321     0.018""",
          0.4, d.below(b, 0.05), 12.5, 0.9, size=12)
d.text(s, [
    "**WNS** (worst negative slack) ≥ 0 and **0 failing endpoints** for setup "
    "(TNS) and hold (THS) = timing met.",
    "*clk_out1_harnessSysPLL* is the 75 MHz system clock; *JTCK* is the JTAG clock "
    "from PMOD JD (10 MHz constraint, easily met).",
], 0.4, d.below(b, 0.3), 12.5, 2.0, size=18)

s = d.content(S4, "(4/5) When timing fails: the closure recipe")
d.text(s, [
    "75 MHz is close to the limit (≈ 75.8 MHz). Any pin change moves placement and "
    "can flip the result: our radio-pin build first came out at −0.166 ns.",
    "Recipe used to close it, starting from the *post_opt.dcp* checkpoint in Vivado:",
], 0.4, 0.9, 12.5, 1.6, size=18)
d.code(s, """open_checkpoint obj/post_opt.dcp
place_design    -directive Explore
phys_opt_design -directive AlternateFlowWithRetiming
route_design    -directive AggressiveExplore
phys_opt_design -directive Explore              ;# -0.062 ns
route_design -directive AggressiveExplore -tns_cleanup ;# -0.162
phys_opt_design -directive Explore              ;# +0.015 met
report_timing_summary -file timing.txt
write_bitstream Arty100TWithoutDDRHarness.bit""", 0.4, 2.55, 8.2, 3.5, size=13)
d.text(s, [
    "Hold met too (+0.027 ns).",
    "Over-constraining placement (extra clock uncertainty) made it **worse**.",
    "Vivado 2024.2 *phys_opt_design* sometimes crashes after routing (exit 139): "
    "run each attempt as its own process from a checkpoint.",
], 8.8, 2.55, 4.3, 4.4, size=16)

s = d.content(S4, "(5/5) How to accept a new bitstream")
d.table(s, [
    ["Step", "Look at", "Accept when"],
    ["1. Build", "exit status of make", "0 (2 = timing failed, even though a .bit exists)"],
    ["2. Timing", "Design Timing Summary in report/timing.txt",
     "WNS ≥ 0 and WHS ≥ 0, 0 failing endpoints (TNS and THS)"],
    ["3. Area", "report/utilization.txt", "ScratchpadBank uses 16 RAMB36 (64 KiB)"],
    ["4. Program", "program_two.tcl (section 6)", "PROGRAMMED <serial> for both boards"],
    ["5. Bring-up", "jtag, gpio, spi, uart tests (section 6)",
     "each ends in PASS; jtag_test shows MXL = 2, ACIMX"],
    ["6. Keep it", "copy the .bit with config name and date", "—"],
], 0.4, 0.95, 12.5, 3.8, size=15, col_w=[1.8, 5.2, 5.5])
b = d.code(s, """cd fpga/generated-src/chipyard.fpga.arty100t.Arty100TWithoutDDRHarness.\
EdhocRocket6475MHzArty100TConfig/obj
grep -A6 "Design Timing Summary" report/timing.txt""", 0.4, 4.95, 12.5, 1.1, size=14,
           title="Run this — step 2")
d.text(s, [("", "Do not skip step 2 because the board seems to work: a design that "
            "misses timing can fail only now and then, in ways that look like software "
            "bugs.")], 0.4, d.below(b, 0.2), 12.5, 0.9, size=16, bullets=False, color=GRAY)

# ---------------------------------------------------- 5. programming & bring-up
S5 = "6. Programming & Bring-up"
d.outline(5)

s = d.content(S5, "(1/5) Program both FPGAs")
b = d.code(s, """cd fpga/sw/export
BIT=../../generated-src/chipyard.fpga.arty100t.Arty100TWithoutDDRHarness.\\
EdhocRocket6475MHzArty100TConfig/obj/Arty100TWithoutDDRHarness.bit \\
SERIALS="210319B269F6 210319B4A439" \\
vivado -mode batch -source common/board/program_two.tcl""", 0.4, 0.95, 12.5, 1.9, size=14,
           title="Run this — SERIALS are our boards: use your two Arty serials (list_boards.sh)")
b = d.console(s, """PROGRAMMED 210319B269F6
PROGRAMMED 210319B4A439""", 0.4, d.below(b), 4.2, 0.8, size=13)
d.text(s, [
    "SERIALS = the Digilent USB serial of each Arty, as printed by "
    "*common/board/list_boards.sh*. The script uses a running Vivado GUI’s "
    "hardware server if there is one.",
    "At power-up the FPGA loads whatever its QSPI flash holds (on our boards an older "
    "design). Symptom: OpenOCD reports “*dtmcontrol is 0*” → program again.",
    "For a board that starts the EDHOC SoC by itself, write the bitstream to the "
    "QSPI flash (Vivado → Add Configuration Memory Device).",
], 0.4, d.below(b, 0.3), 12.5, 3.0, size=18)

s = d.content(S5, "(2/5) Load firmware over JTAG")
b = d.code(s, """cd fpga/sw/export/tests
make gpio_test                          # build a test program
BOARD=initiator \\
  ../common/board/run_one.sh build/gpio_test.elf 5   # load, run, print console
# both boards at once (responder first):
../common/board/load_both.sh A.elf B.elf""", 0.4, 0.95, 8.0, 2.6, size=13, title="Run this")
b = d.code(s, """openocd -c "adapter serial $SERIAL" -f c232hm.cfg \\
  -c "halt" -c "load_image $ELF" \\
  -c "resume 0x80000000" -c "shutdown\"""", 0.4, d.below(b), 8.0, 1.3, size=13,
       title="Run this — what run_one.sh does (simplified)")
d.text(s, [
    "`run_one.sh`: halt the core, write the ELF into the scratchpad, start at "
    "0x8000_0000, show the console.",
    "Cable and console of each board come from *boards.env*; Lesson 2 shows how to "
    "fill it in with your serials.",
    "The console tty is found by the board's serial, so moving ttyUSB numbers do not "
    "matter (57600 baud).",
], 8.6, 1.0, 4.5, 5.9, size=16)
d.code(s, """../common/board/list_boards.sh     # serial and tty of every board and cable""",
       0.4, d.below(b), 8.0, 0.8, size=13, title="Run this — which tty is which board?")

s = d.content(S5, "(3/5) Bring-up: GPIO and JTAG")
b0 = d.console(s, """=== GPIO test (0x64002000, 8 pins) ===
  output_en   : got=ff want=ff PASS
  all low     : got=0 want=0 PASS
  all high    : got=ff want=ff PASS
  walking ones (watch the LEDs):
    walk: PASS
  xor set     : got=ff want=ff PASS
  pattern AA  : got=aa want=aa PASS
  pattern 55  : got=55 want=55 PASS
GPIO TEST: PASS (0 failures)""", 0.4, 1.0, 6.2, 3.9, size=13, title="tests/build/gpio_test.elf")
b = d.console(s, """=== JTAG / debug module test ===
  Loaded and resumed over JTAG: PASS (this output is the proof)
  mhartid     : 0
  mvendorid   : 0
  marchid     : 1
  mimpid      : 20181004
  misa low32  : 801105  (MXL=2 -> RV64)
  extensions  : ACIMX
JTAG TEST: PASS (0 failures)""", 6.8, 1.0, 6.3, 3.9, size=13, title="tests/build/jtag_test.elf")
b = max(b, b0, key=lambda x: x.top + x.height)
d.text(s, [
    "Real output from board A. The GPIO walk lights the four LEDs one after another.",
    "*misa* confirms the hardware: MXL = 2 → 64-bit; extensions A, C, I, M "
    "(X = non-standard extensions present); *marchid* 1 = Rocket.",
], 0.4, d.below(b, 0.3), 12.7, 1.8, size=18)

s = d.content(S5, "(4/5) Bring-up: SPI (SD card) and UART")
b0 = d.console(s, """=== SPI test (SPI0 @ 0x64001000, SD slot) ===
  sckdiv      : got=c want=c PASS
  sckmode     : got=0 want=0 PASS
  csdef       : got=1 want=1 PASS
  SD CMD0     : R1=1 PASS (card in idle state)
SPI TEST: PASS (0 failures)""", 0.4, 1.0, 6.2, 2.8, size=13, title="tests/build/spi_test.elf")
b = d.console(s, """=== UART test ===
  UART0 @ 0x64000000 (console), UART1 @ 0x64003000 (PMOD JB)
  UART0 console TX: PASS (you are reading it)
  UART0 div   : got=2a want=2a PASS
  UART1 div   : got=2a want=2a PASS
  UART1 txen  : got=1 want=1 PASS
  UART1 rxen  : got=1 want=1 PASS
  UART1 loop  : SKIP (no echo; jumper JB1-JB2 to test)
UART TEST: PASS (0 failures)""", 6.8, 1.0, 6.3, 3.6, size=12, title="tests/build/uart_test.elf")
b = max(b, b0, key=lambda x: x.top + x.height)
d.text(s, [
    "**SD CMD0 → R1 = 0x01** proves clock, chip select and both data lines work "
    "against a real card.",
    "Lesson from bring-up: right after power-up the card answers the first CMD0 with "
    "one junk byte (e.g. 0x3f). The test and the firmware send CMD0 again; the "
    "second answer is always clean.",
    "UART1 loopback needs a jumper JB1–JB2; without it the step is skipped, not failed.",
], 0.4, d.below(b, 0.3), 12.7, 2.2, size=17)

s = d.content(S5, "(5/5) Booting from the SD card")
b = d.code(s, """sudo fpga/sw/export/tools/mksd.sh /dev/sdX            # once: partitions + FAT32
sudo fpga/sw/export/common/board/sd_boot.sh build/app.bin sdX1   # firmware -> LBA 2048""",
       0.4, 0.95, 12.5, 1.1, size=14, title="Run this")
d.table(s, [
    ["Card area", "Content"],
    ["LBA 0", "MBR partition table"],
    ["LBA 2048 … (partition 1, raw, 32 MiB)", "firmware image read by the boot ROM"],
    ["LBA 67584 … (partition 2, FAT32)", "files: SEND.BIN / RECV.BIN (Lesson 5)"],
], 0.4, d.below(b, 0.3), 8.2, 2.0, size=15, col_w=[4.3, 3.9])
d.text(s, [
    "At reset the boot ROM copies 126 sectors (63 KiB) from LBA 2048 into the "
    "scratchpad and jumps there.",
    "**Known issue:** the boot ROM still sends CMD0 only once, so the first boot "
    "after power-up can fail; press reset once more. The fix needs a new bitstream.",
    "No card reader? *tests/sd_prep* formats the card from the board over JTAG.",
], 0.4, 4.5, 12.5, 2.5, size=17)
d.photo(s, "microSD card in the PMOD JA slot", 8.8, d.below(b, 0.3), 4.3, 2.0)

# ---------------------------------------------------------------- 6. practice
S6 = "7. Practice"
d.outline(6)

s = d.content(S6, "(1/3) Exercises")
for y, title, body in (
        (1.0, "Exercise 1:", ["Add **EdhocRocket128K75MHzArty100TConfig**: the same SoC with a "
                              "128 KiB scratchpad.",
                              "Build it. How many block RAMs does the scratchpad use now? "
                              "Does 75 MHz still close?"]),
        (3.0, "Exercise 2:", ["Program both boards with the EDHOC bitstream and run "
                              "`gpio_test`, `spi_test`, `jtag_test` and `uart_test` on each.",
                              "Put a jumper on JB1–JB2 and make the UART1 loopback PASS."]),
        (5.0, "Exercise 3:", ["Move UART1 back to PMOD JC (build without `WithArtyJCRadio`). "
                              "Which pins change in the generated XDC file?"])):
    d.box(s, title, 0.4, y, 1.9, 0.45, fill=WHITE, line=RED, size=18, shape=1)
    d.text(s, body, 0.5, y + 0.5, 12.5, 1.4, size=18)

s = d.content(S6, "(2/3) What to put in the report")
d.text(s, [
    "Exercise 1: your config class, the utilization table (block RAM count) and the "
    "Design Timing Summary lines (WNS, failing endpoints).",
    "Exercise 2: the console output of all four tests on both boards, and a photo of "
    "your wiring with the PMOD ports labelled.",
    "Exercise 3: the pin lines of the generated XDC before and after.",
    "For every step: the command you ran and how long it took on your PC.",
], 0.5, 1.1, 12.3, 5.6, size=20)

s = d.content(S6, "(3/3) Answer notes")
d.table(s, [
    ["Exercise", "What should change", "What should stay the same", "Why"],
    ["1. 128 KiB", "ScratchpadBank: 16 → 32 RAMB36; size = BigInt(128 << 10) in a copy "
                   "of EdhocRocket64Config", "the core, caches and pins",
     "one RAMB36 holds 4 KiB. Timing may or may not still close: read timing.txt. The "
     "firmware still uses 64 KiB until memory.lds changes"],
    ["2. Tests", "UART1 loop: SKIP → PASS with the jumper", "every other line PASS",
     "SKIP means “not run”; the jumper lets UART1 hear itself"],
    ["3. UART1 → JC", "UART1 rxd / txd: E15 / E16 → U12 / V12; GPIO 5 / 7 back to F6 / G4",
     "JA, JD and UART0 pins", "WithArtyJCRadio switches these overlays"],
], 0.4, 0.95, 12.5, 4.4, size=14, col_w=[1.6, 4.0, 2.6, 4.3])
d.text(s, [
    "Negative case to recognise: a bitstream with WNS < 0 may load and even pass a "
    "test — reject it anyway (section 5, (5/5)).",
], 0.4, 5.6, 12.5, 1.2, size=17)

# ---------------------------------------------------------------- closing
d.highlight("Today’s lecture highlight:", [
    "*EdhocRocket6475MHzArty100TConfig* = small RV64 Rocket, 8 KiB caches, 64 KiB "
    "scratchpad, no DDR, GPIO / 2 UART / 3 SPI / JTAG.",
    "64 KiB because the largest EDHOC build needs 61.4 KB with its stack; 75 MHz "
    "because this implementation failed timing at 100 MHz and closes at 75 MHz.",
    "Pins: JA SD card, JB UART1, JC MRF24J40 radio, JD JTAG — set in the shell "
    "overlays, selected by config keys.",
    "Accept a bitstream only after its timing report: a failing build still writes "
    "a .bit file.",
    "Program both boards, load over JTAG, prove each peripheral with a test program.",
], next_title="Next lesson:", next_text="「 Lesson 2 」 Software environment and tests")
d.thanks()

d.save(OUT)
print("wrote", OUT, len(d.prs.slides), "slides")
