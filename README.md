# EDHOC on a Rocket RV64 SoC (Arty A7-100T) — Chipyard 1.11.0 fork

This fork adds an EDHOC SoC and its firmware to Chipyard 1.11.0: a small 64-bit
Rocket core at 75 MHz with a 64 KiB on-chip scratchpad, on two Digilent Arty
A7-100T boards that talk over an MRF24J40 802.15.4 radio. The firmware runs
EDHOC (RFC 9528, methods 0–3, all 9 cipher suites), post-quantum EDHOC AuthKEM
(ML-KEM, suites TBD1–TBD3), and an encrypted SD-card-to-SD-card file transfer.

The step-by-step course (5 lessons, PPTX + PDF) is in
[`fpga/sw/export/docs/slides/`](fpga/sw/export/docs/slides/): start with Lesson 1,
section "Start Here". This repository is private; ask the author for access.

## What you need

* 2 × Arty A7-100T, 2 × micro-USB cable, 2 × FTDI C232HM-DDHSL-0 (JTAG on PMOD JD),
  2 × PmodSD + microSD card (PMOD JA), 2 × MRF24J40MA radio on a PMOD adapter (PMOD JC).
* Ubuntu 24.04, Vivado 2024.2, `riscv64-unknown-elf-gcc` 15.1 (rv64imac/lp64),
  OpenOCD 0.12, Python 3.

## Setup

```bash
git clone git@github.com:Khaiduy/chipyard-edhoc.git chipyard
cd chipyard
git checkout edhoc-course-v1      # the revision the slides describe
```

**Route A — build the hardware** (Chipyard toolchain, Vivado):

```bash
./build-setup.sh riscv-tools
source env.sh
./scripts/init-fpga.sh
./patches/apply.sh                # fork changes to fpga-shells and rocket-chip-blocks
cd fpga
make SUB_PROJECT=arty100t CONFIG=EdhocRocket6475MHzArty100TConfig bitstream
```

Accept the bitstream only if `report/timing.txt` shows WNS ≥ 0 and WHS ≥ 0
(Lesson 1, section 5). Program both boards with `fpga/sw/export/common/board/program_two.tcl`.

**Route B — firmware only** (boards already hold the EDHOC bitstream of this revision):
only the RISC-V GCC, OpenOCD and Python are needed.

```bash
cd fpga/sw/export
./common/board/list_boards.sh     # put your four serials into common/board/boards.env
cd edhoc-wolfssl
make edhoc_m3_initiator edhoc_m3_responder CRYPTO_SUITE=2
../common/board/run_pair.sh s2_m3 build/edhoc_m3_initiator.elf build/edhoc_m3_responder.elf
#  -> s2_m3 PASS hs=2.74s stack_i=5360 stack_r=4736 prk=- 7s
```

## Where things are

| Path | Contents |
|------|----------|
| `generators/chipyard/src/main/scala/config/EdhocConfigs.scala` | `EdhocRocket64Config`: the SoC |
| `fpga/src/main/scala/arty100t/` | board configs (`EdhocRocket6475MHzArty100TConfig`), shell, overlays, binders |
| `fpga/src/main/resources/arty35t/sdboot/` | boot ROM (SD boot) |
| `patches/` | changes to the `fpga-shells` and `rocket-chip-blocks` submodules |
| `fpga/sw/export/` | firmware: [`edhoc-wolfssl`](fpga/sw/export/edhoc-wolfssl/), [`edhoc-authkem`](fpga/sw/export/edhoc-authkem/), `tests`, `common`, board scripts — see its [README](fpga/sw/export/README.md) |
| `fpga/sw/export/docs/slides/` | the course |

`fpga/sw/export/edhoc-wolfssl/wolfssl/` is a wolfCrypt subset under GPLv2; the rest of
Chipyard keeps its BSD licence (`LICENSE`).

---

## Upstream Chipyard

The text below is Chipyard's own README (version 1.11.0).

![CHIPYARD](https://github.com/ucb-bar/chipyard/raw/main/docs/_static/images/chipyard-logo-full.png)

# Chipyard Framework [![Test](https://github.com/ucb-bar/chipyard/actions/workflows/chipyard-run-tests.yml/badge.svg)](https://github.com/ucb-bar/chipyard/actions)

## Quick Links

* **Stable Documentation**: https://chipyard.readthedocs.io/
* **User Question Forum**: https://groups.google.com/forum/#!forum/chipyard
* **Bugs and Feature Requests**: https://github.com/ucb-bar/chipyard/issues

## Using Chipyard

To get started using Chipyard, see the stable documentation on the Chipyard documentation site: https://chipyard.readthedocs.io/

## What is Chipyard

Chipyard is an open source framework for agile development of Chisel-based systems-on-chip.
It will allow you to leverage the Chisel HDL, Rocket Chip SoC generator, and other [Berkeley][berkeley] projects to produce a [RISC-V][riscv] SoC with everything from MMIO-mapped peripherals to custom accelerators.
Chipyard contains processor cores ([Rocket][rocket-chip], [BOOM][boom], [CVA6 (Ariane)][cva6]), accelerators ([Hwacha][hwacha], [Gemmini][gemmini], [NVDLA][nvdla]), memory systems, and additional peripherals and tooling to help create a full featured SoC.
Chipyard supports multiple concurrent flows of agile hardware development, including software RTL simulation, FPGA-accelerated simulation ([FireSim][firesim]), automated VLSI flows ([Hammer][hammer]), and software workload generation for bare-metal and Linux-based systems ([FireMarshal][firemarshal]).
Chipyard is actively developed in the [Berkeley Architecture Research Group][ucb-bar] in the [Electrical Engineering and Computer Sciences Department][eecs] at the [University of California, Berkeley][berkeley].

## Resources

* Chipyard Stable Documentation: https://chipyard.readthedocs.io/
* Chipyard (x FireSim) Tutorial: https://fires.im/tutorial-recent/
* Chipyard Basics slides: https://fires.im/asplos23-slides-pdf/02_chipyard_basics.pdf

## Need help?

* Join the Chipyard Mailing List: https://groups.google.com/forum/#!forum/chipyard
* If you find a bug or would like propose a feature, post an issue on this repo: https://github.com/ucb-bar/chipyard/issues

## Contributing

* See [CONTRIBUTING.md](/CONTRIBUTING.md)

## Attribution and Chipyard-related Publications

If used for research, please cite Chipyard by the following publication:

```
@article{chipyard,
  author={Amid, Alon and Biancolin, David and Gonzalez, Abraham and Grubb, Daniel and Karandikar, Sagar and Liew, Harrison and Magyar,   Albert and Mao, Howard and Ou, Albert and Pemberton, Nathan and Rigge, Paul and Schmidt, Colin and Wright, John and Zhao, Jerry and Shao, Yakun Sophia and Asanovi\'{c}, Krste and Nikoli\'{c}, Borivoje},
  journal={IEEE Micro},
  title={Chipyard: Integrated Design, Simulation, and Implementation Framework for Custom SoCs},
  year={2020},
  volume={40},
  number={4},
  pages={10-21},
  doi={10.1109/MM.2020.2996616},
  ISSN={1937-4143},
}
```

* **Chipyard**
    * A. Amid, et al. *IEEE Micro'20* [PDF](https://ieeexplore.ieee.org/document/9099108).
    * A. Amid, et al. *DAC'20* [PDF](https://ieeexplore.ieee.org/document/9218756).
    * A. Amid, et al. *ISCAS'21* [PDF](https://ieeexplore.ieee.org/abstract/document/9401515).

These additional publications cover many of the internal components used in Chipyard. However, for the most up-to-date details, users should refer to the Chipyard docs.

* **Generators**
    * **Rocket Chip**: K. Asanovic, et al., *UCB EECS TR*. [PDF](http://www2.eecs.berkeley.edu/Pubs/TechRpts/2016/EECS-2016-17.pdf).
    * **BOOM**: C. Celio, et al., *Hot Chips 30*. [PDF](https://old.hotchips.org/hc30/1conf/1.03_Berkeley_BROOM_HC30.Berkeley.Celio.v02.pdf).
      * **SonicBOOM (BOOMv3)**: J. Zhao, et al., *CARRV'20*. [PDF](https://carrv.github.io/2020/papers/CARRV2020_paper_15_Zhao.pdf).
      * **COBRA (BOOM Branch Prediction)**: J. Zhao, et al., *ISPASS'21*. [PDF](https://ieeexplore.ieee.org/document/9408173).
    * **Hwacha**: Y. Lee, et al., *ESSCIRC'14*. [PDF](http://hwacha.org/papers/riscv-esscirc2014.pdf).
    * **Gemmini**: H. Genc, et al., *DAC'21*. [PDF](https://arxiv.org/pdf/1911.09925).
* **Sims**
    * **FireSim**: S. Karandikar, et al., *ISCA'18*. [PDF](https://sagark.org/assets/pubs/firesim-isca2018.pdf).
        * **FireSim Micro Top Picks**: S. Karandikar, et al., *IEEE Micro, Top Picks 2018*. [PDF](https://sagark.org/assets/pubs/firesim-micro-top-picks2018.pdf).
        * **FASED**: D. Biancolin, et al., *FPGA'19*. [PDF](https://people.eecs.berkeley.edu/~biancolin/papers/fased-fpga19.pdf).
        * **Golden Gate**: A. Magyar, et al., *ICCAD'19*. [PDF](https://davidbiancolin.github.io/papers/goldengate-iccad19.pdf).
        * **FirePerf**: S. Karandikar, et al., *ASPLOS'20*. [PDF](https://sagark.org/assets/pubs/fireperf-asplos2020.pdf).
        * **FireSim ISCA@50 Retrospective**: S. Karandikar, et al., *ISCA@50 Retrospective: 1996-2020*. [PDF](https://sites.coecis.cornell.edu/isca50retrospective/files/2023/06/Karandikar_2018_FireSim.pdf)
* **Tools**
    * **Chisel**: J. Bachrach, et al., *DAC'12*. [PDF](https://people.eecs.berkeley.edu/~krste/papers/chisel-dac2012.pdf).
    * **FIRRTL**: A. Izraelevitz, et al., *ICCAD'17*. [PDF](https://ieeexplore.ieee.org/document/8203780).
    * **Chisel DSP**: A. Wang, et al., *DAC'18*. [PDF](https://ieeexplore.ieee.org/document/8465790).
    * **FireMarshal**: N. Pemberton, et al., *ISPASS'21*. [PDF](https://ieeexplore.ieee.org/document/9408192).
* **VLSI**
    * **Hammer**: E. Wang, et al., *ISQED'20*. [PDF](https://www.isqed.org/English/Archives/2020/Technical_Sessions/113.html).
    * **Hammer**: H. Liew, et al., *DAC'22*. [PDF](https://dl.acm.org/doi/abs/10.1145/3489517.3530672).

## Acknowledgements

This work is supported by the NSF CCRI ENS Chipyard Award #2016662.

[hwacha]:https://www2.eecs.berkeley.edu/Pubs/TechRpts/2015/EECS-2015-262.pdf
[hammer]:https://github.com/ucb-bar/hammer
[firesim]:https://fires.im
[ucb-bar]: http://bar.eecs.berkeley.edu
[eecs]: https://eecs.berkeley.edu
[berkeley]: https://berkeley.edu
[riscv]: https://riscv.org/
[rocket-chip]: https://github.com/freechipsproject/rocket-chip
[boom]: https://github.com/riscv-boom/riscv-boom
[firemarshal]: https://github.com/firesim/FireMarshal/
[cva6]: https://github.com/openhwgroup/cva6/
[gemmini]: https://github.com/ucb-bar/gemmini
[nvdla]: http://nvdla.org/
