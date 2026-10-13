package chipyard

import org.chipsalliance.cde.config.{Config}

// ---------------------------------------------------------------------------
// EDHOC RV32 Rocket configs
// ---------------------------------------------------------------------------
// Ported from the RISC-V_Tutorial tree (chipyard 1.10) with the 1.11 renames:
//   testchipip.WithMbusScratchpad             -> testchipip.soc.WithMbusScratchpad
//   chipyard.iobinders.WithDontTouchIOBinders -> chipyard.harness.WithDontTouchChipTopPorts
// Kept in their own file so a future chipyard bump does not conflict with
// upstream's RocketConfigs.scala.

// RV64 small Rocket, 64 kB on-chip scratchpad. Base for the on-chip-SRAM-only
// Arty config; upstream 1.11 has no SmallRocketConfig of its own.
class SmallRocketConfig extends Config(
    new testchipip.soc.WithMbusScratchpad(base = 0x80000000L, size=BigInt(64 << 10)) ++   // SRAM on-chip 64kB
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++         // single rocket-core
    new freechips.rocketchip.subsystem.WithoutTLMonitors ++
    new chipyard.config.AbstractConfig)

// RV64 Rocket sized to the EDHOC hardware requirement: 64-bit core, 8 KiB L1
// I-cache and D-cache, 128 kB on-chip scratchpad (the requirement's 32 kB floor
// is not enough for the EDHOC images). Boot path is unchanged from the RV32
// configs: the same sdboot bootrom, built for XLEN=64 because
// WithSystemModifications passes site(XLen) to its Makefile, and the same SD
// card over SPI0.
//
// The cache-set fragments rewrite the tiles produced by WithNSmallCores, so
// they must stay to its left. 128 sets x 1 way x 64 B block = 8 KiB per cache.
class SmallRocket64Config extends Config(
  new freechips.rocketchip.subsystem.WithL1ICacheSets(128) ++     // 8 KiB I-cache
    new freechips.rocketchip.subsystem.WithL1DCacheSets(128) ++   // 8 KiB D-cache
    new chipyard.harness.WithDontTouchChipTopPorts(false) ++
    new testchipip.soc.WithMbusScratchpad(base = 0x80000000L, size=BigInt(128 << 10)) ++  // SRAM on-chip 128kB
    new freechips.rocketchip.subsystem.WithNoMemPort ++           // remove off-chip mem port
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++      // single rocket-core, RV64 (no WithRV32)
    new freechips.rocketchip.subsystem.WithoutTLMonitors ++
    new chipyard.config.AbstractConfig)

// RV32 pure-software EDHOC config, 128 kB on-chip scratchpad.
// MbusScratchpad avoids the L2 cache configuration issues RV32 hits.
class SmallRocket32Config extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++                    // 32-bit RISC-V
    new chipyard.harness.WithDontTouchChipTopPorts(false) ++
    new testchipip.soc.WithMbusScratchpad(base = 0x80000000L, size=BigInt(128 << 10)) ++  // SRAM on-chip 128kB
    new freechips.rocketchip.subsystem.WithNoMemPort ++             // remove off-chip mem port
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++        // single small rocket-core
    new freechips.rocketchip.subsystem.WithoutTLMonitors ++
    new chipyard.config.AbstractConfig)

// RV32 pure-software EDHOC config (no hardware accelerator), 128 kB on-chip scratchpad
class SmallRocket32M3Config extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++                    // 32-bit RISC-V
    new chipyard.harness.WithDontTouchChipTopPorts(false) ++
    new testchipip.soc.WithMbusScratchpad(base = 0x80000000L, size=BigInt(128 << 10)) ++  // SRAM on-chip 128kB
    new freechips.rocketchip.subsystem.WithNoMemPort ++             // remove off-chip mem port
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++        // single small rocket-core
    new freechips.rocketchip.subsystem.WithoutTLMonitors ++
    new chipyard.config.AbstractConfig)

// RV32IMAC pure-software config (no hardware accelerator), 64 kB on-chip scratchpad
class SmallRocket32Bare64kConfig extends Config(
  new freechips.rocketchip.subsystem.WithRV32 ++                    // 32-bit RISC-V (IMAC via small-core defaults)
    new chipyard.harness.WithDontTouchChipTopPorts(false) ++
    new testchipip.soc.WithMbusScratchpad(base = 0x80000000L, size=BigInt(64 << 10)) ++  // SRAM on-chip 64kB
    new freechips.rocketchip.subsystem.WithNoMemPort ++             // remove off-chip mem port
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++        // single small rocket-core
    new freechips.rocketchip.subsystem.WithoutTLMonitors ++
    new chipyard.config.AbstractConfig)

// ---------------------------------------------------------------------------
// Requirement-aligned EDHOC config (requirement_edhoc section A.3)
// ---------------------------------------------------------------------------
// Rocket 64-bit, 8 KiB L1 I-cache and D-cache, 64 kB on-chip scratchpad,
// no off-chip memory port. Peripherals (GPIO, UART, JTAG, SPI) and the
// 100 MHz clock come from the Arty100T wrapper config.
//
// Identical to SmallRocket64Config except the scratchpad is 64 kB instead of
// 128 kB. The cache-set fragments rewrite the tiles produced by
// WithNSmallCores, so they must stay to its left.
// 128 sets x 1 way x 64 B block = 8 KiB per cache.
class EdhocRocket64Config extends Config(
  new freechips.rocketchip.subsystem.WithL1ICacheSets(128) ++     // 8 KiB I-cache
    new freechips.rocketchip.subsystem.WithL1DCacheSets(128) ++   // 8 KiB D-cache
    new chipyard.harness.WithDontTouchChipTopPorts(false) ++
    new testchipip.soc.WithMbusScratchpad(base = 0x80000000L, size=BigInt(64 << 10)) ++  // SRAM on-chip 64kB
    new freechips.rocketchip.subsystem.WithNoMemPort ++           // remove off-chip mem port
    new freechips.rocketchip.subsystem.WithNSmallCores(1) ++      // single rocket-core, RV64
    new freechips.rocketchip.subsystem.WithoutTLMonitors ++
    new chipyard.config.AbstractConfig)
