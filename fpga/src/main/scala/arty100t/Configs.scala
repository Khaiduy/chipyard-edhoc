// See LICENSE for license details.
package chipyard.fpga.arty100t

import chipyard.ExtTLMem
import chipyard.config.{WithBroadcastManager, WithTLBackingMemory}
import freechips.rocketchip.devices.debug.DebugModuleKey
import freechips.rocketchip.devices.tilelink.BootROMLocated
import freechips.rocketchip.diplomacy._
import freechips.rocketchip.subsystem._
import freechips.rocketchip.tile.XLen
import org.chipsalliance.cde.config._
import sifive.blocks.devices.spi.{PeripherySPIKey, SPIParams}
import sifive.blocks.devices.uart.{PeripheryUARTKey, UARTParams}
import sifive.fpgashells.shell.DesignKey
import testchipip.boot.{CustomBootPinKey}
import testchipip.serdes.{SerialTLKey}

import scala.sys.process._
import sifive.blocks.devices.gpio.PeripheryGPIOKey
import sifive.blocks.devices.gpio.GPIOParams

class WithSystemModifications extends Config((site, here, up) => {
  case DTSTimebase => BigInt{(1e6).toLong}
  case BootROMLocated(x) => up(BootROMLocated(x), site).map{ p =>
    val freqMHz = (site(SystemBusKey).dtsFrequency.get / (1000 * 1000)).toLong
    // Make sure that the bootrom is always rebuilt
    val clean = s"make -C fpga/src/main/resources/arty35t/sdboot clean"
    require (clean.! == 0, "Failed to clean")
    // Build the bootrom
    val make = s"make -C fpga/src/main/resources/arty35t/sdboot XLEN=${site(XLen)} PBUS_CLK=${freqMHz}"
    require (make.! == 0, "Failed to build bootrom")
    p.copy(hang = 0x10000, size = 0x2000, contentFileName = s"./fpga/src/main/resources/arty35t/sdboot/build/sdboot.bin")
  }
  case DesignKey => (p: Parameters) => new SimpleLazyModule()(p)
  case DebugModuleKey => up(DebugModuleKey).map{ debug =>
    debug.copy(clockGate = false)
  }
  case CustomBootPinKey => None

})

class WithoutSerial extends Config((site, here, up) => {
  case SerialTLKey => Nil
})

class WithDDR extends Config((site, here, up) => {
  case ExtMem => None
  case ExtTLMem => up(ExtMem, site).map(x => x.copy(master = x.master.copy(size = site(ArtyDDRSize)))) // set extmem
})

class WithoutDDR extends Config((site, here, up) => {
  case ExtMem => None
  case ExtTLMem => None
})

class WithDefaultPeripherals extends Config((site, here, up) => {
  case PeripheryUARTKey => List(
    UARTParams(address = BigInt(0x64000000L)),  // UART0 - USB UART
    UARTParams(address = BigInt(0x64003000L)))  // UART1 - PMOD C (PMOD B with the radio)
  case PeripherySPIKey => List(
    SPIParams(rAddress = BigInt(0x64001000L)),  // SPI0
    SPIParams(rAddress = BigInt(0x64006000L)),  // SPI1
    SPIParams(rAddress = BigInt(0x64005000L)))  // SPI2
  case PeripheryGPIOKey => List(GPIOParams(address = BigInt(0x64002000L), width = 8))
})

// chipyard 1.11 splits out the front/control/offchip bus clocks, which default
// to 500 MHz. All buses in the `uncore` clock group must request the same
// frequency, so every one of them is set here (upstream's WithArty100TTweaks
// does the same). freqMHz is a parameter so higher-clock variants do not have
// to repeat the list.
// MRF24J40 radio on PMOD JC, UART1 on PMOD JB (see ArtyJCRadioKey in CustomOverlay.scala)
class WithArtyJCRadio extends Config((site, here, up) => {
  case ArtyJCRadioKey => true
})

class WithTinyArty100TTweaks(freqMHz: Double = 50) extends Config(
  // Clock configs
  new chipyard.harness.WithAllClocksFromHarnessClockInstantiator ++
  new chipyard.harness.WithHarnessBinderClockFreqMHz(freqMHz) ++
  new chipyard.config.WithMemoryBusFrequency(freqMHz) ++
  new chipyard.config.WithFrontBusFrequency(freqMHz) ++
  new chipyard.config.WithSystemBusFrequency(freqMHz) ++
  new chipyard.config.WithPeripheryBusFrequency(freqMHz) ++
  new chipyard.config.WithControlBusFrequency(freqMHz) ++
  new chipyard.config.WithOffchipBusFrequency(freqMHz) ++
  new chipyard.clocking.WithPassthroughClockGenerator ++
  // Harness Binder
  new WithArty100TUARTHarnessBinder ++    // from HarnessBinders, to connect the Harness to IO of module
  new WithArty100TSPISDCardHarnessBinder ++
  new WithArty100TJTAGHarnessBinder ++
  // new WithArty100TJTAGBScanHarnessBinder ++
  new WithArty100TGPIOHarnessBinder ++
  // IO Binders
  // UART ports come from the AbstractConfig's WithUARTIOCells (UARTPort carries
  // uartNo); GPIO needs the punchthrough (bundle, not per-pin Analog); SPI needs
  // the local indexed variant. TSI tie-off is unnecessary: WithoutSerial sets
  // SerialTLKey => Nil, so no serial port is generated at all.
  new chipyard.iobinders.WithGPIOPunchthrough ++
  new WithArtySPIIOPunchthrough ++
  // Other configurations
  new WithoutSerial ++
  new WithoutDDR ++
  new WithDefaultPeripherals ++
  new WithSystemModifications ++
  new freechips.rocketchip.subsystem.WithoutTLMonitors)


class RocketOnChipSRAMArty100TConfig extends Config( // one small rocket CPU on-chip RAM only
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocketConfig
)

// RV32 version of SmallRocket for Arty 100T (with TRNG hardware)
// RV64 Rocket for the Arty 100T -- 8 kB L1 I+D, 128 kB on-chip SRAM, and the
// same sdboot bootrom / SD boot flow as the RV32 configs (the bootrom is built
// for XLEN=64 automatically by WithSystemModifications).
class SmallRocket64Arty100TConfig extends Config(
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket64Config
)

class SmallRocket32Arty100TConfig extends Config(
  // new WithTRNG(0x10030000L) ++  // Add TRNG peripheral at address 0x10030000
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32Config
)

// RV32 version of SmallRocket for Arty 100T — pure software EDHOC (no hardware accelerator)
class SmallRocket32M3Arty100TConfig extends Config(
  new WithTinyArty100TTweaks ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32M3Config
)


// ---- 100 MHz timing-check configs -------------------------------------
// On chipyard 1.10 the bare 64 kB RV32 design reached only Fmax ~81 MHz
// (100 MHz: post-route WNS -2.315 ns). These rebuild the same question on
// 1.11. Functional use depends on whether they actually close.
class SmallRocket32100MHzArty100TConfig extends Config(
  new WithTinyArty100TTweaks(100) ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32Config
)

class SmallRocket64100MHzArty100TConfig extends Config(
  new WithTinyArty100TTweaks(100) ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket64Config
)

// RV32IMAC bare core, 64 kB on-chip SRAM, no accelerator, 80 MHz — Arty 100T
// (100 MHz did not close: post-route WNS -2.315ns, Fmax ~81 MHz; 80 MHz closes with margin)
class SmallRocket3264k80MHzArty100TConfig extends Config(
  new WithTinyArty100TTweaks(80) ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.SmallRocket32Bare64kConfig
)


// Requirement-aligned EDHOC target (requirement_edhoc section A.3) at 75 MHz:
// Rocket 64-bit, 8 KiB I+D L1, 64 kB on-chip scratchpad, GPIO/UART/JTAG/SPI,
// Artix-7 100T. 100 MHz did not close on this device: post-route WNS -3.191 ns => Fmax ~75.8 MHz, with the
// critical path inside the Rocket tile (fetch queue -> RVC expand -> decode ->
// hazard -> EX operand register clear, 13 LUT levels, 83% routing).
// WithTinyArty100TTweaks fans one frequency out to all seven uncore bus clocks,
// so the whole SoC moves together.
class EdhocRocket6475MHzArty100TConfig extends Config(
  new WithArtyJCRadio ++                  // board-to-board link: MRF24J40 on PMOD JC (SPI1)
  new WithTinyArty100TTweaks(75) ++
  new chipyard.config.WithBroadcastManager ++
  new chipyard.EdhocRocket64Config
)
