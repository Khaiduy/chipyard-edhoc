package chipyard.fpga.arty100t

import chisel3._

import chipyard.iobinders._

import freechips.rocketchip.diplomacy.{InModuleBody, Resource, ResourceAddress, ResourceBinding}
import freechips.rocketchip.subsystem.BaseSubsystem

import sifive.blocks.devices.spi.{HasPeripherySPI, HasPeripherySPIBundle, MMCDevice, SPIPortIO}

// chipyard 1.11's own SPIPort carries no index, but this board has three SPI
// controllers (SD card on SPI0, two PMOD headers on SPI1/SPI2). Carry the index
// so the harness binder can reach the matching BundleBridge in the shell.
// UART and GPIO need no equivalent: upstream's UARTPort has `uartNo` and
// GPIOPinsPort has `gpioId`, so those use the stock punchthrough binders.
case class ArtySPIPort(val getIO: () => SPIPortIO, val spiId: Int) extends Port[SPIPortIO]

class WithArtySPIIOPunchthrough extends OverrideLazyIOBinder({
  (system: HasPeripherySPI) => {
    // attach the MMC resource to the 1st SPI, as upstream's WithSPIIOPunchthrough does
    if (system.tlSpiNodes.size > 0) ResourceBinding {
      Resource(new MMCDevice(system.tlSpiNodes.head.device, 1), "reg").bind(ResourceAddress(0))
    }
    InModuleBody {
      val spi = system.asInstanceOf[BaseSubsystem].module.asInstanceOf[HasPeripherySPIBundle].spi
      val ports = spi.zipWithIndex.map { case (s, i) =>
        val io_spi = IO(s.cloneType).suggestName(s"spi_$i")
        io_spi <> s
        ArtySPIPort(() => io_spi, i)
      }
      (ports, Nil)
    }
  }
})
