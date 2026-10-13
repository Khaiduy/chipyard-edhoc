package chipyard.fpga.arty100t

import chisel3._

import chipyard._
import chipyard.harness._
import chipyard.iobinders._

// chipyard 1.11 HarnessBinders take one port at a time
//   case (th: <HarnessImp>, port: <Port>, chipId: Int)
// instead of the 1.10 (system, th, ports: Seq[...]) form. The DDR harness
// variants are not built here, so each binder has a single harness case.

/*** UART ***/
class WithArty100TUARTHarnessBinder extends HarnessBinder({
  case (th: Arty100TWithoutDDRHarnessImp, port: UARTPort, chipId: Int) => {
    th.athOuter.io_uart_bb(port.uartNo).bundle <> port.io
  }
})

/*** SPI (SD card on SPI0) ***/
class WithArty100TSPISDCardHarnessBinder extends HarnessBinder({
  case (th: Arty100TWithoutDDRHarnessImp, port: ArtySPIPort, chipId: Int) => {
    th.athOuter.io_spi_bb(port.spiId).bundle <> port.io
  }
})

/*** GPIO ***/
class WithArty100TGPIOHarnessBinder extends HarnessBinder({
  case (th: Arty100TWithoutDDRHarnessImp, port: GPIOPinsPort, chipId: Int) => {
    th.athOuter.io_gpio_bb(port.gpioId).bundle <> port.io
  }
})

/*** JTAG (external adapter on PMOD JD) ***/
class WithArty100TJTAGHarnessBinder extends HarnessBinder({
  case (th: Arty100TWithoutDDRHarnessImp, port: JTAGPort, chipId: Int) => {
    val jtagModule = th.athOuter.jtagModule
    jtagModule.TDO.data := port.io.TDO
    jtagModule.TDO.driven := true.B
    port.io.TCK := jtagModule.TCK
    port.io.TMS := jtagModule.TMS
    port.io.TDI := jtagModule.TDI
  }
})

/*** JTAG BScan (onboard FT2232H USB, Channel A — no external adapter) ***/
// Mutually exclusive with WithArty100TJTAGHarnessBinder: both match JTAGPort,
// so a config must include exactly one of them.
class WithArty100TJTAGBScanHarnessBinder extends HarnessBinder({
  case (th: Arty100TWithoutDDRHarnessImp, port: JTAGPort, chipId: Int) => {
    val jtagBScanModule = th.athOuter.jtagBScanModule
    jtagBScanModule.TDO.data := port.io.TDO
    jtagBScanModule.TDO.driven := true.B
    port.io.TCK := jtagBScanModule.TCK
    port.io.TMS := jtagBScanModule.TMS
    port.io.TDI := jtagBScanModule.TDI
  }
})
