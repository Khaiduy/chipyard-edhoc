# program_two.tcl — program both Arty A7-100T boards with one bitstream
# through the hw_server on localhost:3121 (the Vivado GUI's, if it runs).
#   BIT=<file.bit> SERIALS="<serial> <serial>" vivado -mode batch -source program_two.tcl
open_hw_manager
if {[catch {connect_hw_server -url localhost:3121}]} { connect_hw_server }
foreach s $::env(SERIALS) {
    set t [lindex [get_hw_targets *$s*] 0]
    if {$t eq ""} { error "no hw target for board $s" }
    open_hw_target $t
    set dev [lindex [get_hw_devices xc7a100t*] 0]
    current_hw_device $dev
    set_property PROGRAM.FILE $::env(BIT) $dev
    program_hw_devices $dev
    puts "PROGRAMMED $s"
    close_hw_target $t
}
disconnect_hw_server
