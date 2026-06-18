# scan.tcl - One-shot file/directory scanner

load_module yara; load_module signatures; load_module heuristics; load_module entropy

namespace eval roguescan::scan {

    proc run {argv} {
        set parsed [::roguescan::config::parse $argv]
        set skip_flags [lindex $parsed 0]
        set positional [lindex $parsed 1]

        if {[llength $positional] == 0} {
            puts stderr "Usage: roguescan scan <path> [options]"
            exit 1
        }

        set target [lindex $positional 0]
        if {![file exists $target]} {
            puts stderr "Error: $target does not exist"
            exit 1
        }

        puts "=== Scanning $target ==="
        ::roguescan::finding::reset
        set start [clock seconds]

        if {[file isdirectory $target]} {
            # Heuristics
            if {![dict get $skip_flags no-heuristics]} {
                puts "  Running heuristics..."
                ::roguescan::heuristics::scan_directory $target
            }
            # YARA
            if {![dict get $skip_flags no-yara]} {
                puts "  Running YARA..."
                ::roguescan::yara::scan_directory $target
            }
            # Signatures
            if {![dict get $skip_flags no-signatures]} {
                puts "  Checking signatures..."
                ::roguescan::signatures::scan_directory $target
            }
            # Entropy
            if {![dict get $skip_flags no-entropy]} {
                puts "  Checking entropy..."
                ::roguescan::entropy::scan_directory $target
            }
        } else {
            if {![dict get $skip_flags no-heuristics]} {
                ::roguescan::heuristics::scan_file $target
            }
            if {![dict get $skip_flags no-yara]} {
                ::roguescan::yara::scan_file $target
            }
            if {![dict get $skip_flags no-signatures]} {
                ::roguescan::signatures::scan_file $target
            }
            if {![dict get $skip_flags no-entropy]} {
                ::roguescan::entropy::scan_file $target
            }
        }

        set elapsed [expr {[clock seconds] - $start}]
        set count [::roguescan::finding::count]
        puts "=== Scan complete in ${elapsed}s, $count findings ==="
        ::roguescan::finding::print
    }
}
