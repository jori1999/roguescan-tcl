# audit.tcl - Full system audit orchestrator

# Source all scanner modules
load_module process; load_module network; load_module rootkit
load_module persistence; load_module filesystem; load_module browser
load_module scam; load_module yara; load_module heuristics
load_module signatures; load_module entropy

namespace eval roguescan::audit {

    proc run {argv} {
        set parsed [::roguescan::config::parse $argv]
        set skip_flags [lindex $parsed 0]

        set start [clock seconds]
        puts "=== roguescan audit ==="
        puts "Starting full system audit..."
        puts ""

        ::roguescan::finding::reset
        ::roguescan::db::init

        # Step 1: Process scanning
        puts {  [1/9] Scanning processes...}
        ::roguescan::process::scan_all

        # Step 2: Network scanning
        puts {  [2/9] Scanning network...}
        ::roguescan::network::scan

        # Step 3: Persistence scanning
        if {![dict get $skip_flags no-persistence]} {
            puts {  [3/9] Scanning persistence mechanisms...}
            ::roguescan::persistence::scan
        }

        # Step 4: Filesystem scanning
        if {![dict get $skip_flags no-filesystem]} {
            puts {  [4/9] Scanning filesystem...}
            ::roguescan::filesystem::scan
        }

        # Step 5: Browser extensions
        if {![dict get $skip_flags no-browser]} {
            puts {  [5/9] Scanning browser extensions...}
            ::roguescan::browser::scan
        }

        # Step 6: Scam/PUP
        if {![dict get $skip_flags no-scam]} {
            puts {  [6/9] Scanning for PUPs...}
            ::roguescan::scam::scan
        }

        # Step 7: Rootkit detection
        if {![dict get $skip_flags no-rootkit]} {
            puts {  [7/9] Scanning for rootkits...}
            ::roguescan::rootkit::scan
        }

        # Step 8: Process ancestry
        if {![dict get $skip_flags no-ancestry]} {
            puts {  [8/9] Tracking process ancestry...}
            ::roguescan::process::scan_ancestry
        }

        # Step 9: DGA
        if {![dict get $skip_flags no-dga]} {
            puts {  [9/9] Scanning for DGA domains...}
            ::roguescan::network::scan_dga
        }

        # Fileless + injection (always on with process scanner)
        if {![dict get $skip_flags no-fileless]} {
            ::roguescan::process::scan_fileless
        }
        if {![dict get $skip_flags no-injection]} {
            ::roguescan::process::scan_injection
        }

        # YARA process memory
        if {![dict get $skip_flags no-yara] && ![dict get $skip_flags no-yara-proc]} {
            puts {  [extra] Scanning process memory with YARA...}
            ::roguescan::yara::scan_all_processes
        }

        set elapsed [expr {[clock seconds] - $start}]
        set count [::roguescan::finding::count]
        puts ""
        puts "=== Audit complete in ${elapsed}s ==="
        puts "Total findings: $count"
        puts ""

        # Print findings grouped by severity
        ::roguescan::finding::print

        # Store in DB
        ::roguescan::db::store_all_findings
        ::roguescan::db::close
    }
}
