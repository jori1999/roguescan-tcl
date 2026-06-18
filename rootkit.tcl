# rootkit.tcl - Rootkit detection: LD_PRELOAD, memmap, hidden procs, kernel modules

namespace eval roguescan::rootkit {

    proc scan {} {
        scan_ld_preload
        scan_memmaps
        scan_hidden_processes
        scan_kernel_modules
    }

    # --- LD_PRELOAD (global) ---
    proc scan_ld_preload {} {
        if {[file exists "/etc/ld.so.preload"]} {
            set f [open "/etc/ld.so.preload"]
            set data [string trim [read $f]]
            close $f
            if {$data ne ""} {
                foreach line [split $data \n] {
                    set line [string trim $line]
                    if {$line eq ""} continue
                    roguescan::finding::add rootkit \
                        ld_preload CRITICAL 0 "" \
                        "LD_PRELOAD file has entries: /etc/ld.so.preload" $line
                }
            }
        }
    }

    # --- Memory map analysis per PID ---
    proc scan_memmaps {} {
        foreach pid [get_all_pids] {
            if {[is_kernel_thread $pid]} continue
            set name [get_process_name $pid]
            set maps [read_proc_file "/proc/$pid/maps"]
            if {$maps eq ""} continue

            set found_rwx 0
            set found_memfd 0
            set found_deleted 0
            set memfd_details [list]
            set deleted_details [list]

            foreach line [split $maps \n] {
                # Check for memfd mappings
                if {[string match "*memfd:*" $line] || [string match "*[memfd:*" $line]} {
                    if {![roguescan::process::is_jit_process $name]} {
                        incr found_memfd
                        lappend memfd_details [string trim [lindex [split $line] 0]]
                    }
                }
                # Check for rwx mappings
                if {[regexp {^[0-9a-f]+-[0-9a-f]+\s+rwxp\s} $line]} {
                    if {![roguescan::process::is_jit_process $name]} {
                        incr found_rwx
                    }
                }
                # Check for deleted file-backed mappings
                if {[string match "*(deleted)*" $line]} {
                    if {![roguescan::process::is_jit_process $name]} {
                        incr found_deleted
                        lappend deleted_details [string trim [lindex [split $line] 0]]
                    }
                }
            }

            if {$found_memfd > 0} {
                roguescan::finding::add rootkit \
                    memfd_mapping HIGH $pid $name \
                    "memfd mappings found ($found_memfd regions)" [join [lrange $memfd_details 0 5] ", "]
            }
            if {$found_rwx > 5} {
                # More than a few rwx regions is suspicious even for JIT (if not excluded above)
                roguescan::finding::add rootkit \
                    rwx_mapping MEDIUM $pid $name \
                    "Excessive rwx memory mappings ($found_rwx regions)" ""
            }
            if {$found_deleted > 0} {
                roguescan::finding::add rootkit \
                    deleted_mapping HIGH $pid $name \
                    "Deleted file-backed mappings ($found_deleted regions)" [join [lrange $deleted_details 0 5] ", "]
            }
        }
    }

    # --- Hidden processes ---
    proc scan_hidden_processes {} {
        # Compare PID from /proc listing vs Tgid in /proc/{pid}/status
        foreach pid [get_all_pids] {
            set st [parse_status $pid]
            if {![dict exists $st Tgid]} continue
            set tgid [dict get $st Tgid]
            if {$tgid ne "" && $tgid != $pid} {
                set name [get_process_name $pid]
                roguescan::finding::add rootkit \
                    hidden_process CRITICAL $pid $name \
                    "PID $pid does not match Tgid $tgid (process hiding)" ""
            }
        }

        # Check for processes with unusual names or missing cmdline
        foreach pid [get_all_pids] {
            set cmdline [read_cmdline $pid]
            set name [get_process_name $pid]
            if {$cmdline eq "" && ![is_kernel_thread $pid]} {
                roguescan::finding::add rootkit \
                    hidden_cmdline MEDIUM $pid $name \
                    "Process has empty command line" ""
            }
        }
    }

    # --- Kernel module enumeration ---
    proc scan_kernel_modules {} {
        set modules_proc [list]
        set modules_sys [list]

        # Read /proc/modules
        set data [read_proc_file "/proc/modules"]
        if {$data ne ""} {
            foreach line [split $data \n] {
                if {[regexp {^(\S+)} $line -> mod]} {
                    lappend modules_proc $mod
                }
            }
        }

        # Read /sys/module
        catch {
            foreach entry [glob -nocomplain /sys/module/*] {
                lappend modules_sys [file tail $entry]
            }
        }

        # Find modules in one list but not the other
        set only_in_proc [list]
        foreach mod $modules_proc {
            if {$mod ni $modules_sys} {
                lappend only_in_proc $mod
            }
        }
        set only_in_sys [list]
        foreach mod $modules_sys {
            if {$mod ni $modules_proc} {
                lappend only_in_sys $mod
            }
        }

        if {[llength $only_in_proc] > 0} {
            roguescan::finding::add rootkit \
                module_inconsistency MEDIUM 0 "" \
                "Kernel module inconsistency: in /proc/modules but not /sys/module" [join $only_in_proc ", "]
        }
        if {[llength $only_in_sys] > 0} {
            roguescan::finding::add rootkit \
                module_inconsistency MEDIUM 0 "" \
                "Kernel module inconsistency: in /sys/module but not /proc/modules" [join $only_in_sys ", "]
        }
    }
}

