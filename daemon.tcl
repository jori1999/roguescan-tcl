# daemon.tcl - Real-time monitoring daemon

load_module process; load_module network; load_module rootkit; load_module beacon

namespace eval roguescan::daemon {

    variable running 0
    variable pid_file ""
    variable log_file "/var/log/roguescan.log"

    proc run {argv} {
        set parsed [::roguescan::config::parse $argv]
        set skip_flags [lindex $parsed 0]

        puts "=== roguescan daemon ==="
        puts "Starting monitoring daemon..."
        puts ""

        ::roguescan::db::init

        # Periodic audit snapshot (every 5 minutes)
        proc periodic_audit {} {
            puts "[clock format [clock seconds] -format %T] Running periodic audit..."
            ::roguescan::finding::reset
            ::roguescan::process::scan_all
            ::roguescan::network::scan
            ::roguescan::db::store_all_findings
        }

        # Schedule periodic tasks
        after 60000 {
            # 1 min: first quick scan
            if {![dict get $::roguescan::daemon::skip_flags no-rootkit]} {
                ::roguescan::rootkit::scan
            }
        }

        after 120000 {
            if {![dict get $::roguescan::daemon::skip_flags no-ancestry]} {
                ::roguescan::process::scan_ancestry
            }
        }

        after 180000 {
            if {![dict get $::roguescan::daemon::skip_flags no-fileless]} {
                ::roguescan::process::scan_fileless
            }
            if {![dict get $::roguescan::daemon::skip_flags no-injection]} {
                ::roguescan::process::scan_injection
            }
        }

        after 300000 {
            if {![dict get $::roguescan::daemon::skip_flags no-dga]} {
                ::roguescan::network::scan_dga
            }
        }

        after 60000 periodic_audit_loop
        proc periodic_audit_loop {} {
            after 300000 ::roguescan::daemon::periodic_audit_loop
            ::roguescan::daemon::periodic_audit
        }

        # Beacon detection
        if {![dict get $skip_flags no-beacon]} {
            puts "  Starting beacon detector (30s interval)..."
            ::roguescan::beacon::reset
            ::roguescan::beacon::daemon_tick
        }

        # Fanotify is hard in Tcl without C extension.
        # Fallback to inotifywait polling:
        puts "  Starting inotify watcher..."
        proc inotify_loop {} {
            set watched_dirs {/tmp /dev/shm}
            foreach dir $watched_dirs {
                if {![file exists $dir]} continue
                catch {
                    exec inotifywait -q -t 30 -r $dir -e create,modify,move -o /dev/null &
                }
            }
            after 30000 ::roguescan::daemon::inotify_loop
        }
        inotify_loop

        # Beacon detector is already tick-based, vwait handles it
        puts "Daemon running. PID: [pid]"
        puts "Press Ctrl+C to stop."

        set ::roguescan::daemon::running 1
        vwait ::roguescan::daemon::running
    }
}
