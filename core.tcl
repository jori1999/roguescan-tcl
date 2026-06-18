# core.tcl - Core utilities, DB, findings, config for roguescan
# All scanners register findings through roguescan::finding::add

catch { package require sqlite3 }

namespace eval roguescan {
    variable version "0.1.0"
    variable verbose 0
    variable max_file_size 100000
    variable yara_rules ""
    variable signatures_path ""
    variable db_path ""
    variable db_handle ""

    namespace eval finding {
        variable next_id 0
        variable findings [list]

        proc add {scanner type severity pid pname desc {detail ""}} {
            variable next_id
            variable findings
            set ts [clock format [clock seconds] -format "%Y-%m-%dT%H:%M:%S"]
            set f [dict create \
                id [incr next_id] \
                timestamp $ts \
                scanner $scanner \
                type $type \
                severity $severity \
                pid $pid \
                process_name $pname \
                description $desc \
                detail $detail]
            lappend findings $f
            return $f
        }

        proc count {} {
            variable findings
            return [llength $findings]
        }

        proc get_all {} {
            variable findings
            return $findings
        }

        proc reset {} {
            variable findings [list]
            variable next_id 0
        }

        proc print {} {
            variable findings
            set sev_order {CRITICAL HIGH MEDIUM LOW INFO}
            set groups [dict create]
            foreach f $findings {
                set s [dict get $f severity]
                dict lappend groups $s $f
            }
            foreach s $sev_order {
                if {![dict exists $groups $s]} continue
                set count [llength [dict get $groups $s]]
                puts "[format %-9s $s] $count finding(s)"
                foreach f [dict get $groups $s] {
                    set pid [dict get $f pid]
                    set pname [dict get $f process_name]
                    set scanner [dict get $f scanner]
                    set type [dict get $f type]
                    set desc [dict get $f description]
                    if {$pid > 0} {
                        set tag [string cat {[} $scanner {/} $type {]}]
                        puts "  PID $pid ($pname) $tag $desc"
                    } else {
                        set tag [string cat {[} $scanner {/} $type {]}]
                        puts "  $tag $desc"
                    }
                    set detail [dict get $f detail]
                    if {$detail ne ""} {
                        puts "    -> $detail"
                    }
                }
            }
        }
    }

    namespace eval config {
        proc parse {argv} {
            variable ::roguescan::verbose
            variable ::roguescan::max_file_size
            variable ::roguescan::yara_rules
            variable ::roguescan::signatures_path
            variable ::roguescan::db_path

            set skip_flags [dict create \
                no-yara 0 no-yara-proc 0 no-rootkit 0 \
                no-ancestry 0 no-fileless 0 no-injection 0 \
                no-dga 0 no-beacon 0 no-persistence 0 \
                no-filesystem 0 no-browser 0 no-scam 0 \
                no-heuristics 0 no-signatures 0 no-entropy 0]

            set args $argv
            set positional [list]
            while {[llength $args] > 0} {
                set a [lindex $args 0]
                set args [lrange $args 1 end]
                switch -glob -- $a {
                    --db {
                        set ::roguescan::db_path [lindex $args 0]
                        set args [lrange $args 1 end]
                    }
                    --yara {
                        set ::roguescan::yara_rules [lindex $args 0]
                        set args [lrange $args 1 end]
                    }
                    --signatures {
                        set ::roguescan::signatures_path [lindex $args 0]
                        set args [lrange $args 1 end]
                    }
                    --max-file-size {
                        set ::roguescan::max_file_size [lindex $args 0]
                        set args [lrange $args 1 end]
                    }
                    --verbose {
                        set ::roguescan::verbose 1
                    }
                    --no-* {
                        set flag [string range $a 2 end]
                        if {[dict exists $skip_flags $flag]} {
                            dict set skip_flags $flag 1
                        }
                    }
                    default {
                        lappend positional $a
                    }
                }
            }
            return [list $skip_flags $positional]
        }

        proc parse_skip_flags {skip_flags} {
            return $skip_flags
        }
    }

    namespace eval db {
        proc available {} {
            return [expr {[llength [info commands ::sqlite3]] > 0}]
        }

        proc init {} {
            variable ::roguescan::db_path
            variable ::roguescan::db_handle

            catch { package require sqlite3 }
            if {![available]} {
                puts stderr "  Warning: sqlite3 Tcl package not available, findings will not be persisted"
                return
            }

            if {$db_path eq ""} {
                set db_path "/var/db/roguescan.db"
            }
            set dir [file dirname $db_path]
            if {![file exists $dir]} {
                file mkdir $dir
            }
            set db_handle [sqlite3 db $db_path]
            db eval {
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    scanner TEXT,
                    type TEXT,
                    severity TEXT,
                    pid INTEGER,
                    process_name TEXT,
                    description TEXT,
                    detail TEXT
                )
            }
            db eval {
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            }
        }

        proc close {} {
            if {![available]} return
            variable ::roguescan::db_handle
            catch {$db_handle close}
        }

        proc store_finding {f} {
            if {![available]} return
            variable ::roguescan::db_handle
            db eval {
                INSERT INTO findings(timestamp,scanner,type,severity,pid,process_name,description,detail)
                VALUES(
                    [dict get $f timestamp],
                    [dict get $f scanner],
                    [dict get $f type],
                    [dict get $f severity],
                    [dict get $f pid],
                    [dict get $f process_name],
                    [dict get $f description],
                    [dict get $f detail]
                )
            }
        }

        proc store_all_findings {} {
            if {![available]} return
            foreach f [roguescan::finding::get_all] {
                store_finding $f
            }
        }

        proc list_findings {{severity ""} {limit 100}} {
            if {![available]} { puts "No database available"; return }
            variable ::roguescan::db_handle
            if {$severity ne ""} {
                set rows [db eval "SELECT * FROM findings WHERE severity='$severity' ORDER BY id DESC LIMIT $limit"]
            } else {
                set rows [db eval "SELECT * FROM findings ORDER BY id DESC LIMIT $limit"]
            }
            foreach row $rows {
                puts "\[[dict get $row severity]\] [dict get $row timestamp] \
                    PID [dict get $row pid] ([dict get $row process_name]) \
                    [dict get $row scanner]/[dict get $row type] \
                    [dict get $row description]"
                set detail [dict get $row detail]
                if {$detail ne ""} {
                    puts "  -> $detail"
                }
            }
        }

        proc summary_report {} {
            if {![available]} { puts "No database available"; return }
            variable ::roguescan::db_handle
            set results [db eval {SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity ORDER BY
                CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 WHEN 'INFO' THEN 5 ELSE 6 END}]
            set total 0
            puts "=== roguescan Summary ==="
            foreach row $results {
                puts "  [format %-9s [dict get $row severity]] [dict get $row cnt]"
                incr total [dict get $row cnt]
            }
            puts "  ---"
            puts "  TOTAL     $total"
            puts ""
            set top [db eval {SELECT severity, type, COUNT(*) as cnt FROM findings GROUP BY severity, type ORDER BY cnt DESC LIMIT 10}]
            puts "Top finding types:"
            foreach row $top {
                puts "  [format %-9s [dict get $row severity]] [dict get $row type] ([dict get $row cnt])"
            }
        }
    }
}

# Module loading helper: source file if it exists
proc load_module {name} {
    set path [file join $::script_dir lib ${name}.tcl]
    if {[file exists $path]} {
        source $path
    } else {
        puts stderr "Warning: module $name not found at $path"
    }
}

# Safe /proc reading
proc read_proc_file {path} {
    if {![file exists $path]} { return "" }
    catch {
        set f [open $path r]
        set data [read $f]
        close $f
        return $data
    } err
    return ""
}

# Process status parser - returns dict
proc parse_status {pid} {
    set data [read_proc_file "/proc/$pid/status"]
    if {$data eq ""} { return [dict create] }
    set result [dict create]
    foreach line [split $data \n] {
        if {[regexp {^(\w[\w-]*):\s+(.+)$} $line -> key val]} {
            dict set result $key [string trim $val]
        }
    }
    return $result
}

# Read cmdline (null-separated -> space-separated)
proc read_cmdline {pid} {
    set data [read_proc_file "/proc/$pid/cmdline"]
    if {$data eq ""} { return "" }
    return [string map {"\0" " "} $data]
}

# Get process name from status
proc get_process_name {pid} {
    set st [parse_status $pid]
    if {[dict exists $st Name]} {
        return [dict get $st Name]
    }
    return ""
}

# Get all PIDs
proc get_all_pids {} {
    set pids [list]
    catch {
        foreach entry [glob -nocomplain /proc/[0-9]*] {
            set pid [file tail $entry]
            if {[string is digit -strict $pid]} {
                lappend pids $pid
            }
        }
    }
    return [lsort -integer $pids]
}

# Check if process is a kernel thread (bracketed name, no exe link)
proc is_kernel_thread {pid} {
    set name [get_process_name $pid]
    if {$name ne "" && [string match {[*} $name]} { return 1 }
    if {![file exists "/proc/$pid/exe"]} { return 1 }
    return 0
}
