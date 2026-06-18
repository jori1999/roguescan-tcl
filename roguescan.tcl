#!/usr/bin/env tclsh8.6

set script_dir [file dirname [file normalize [info script]]]
lappend auto_path [file join $script_dir lib]

package require Tcl 8.6

# Load core first
source [file join $script_dir lib core.tcl]

# Subcommand dispatchers
proc cmd_audit {argv} {
    source [file join $::script_dir lib audit.tcl]
    roguescan::audit::run $argv
}

proc cmd_scan {argv} {
    source [file join $::script_dir lib scan.tcl]
    roguescan::scan::run $argv
}

proc cmd_daemon {argv} {
    source [file join $::script_dir lib daemon.tcl]
    roguescan::daemon::run $argv
}

proc cmd_list {argv} {
    roguescan::db::list_findings {*}$argv
}

proc cmd_summary {} {
    roguescan::db::summary_report
}

proc cmd_help {} {
    puts {roguescan - Linux malware scanner

Usage: roguescan <command> [options]

Commands:
  audit                  Full system audit
  scan <path>            One-shot file scan
  daemon                 Real-time monitoring daemon
  list [--severity S]    List findings from database
  summary                Summary report of findings
  help                   Show this help

Options (audit/scan):
  --db <path>            Database path (default: /var/db/roguescan.db)
  --yara <path>          YARA rules file (.yar)
  --signatures <path>    Additional signature database
  --max-file-size <n>    Max file size for scanning (default: 100000)
  --verbose              Verbose output

Audit skip flags:
  --no-yara              Skip YARA (file + process)
  --no-yara-proc         Skip YARA process memory only
  --no-rootkit           Skip rootkit checks
  --no-ancestry          Skip process ancestry
  --no-fileless          Skip fileless execution detection
  --no-injection         Skip process injection detection
  --no-dga               Skip DGA scoring
  --no-beacon            Skip beacon detection (daemon)
  --no-persistence       Skip persistence scanning
  --no-filesystem        Skip filesystem scanning
  --no-browser           Skip browser extension scanning
  --no-scam              Skip scam/PUP scanning
  --no-heuristics        Skip content heuristics
  --no-signatures        Skip signature matching
  --no-entropy           Skip entropy detection}
}

# --- Main ---
if {$argc == 0} {
    cmd_help
    exit 0
}

set cmd [lindex $argv 0]
set cmd_argv [lrange $argv 1 end]

switch -- $cmd {
    audit   { cmd_audit $cmd_argv }
    scan    { cmd_scan $cmd_argv }
    daemon  { cmd_daemon $cmd_argv }
    list    { cmd_list $cmd_argv }
    summary { cmd_summary }
    help    { cmd_help }
    default {
        puts stderr "Unknown command: $cmd"
        cmd_help
        exit 1
    }
}
