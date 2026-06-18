# signatures.tcl - SHA256 hash + filename signature matching

namespace eval roguescan::signatures {

    proc load_db {} {
        set db [list]
        # Built-in
        set builtin [file join $::script_dir data known_bad.json]
        if {[file exists $builtin]} {
            set f [open $builtin]
            set data [read $f]
            close $f
            if {[catch {set db [json_parse $data]} err]} {
                puts stderr "  Error parsing built-in signatures: $err"
            }
        }
        # Custom
        if {$::roguescan::signatures_path ne "" && [file exists $::roguescan::signatures_path]} {
            set f [open $::roguescan::signatures_path]
            set data [read $f]
            close $f
            if {[catch {set custom [json_parse $data]} err]} {
                puts stderr "  Error parsing custom signatures: $err"
            } else {
                set db [concat $db $custom]
            }
        }
        return $db
    }

    # Minimal JSON parser for array of objects
    proc json_parse {data} {
        set result [list]
        # Simple line-by-line extraction of name/sha256/filename from JSON
        set current [dict create]
        foreach line [split $data \n] {
            set line [string trim $line]
            if {$line eq "" || $line eq "\[" || $line eq "\]"} continue
            if {$line eq "\{"} { set current [dict create]; continue }
            if {$line eq "\}," || $line eq "\}"} {
                if {[dict size $current] > 0} { lappend result $current }
                continue
            }
            if {[regexp {^\s*"([^"]+)"\s*:\s*"([^"]*)"\s*,?\s*$} $line -> key val]} {
                if {$key eq "sha256"} {
                    dict set current sha256 [string tolower $val]
                } elseif {$key eq "filename"} {
                    dict set current filename $val
                } elseif {$key eq "name"} {
                    dict set current name $val
                } elseif {$key eq "description"} {
                    dict set current description $val
                } elseif {$key eq "severity"} {
                    dict set current severity $val
                }
            }
        }
        return $result
    }

    proc scan_file {path} {
        set db [load_db]
        if {[llength $db] == 0} return

        set filename [file tail $path]
        set dir [file dirname $path]

        # Check filename
        foreach entry $db {
            if {![dict exists $entry filename]} continue
            set pattern [dict get $entry filename]
            if {[string match -nocase "*$pattern*" $filename]} {
                set sev [dict get $entry "severity"]
                set name [dict get $entry "name"]
                roguescan::finding::add signature \
                    filename_match $sev 0 "" \
                    "Signature filename match: $name" $path
            }
        }

        # Check SHA256
        set sha [compute_sha256 $path]
        if {$sha eq ""} return
        foreach entry $db {
            if {![dict exists $entry sha256]} continue
            if {[dict get $entry sha256] eq $sha} {
                set sev [dict get $entry "severity"]
                set name [dict get $entry "name"]
                roguescan::finding::add signature \
                    hash_match $sev 0 "" \
                    "Signature hash match: $name" $path
            }
        }
    }

    proc scan_directory {path} {
        set max_size $::roguescan::max_file_size
        set db [load_db]
        if {[llength $db] == 0} return

        # Filename matching pass
        foreach entry $db {
            if {![dict exists $entry filename]} continue
            set pattern [dict get $entry filename]
            set sev [dict get $entry "severity"]
            set name [dict get $entry "name"]
            catch {
                set result [exec find $path -name "*$pattern*" -type f 2>/dev/null]
                foreach line [split $result \n] {
                    set line [string trim $line]
                    if {$line ne ""} {
                        roguescan::finding::add signature \
                            filename_match $sev 0 "" \
                            "Signature filename match: $name" $line
                    }
                }
            }
        }
    }

    proc compute_sha256 {path} {
        if {![file exists $path]} return ""
        if {![file isfile $path]} return ""
        set max_size $::roguescan::max_file_size
        if {[file size $path] > $max_size * 2} return ""
        catch {
            set result [exec sha256sum $path 2>/dev/null]
            return [lindex $result 0]
        }
        return ""
    }
}
