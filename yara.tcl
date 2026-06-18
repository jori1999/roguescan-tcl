# yara.tcl - YARA integration (file + process memory scanning)

namespace eval roguescan::yara {

    proc has_yara {} {
        catch {exec yara --version 2>/dev/null} version
        return [expr {$version ne ""}]
    }

    proc get_rules {} {
        if {$::roguescan::yara_rules ne "" && [file exists $::roguescan::yara_rules]} {
            return $::roguescan::yara_rules
        }
        # Built-in rules
        set builtin [file join $::script_dir rules builtin.yar]
        if {[file exists $builtin]} {
            return $builtin
        }
        return ""
    }

    proc scan_file {path} {
        set rules [get_rules]
        if {$rules eq ""} {
            puts stderr "  YARA rules not found, skipping"
            return
        }
        if {![has_yara]} {
            puts stderr "  yara CLI not found, skipping"
            return
        }
        catch {
            set result [exec yara $rules $path 2>/dev/null]
            foreach line [split $result \n] {
                set line [string trim $line]
                if {$line eq ""} continue
                if {[regexp {^(\S+)\s+(.+)$} $line -> rule file]} {
                    roguescan::finding::add yara \
                        yara_match HIGH 0 "" \
                        "YARA rule match: $rule" $file
                }
            }
        }
    }

    proc scan_directory {path} {
        set rules [get_rules]
        if {$rules eq ""} return
        if {![has_yara]} return

        set max_size $::roguescan::max_file_size
        catch {
            set result [exec find $path -type f -size -${max_size}c -exec yara $rules {} \; 2>/dev/null]
            foreach line [split $result \n] {
                set line [string trim $line]
                if {$line eq ""} continue
                if {[regexp {^(\S+)\s+(.+)$} $line -> rule file]} {
                    roguescan::finding::add yara \
                        yara_match HIGH 0 "" \
                        "YARA rule match: $rule" $file
                }
            }
        }
    }

    proc scan_process {pid} {
        set rules [get_rules]
        if {$rules eq ""} return
        if {![has_yara]} return
        if {[is_kernel_thread $pid]} return

        set mem_path "/proc/$pid/mem"
        if {![file exists $mem_path]} return
        if {![file readable $mem_path]} return

        catch {
            set result [exec timeout 5 yara $rules $mem_path 2>/dev/null]
            foreach line [split $result \n] {
                set line [string trim $line]
                if {$line eq ""} continue
                if {[regexp {^(\S+)\s+(.+)$} $line -> rule _]} {
                    set name [get_process_name $pid]
                    roguescan::finding::add yara \
                        yara_proc_match HIGH $pid $name \
                        "YARA process memory match: $rule" ""
                }
            }
        }
    }

    proc scan_all_processes {} {
        foreach pid [get_all_pids] {
            if {[is_kernel_thread $pid]} continue
            scan_process $pid
        }
    }
}
