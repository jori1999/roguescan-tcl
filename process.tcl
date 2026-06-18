# process.tcl - Process scanning, ancestry, fileless, injection detection

namespace eval roguescan::process {

    # Suspicious process name patterns
    variable suspicious_names {
        meterpreter mimikatz xmrig cryptominer miner
        cobaltstrike beacon payload dropper keylog
        reverse_shell bindshell shells windows-update
        svchost (not svchost) csrss winlogon
    }

    # Known JIT/legitimate rwx processes to exclude
    variable jit_processes {
        chrome firefox chromium alacritty node python
        java jetbrains Xorg X xeyes pipewire
        gnome-shell plasmashell code sublime_text
        go ruby lua v8 js
    }

    # Suspicious paths for executables
    variable suspicious_paths {
        /tmp /dev/shm /var/tmp /run/shm
    }

    # Known system process names
    variable system_processes {
        systemd init sshd cron crond nginx apache2 httpd
        mysqld postgresql rsyslog journald NetworkManager
        dhclient wpa_supplicant polkitd accounts-daemon
        systemd-journald systemd-logind systemd-udevd
        systemd-resolved systemd-timesyncd
    }

    # Suspicious interpreters
    variable interpreters {python perl ruby php lua node}

    proc scan {pid} {
        set name [get_process_name $pid]
        set cmdline [read_cmdline $pid]
        set exe ""
        catch {set exe [file readlink "/proc/$pid/exe"]}

        # Suspicious names
        foreach pat $::roguescan::process::suspicious_names {
            if {[string match -nocase "*$pat*" $name]} {
                roguescan::finding::add process \
                    suspicious_name HIGH $pid $name \
                    "Suspicious process name: $name" $cmdline
            }
        }

        # Suspicious paths
        foreach sp $::roguescan::process::suspicious_paths {
            if {$exe ne "" && [string match "$sp*" $exe]} {
                roguescan::finding::add process \
                    suspicious_path HIGH $pid $name \
                    "Process running from $sp: $exe" $cmdline
            }
            if {[string match "$sp*" $cmdline]} {
                roguescan::finding::add process \
                    suspicious_path MEDIUM $pid $name \
                    "Command line references $sp" $cmdline
            }
        }

        # Deleted executable
        if {[file exists "/proc/$pid/exe"]} {
            catch {
                if {[string match "*(deleted)*" [file readlink "/proc/$pid/exe"]]} {
                    roguescan::finding::add process \
                        deleted_exe HIGH $pid $name \
                        "Process executable has been deleted" $exe
                }
            }
        }

        # LD_PRELOAD / LD_LIBRARY_PATH
        set environ [read_proc_file "/proc/$pid/environ"]
        if {$environ ne ""} {
            set environ [string map {"\0" "\n"} $environ]
            foreach line [split $environ \n] {
                if {[string match {LD_PRELOAD=*} $line]} {
                    set val [string range $line 11 end]
                    roguescan::finding::add process \
                        ld_preload HIGH $pid $name \
                        "LD_PRELOAD set: $val" $cmdline
                }
                if {[string match {LD_LIBRARY_PATH=*} $line]} {
                    set val [string range $line 17 end]
                    roguescan::finding::add process \
                        ld_library_path MEDIUM $pid $name \
                        "LD_LIBRARY_PATH set to suspicious path" $cmdline
                }
            }
        }
    }

    proc scan_all {} {
        foreach pid [get_all_pids] {
            scan $pid
        }
    }

    # --- Ancestry tracking ---
    proc scan_ancestry {} {
        foreach pid [get_all_pids] {
            if {[is_kernel_thread $pid]} continue
            set name [get_process_name $pid]
            set cmdline [read_cmdline $pid]
            set ancestry [get_ancestry $pid]
            check_ancestry $pid $name $cmdline $ancestry
        }
    }

    proc get_ancestry {pid} {
        set chain [list]
        set current $pid
        for {set i 0} {$i < 10 && $current > 0} {incr i} {
            set st [parse_status $current]
            if {![dict exists $st Name]} break
            set pname [dict get $st Name]
            lappend chain [list $current $pname]
            if {[dict exists $st PPid]} {
                set current [dict get $st PPid]
            } else {
                break
            }
            if {$current == 0} break
        }
        return $chain
    }

    proc check_ancestry {pid name cmdline ancestry} {
        if {[llength $ancestry] < 2} return

        set child [lindex $ancestry 0 1]
        set parent [lindex $ancestry 1 1]

        # Browser -> shell
        if {[is_browser $parent] && [is_shell $child]} {
            roguescan::finding::add process \
                ancestry_browser_shell HIGH $pid $name \
                "Browser ($parent) spawned shell ($child)" [join [lmap e $ancestry {lindex $e 1}] " -> "]
        }

        # Browser -> interpreter
        if {[is_browser $parent] && [is_interpreter $child]} {
            roguescan::finding::add process \
                ancestry_browser_interp HIGH $pid $name \
                "Browser ($parent) spawned interpreter ($child)" [join [lmap e $ancestry {lindex $e 1}] " -> "]
        }

        # Shell -> miner
        if {[is_shell $parent] && [is_miner $child]} {
            roguescan::finding::add process \
                ancestry_shell_miner CRITICAL $pid $name \
                "Shell spawned cryptominer: $child" [join [lmap e $ancestry {lindex $e 1}] " -> "]
        }

        # SSHD -> unusual child (not shell)
        if {[string match -nocase "sshd" $parent] && ![is_shell $child]} {
            roguescan::finding::add process \
                ancestry_sshd_unusual HIGH $pid $name \
                "SSHD spawned unusual child: $child" [join [lmap e $ancestry {lindex $e 1}] " -> "]
        }

        # System process -> interpreter
        if {[is_system_proc $parent] && [is_interpreter $child]} {
            roguescan::finding::add process \
                ancestry_system_interp MEDIUM $pid $name \
                "System process ($parent) spawned interpreter ($child)" [join [lmap e $ancestry {lindex $e 1}] " -> "]
        }
    }

    proc is_browser {name} {
        return [expr {[string match -nocase "*chrome*" $name] ||
                      [string match -nocase "*firefox*" $name] ||
                      [string match -nocase "*chromium*" $name] ||
                      [string match -nocase "*brave*" $name] ||
                      [string match -nocase "*browser*" $name]}]
    }

    proc is_shell {name} {
        return [expr {[string match -nocase "*bash*" $name] ||
                      [string match -nocase "*zsh*" $name] ||
                      [string match -nocase "*sh" $name] ||
                      [string match -nocase "*dash*" $name] ||
                      [string match -nocase "*fish*" $name]}]
    }

    proc is_interpreter {name} {
        foreach interp $::roguescan::process::interpreters {
            if {[string match -nocase "*$interp*" $name]} { return 1 }
        }
        return 0
    }

    proc is_miner {name} {
        return [expr {[string match -nocase "*xmrig*" $name] ||
                      [string match -nocase "*miner*" $name] ||
                      [string match -nocase "*cryptonight*" $name] ||
                      [string match -nocase "*ethminer*" $name] ||
                      [string match -nocase "*ccminer*" $name] ||
                      [string match -nocase "*cpuminer*" $name] ||
                      [string match -nocase "*cryptominer*" $name]}]
    }

    proc is_system_proc {name} {
        foreach sp $::roguescan::process::system_processes {
            if {[string compare -nocase $sp $name] == 0} { return 1 }
        }
        return 0
    }

    # --- Fileless execution detection ---
    proc scan_fileless {} {
        foreach pid [get_all_pids] {
            if {[is_kernel_thread $pid]} continue
            set name [get_process_name $pid]
            set cmdline [read_cmdline $pid]

            # memfd detection
            catch {
                set exe [file readlink "/proc/$pid/exe"]
                if {[string match "*/memfd:*" $exe] || [string match "*/[memfd:*" $exe]} {
                    roguescan::finding::add process \
                        fileless_memfd CRITICAL $pid $name \
                        "Process running from memfd (fileless)" "$exe | $cmdline"
                }
            }

            # /dev/shm execution
            catch {
                if {[file exists "/proc/$pid/exe"]} {
                    set exe [file readlink "/proc/$pid/exe"]
                    if {[string match "/dev/shm*" $exe]} {
                        roguescan::finding::add process \
                            fileless_devshm HIGH $pid $name \
                            "Process running from /dev/shm" "$exe | $cmdline"
                    }
                }
            }

            # Missing executable (deleted binary)
            if {![file exists "/proc/$pid/exe"]} {
                roguescan::finding::add process \
                    fileless_no_exe HIGH $pid $name \
                    "Process has no executable link" $cmdline
            }

            # Check maps for anonymous rwx
            set maps [read_proc_file "/proc/$pid/maps"]
            if {$maps ne ""} {
                set anon_rwx 0
                foreach line [split $maps \n] {
                    if {[regexp {^[0-9a-f]+-[0-9a-f]+\s+rwxp\s} $line]} {
                        if {![is_jit_process $name]} {
                            incr anon_rwx
                        }
                    }
                }
                if {$anon_rwx > 0} {
                    roguescan::finding::add process \
                        fileless_anon_rwx HIGH $pid $name \
                        "Anonymous rwx mappings ($anon_rwx regions)" $cmdline
                }
            }
        }
    }

    proc is_jit_process {name} {
        foreach jp $::roguescan::process::jit_processes {
            if {[string match -nocase "*$jp*" $name]} { return 1 }
        }
        return 0
    }

    # --- Process injection detection ---
    proc scan_injection {} {
        foreach pid [get_all_pids] {
            if {[is_kernel_thread $pid]} continue
            set st [parse_status $pid]
            if {![dict exists $st TracerPid]} continue
            set tracer [dict get $st TracerPid]
            if {$tracer eq "" || $tracer == 0} continue

            set name [get_process_name $pid]
            set tname [get_process_name $tracer]
            set cmdline [read_cmdline $pid]

            # System process being debugged
            if {[is_critical_proc $name]} {
                roguescan::finding::add process \
                    injection_critical CRITICAL $pid $name \
                    "System process is being traced by PID $tracer ($tname)" $cmdline
            } else {
                roguescan::finding::add process \
                    injection_traced MEDIUM $pid $name \
                    "Process is being traced by PID $tracer ($tname)" $cmdline
            }
        }
    }

    proc is_critical_proc {name} {
        set critical {systemd init sshd cron crond login screen sudo su
                      auditd rsyslog journald systemd-journald
                      NetworkManager polkitd dbus-daemon accounts-daemon}
        foreach c $critical {
            if {[string compare -nocase $c $name] == 0} { return 1 }
        }
        return 0
    }
}
