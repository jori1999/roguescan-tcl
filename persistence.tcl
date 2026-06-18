# persistence.tcl - Startup/persistence mechanism scanning

namespace eval roguescan::persistence {

    proc scan {} {
        scan_systemd
        scan_cron
        scan_shell_rc
        scan_ssh_keys
        scan_hosts
        scan_rc_local
    }

    proc scan_systemd {} {
        set dirs {
            /etc/systemd/system
            /lib/systemd/system
        }
        # Also user systemd
        set home [file normalize ~]
        if {$home ne ""} {
            lappend dirs [file join $home .config systemd user]
        }
        foreach dir $dirs {
            if {![file exists $dir]} continue
            foreach entry [glob -nocomplain -directory $dir *.service] {
                set f [open $entry]
                set content [read $f]
                close $f
                # Check for ExecStart pointing to /tmp, /dev/shm
                if {[regexp {ExecStart=.*/(tmp|dev/shm)/\S+} $content]} {
                    roguescan::finding::add persistence \
                        systemd_tmp HIGH 0 "" \
                        "systemd unit starts from /tmp or /dev/shm" $entry
                }
                # Check for network-accessible services
                if {[regexp {ExecStart=.*(python|perl|bash|nc|ncat|socat).*[0-9]{4,5}} $content]} {
                    roguescan::finding::add persistence \
                        systemd_network MEDIUM 0 "" \
                        "systemd unit may expose network service" $entry
                }
            }
        }
    }

    proc scan_cron {} {
        set files {
            /etc/crontab
        }
        set dirs {
            /etc/cron.d /etc/cron.hourly /etc/cron.daily
            /etc/cron.weekly /etc/cron.monthly
        }
        foreach f $files {
            if {[file exists $f]} {
                set data [read_proc_file $f]
                foreach line [split $data \n] {
                    set line [string trim $line]
                    if {$line eq "" || [string match "#*" $line]} continue
                    if {[regexp {(python|perl|bash|curl|wget|base64|/tmp|/dev/shm)} $line]} {
                        roguescan::finding::add persistence \
                            cron_suspicious MEDIUM 0 "" \
                            "Suspicious cron entry" $line
                    }
                }
            }
        }
        foreach dir $dirs {
            if {![file exists $dir]} continue
            foreach entry [glob -nocomplain -directory $dir *] {
                if {[file isdirectory $entry]} continue
                set data [read_proc_file $entry]
                if {[regexp {(python|perl|bash|curl|wget|/tmp|/dev/shm|base64)} $data]} {
                    roguescan::finding::add persistence \
                        cron_suspicious MEDIUM 0 "" \
                        "Suspicious cron script" $entry
                }
            }
        }
    }

    proc scan_shell_rc {} {
        set home [file normalize ~]
        set files [list]
        if {$home ne ""} {
            foreach f {.bashrc .profile .bash_profile .zshrc .config/fish/config.fish .tcshrc} {
                lappend files [file join $home $f]
            }
        }
        lappend files /etc/profile /etc/bash.bashrc /etc/zsh/zshrc /etc/skel/.bashrc
        foreach f $files {
            if {![file exists $f]} continue
            set data [read_proc_file $f]
            set lineno 0
            foreach line [split $data \n] {
                incr lineno
                set line [string trim $line]
                if {$line eq "" || [string match "#*" $line]} continue
                if {[regexp {(curl|wget)\s+.*\||base64.*\||python.*-c|bash.*-c} $line]} {
                    roguescan::finding::add persistence \
                        shell_rc_injection HIGH 0 "" \
                        "Suspicious shell rc entry in $f" "Line $lineno: $line"
                }
            }
        }
    }

    proc scan_ssh_keys {} {
        set home [file normalize ~]
        if {$home eq ""} return
        set auth_keys [file join $home .ssh authorized_keys]
        if {![file exists $auth_keys]} return
        set data [read_proc_file $auth_keys]
        set count 0
        foreach line [split $data \n] {
            set line [string trim $line]
            if {$line eq ""} continue
            incr count
        }
        if {$count > 10} {
            roguescan::finding::add persistence \
                ssh_keys_many LOW 0 "" \
                "Unusually many SSH authorized keys ($count)" "~/.ssh/authorized_keys"
        }
        if {$count == 0 && [file exists $auth_keys]} {
            roguescan::finding::add persistence \
                ssh_keys_empty LOW 0 "" \
                "SSH authorized_keys is empty" $auth_keys
        }
    }

    proc scan_hosts {} {
        if {![file exists "/etc/hosts"]} return
        set data [read_proc_file "/etc/hosts"]
        foreach line [split $data \n] {
            set line [string trim $line]
            if {$line eq "" || [string match "#*" $line]} continue
            if {[regexp {^127\.0\.0\.1\s+.*\.(com|org|net|io)\s*} $line]} {
                roguescan::finding::add persistence \
                    hosts_redirect MEDIUM 0 "" \
                    "Possible hosts file redirect" $line
            }
        }
    }

    proc scan_rc_local {} {
        foreach f {/etc/rc.local /etc/rc.d/rc.local} {
            if {![file exists $f]} continue
            set data [read_proc_file $f]
            if {[regexp {(python|perl|bash|/tmp|/dev/shm|curl|wget)} $data]} {
                roguescan::finding::add persistence \
                    rc_local MEDIUM 0 "" \
                    "Suspicious entry in $f" ""
            }
        }
    }
}
