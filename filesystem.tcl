# filesystem.tcl - Filesystem scanning

namespace eval roguescan::filesystem {

    variable walk_paths {/tmp /dev/shm /home /etc /var/tmp /opt /root}

    proc scan {} {
        foreach path $::roguescan::filesystem::walk_paths {
            if {![file exists $path]} continue
            scan_suid $path
            scan_world_writable $path
            scan_foreign_binaries $path
        }
    }

    proc scan_suid {path} {
        set found 0
        catch {
            set result [exec find $path -type f -perm -4000 2>/dev/null]
            foreach line [split $result \n] {
                set line [string trim $line]
                if {$line eq ""} continue
                if {[string match "/nix/store/*" $line]} continue
                incr found
                if {$found <= 20} {
                    roguescan::finding::add filesystem \
                        suid_binary MEDIUM 0 "" \
                        "SUID binary found" $line
                }
            }
        }
        if {$found > 20} {
            roguescan::finding::add filesystem \
                suid_many MEDIUM 0 "" \
                "Many SUID binaries found ($found total)" $path
        }
    }

    proc scan_world_writable {path} {
        set found 0
        catch {
            set result [exec find $path -type f -perm -0002 2>/dev/null]
            foreach line [split $result \n] {
                set line [string trim $line]
                if {$line eq ""} continue
                if {[string match "*/lost+found/*" $line]} continue
                if {[string match "/tmp/*" $line] && $path eq "/tmp"} continue
                incr found
                if {$found <= 10} {
                    roguescan::finding::add filesystem \
                        world_writable INFO 0 "" \
                        "World-writable file" $line
                }
            }
        }
        if {$found > 10} {
            roguescan::finding::add filesystem \
                world_writable_many INFO 0 "" \
                "World-writable file count: $found" $path
        }
    }

    proc scan_foreign_binaries {path} {
        catch {
            set result [exec find $path -type f -exec file -m /dev/null {} \; 2>/dev/null]
            foreach line [split $result \n] {
                set line [string trim $line]
                if {[regexp {PE32|PE32\+|MS-DOS executable|Mach-O} $line]} {
                    set fpath [lindex [split $line ":"] 0]
                    roguescan::finding::add filesystem \
                        foreign_binary MEDIUM 0 "" \
                        "Windows/Mac binary on Linux" $fpath
                }
            }
        }
    }
}
