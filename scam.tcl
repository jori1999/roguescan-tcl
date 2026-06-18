# scam.tcl - Scam/PUP detection (dpkg packages, .desktop files)

namespace eval roguescan::scam {

    proc scan {} {
        scan_dpkg
        scan_desktop_files
    }

    proc scan_dpkg {} {
        if {![file exists "/var/lib/dpkg/status"]} return
        set data [read_proc_file "/var/lib/dpkg/status"]
        set pkg_name ""
        foreach line [split $data \n] {
            if {[regexp {^Package:\s+(.+)$} $line -> name]} {
                set pkg_name $name
            }
            if {[regexp {^Description:\s+(.+)$} $line -> desc]} {
                if {[is_pup_package $pkg_name $desc]} {
                    roguescan::finding::add scam \
                        pup_package MEDIUM 0 "" \
                        "Potentially unwanted package installed" "$pkg_name: $desc"
                }
            }
        }
    }

    proc is_pup_package {name desc} {
        set pkg_patterns {teamviewer anydesk logmein vncviewer remote-desktop
                          browser-optimizer pc-cleaner driver-booster system-cleaner
                          mackeeper mycleanpc pc-mate advanced-system-care
                          wise-care adwcleaner junk-tool}
        set desc_patterns {optimize.*system clean.*registry boost.*performance
                           driver.*update remote.*support}
        set lname [string tolower $name]
        set ldesc [string tolower $desc]
        foreach pat $pkg_patterns {
            if {[string match "*$pat*" $lname]} { return 1 }
        }
        foreach pat $desc_patterns {
            if {[regexp $pat $ldesc]} { return 1 }
        }
        return 0
    }

    proc scan_desktop_files {} {
        set dirs {/usr/share/applications ~/.local/share/applications}
        set home [file normalize ~]
        foreach dir $dirs {
            # Expand ~
            set d [string map [list "~" $home] $dir]
            if {![file exists $d]} continue
            foreach entry [glob -nocomplain -directory $d *.desktop] {
                set data [read_proc_file $entry]
                set name ""
                set exec ""
                foreach line [split $data \n] {
                    if {[regexp {^Name=(.+)$} $line -> n]} { set name $n }
                    if {[regexp {^Exec=(.+)$} $line -> e]} { set exec $e }
                }
                if {[is_pup_desktop $name $exec]} {
                    roguescan::finding::add scam \
                        pup_desktop MEDIUM 0 "" \
                        "Potentially unwanted .desktop file" "$name -> $exec ($entry)"
                }
            }
        }
    }

    proc is_pup_desktop {name exec} {
        set lname [string tolower $name]
        set lexec [string tolower $exec]
        set patterns {teamviewer anydesk logmein remote-desktop
                      pc-optimizer system-cleaner driver-booster
                      advanced-system-care wise-care mycleanpc}
        foreach pat $patterns {
            if {[string match "*$pat*" $lname]} { return 1 }
            if {[string match "*$pat*" $lexec]} { return 1 }
        }
        return 0
    }
}
