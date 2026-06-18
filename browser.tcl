# browser.tcl - Browser extension scanner

namespace eval roguescan::browser {

    proc scan {} {
        scan_chrome_extensions
        scan_firefox_extensions
    }

    proc scan_chrome_extensions {} {
        set home [file normalize ~]
        if {$home eq ""} return

        set base_dirs {
            .config/google-chrome
            .config/chromium
            .config/BraveSoftware/Brave-Browser
        }

        foreach rel $base_dirs {
            set dir [file join $home $rel Default Extensions]
            if {![file exists $dir]} continue
            foreach ext_dir [glob -nocomplain -directory $dir *] {
                set manifest [file join $ext_dir * manifest.json]
                set files [glob -nocomplain $manifest]
                foreach mf $files {
                    scan_chrome_manifest $mf $dir
                }
            }
        }
    }

    proc scan_chrome_manifest {path browser} {
        if {![file exists $path]} return
        set f [open $path]
        set data [read $f]
        close $f

        # Simple checks (not a full JSON parser, but enough)
        set suspicious_perms [list]
        foreach perm {nativeMessaging debugger "<all_urls>" webRequest proxy clipboardRead} {
            if {[string match "*\"$perm\"*" $data]} {
                lappend suspicious_perms $perm
            }
        }
        if {[llength $suspicious_perms] > 0} {
            roguescan::finding::add browser \
                chrome_suspicious MEDIUM 0 "" \
                "Chrome extension with suspicious permissions" \
                "$path: [join $suspicious_perms ", "]"
        }
    }

    proc scan_firefox_extensions {} {
        set home [file normalize ~]
        if {$home eq ""} return

        set candidates {
            .mozilla/firefox/*.default/extensions.json
            .mozilla/firefox/*.default-release/extensions.json
        }

        foreach pattern [list .mozilla/firefox/*.default/extensions.json .mozilla/firefox/*.default-release/extensions.json] {
            set path [file join $home $pattern]
            set files [glob -nocomplain $path]
            foreach f $files {
                if {![file exists $f]} continue
                set data [read_proc_file $f]
                # Look for suspicious addon names
                foreach line [split $data \n] {
                    if {[regexp {adware|browser.?hijack|search.?tab|price.?match|coupon|deal} $line]} {
                        roguescan::finding::add browser \
                            firefox_suspicious MEDIUM 0 "" \
                            "Suspicious Firefox extension" $line
                    }
                }
            }
        }
    }
}
