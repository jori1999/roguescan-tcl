# entropy.tcl - Shannon entropy / packed binary detection

namespace eval roguescan::entropy {

    proc scan_file {path} {
        if {![file exists $path]} return
        if {![file isfile $path]} return
        set size [file size $path]
        if {$size > $::roguescan::max_file_size || $size == 0} return

        # Delegate to Perl helper for speed
        set helper [file join $::script_dir helpers entropy.pl]
        if {![file exists $helper]} {
            # Fallback to Tcl implementation
            return [scan_file_tcl $path]
        }

        catch {
            set result [exec perl $helper $path 2>/dev/null]
            set result [string trim $result]
            if {$result eq ""} return

            foreach line [split $result \n] {
                set line [string trim $line]
                if {$line eq ""} continue
                if {[regexp {block\s+(\d+):\s+entropy\s+([\d.]+)$} $line -> block entropy]} {
                    set e [expr {$entropy + 0.0}]
                    if {$e > 7.5} {
                        roguescan::finding::add entropy \
                            high_entropy MEDIUM 0 "" \
                            "High entropy block $block ($entropy) - possible packed/encrypted" $path
                    } elseif {$e > 7.0} {
                        roguescan::finding::add entropy \
                            elevated_entropy INFO 0 "" \
                            "Elevated entropy block $block ($entropy)" $path
                    }
                }
                if {[regexp {file\s+entropy:\s+([\d.]+)$} $line -> fent]} {
                    if {$fent > 7.5} {
                        roguescan::finding::add entropy \
                            packed_binary HIGH 0 "" \
                            "File-wide entropy $fent - likely packed binary" $path
                    }
                }
            }
        }
    }

    proc scan_directory {path} {
        set max_size $::roguescan::max_file_size
        # Scan ELF and PE binaries
        catch {
            set files [exec find $path -type f -size -${max_size}c \
                \( -name "*.elf" -o -name "*.exe" -o -name "*.dll" -o \
                   -name "*.bin" -o -name "*.so*" -o -name "*.o" \) \
                2>/dev/null]
            foreach f [split $files \n] {
                set f [string trim $f]
                if {$f ne ""} {
                    scan_file $f
                }
            }
        }
        # Also scan files identified as ELF by `file`
        catch {
            set files [exec find $path -type f -size -${max_size}c -exec file -m /dev/null {} \; 2>/dev/null | grep ELF | cut -d: -f1]
            foreach f [split $files \n] {
                set f [string trim $f]
                if {$f ne ""} {
                    scan_file $f
                }
            }
        }
    }

    # Pure Tcl fallback
    proc scan_file_tcl {path} {
        set f [open $path r]
        fconfigure $f -translation binary
        set data [read $f]
        close $f

        set n [string length $data]
        if {$n < 256} return

        # Compute overall file entropy
        set counts [dict create]
        binary scan $data c* bytes
        foreach b $bytes {
            dict incr counts $b
        }

        set file_entropy 0.0
        dict for {_ cnt} $counts {
            set p [expr {$cnt / double($n)}]
            if {$p > 0} {
                set file_entropy [expr {$file_entropy - $p * log($p) / log(2)}]
            }
        }

        if {$file_entropy > 7.5} {
            roguescan::finding::add entropy \
                packed_binary HIGH 0 "" \
                "File-wide entropy [format %.2f $file_entropy] - likely packed" $path
        }

        # Block-level
        set block_size 4096
        set num_blocks [expr {$n / $block_size}]
        for {set i 0} {$i < $num_blocks && $i < 256} {incr i} {
            set block [string range $data [expr {$i * $block_size}] [expr {($i + 1) * $block_size - 1}]]
            set bcounts [dict create]
            binary scan $block c* bbytes
            foreach b $bbytes {
                dict incr bcounts $b
            }
            set be 0.0
            set blen [string length $block]
            dict for {_ cnt} $bcounts {
                set p [expr {$cnt / double($blen)}]
                if {$p > 0} {
                    set be [expr {$be - $p * log($p) / log(2)}]
                }
            }
            if {$be > 7.5} {
                roguescan::finding::add entropy \
                    high_entropy MEDIUM 0 "" \
                    "Block $i entropy [format %.2f $be]" $path
            }
        }
    }
}
