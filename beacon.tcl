# beacon.tcl - TCP beacon detection via periodic /proc/net/tcp sampling

namespace eval roguescan::beacon {

    # state: dict of beacon_key -> list of timestamps
    variable state [dict create]
    variable sample_interval 30000  ;# 30s
    variable prune_age 300000       ;# 5 min
    variable min_samples 3
    variable jitter_threshold 0.20

    proc reset {} {
        variable state [dict create]
    }

    proc get_connections {} {
        set data [read_proc_file "/proc/net/tcp"]
        if {$data eq ""} return

        set conns [list]
        foreach line [split $data \n] {
            if {![regexp {^\s*\d+:\s+([0-9A-F]+):([0-9A-F]+)\s+([0-9A-F]+):([0-9A-F]+)\s+01\s} $line -> _ _ raddr rport]} continue
            set rip [::roguescan::network::hex_to_ip $raddr]
            set rp [::roguescan::network::hex_to_port $rport]
            # Skip RFC1918
            if {[::roguescan::network::is_rfc1918 $rip]} continue
            lappend conns [list $rip $rp]
        }
        return $conns
    }

    proc sample {} {
        variable state
        variable prune_age

        set now [clock milliseconds]
        set conns [get_connections]

        # Update state with current connections
        set seen_keys [list]
        foreach conn $conns {
            set key [lindex $conn 0]:[lindex $conn 1]
            if {$key ni $seen_keys} {
                lappend seen_keys $key
            }
            if {![dict exists $state $key]} {
                dict set state $key [list]
            }
            dict with state $key {
                lappend state $key $now
            }
        }

        # Prune old entries
        set new_state [dict create]
        dict for {key timestamps} $state {
            set recent [list]
            foreach ts $timestamps {
                if {$now - $ts < $prune_age} {
                    lappend recent $ts
                }
            }
            if {[llength $recent] > 0} {
                dict set new_state $key $recent
            }
        }
        set state $new_state

        # Check for beacons
        dict for {key timestamps} $state {
            if {[llength $timestamps] < $min_samples} continue
            if {[is_beacon $timestamps]} {
                set dest [lindex [split $key ":"] 0]
                set port [lindex [split $key ":"] 1]
                roguescan::finding::add beacon \
                    tcp_beacon HIGH 0 "" \
                    "Beaconing to $dest:$port" \
                    "Samples: [llength $timestamps], interval ~[format %.1f [avg_interval $timestamps]]s"
                # Clear after detection to avoid repeats
                dict unset state $key
            }
        }
    }

    proc is_beacon {timestamps} {
        variable jitter_threshold
        set intervals [list]
        set sorted [lsort -real $timestamps]
        for {set i 1} {$i < [llength $sorted]} {incr i} {
            set diff [expr {[lindex $sorted $i] - [lindex $sorted [expr {$i-1}]]}]
            lappend intervals $diff
        }
        if {[llength $intervals] < 2} return 0
        set mean [avg $intervals]
        if {$mean == 0} return 0
        set max_dev 0
        foreach i $intervals {
            set dev [expr {abs($i - $mean) / $mean}]
            if {$dev > $max_dev} { set max_dev $dev }
        }
        return [expr {$max_dev < $jitter_threshold}]
    }

    proc avg {list} {
        if {[llength $list] == 0} return 0
        set sum 0
        foreach x $list { set sum [expr {$sum + $x}] }
        return [expr {$sum / double([llength $list])}]
    }

    proc avg_interval {timestamps} {
        set sorted [lsort -real $timestamps]
        if {[llength $sorted] < 2} return 0
        set intervals [list]
        for {set i 1} {$i < [llength $sorted]} {incr i} {
            lappend intervals [expr {([lindex $sorted $i] - [lindex $sorted [expr {$i-1}]]) / 1000.0}]
        }
        return [avg $intervals]
    }

    # Daemon loop: sample every 30s
    proc daemon_loop {} {
        variable sample_interval
        after $sample_interval ::roguescan::beacon::daemon_tick
        vwait forever
    }

    proc daemon_tick {} {
        variable sample_interval
        sample
        after $sample_interval ::roguescan::beacon::daemon_tick
    }
}
