# network.tcl - Network scanning and DGA detection

namespace eval roguescan::network {

    # Suspicious ports
    variable suspicious_ports {
        1080 socks 4444 metasploit 31337 backorifice
        50050 cobaltstrike 5555 6666 6667 6668
        6669 9001 tor 9050 tor 9150 tor
        7674 1234 1337 37337 4711
    }

    proc hex_to_ip {hex} {
        set bytes [list]
        for {set i 6} {$i >= 0} {incr i -2} {
            set byte [string range $hex $i [expr {$i+1}]]
            lappend bytes [expr 0x$byte]
        }
        return [join $bytes "."]
    }

    proc hex_to_port {hex} {
        return [expr 0x$hex]
    }

    proc is_rfc1918 {ip} {
        if {[regexp {^10\.} $ip]} { return 1 }
        if {[regexp {^172\.(1[6-9]|2\d|3[01])\.} $ip]} { return 1 }
        if {[regexp {^192\.168\.} $ip]} { return 1 }
        if {$ip eq "127.0.0.1"} { return 1 }
        if {$ip eq "0.0.0.0"} { return 1 }
        return 0
    }

    proc scan {} {
        scan_tcp
        scan_udp
    }

    proc scan_tcp {} {
        set data [read_proc_file "/proc/net/tcp"]
        if {$data eq ""} return

        set found_listeners 0
        set found_conns 0

        foreach line [split $data \n] {
            if {![regexp {^\s*\d+:\s+([0-9A-F]+):([0-9A-F]+)\s+([0-9A-F]+):([0-9A-F]+)\s+([0-9A-F]+)} $line -> laddr lport raddr rport state]} continue

            set lip [hex_to_ip $laddr]
            set lp [hex_to_port $lport]
            set rip [hex_to_ip $raddr]
            set rp [hex_to_port $rport]

            # Listening socket
            if {$state eq "0A"} {
                if {$lp > 1024 && $lp != 1080 && ![is_common_port $lp]} {
                    incr found_listeners
                    if {$found_listeners <= 20} {
                        roguescan::finding::add network \
                            nonstandard_listener MEDIUM 0 "" \
                            "Non-standard listening port $lp ($lip)" ""
                    }
                }
                continue
            }

            # Established connection
            if {$state eq "01"} {
                incr found_conns

                # Suspicious remote port
                if {[is_suspicious_port $rp]} {
                    roguescan::finding::add network \
                        suspicious_port HIGH 0 "" \
                        "Connection to suspicious port $rp ($rip)" ""
                }

                # External connection
                if {![is_rfc1918 $rip] && $rip ne "127.0.0.1"} {
                    roguescan::finding::add network \
                        external_conn INFO 0 "" \
                        "External connection to $rip:$rp" ""
                }
            }
        }
    }

    proc scan_udp {} {
        set data [read_proc_file "/proc/net/udp"]
        if {$data eq ""} return

        foreach line [split $data \n] {
            if {![regexp {^\s*\d+:\s+([0-9A-F]+):([0-9A-F]+)} $line -> laddr lport]} continue
            set lip [hex_to_ip $laddr]
            set lp [hex_to_port $lport]
            if {$lp > 1024 && ![is_common_port $lp]} {
                roguescan::finding::add network \
                    udp_listener MEDIUM 0 "" \
                    "UDP listening on non-standard port $lp" ""
            }
        }
    }

    proc is_suspicious_port {port} {
        variable suspicious_ports
        foreach {p desc} $suspicious_ports {
            if {$port == $p} { return 1 }
        }
        return 0
    }

    proc is_common_port {port} {
        set common {80 443 22 21 25 53 110 143 993 995 3306 5432 6379 8080 8443}
        return [expr {$port in $common}]
    }

    # --- DGA Detection ---
    variable dga_findings [list]

    proc scan_dga {} {
        variable dga_findings
        set dga_findings [list]
        set count 0

        foreach pid [get_all_pids] {
            if {[is_kernel_thread $pid]} continue
            set cmdline [read_cmdline $pid]
            set name [get_process_name $pid]
            set domains [extract_domains $cmdline]
            foreach domain $domains {
                set score [dga_score $domain]
                if {$score > 0.75} {
                    roguescan::finding::add network \
                        dga_domain MEDIUM $pid $name \
                        "Possible DGA domain: $domain (score: [format %.2f $score])" $cmdline
                    incr count
                }
            }
        }
        if {$count > 0} {
            set ::roguescan::verbose 1
        }
    }

    # Extract domain-like patterns from text
    proc extract_domains {text} {
        set domains [list]
        # Match patterns like word.word or word.word.word
        foreach tok [split $text] {
            # Remove common punctuation
            regsub -all {[\[\](){}<>\"\':;,!?|=]} $tok "" clean
            # Domain-like: 2-4 dot-separated parts, each 2+ alnum chars, no protocol prefix
            if {[regexp {(?:^|[^a-zA-Z0-9.])([a-zA-Z][a-zA-Z0-9-]{1,63}\.[a-zA-Z][a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z][a-zA-Z0-9-]{1,63}){0,2})(?:$|[^a-zA-Z0-9.])} $clean -> domain]} {
                # Skip IP addresses
                if {![regexp {^\d+\.\d+\.\d+\.\d+$} $domain]} {
                    # Skip very common domains
                    if {![is_common_domain $domain]} {
                        set domain [string tolower $domain]
                        if {$domain ni $domains} {
                            lappend domains $domain
                        }
                    }
                }
            }
        }
        return $domains
    }

    proc is_common_domain {domain} {
        set common {google.com gmail.com yahoo.com outlook.com live.com
                    hotmail.com aol.com mail.ru yandex.com github.com
                    gitlab.com bitbucket.org stackoverflow.com
                    youtube.com facebook.com twitter.com x.com
                    reddit.com amazon.com wikipedia.org microsoft.com
                    apple.com cloudflare.com docker.com npmjs.com
                    rust-lang.org python.org perl.org tcl.tk
                    debian.org ubuntu.com archlinux.org
                    kernel.org gnome.org kde.org}
        foreach c $common {
            if {$domain eq $c} { return 1 }
        }
        return 0
    }

    # DGA score via character n-gram entropy (0-1 normalized)
    proc dga_score {domain} {
        # Remove TLD
        set body $domain
        set parts [split $domain "."]
        if {[llength $parts] > 2} {
            set body [lindex $parts 0]
            for {set i 1} {$i < [llength $parts] - 1} {incr i} {
                append body "." [lindex $parts $i]
            }
        }

        set n [string length $body]
        if {$n < 4} { return 0.0 }

        # Unigram entropy (normalized 0-1)
        set counts [dict create]
        foreach c [split $body ""] {
            dict incr counts $c
        }
        set unigram_entropy 0.0
        dict for {_ cnt} $counts {
            set p [expr {$cnt / double($n)}]
            set unigram_entropy [expr {$unigram_entropy - $p * log($p) / log(2)}]
        }
        set max_entropy [expr {log($n) / log(2)}]
        if {$max_entropy > 0} {
            set unigram_entropy [expr {$unigram_entropy / $max_entropy}]
        } else {
            set unigram_entropy 1.0
        }

        # Vowel ratio (DGA domains tend to have low vowel ratio)
        set vowels [regexp -all -inline {[aeiou]} $body]
        set vowel_ratio [expr {[llength $vowels] / double($n)}]
        # Normalize: 0.3-0.5 is normal, lower is suspicious
        set vowel_score [expr {1.0 - abs($vowel_ratio - 0.4) * 2.5}]
        if {$vowel_score < 0} { set vowel_score 0 }
        if {$vowel_score > 1} { set vowel_score 1 }

        # Entropy of bigrams (character pairs)
        set bigram_counts [dict create]
        for {set i 0} {$i < $n - 1} {incr i} {
            set bg [string range $body $i [expr {$i+1}]]
            dict incr bigram_counts $bg
        }
        set bigram_entropy 0.0
        set total_bigrams [expr {$n - 1}]
        if {$total_bigrams > 0} {
            dict for {_ cnt} $bigram_counts {
                set p [expr {$cnt / double($total_bigrams)}]
                set bigram_entropy [expr {$bigram_entropy - $p * log($p) / log(2)}]
            }
            set max_bigram [expr {log($total_bigrams) / log(2)}]
            if {$max_bigram > 0} {
                set bigram_entropy [expr {$bigram_entropy / $max_bigram}]
            } else {
                set bigram_entropy 1.0
            }
        }

        # Combined score (weighted)
        return [expr {$unigram_entropy * 0.4 + $vowel_score * 0.3 + $bigram_entropy * 0.3}]
    }
}
