# heuristics.tcl - File content pattern matching

namespace eval roguescan::heuristics {

    proc scan_file {path} {
        if {![file exists $path]} return
        if {[file size $path] > $::roguescan::max_file_size} return
        if {![file isfile $path]} return

        # Read first 50KB for pattern matching
        set f [open $path r]
        set data [read $f 51200]
        close $f

        # Reverse shell patterns
        foreach {pattern severity desc} {
            {>/dev/tcp/}     CRITICAL "Reverse shell (bash /dev/tcp)"
            {mkfifo}         HIGH     "Reverse shell (mkfifo)"
            {bash -i}        HIGH     "Reverse shell (bash -i)"
            {sh -i}          HIGH     "Reverse shell (sh -i)"
            {/dev/null.*/dev/tcp} CRITICAL "Reverse shell (stream redirection)"
        } {
            if {[string match *$pattern* $data]} {
                roguescan::finding::add heuristics \
                    reverse_shell $severity 0 "" \
                    "$desc detected" $path
                return
            }
        }

        # Webshell patterns
        foreach {pattern severity desc} {
            {system\$_}   HIGH "Webshell (system + request)"
            {eval\$_}     HIGH "Webshell (eval + request)"
            {assert\$_}   HIGH "Webshell (assert + request)"
            {shell_exec}  MEDIUM "Webshell (shell_exec)"
            {exec\$_}     HIGH "Webshell (exec + request)"
        } {
            if {[string match *$pattern* $data]} {
                roguescan::finding::add heuristics \
                    webshell $severity 0 "" \
                    "$desc detected" $path
                return
            }
        }

        # Obfuscation patterns
        set obfuscated 0
        if {[regexp -nocase {base64_decode.*(eval|exec|system|assert)} $data]} {
            incr obfuscated
        }
        if {[regexp -nocase {gzinflate.*(eval|exec|system)} $data]} {
            incr obfuscated
        }
        if {[regexp {\\x[0-9a-f]{2}[\\x]} $data]} {
            incr obfuscated
        }
        if {$obfuscated > 0} {
            roguescan::finding::add heuristics \
                obfuscated MEDIUM 0 "" \
                "Obfuscated code detected" $path
        }
    }

    proc scan_directory {path} {
        # Only scan text-like files
        set max_size $::roguescan::max_file_size
        catch {
            set files [exec find $path -type f -size -${max_size}c \
                -name "*.sh" -o -name "*.pl" -o -name "*.py" -o \
                -name "*.php" -o -name "*.rb" -o -name "*.tcl" -o \
                -name "*.bash" -o -name "*.zsh" 2>/dev/null]
            foreach f [split $files \n] {
                set f [string trim $f]
                if {$f ne ""} { scan_file $f }
            }
        }
        # Also check any file with shebang
        catch {
            set files [exec find $path -type f -size -${max_size}c -exec grep -l "^#!" {} \; 2>/dev/null]
            foreach f [split $files \n] {
                set f [string trim $f]
                if {$f ne ""} {
                    catch { scan_file $f }
                }
            }
        }
    }
}
