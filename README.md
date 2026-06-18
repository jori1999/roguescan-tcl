# roguescan-tcl

Linux malware scanner built with Tcl, bash, AWK, and Perl. Same detection capabilities as the Rust version — no compile step, no heavy dependencies, runs on any box with Tcl 8.6.

## Quick start

```bash
./roguescan audit                       # full system audit
./roguescan scan /tmp                   # one-shot file scan
./roguescan daemon                      # monitoring daemon
sudo ./roguescan audit                  # root for fuller /proc access
```

## Dependencies

- **Tcl 8.6+** with `sqlite3` package (built-in on Debian/Ubuntu `tcl8.6-dev`, Arch `tcl`)
- **YARA** CLI (`apt install yara` / `pacman -S yara`) — optional, for YARA scanning
- **inotifywait** (`apt install inotify-tools`) — optional, for daemon file events
- **Perl 5** — optional, for faster entropy computation (falls back to pure Tcl)

No `cargo`, no `rustc`, no `gcc` needed. Works on any Linux.

## Architecture

```
roguescan-tcl/
├── roguescan              # Main Tcl CLI (chmod +x)
├── lib/
│   ├── core.tcl           # DB, findings, config, utilities
│   ├── process.tcl        # Process scanning, ancestry, fileless, injection
│   ├── network.tcl        # Network scanning, DGA detection
│   ├── rootkit.tcl        # LD_PRELOAD, memmap, hidden procs, kernel modules
│   ├── beacon.tcl         # TCP beacon detection (daemon)
│   ├── persistence.tcl    # systemd, cron, shell rc, SSH keys
│   ├── filesystem.tcl     # SUID, world-writable, foreign binaries
│   ├── browser.tcl        # Chrome/Firefox extension scanning
│   ├── scam.tcl           # PUP package/desktop detection
│   ├── yara.tcl           # YARA CLI integration
│   ├── signatures.tcl     # SHA256 + filename signature matching
│   ├── heuristics.tcl     # Reverse shell, webshell, obfuscation patterns
│   ├── entropy.tcl        # Shannon entropy / packed binary detection
│   ├── audit.tcl          # Audit orchestrator (9-step pipeline)
│   ├── scan.tcl           # File scan orchestrator
│   └── daemon.tcl         # Daemon orchestrator
├── helpers/
│   ├── entropy.pl         # Perl: fast block-level Shannon entropy
├── rules/
│   └── builtin.yar        # Built-in YARA rules
└── data/
    └── known_bad.json     # Signature database
```

## Scanners

| Scanner | Description |
|---------|-------------|
| **Process** | /proc introspection — suspicious names, paths, deleted exe, LD_PRELOAD |
| **Ancestry** | Parent-child chain analysis — browser→shell, shell→miner, sshd→unusual |
| **Fileless** | memfd, /dev/shm, anonymous rwx, missing executable |
| **Injection** | TracerPid detection — debugger on system processes |
| **Network** | /proc/net/tcp — suspicious ports, non-standard listeners, external connections |
| **DGA** | Character n-gram entropy on domain-like strings (0-1 score, >0.75 flagged) |
| **Rootkit** | LD_PRELOAD, rwx/memfd/deleted maps, PID/Tgid mismatch, kernel module comparison |
| **Persistence** | systemd, cron, shell rc, SSH keys, /etc/hosts, rc.local |
| **Filesystem** | SUID/SGID, world-writable, PE/Mach-O on Linux |
| **Beacon (daemon)** | /proc/net/tcp periodic sampling, interval-consistency analysis |
| **YARA** | File + process memory scanning via `yara` CLI |
| **Signatures** | SHA256 + filename matching against known_bad.json |
| **Heuristics** | Reverse shell, webshell, obfuscated code patterns |
| **Entropy** | Shannon entropy (block + file level), packed binary detection |
| **Browser** | Chrome/Firefox extension permission analysis |
| **Scam/PUP** | dpkg packages + .desktop files matching PUP indicators |

## Why Tcl?

Tcl is better suited than shell for this kind of tool:
- **Built-in SQLite** — `package require sqlite3`, no external database CLI
- **dict/array** — proper state management for beacon tracking, findings storage
- **`after` + `vwait`** — clean timer-driven event loop for daemon mode
- **`exec`** — call yara, perl, find, inotifywait as subprocesses
- **`file` + `read`** — natural /proc filesystem access
- **No IFS/quoting issues** — shell's biggest footgun, Tcl avoids entirely

## What's different from the Rust version

- **YARA process scanning** uses `yara rules /proc/$pid/mem` instead of `yr_rules_scan_proc` — functionally identical, ~2x slower
- **Daemon** uses `inotifywait` polling instead of fanotify + netlink — adequate for personal use
- **All findings ephemeral** during a run, stored to SQLite at end — simpler, no async
- **No static binary** — needs Tcl on the target system (but Tcl is ~5MB, trivially bundled)

## Example

```bash
# Audit
$ ./roguescan audit
=== roguescan audit ===
Starting full system audit...

  [1/9] Scanning processes...
  [2/9] Scanning network...
  [3/9] Scanning persistence mechanisms...
  [4/9] Scanning filesystem...
  [5/9] Scanning browser extensions...

=== Audit complete in 4s ===
Total findings: 128

CRITICAL 1 finding(s)
  PID 1234 (pipewire) [process/fileless_memfd] Process running from memfd (fileless)
HIGH     45 finding(s)
  PID 5678 (chrome) [process/fileless_anon_rwx] Anonymous rwx mappings (12 regions)
  ...
```

```bash
# List stored findings
$ ./roguescan list --severity CRITICAL
[CRITICAL] 2026-06-18T04:00:00 PID 1234 (pipewire) process/fileless_memfd Process running from memfd
```

```bash
# Summary report
$ ./roguescan summary
=== roguescan Summary ===
  CRITICAL  1
  HIGH     45
  MEDIUM    5
  LOW       5
  INFO     42
  ---
  TOTAL    128

Top finding types:
  CRITICAL  fileless_memfd (1)
  HIGH      fileless_anon_rwx (12)
  HIGH      rwx_mapping (10)
  INFO      external_conn (42)
```
