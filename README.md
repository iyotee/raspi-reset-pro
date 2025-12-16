# raspi-reset-pro

A professional, interactive Raspberry Pi reset utility implemented in Bash. This project provides a single-script toolkit to safely backup, clean, reset, and harden a Raspberry Pi system. The script is designed for advanced users and administrators who need to prepare devices for redistribution, cleanup, or full reset.

---

## Table of Contents

- [Features](#features) ✅
- [Quick Warning & Safety](#quick-warning--safety) ⚠️
- [Requirements & Compatibility](#requirements--compatibility) 🔧
- [Installation & Usage](#installation--usage) ▶️
- [Interactive Menu & Options](#interactive-menu--options) 🧭
- [Detailed Actions & Behavior](#detailed-actions--behavior) 🔍
- [Configuration & Customization](#configuration--customization) ⚙️
- [Logging & State](#logging--state) 📋
- [Troubleshooting & Common Issues](#troubleshooting--common-issues) 🛠️
- [Development & Contributing](#development--contributing) 🧑‍💻
- [Authors & License](#authors--license) ℹ️

---

## Features

- Interactive menu-driven reset workflow for Raspberry Pi devices
- Full-system backup (files, configs, package lists, services)
- Cache and log cleanup to free disk space
- User account cleanup (removes non-system users, preserves a configurable list)
- Package purging (autoremove and optional optional package list)
- Network and SSH reset (erase saved networks, regenerate host keys)
- Machine ID regeneration and Raspberry Pi package reinstallation
- Safe operation with confirmation prompts and a force mode to skip confirmations
- Dry-run mode that prints the commands that would run without executing them
- Logging and JSON state snapshots to track progress

---

## Quick Warning & Safety ⚠️

This script performs destructive operations (removing users, purging packages, regenerating keys, and a full system reset). ALWAYS create a backup before performing irreversible actions. The `full_reset` flow and commands like `userdel -r`, `apt purge`, and removals of `/etc` or network configs will permanently change or delete data.

If you are uncertain, use the interactive dry-run or enable verbose logging and review the logs before proceeding.

---

## Requirements & Compatibility 🔧

- Intended for Raspberry Pi systems (the script warns if /proc/cpuinfo does not show Raspberry Pi identifiers)
- Must be run as root (the script exits if not run with root privileges)
- Tested and written for Debian-based OSes such as Raspberry Pi OS. Uses APT, systemctl, journalctl, dpkg, tar, gzip, and standard GNU userland tools.
- Minimum recommended free space before running: 2 GB (configurable in the script via `MIN_FREE_SPACE_GB`)

Recommended (not strictly required but helpful): `jq` for better `show_system_info` output parsing.

---

## Installation & Usage ▶️

Clone or copy the repository onto your Raspberry Pi and run it as root:

```bash
# Clone repository
git clone https://github.com/iyotee/raspi-reset-pro.git
cd raspi-reset-pro

# Make the script executable and run as root
chmod +x raspi-reset.sh
sudo ./raspi-reset.sh
```

Notes:
- The script opens an interactive menu to select operations. Follow prompts carefully.
- To temporarily toggle features inside the menu, use the menu letters:
  - `d` - toggle Dry-Run (simulation) mode
  - `v` - toggle Verbose mode
  - `f` - toggle Force mode (skip confirmations)

If you prefer to change defaults permanently, edit variables at the top of `raspi-reset.sh` (for example, `DRY_RUN`, `VERBOSE`, `FORCE_MODE`, `MIN_FREE_SPACE_GB`, or `BACKUP_DIR` template).

---

## Interactive Menu & Options 🧭

The script presents a menu of operations:

1) Backup: saves `/home`, `/etc`, package list, enabled services, crontabs, SSH keys, network configs, and a system summary into a timestamped backup directory (e.g. `/backup/rpi-reset-YYYYMMDD-HHMMSS`). Checksums are generated for archive files.

2) Cache & Logs Cleanup: cleans APT cache, rotates and vacuums `journalctl` logs, deletes old log and archive files, expires temporary files, and removes user thumbnail/cache directories.

3) Purge Packages: runs `apt autoremove --purge` and optionally purges a list of common optional packages (Wolfram, LibreOffice, Scratch, Minecraft Pi, Sonic Pi).

4) Remove Users: removes non-system users (UID >= 1000) except users listed in `excluded_users` (default includes `pi`, `ubuntu`, `root`). The operation kills user processes and deletes home directories.

5) Reset Configs: resets hostname to `raspberrypi`, regenerates SSH host keys, optionally resets network configs (like `dhcpcd.conf`), reinstalls core Raspberry Pi packages, and regenerates the machine-id.

6) Reset Network: deletes saved Wi-Fi networks and NetworkManager connections, resets UFW firewall rules (if installed), and flushes ARP cache.

7) Full Reset: a multi-confirm irreversible flow that performs full backup, user removal, package purge, configuration reset, network reset, cache cleanup, then reboots the system.

8) Security Audit: prints checks such as default password detection for `pi`, SSH root login status, firewall state, and available upgrades.

9) Show System Info: displays hostname, OS, kernel, uptime, storage, memory, users, running services, and the last recorded operation from the state file (JSON).

0) Quit

---

## Detailed Actions & Behavior 🔍

Important variables (top of the script):

- `SCRIPT_VERSION` — Script version string
- `LOG_FILE` — Default: `/var/log/rpi-reset.log` (the script appends logs here)
- `BACKUP_DIR` — Default template: `/backup/rpi-reset-$(date +%Y%m%d-%H%M%S)`
- `LOCK_FILE` — Default: `/var/run/rpi-reset.lock` (prevents concurrent runs)
- `CONFIG_FILE` — Default: `/etc/rpi-reset.conf` (not extensively used by default)
- `STATE_FILE` — Default: `/var/lib/rpi-reset/state.json` (records operation, status, timestamp)
- `MIN_FREE_SPACE_GB` — Default min free space check

Logging and execution helpers:

- `log "message" "LEVEL"` writes a time-stamped entry to both console (when verbose) and the log file.
- `run "command"` executes commands; when `DRY_RUN` is true it logs the command instead of executing it; on failure it logs an error and returns non-zero so the calling flow can act accordingly.
- `confirm "Prompt"` asks the user to type `YES` to proceed unless `FORCE_MODE` is enabled in which case it auto-confirms.

State management:

- `save_state "operation" "status"` writes a short JSON object to the state file with operation, status (`in_progress`, `completed`), timestamp, human date, and script version.
- `get_last_operation()` prints the state file or `{}` if not present.

Backup behavior:

- Backs up packages list (`dpkg -l`), enabled services list, `/home` (excludes caches), `/etc`, crontabs, SSH keys, network configs when found, then generates checksums and prints backup size.

Cleanup behavior:

- Uses `apt clean`, `apt autoclean`, `journalctl --vacuum-*`, deletes old archived logs and temporary files.

User removal behavior:

- Enumerates `/etc/passwd` entries with UID >= 1000 and removes them (except excluded users). Kills their processes and runs `userdel -r`.

Package purge behavior:

- Runs `apt autoremove --purge -y` and optionally purges a hard-coded list of optional packages.

Configuration reset behavior:

- Resets `/etc/hostname` and corresponding `/etc/hosts` entry, optionally removes SSH host keys and reconfigures the `openssh-server` package, reinstalls Raspberry Pi packages, and regenerates machine id with `systemd-machine-id-setup`.

Network reset behavior:

- Deletes `/etc/wpa_supplicant/wpa_supplicant.conf` (if it exists), clears NetworkManager system connections, resets UFW if present, and clears ARP cache.

Full reset:

- Runs backup -> remove users -> purge packages -> reset configs -> reset network -> clear caches, records state and then reboots.

---

## Configuration & Customization ⚙️

You can customize behavior by editing constants at the top of the script:

- `MIN_FREE_SPACE_GB` — increase or decrease the required free space check
- `excluded_users` — add names you want preserved during `remove_users`
- `packages_to_remove` — modify which optional packages will be offered for removal
- `BACKUP_DIR` template — change backup location pattern
- `LOG_FILE` or `STATE_FILE` — change where logs and state are written

Advanced users can modify the `run()` function to add additional safety checks, or add a command-line argument parser to control options non-interactively.

---

## Logging & State 📋

- Main log: `/var/log/rpi-reset.log` (requires root to view)
- Lock file: `/var/run/rpi-reset.lock` prevents concurrent executions
- State file: `/var/lib/rpi-reset/state.json` holds the last recorded operation and status. Typical content:

```json
{
  "operation": "backup",
  "status": "completed",
  "timestamp": 1234567890,
  "date": "YYYY-MM-DD HH:MM:SS",
  "version": "3.0"
}
```

Note: `jq` is used in `show_system_info` to pretty-print state entries; install `jq` for convenience (`sudo apt install jq`).

---

## Troubleshooting & Common Issues 🛠️

- "Script must be run as root": re-run with `sudo` or as root user.
- Lock file present and active: check the PID in `/var/run/rpi-reset.lock` and ensure no other instance is running.
- Not a Raspberry Pi warning: the script will ask whether to continue if it detects a non-Pi CPU. Proceed only if you know the script is still appropriate.
- Insufficient disk space: increase available space or change `MIN_FREE_SPACE_GB` if you understand the risk.
- Missing commands: the script checks for `tar gzip apt systemctl journalctl dpkg` at startup; install missing packages or verify your PATH.
- `show_system_info` requires `jq` for nicer output; install if you need structured state parsing.

---

## Development & Contributing 🧑‍💻

- The script is a single-file utility. Contributions are welcome—open issues or PRs to add features, fix bugs, or improve safety checks and test coverage.
- If you add new interactive behavior, ensure the script remains safe by testing `DRY_RUN` and adding adequate confirmation steps for destructive operations.

---

## Authors & License ℹ️

- Author: SwissLabs (listed inside `raspi-reset.sh`)
- Repository owner: iyotee
- Version: 3.0 (script header)

Add a license file (for example MIT) if you plan to publish and accept external contributions.

---

If you want, I can also:
- Add a `--yes` CLI flag to enable non-interactive automation
- Add `--log-level` or structured JSON logging
- Add unit or integration tests for non-destructive parts

If you'd like any of that, tell me which feature you'd like next and I can prepare a patch. ✅
