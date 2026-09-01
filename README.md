```
  ______    ______   __    __      __  _______    ______    ______
 /      \  /      \ |  \  |  \    /  \|       \  /      \  /      \
|  $$$$$$\|  $$$$$$\| $$   \$$\  /  $$| $$$$$$$\|  $$$$$$\|  $$$$$$\
| $$   \$$| $$__| $$| $$    \$$\/  $$ | $$__/ $$| $$___\$$| $$  | $$
| $$      | $$    $$| $$     \$$  $$  | $$    $$ \$$    \ | $$  | $$
| $$   __ | $$$$$$$$| $$      \$$$$   | $$$$$$$  _\$$$$$$\| $$  | $$
| $$__/  \| $$  | $$| $$_____ | $$    | $$      |  \__| $$| $$__/ $$
 \$$    $$| $$  | $$| $$     \| $$    | $$       \$$    $$ \$$    $$
  \$$$$$$  \$$   \$$ \$$$$$$$$ \$$     \$$        \$$$$$$   \$$$$$$
```

<p align="center">
  <strong>Professional-grade command-line malware scanner with real-time protection</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0-00B4D8?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/go-1.22+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-gray?style=flat-square" alt="Platform">
</p>

<p align="center">
  <em>Defend before you open.</em>
</p>

---

## What is Calypso?

Calypso is a multi-engine malware scanner built in Go. It runs six detection engines in parallel, scores threats on a 0-100 scale, and presents results through a rich terminal UI. It can quarantine infected files, monitor directories in real-time, and integrate with VirusTotal for cloud-based analysis.

---

## Features

| Feature | Description |
|---|---|
| **6 Scan Engines** | Hash lookup, file type validation, ClamAV, YARA rules, heuristic analysis, and VirusTotal cloud |
| **Interactive TUI** | Full terminal interface with menus, progress bars, live status, and styled verdicts |
| **Real-Time Watch** | Monitor any directory and auto-scan new files as they appear |
| **Auto-Quarantine** | Isolate threats by locking file permissions with a single flag |
| **Scan History** | Persistent log of every scan with lookup by ID |
| **Cloud Analysis** | Optional VirusTotal integration for full-file reputation checks |
| **YARA-Inspired Pattern Rules** | Ships with 8 built-in substring pattern rules covering PowerShell, macros, packers, shellcode, ransomware, network beacons, and credential dumping |
| **Scripting Mode** | `--no-tui` and `--json` flags for CI/CD pipelines and automation |
| **Health Checks** | `doctor` command verifies all dependencies are installed and configured |

---

## Quick Start

### Install

```bash
# Clone the repository
git clone https://github.com/SupRogueSoul/Calypso.git
cd Calypso

# Build
go build -o calypso .

# Or install to GOPATH
go install .
```

### First Scan

```bash
# Launch the interactive menu
calypso

# Scan a file directly
calypso scan C:\Downloads\suspicious.exe

# Scan a directory recursively
calypso scan C:\Downloads -r

# Scan with auto-quarantine
calypso scan C:\Downloads\suspicious.exe --quarantine
```

---

## Commands

### `calypso` (Interactive Menu)

Launches the full TUI main menu with navigation to all features. Use arrow keys or `j`/`k` to navigate, `enter` to select, `q` to quit.

```
  1. Scan        Scan a file or directory for threats
  2. Watch       Monitor a directory in real-time
  3. History     View past scan results
  4. Quarantine  Manage quarantined files
  5. Update      Refresh ClamAV + YARA signatures
  6. Doctor      Check system health & dependencies
  7. Config      View or edit configuration
```

### `calypso scan <path>`

Run the detection pipeline against a file or directory.

| Flag | Description | Default |
|---|---|---|
| `-r`, `--recursive` | Scan directories recursively | `false` |
| `--deep` | Enable VirusTotal cloud analysis | `false` |
| `--engines` | Comma-separated engine filter (`hash,file_type,clamav,yara,heuristic,cloud`) | all enabled |
| `--json` | Output results as JSON | `false` |
| `--quarantine` | Auto-quarantine detected threats | `false` |
| `--no-tui` | Disable interactive TUI | `false` |

### `calypso watch <dir>`

Monitor a directory for new files and scan them automatically.

| Flag | Description | Default |
|---|---|---|
| `--no-tui` | Disable interactive TUI | `false` |

### `calypso quarantine`

Manage quarantined files.

| Subcommand | Description |
|---|---|
| `quarantine list` | List all quarantined files |
| `quarantine restore <id>` | Restore a file to its original location |

### `calypso history`

View past scan results.

| Flag | Description | Default |
|---|---|---|
| `--show <id>` | Show full details for a specific scan | none |

### `calypso update`

Update ClamAV signatures (via `freshclam`) and install community YARA rules.

### `calypso doctor`

Check that all dependencies and configuration are in place.

| Check | What It Verifies |
|---|---|
| ClamAV | `clamscan` binary in PATH |
| Freshclam | `freshclam` binary in PATH |
| YARA Rules | `.yar` files exist under rules path |
| Config File | `~/.calypso/config.yaml` exists |
| Database | `~/.calypso/calypso.db` exists |
| Quarantine Dir | `~/.calypso/quarantine/` exists |
| VirusTotal Key | API key set in config |

### `calypso config`

View current configuration or open it in an editor (`$EDITOR` or `notepad`).

---

## Scan Engines

Calypso runs six engines in parallel. Each engine contributes to a weighted risk score.

| Engine | Weight | Requires | What It Detects |
|---|---|---|---|
| **Hash Lookup** | 0.35 | nothing | Known-bad files via local SHA-256 blocklist |
| **File Type Check** | 0.15 | nothing | MIME mismatches, executable disguises |
| **ClamAV** | 0.40 | `clamscan` in PATH | Signature-based malware detection |
| **YARA Rules** | 0.30 | nothing | Pattern matching across 8 built-in categories |
| **Heuristic Analysis** | 0.25 | nothing | Entropy anomalies, PE/ELF analysis, macro detection, archive bombs |
| **Cloud Analysis** | 0.50 | VirusTotal API key | Full-file upload for multi-engine reputation |

### YARA Rules

The "YARA Rules" engine is **YARA-inspired pattern matching**, not real YARA rule
compilation. It runs plain substring matching against 8 built-in rule categories
compiled directly into the binary — no `.yar` file parsing and no external YARA
binary needed.

| Rule | What It Catches | Threshold |
|---|---|---|
| `POWERSHELL_OBFUSCATED` | Base64 payloads, Invoke-Expression, encoded commands | 1+ hit |
| `MACRO_DROPPER` | Auto-executing Office macros with shell capabilities | 1+ hit |
| `PE_PACKER_SIGNS` | UPX, ASPack, MEW, FSG, PECompact packers | 1+ hit |
| `SUSPICIOUS_JS` | eval() obfuscation, ActiveX, WScript.Shell | 1+ hit |
| `RANSOMWARE_INDICATORS` | Onion links, BTC/Bitcoin keywords, encrypt/decrypt language | 5+ hits |
| `SHELLCODE_PATTERNS` | VirtualAlloc, WriteProcessMemory, CreateRemoteThread, NOP sleds | 1+ hit |
| `NETWORK_BEACON` | certutil, bitsadmin, mshta, suspicious cmd patterns | 1+ hit |
| `CREDENTIAL_ACCESS` | mimikatz, sekurlsa, lsass, SAM dump patterns | 1+ hit |

> **Note:** community `.yar` files placed in `~/.calypso/rules/community/` are
> detected (which enables the engine) but are **not** parsed or evaluated by the
> current substring matcher. If you need real YARA rule compilation, drop in a
> proper YARA engine; otherwise treat the community folder as opt-in presence.

### Heuristic Analysis

| Check | What It Does |
|---|---|
| **Entropy** | Shannon entropy detection (threshold 7.2, 8.05 for PDFs/Office) |
| **PE Imports** | Flags suspicious imports (VirtualAlloc, WriteProcessMemory, etc.) |
| **PE Packer** | Detects high-entropy packed sections |
| **ELF Symbols** | Flags ptrace, dlopen, mprotect, /bin/sh |
| **Office Macros** | Detects VBAProject with auto-execution triggers |
| **Archive Bombs** | ZIP files with >100x compression ratio |

---

## Scoring System

Each engine reports a status (clean, suspicious, or malicious) with a confidence value. The orchestrator computes a final score as a **weighted sum** across only the engines that actually ran for that scan:

1. **Badness per engine** — each engine's result is mapped to a 0–1 value:
   - `malicious` → `confidence` (a high-confidence malicious match = 1.0)
   - `suspicious` → `confidence × 0.5`
   - `clean` → `0`
2. **Weighted sum** — engine weights (see the table below) are **normalized to sum to 1 across the engines that actually ran**. Engines that were skipped or errored (e.g. ClamAV not installed, no API key) are excluded from the normalization, so they neither inflate nor deflate the score.
3. `Score` = `(Σ weightᵢ × badnessᵢ) / (Σ weightᵢ) × 100`, clamped to **0–100**.

Because weights are normalized to the engines present, a single high-confidence detection only reaches the maximum if it comes from a high-weight engine (or several lower-weight engines agree).

| Score | Verdict |
|---|---|
| 66 - 100 | **MALICIOUS** (red) |
| 21 - 65 | **SUSPICIOUS** (amber) |
| 0 - 20 | **CLEAN** (green) |

---

## Configuration

Calypso is configured via `~/.calypso/config.yaml`. It is auto-created on first run.

```yaml
virustotal_api_key: ""          # VirusTotal API key for cloud analysis
quarantine_path: ~/.calypso/quarantine
db_path: ~/.calypso/calypso.db
rules_path: ~/.calypso/rules
excluded_paths: []              # Paths to skip during directory scans
theme: default
deep_scan_confirmed: false

engines:
  hash: true
  file_type: true
  clamav: true
  yara: true
  heuristic: true
  cloud: false                  # Enable after setting virustotal_api_key
```

Override with a custom path:

```bash
calypso scan file.exe --config /path/to/config.yaml
```

---

## Quarantine System

When a file is quarantined:

1. The file is **copied** to `~/.calypso/quarantine/<timestamp>/`
2. The quarantine copy is locked to **0600** permissions
3. The original file's permissions are set to **0000** (fully locked)
4. A record is stored in the database

To restore:

```bash
calypso quarantine list          # find the ID
calypso quarantine restore <id>  # restore to original location
```

---

## Project Structure

```
calypso/
  main.go                          Entry point
  cmd/
    root.go                        Root command + interactive menu
    scan.go                        Scan command + engine pipeline
    watch.go                       Real-time directory monitoring
    update.go                      Signature updates
    doctor.go                      System health checks
    config.go                      Configuration viewer/editor
    history.go                     Scan history
    quarantine.go                  Quarantine management
  internal/
    config/config.go               YAML config loading via Viper
    engine/
      engine.go                    ScanEngine interface + types
      hash.go                      SHA-256 / MD5 blocklist lookup
      filetype.go                  Magic-byte file type validation
      clamav.go                    ClamAV signature scanning
      yara.go                      Built-in YARA pattern matching
      heuristic.go                 Static analysis + entropy
      cloud.go                     VirusTotal API integration
    orchestrator/orchestrator.go   Concurrent execution + scoring
    store/store.go                 JSON-file persistence
    ui/
      menu_model.go                Main menu TUI
      scan_model.go                Scan progress/results TUI
      watch_model.go               Watch mode live table TUI
      quarantine_model.go          Quarantine list/choice TUI
      theme.go                     Lipgloss color palette
```

---

## Requirements

| Requirement | Required | Purpose |
|---|---|---|
| **Go 1.22+** | Yes | Build from source |
| **ClamAV** | Optional | Signature-based detection (`clamscan`, `freshclam`) |
| **VirusTotal API Key** | Optional | Cloud analysis with `--deep` flag |

---

## Dependencies

| Library | Purpose |
|---|---|
| [Cobra](https://github.com/spf13/cobra) | CLI framework |
| [Viper](https://github.com/spf13/viper) | YAML configuration |
| [Bubble Tea](https://github.com/charmbracelet/bubbletea) | Terminal UI framework |
| [Bubbles](https://github.com/charmbracelet/bubbles) | TUI widgets |
| [Lipgloss](https://github.com/charmbracelet/lipgloss) | TUI styling |
| [fsnotify](https://github.com/fsnotify/fsnotify) | Filesystem event watching |
| [filetype](https://github.com/h2non/filetype) | Magic-byte file detection |

---

## Examples

### Scan a file with JSON output

```bash
calypso scan malware.exe --json --no-tui
```

### Scan only with YARA and heuristic engines

```bash
calypso scan suspicious.doc --engines yara,heuristic
```

### Watch a downloads folder

```bash
calypso watch C:\Users\You\Downloads
```

### Check system health

```bash
calypso doctor
```

### View scan history details

```bash
calypso history
calypso history --show 3
```

---

## License

MIT

---

<p align="center">
  Built with Go, Bubble Tea, and six detection engines working in parallel.
</p>
