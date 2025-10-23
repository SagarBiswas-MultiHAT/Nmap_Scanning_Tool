# Nmap Scanning Tool (main_v1.7.py)

Interactive wrapper around Nmap that makes common scans quick to run and easy to read. It prints a banner, asks for a target and ports, lets you choose a scan type (SYN, Aggressive, OS Detect, NSE vuln checks, and more), and can optionally show only the lines that contain open ports.

> Note: This tool executes the local `nmap` binary. You must have Nmap installed and available on your PATH.
### A). -------------------------------------------------------------------------------------------------------------------
![Nmap Scanning Tool](https://imgur.com/GHvPuD6.jpg)
<br>

### B). -------------------------------------------------------------------------------------------------------------------
![Nmap Scanning Tool](https://imgur.com/zejtHl3.jpg)

## Features

- Target + ports prompt (single port, range like `1-1000`, or leave blank for all `1-65535`)
- 12 ready-to-use scan profiles:
  1. SYN (stealth) scan `-sS` + OS detect `-O`
  2. Aggressive scan `-A` (OS + services + scripts + traceroute)
  3. Service/version detection `-sV`
  4. NSE vulnerability scan `--script=vuln`
  5. Heartbleed test `--script=ssl-heartbleed`
  6. HTTP security headers `--script=http-security-headers`
  7. HTTP SQL injection test `--script=http-sql-injection`
  8. SMB vulnerability scan `--script=smb-vuln*`
  9. SSL/TLS ciphers `--script=ssl-enum-ciphers`
  10. Service discovery (default NSE set) `--script=default`
  11. OS detection only `-O`
  12. Custom: you type additional Nmap args (e.g., `-sU -T4 --top-ports 200`)
- Optional output filter: show only lines that contain the word "open"
- Helpful checks and messages:
  - Warns if you’re not running with Administrator/root when some scans may need it
  - Verifies that Nmap is installed and in PATH, with OS-specific tips

## Requirements

- Python 3.8+ (tested with Python 3)
- Nmap installed and on PATH
  - Windows: https://nmap.org/download.html (use the official installer, then restart the terminal)
  - Linux (Debian/Ubuntu): `sudo apt install nmap`
  - Linux (RHEL/CentOS): `sudo yum install nmap`
  - macOS (Homebrew): `brew install nmap`
- Python packages: `pyfiglet`, `termcolor`

## Quick start

The script you run is `main_v1.7.py` in this folder.

### Windows (PowerShell)

Optional, but recommended: create and use a virtual environment.

```powershell
# Optional: allow the current PowerShell session to run the venv activation script
# (only needed if you see an execution policy error)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# Create and activate a virtual environment in .venv
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Upgrade pip and install dependencies
python -m pip install --upgrade pip
python -m pip install pyfiglet termcolor

# Run
python .\main_v1.7.py
```

Alternatively, if you prefer a requirements file, create one with:

```powershell
# Optional alternative
python -m pip install -r requirements.txt
```

### Linux / macOS (Bash/Zsh)

```bash
python3 -m venv ~/myvenv
source ~/myvenv/bin/activate
python -m pip install --upgrade pip
python -m pip install pyfiglet termcolor
python main_v1.7.py
```

## Usage flow

1. Enter target IP or hostname: `192.168.1.10` or `scanme.nmap.org`
2. Enter port or range (or leave blank for all `1-65535`)
3. Choose a scan type (1–12)
4. Choose whether to filter and show only lines containing "open"
5. Read the output; warnings (if any) are shown after the main results

### Examples

- Fast service/version scan on top 1000 ports:
  - Select scan type `3` (Service Version Detection)
- Broad vulnerability sweep:
  - Select scan type `4` (NSE vuln scripts)
- Custom UDP-focused scan:
  - Select `12` and enter: `-sU --top-ports 200 -T4`

## Privileges and permissions

- SYN scans (`-sS`) and OS detection (`-O`) often require elevated privileges
  - Windows: run PowerShell as Administrator
  - Linux/macOS: run with `sudo` if the script warns about privileges
- If a scan fails or shows very few results, try rerunning with elevation

## Troubleshooting

- "Nmap executable was not found"
  - Install Nmap, then close and reopen your terminal
  - Confirm `nmap` runs from your terminal: `nmap -V`
- "Permission denied" or missing SYN/OS results
  - Run the terminal as Administrator (Windows) or use `sudo` (Linux/macOS)
- No output / only warnings
  - Check firewall rules on the target and your network
  - Try different timing options (e.g., `-T3` or `-T4`) via custom scan

## Safety and ethics

Only scan systems you own or are explicitly authorized to test. Unauthorized scanning may be illegal or violate terms of service.

## File map

- `main_v1.7.py` – interactive Nmap wrapper with multiple scan profiles
- `main_v1.6.py` – previous iteration; deprecated in favor of v1.7, kept for reference
- `main_v1.1.py` – earlier, simpler version (basic SYN/TCP scan)

## Credits

- Created by Sagar Biswas
- Uses: [Nmap](https://nmap.org/), [pyfiglet](https://pypi.org/project/pyfiglet/), [termcolor](https://pypi.org/project/termcolor/)
