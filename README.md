# EXAMINER

**Advanced Reconnaissance Tool** - Version 1.0
**Developed by: Ahmed Ekramy**

EXAMINER is a cross-platform (Windows / Kali Linux / other Linux) command-line framework for
**authorized** reconnaissance and information gathering. It combines its own Python logic with
external tools such as Nmap, organized into independent modules with structured results,
persistent configuration and reporting.

> ## Legal warning
> Use EXAMINER **only** on systems you own or have **explicit written permission** to test.
> Unauthorized scanning may be illegal. The author accepts no liability for misuse.
> EXAMINER contains no exploitation, brute-forcing, credential theft, persistence or evasion features.

## Development status

The project is built in stages. Menu entries for unfinished modules say
"not implemented yet" - the tool never fabricates results.

| Stage | Content | Status |
|-------|---------|--------|
| 1 | Foundation: architecture, banner, menu, validation, config, logging, dependency detection | **Done** |
| 2 | Port scanning (Nmap + native engine): Quick / Full / UDP / Custom | **Done** |
| 3 | DNS, WHOIS, subdomains, IP info | Planned |
| 4 | HTTP headers, SSL/TLS, technology detection | Planned |
| 3 | DNS, WHOIS, IP/host, HTTP headers, TLS summary | **Done** |
| 6 | Testing and optimization | Planned |

## Main menu

```
[1] Port Scanning          -> Quick TCP / Full TCP / UDP / Custom / Scan Options
[2] Information Gathering  -> DNS, WHOIS, IP/host, HTTP headers, TLS certificate
[3] Vulnerability Assessment
[4] Network Discovery
[0] Exit
```

## Port scanning notes

- **Engines:** `auto` (default) uses Nmap when available, otherwise the built-in native engine;
  `nmap` fails with a clear message if Nmap is missing (no silent fallback); `native` never uses Nmap.
- **Quick scan** = ~108 common TCP ports. **UDP scan** = ~26 common UDP ports. **Custom** = your ports + protocol.
- **Port states:** open, closed, filtered, unknown (UDP "no response" is reported as unknown).
- **Service/version detection:** Nmap `-sV` (accurate) or native banner grabbing (basic).
- **OS fingerprinting / Nmap UDP** need Administrator (Windows) or root (Linux) and Nmap.
- Nmap runs with `-Pn` (no ping check), so hosts that block ping are still scanned.
- Every active scan asks you to type `yes` to confirm you are authorized. `Ctrl+C` cancels a running scan.

## Requirements

- Python **3.8+**
- Python packages: see `requirements.txt` (`rich`, `requests`, `dnspython`, `python-whois`)
- Optional: **Nmap** (EXAMINER detects it and explains how to install it if missing)

## Installation

### Kali Linux / Debian / Ubuntu
```bash
sudo apt update && sudo apt install -y python3 python3-venv nmap git
git clone <your-repository-url> EXAMINER && cd EXAMINER
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e .
python3 main.py
# After editable installation, the command below works from any directory:
examiner
```
(Kali uses a protected system Python - a virtualenv avoids the "externally-managed-environment" error.)
Scans that need raw sockets (UDP, SYN, OS detection) require `sudo`; with a virtualenv run
`sudo .venv/bin/python main.py`.

### Windows (PowerShell)
```powershell
winget install Python.Python.3.12
winget install Insecure.Nmap      # or download from https://nmap.org/download.html (includes Npcap)
git clone <your-repository-url> EXAMINER; cd EXAMINER
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e .
python main.py
# Or, from the project directory:
examiner.bat
```
Open PowerShell **as Administrator** for scans that need raw packets.
If script activation is blocked: `Set-ExecutionPolicy -Scope Process Bypass`.

## Usage

```bash
python main.py                # interactive menu
python main.py --check-deps   # print system + dependency status and exit
python main.py --no-color     # disable colors
python main.py --version
```

Run the tests:
```bash
python -m unittest discover -s tests -t . -v
```

## Project structure

```
EXAMINER/
|-- main.py                  entry point
|-- config/settings.json     persistent settings (auto-created, auto-repaired)
|-- core/                    banner, menu, engine, validator, dependency_manager, logger, config
|-- modules/                 port_scanner, information_gathering, vulnerability_assessment, network_discovery
|-- utils/                   colors, helpers, output (Rich with plain-text fallback)
`-- tests/                   automated tests
```

## Information-gathering safety notes

- Every information-gathering action asks for explicit scope confirmation.
- HTTP checks send one `HEAD` request and do not follow redirects automatically.
- TLS inspection reads the certificate from port 443; it does not downgrade or bypass certificate validation.
- Subdomain brute-force, exploitation, credential attacks, evasion, and persistence are intentionally not included.

## Known limitations

- Vulnerability assessment and network discovery are not implemented yet.
- Native UDP probing is inconclusive for silent services; use Nmap (with privileges) for accurate UDP results.
- Developed and tested on Linux; Windows was verified for the menu/UI only - please report any issue.
