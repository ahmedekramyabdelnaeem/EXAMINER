# EXAMINER
### Advanced Reconnaissance Tool – Version 1.0

**Developed by: Ahmed Ekramy**

EXAMINER is a cross-platform command-line tool built with Python 3, designed for authorized network reconnaissance, port scanning, and information gathering.

It combines custom Python functionality with external tools such as Nmap to identify open ports, analyze network services, and collect essential information about target systems.

The tool supports Windows, Kali Linux, and other compatible Linux distributions through a simple and interactive command-line interface.

## Main Features

- **Port Scanning:** Discover open TCP and UDP ports on target systems.
- **Open Port Detection:** Identify port states, including open, closed, filtered, and unknown.
- **Service Identification:** Detect services and gather basic version information.
- **Information Gathering:** Collect DNS, WHOIS, IP/host, HTTP header, and TLS certificate information.
- **Nmap Integration:** Use Nmap when available, with a built-in Python scanning engine as an alternative.
- **Cross-Platform Support:** Compatible with Windows and Linux.
- **Interactive CLI:** Navigate through organized menus and scanning options.
- **Structured Results:** Display and organize scanning and information-gathering results.

## Project Objective

EXAMINER aims to simplify network reconnaissance and port scanning by providing essential capabilities for discovering open ports and gathering information within a single, lightweight, and well-organized tool.

## Main Menu

```text
[1] Port Scanning
[2] Information Gathering
[0] Exit
```

## Technology Stack

- Python 3
- Nmap
- Rich
- Requests
- DNSPython
- Python-WHOIS

## Requirements

- Python 3.8 or later.
- Git.
- Optional: Nmap.
- Administrator/root privileges for certain advanced scanning operations.

## Installation

### Kali Linux / Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap git

git clone https://github.com/ahmedekramyabdelnaeem/EXAMINER.git

cd EXAMINER

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -e .

python main.py
```

### Windows

Install Python and Nmap first.

```powershell
git clone https://github.com/ahmedekramyabdelnaeem/EXAMINER.git

cd EXAMINER

python -m venv .venv

.venv\Scripts\Activate.ps1

python -m pip install -e .

python main.py
```

If PowerShell blocks script activation, run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

## Usage

Start the interactive interface:

```bash
python main.py
```

Check system dependencies:

```bash
python main.py --check-deps
```

Disable colored output:

```bash
python main.py --no-color
```

Display the version:

```bash
python main.py --version
```

## Project Structure

```text
EXAMINER/
│
├── main.py
├── examiner
├── examiner.bat
├── README.md
├── requirements.txt
├── pyproject.toml
│
├── config/
│   └── settings.json
│
├── core/
│   ├── banner.py
│   ├── config.py
│   ├── constants.py
│   ├── dependency_manager.py
│   ├── engine.py
│   ├── logger.py
│   ├── menu.py
│   └── validator.py
│
├── modules/
│   ├── information_gathering/
│   └── port_scanner/
│
├── utils/
│
└── tests/
```

## Legal Disclaimer

EXAMINER is developed for educational purposes, authorized penetration testing, and legitimate network security assessments.

Users must obtain explicit permission before scanning any network or system.

The developer is not responsible for unauthorized or illegal use of this tool.

## Developer

**Ahmed Ekramy**

## EXAMINER – Discover. Scan. Analyze.