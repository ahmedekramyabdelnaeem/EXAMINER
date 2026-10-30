"""Detection of the operating system, privileges and external dependencies."""
from __future__ import annotations

import importlib.util
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from importlib import metadata as importlib_metadata
except ImportError:  # pragma: no cover
    importlib_metadata = None  # type: ignore[assignment]

PYTHON_PACKAGES = (
    # (import name, pip name, purpose, verify the distribution name too)
    ("rich", "rich", "Professional terminal interface", False),
    ("requests", "requests", "HTTP communication (web modules)", False),
    ("dns", "dnspython", "DNS queries (information gathering)", False),
    ("whois", "python-whois", "WHOIS lookups (information gathering)", True),
)

WINDOWS_NMAP_DIRS = (
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
)


@dataclass
class SystemInfo:
    os_name: str
    os_release: str
    distro: str
    distro_ids: List[str]
    machine: str
    python_version: str
    is_admin: bool

    @property
    def is_windows(self) -> bool:
        return self.os_name == "Windows"

    @property
    def is_kali(self) -> bool:
        return "kali" in self.distro_ids


@dataclass
class ComponentStatus:
    name: str
    kind: str  # "python" or "external"
    available: bool
    version: str = ""
    path: str = ""
    detail: str = ""
    install_hint: str = ""


def _read_os_release() -> Dict[str, str]:
    values: Dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as handle:
            for line in handle:
                key, sep, value = line.strip().partition("=")
                if sep:
                    values[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def detect_privileges() -> bool:
    """True when running as Administrator (Windows) or root (POSIX)."""
    try:
        if os.name == "nt":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def detect_system() -> SystemInfo:
    """Collect information about the host system."""
    release = _read_os_release()
    ids = [release.get("ID", "").lower()]
    ids += release.get("ID_LIKE", "").lower().split()
    return SystemInfo(
        os_name=platform.system() or "Unknown",
        os_release=platform.release(),
        distro=release.get("PRETTY_NAME", ""),
        distro_ids=[i for i in ids if i],
        machine=platform.machine(),
        python_version=platform.python_version(),
        is_admin=detect_privileges(),
    )


class DependencyManager:
    """Checks Python packages and external tools (Nmap) without ever raising."""

    def __init__(self, config) -> None:
        self.config = config
        self.system = detect_system()

    # ------------------------------------------------------------ hints
    def nmap_install_hint(self) -> str:
        system = self.system
        if system.is_windows:
            return ("Install from https://nmap.org/download.html (includes Npcap) or run "
                    "'winget install Insecure.Nmap', then restart the terminal "
                    "(or set the Nmap path in Settings).")
        if system.os_name == "Darwin":
            return "Run: brew install nmap"
        ids = set(system.distro_ids)
        if ids & {"kali", "debian", "ubuntu", "parrot", "linuxmint"}:
            return "Run: sudo apt update && sudo apt install nmap"
        if ids & {"fedora", "rhel", "centos"}:
            return "Run: sudo dnf install nmap"
        if ids & {"arch", "manjaro"}:
            return "Run: sudo pacman -S nmap"
        return "Install 'nmap' with your distribution's package manager, or see https://nmap.org/download.html"

    @staticmethod
    def python_install_hint(pip_name: str) -> str:
        return (f"python -m pip install {pip_name}  "
                "(or: pip install -r requirements.txt, preferably inside a virtualenv)")

    def privilege_note(self) -> str:
        if self.system.is_admin:
            return "Running with elevated privileges (raw-socket scans are available)."
        who = "Administrator" if self.system.is_windows else "root (sudo)"
        return (f"Not running as {who}. Some scans (UDP, SYN, OS detection) "
                "may be limited or fail without elevated privileges.")

    # ----------------------------------------------------------- checks
    def check_python_packages(self) -> List[ComponentStatus]:
        results: List[ComponentStatus] = []
        for module, pip_name, purpose, verify_dist in PYTHON_PACKAGES:
            try:
                found = importlib.util.find_spec(module) is not None
            except (ImportError, ValueError, AttributeError):
                found = False
            version = ""
            if importlib_metadata is not None:
                try:
                    version = importlib_metadata.version(pip_name)
                except Exception:
                    version = ""
            detail = purpose
            if found and verify_dist and not version:
                found = False
                detail = f"Module '{module}' exists but is not the '{pip_name}' package"
            results.append(ComponentStatus(
                name=pip_name, kind="python", available=found,
                version=version or ("unknown" if found else ""),
                detail=detail,
                install_hint="" if found else self.python_install_hint(pip_name)))
        return results

    def _locate_nmap(self) -> Tuple[Optional[str], str]:
        """Return (path or None, note)."""
        note = ""
        exe = "nmap.exe" if self.system.is_windows else "nmap"
        configured = str(self.config.get("nmap_path") or "").strip()
        if configured:
            candidate = Path(configured).expanduser()
            if candidate.is_dir():
                candidate = candidate / exe
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate), ""
            note = f"Configured Nmap path is not usable: {configured}. "
        found = shutil.which("nmap")
        if found:
            return found, (note + "Using Nmap from PATH.") if note else ""
        if self.system.is_windows:
            for directory in WINDOWS_NMAP_DIRS:
                candidate = Path(directory) / exe
                if candidate.is_file():
                    return str(candidate), note
        return None, note

    @staticmethod
    def _nmap_version(path: str) -> Optional[str]:
        """Run 'nmap --version'. Returns version text or None if it cannot run."""
        try:
            proc = subprocess.run([path, "--version"], capture_output=True,
                                  text=True, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return None
        if proc.returncode != 0:
            return None
        match = re.search(r"Nmap version\s+([\w.\-]+)", proc.stdout or "")
        return match.group(1) if match else "unknown"

    def check_nmap(self) -> ComponentStatus:
        path, note = self._locate_nmap()
        if path is None:
            return ComponentStatus(
                name="Nmap", kind="external", available=False,
                detail=(note + "Not found.").strip(),
                install_hint=self.nmap_install_hint())
        version = self._nmap_version(path)
        if version is None:
            return ComponentStatus(
                name="Nmap", kind="external", available=False, path=path,
                detail=(note + "Found but could not be executed.").strip(),
                install_hint=self.nmap_install_hint())
        return ComponentStatus(name="Nmap", kind="external", available=True,
                               version=version, path=path, detail=note)

    def check_all(self) -> List[ComponentStatus]:
        return self.check_python_packages() + [self.check_nmap()]
