"""Persistent settings stored in config/settings.json."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List

from .validator import ValidationError, validate_timeout

SPEEDS = ("slow", "normal", "fast")
ENGINES = ("auto", "nmap", "native")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

DEFAULTS: Dict[str, Any] = {
    "default_timeout": 3.0,
    "default_speed": "normal",
    "preferred_engine": "auto",
    "nmap_path": "",
    "output_dir": "",
    "colors_enabled": True,
    "logging_enabled": True,
    "log_level": "INFO",
}


class ConfigError(ValueError):
    """Raised when a setting value is invalid."""


def _v_timeout(value: Any) -> float:
    if isinstance(value, bool):
        raise ConfigError("Timeout must be a number.")
    try:
        return validate_timeout(value)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from None


def _v_choice(choices, upper: bool = False) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if not isinstance(value, str):
            raise ConfigError(f"Must be one of: {', '.join(choices)}.")
        text = value.strip().upper() if upper else value.strip().lower()
        if text not in choices:
            raise ConfigError(f"Must be one of: {', '.join(choices)}.")
        return text
    return check


def _v_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "yes", "on", "1"):
            return True
        if text in ("false", "no", "off", "0"):
            return False
    raise ConfigError("Must be true or false.")


def _v_str(value: Any) -> str:
    if not isinstance(value, str):
        raise ConfigError("Must be text.")
    return value.strip()


VALIDATORS: Dict[str, Callable[[Any], Any]] = {
    "default_timeout": _v_timeout,
    "default_speed": _v_choice(SPEEDS),
    "preferred_engine": _v_choice(ENGINES),
    "nmap_path": _v_str,
    "output_dir": _v_str,
    "colors_enabled": _v_bool,
    "logging_enabled": _v_bool,
    "log_level": _v_choice(LOG_LEVELS, upper=True),
}


class ConfigManager:
    """Loads, validates and saves user settings."""

    def __init__(self, path: Path, project_root: Path) -> None:
        self.path = Path(path)
        self.project_root = Path(project_root)
        self.data: Dict[str, Any] = dict(DEFAULTS)
        self.last_error: str = ""

    # ----------------------------------------------------------- access
    def get(self, key: str) -> Any:
        return self.data[key]

    def as_dict(self) -> Dict[str, Any]:
        return dict(self.data)

    def set(self, key: str, value: Any) -> None:
        """Validate and set a value in memory (call ``save`` to persist)."""
        if key not in VALIDATORS:
            raise ConfigError(f"Unknown setting '{key}'.")
        self.data[key] = VALIDATORS[key](value)

    def reset(self) -> None:
        self.data = dict(DEFAULTS)

    # ------------------------------------------------------ persistence
    def load(self) -> List[str]:
        """Load settings from disk. Returns a list of human-readable warnings."""
        warnings: List[str] = []
        self.data = dict(DEFAULTS)
        if not self.path.exists():
            if not self.save():
                warnings.append(f"Could not create settings file: {self.last_error}")
            return warnings
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8-sig"))
            if not isinstance(raw, dict):
                raise ValueError("top-level JSON value must be an object")
        except (OSError, ValueError) as exc:
            warnings.append(f"Settings file is unreadable ({exc}); defaults were restored.")
            self._backup_corrupt_file()
            if not self.save():
                warnings.append(f"Could not rewrite settings file: {self.last_error}")
            return warnings
        for key, value in raw.items():
            if key not in VALIDATORS:
                warnings.append(f"Ignoring unknown setting '{key}'.")
                continue
            try:
                self.data[key] = VALIDATORS[key](value)
            except ConfigError as exc:
                warnings.append(f"Invalid value for '{key}' ({value!r}): {exc} Using default.")
        return warnings

    def _backup_corrupt_file(self) -> None:
        try:
            os.replace(self.path, self.path.with_name(self.path.name + ".bak"))
        except OSError:
            pass

    def save(self) -> bool:
        """Atomically write settings to disk. Returns False on failure."""
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(self.data, indent=4) + "\n", encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            self.last_error = str(exc)
            try:
                tmp.unlink()
            except OSError:
                pass
            return False
        self.last_error = ""
        return True

    # ------------------------------------------------------------ paths
    @property
    def output_dir(self) -> Path:
        configured = self.data["output_dir"]
        if configured:
            return Path(configured).expanduser()
        return self.project_root

    def subdir(self, name: str) -> Path:
        """Return (and create) a sub-directory of the output directory.

        Falls back to ``~/.examiner/<name>`` if the output directory is not writable.
        """
        primary = self.output_dir / name
        try:
            primary.mkdir(parents=True, exist_ok=True)
            return primary
        except OSError:
            fallback = Path.home() / ".examiner" / name
            fallback.mkdir(parents=True, exist_ok=True)
            return fallback
