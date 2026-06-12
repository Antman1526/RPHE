"""Configuration loading.

Non-secret settings live in a YAML file (default: ~/.config/rphe/config.yaml on
macOS/Linux, %APPDATA%\\rphe\\config.yaml on Windows). Secrets are NEVER stored
here — they live in the OS keystore (see secrets.py). The config only references
*which* keystore entries to read.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - surfaced at runtime with a clear msg
    yaml = None


def default_config_dir() -> Path:
    """Cross-platform config directory."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA", str(Path.home()))
        return Path(base) / "rphe"
    return Path.home() / ".config" / "rphe"


def default_data_dir() -> Path:
    """Where the audit log and CSV exports go (non-secret artifacts)."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", str(Path.home()))
        return Path(base) / "rphe"
    return Path.home() / ".local" / "share" / "rphe"


@dataclass
class EmailAccount:
    label: str                      # friendly name, e.g. "personal-gmail"
    provider: str                   # "gmail" | "graph" | "imap"
    address: str
    imap_host: str = ""             # only for provider == "imap"
    imap_port: int = 993
    folders: list = field(default_factory=lambda: ["INBOX"])
    lookback_days: int = 30


@dataclass
class PasswordPolicy:
    length: int = 24
    use_upper: bool = True
    use_lower: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    passphrase_mode: bool = False
    passphrase_words: int = 6
    passphrase_separator: str = "-"
    avoid_ambiguous: bool = True    # drop O/0, l/1/I, etc.


@dataclass
class Config:
    accounts: list = field(default_factory=list)
    policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    bitwarden_folder: str = "RPHE-Rotated"
    nordpass_export_path: str = ""  # defaults into data_dir if blank
    automate_resets: bool = False   # default OFF: guided mode is safer
    data_dir: str = ""

    @property
    def resolved_data_dir(self) -> Path:
        return Path(self.data_dir) if self.data_dir else default_data_dir()

    @property
    def resolved_nordpass_export(self) -> Path:
        if self.nordpass_export_path:
            return Path(self.nordpass_export_path)
        return self.resolved_data_dir / "nordpass_import.csv"


def load_config(path: Path | None = None) -> Config:
    """Load YAML config, falling back to sane defaults if absent."""
    if yaml is None:
        raise RuntimeError("PyYAML is required. Run: pip install -r requirements.txt")

    cfg_path = path or (default_config_dir() / "config.yaml")
    if not cfg_path.exists():
        # First run: return defaults so `rphe init` can write a template.
        return Config()

    with cfg_path.open("r", encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}

    policy = PasswordPolicy(**(raw.get("policy") or {}))
    accounts = [EmailAccount(**a) for a in (raw.get("accounts") or [])]
    return Config(
        accounts=accounts,
        policy=policy,
        bitwarden_folder=raw.get("bitwarden_folder", "RPHE-Rotated"),
        nordpass_export_path=raw.get("nordpass_export_path", ""),
        automate_resets=bool(raw.get("automate_resets", False)),
        data_dir=raw.get("data_dir", ""),
    )
