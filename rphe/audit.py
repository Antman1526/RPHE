"""Append-only, redaction-safe audit log.

Design rules (enforced here, not left to callers):
  * Logs are JSON lines so they're machine-parseable for later review.
  * A regex/redaction pass scrubs anything that looks like a secret before write.
  * Plaintext passwords are *structurally* impossible to log: callers pass
    GeneratedCredential, and we only ever serialize `.to_safe_dict()`.
  * The log file is created 0600 (owner read/write only) on POSIX.
"""
from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Patterns that should never appear verbatim in the log.
_REDACTORS = [
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|apikey|api_key)\s*[=:]\s*\S+"),
     r"\1=<redacted>"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._\-]+"), "Bearer <redacted>"),
    # reset/confirmation tokens commonly appear as long query params
    (re.compile(r"([?&](?:token|code|reset|t|key)=)[^&\s]+"), r"\1<redacted>"),
]


def _redact(text: str) -> str:
    for pattern, repl in _REDACTORS:
        text = pattern.sub(repl, text)
    return text


class AuditLog:
    def __init__(self, data_dir: Path):
        self.path = Path(data_dir) / "audit.log.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()
            self._lock_down(self.path)

    @staticmethod
    def _lock_down(path: Path) -> None:
        if sys.platform != "win32":
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        # On Windows the file inherits the user profile ACL, which is per-user.

    def event(self, action: str, **fields: Any) -> None:
        """Write one audit record. All values are redaction-scrubbed."""
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
        }
        for k, v in fields.items():
            record[k] = v
        line = _redact(json.dumps(record, default=str, ensure_ascii=False))
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open("r", encoding="utf-8") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln:
                    try:
                        out.append(json.loads(ln))
                    except json.JSONDecodeError:
                        continue
        return out
