"""Format-specific log processors - plain text and JSON."""

import json
from typing import Any, Dict, List, Optional, Tuple

from .engine import Redactor


class TextProcessor:
    """Process plain text log files.

    Processes the entire text at once (not line-by-line) so that multi-line
    patterns like PEM key blocks are detected correctly. Findings are mapped
    back to line numbers for reporting.
    """

    def __init__(self, redactor: Redactor):
        self.redactor = redactor

    def process(self, text: str) -> Tuple[str, List[dict]]:
        """Process the full text, redacting secrets across line boundaries.

        Returns:
            Tuple of (redacted_text, all_findings)
        """
        redacted, findings = self.redactor.redact_text(text)

        # Map positions back to line numbers
        lines = text.split("\n")
        line_starts = []
        pos = 0
        for line in lines:
            line_starts.append(pos)
            pos += len(line) + 1  # +1 for the newline

        for f in findings:
            f["line"] = self._pos_to_line(f["position"], line_starts)

        return redacted, findings

    def _pos_to_line(self, pos: int, line_starts: list) -> int:
        """Convert a character position to a 1-based line number."""
        for i in range(len(line_starts) - 1, -1, -1):
            if pos >= line_starts[i]:
                return i + 1
        return 1

    def process_line(self, line: str, line_num: int = 0) -> Tuple[str, List[dict]]:
        """Process a single line."""
        redacted, findings = self.redactor.redact_text(line)
        for f in findings:
            f["line"] = line_num
        return redacted, findings


class JsonProcessor:
    """Process structured JSON log files.

    Walks the JSON object tree and redacts string values while preserving
    the overall structure and data types. Uses key names for context-aware
    detection (e.g., "password" keys trigger PASSWORD pattern matching).
    """

    # Keys whose values should always be treated as secrets
    SENSITIVE_KEYS = {
        "password", "passwd", "pwd", "pass", "secret", "token",
        "auth_token", "access_token", "refresh_token", "private_key",
        "credentials", "api_key", "apikey", "api_secret", "app_key",
        "app_secret", "secret_key", "encryption_key", "signing_key",
        "auth_key", "db_url", "redis_url", "mongo_uri", "database_url",
        "connection_string", "account_key", "storage_key", "client_secret",
        "slack_token", "stripe_key", "github_token", "jwt",
    }

    def __init__(self, redactor: Redactor):
        self.redactor = redactor
        self._findings: List[dict] = []

    def process(self, text: str) -> Tuple[str, List[dict]]:
        """Process JSON log file.

        Each line is expected to be a separate JSON object (JSON Lines format),
        or the entire file is a single JSON array/object.

        Returns:
            Tuple of (redacted_text, all_findings)
        """
        self._findings = []
        text = text.strip()

        if not text:
            return text, []

        # Try JSON Lines first (most common for logs)
        lines = text.split("\n")
        if len(lines) > 1:
            try:
                return self._process_jsonl(lines)
            except (json.JSONDecodeError, ValueError):
                pass

        # Try as a single JSON document
        try:
            data = json.loads(text)
            redacted = self._redact_value(data, path="$")
            return json.dumps(redacted, indent=2), self._findings
        except json.JSONDecodeError:
            pass

        # Fall back to line-by-line text processing with JSON awareness
        return self._process_mixed(lines)

    def _process_jsonl(self, lines: List[str]) -> Tuple[str, List[dict]]:
        """Process JSON Lines format (one JSON object per line)."""
        redacted_lines = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                redacted_lines.append(line)
                continue
            try:
                data = json.loads(stripped)
                redacted_obj = self._redact_value(data, path=f"$[{line_num}]")
                redacted_line = json.dumps(redacted_obj)
                redacted_lines.append(redacted_line)
            except json.JSONDecodeError:
                # Not valid JSON - process as text
                redacted, findings = self.redactor.redact_text(line)
                for f in findings:
                    f["line"] = line_num
                self._findings.extend(findings)
                redacted_lines.append(redacted)

        return "\n".join(redacted_lines), self._findings

    def _process_mixed(self, lines: List[str]) -> Tuple[str, List[dict]]:
        """Process mixed content - some JSON, some text."""
        redacted_lines = []
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    data = json.loads(stripped)
                    redacted_obj = self._redact_value(data, path=f"$[{line_num}]")
                    redacted_lines.append(json.dumps(redacted_obj))
                    continue
                except json.JSONDecodeError:
                    pass
            redacted, findings = self.redactor.redact_text(line)
            for f in findings:
                f["line"] = line_num
            self._findings.extend(findings)
            redacted_lines.append(redacted)

        return "\n".join(redacted_lines), self._findings

    def _redact_value(self, value: Any, path: str = "$", key_name: str = "") -> Any:
        """Recursively walk and redact values in a JSON structure.

        Args:
            value: The JSON value to process.
            path: JSON path for reporting.
            key_name: The key name of this value (for context-aware detection).
        """
        if isinstance(value, str):
            return self._redact_string(value, path, key_name)
        elif isinstance(value, dict):
            return {k: self._redact_value(v, f"{path}.{k}", k) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._redact_value(item, f"{path}[{i}]", key_name) for i, item in enumerate(value)]
        return value

    def _redact_string(self, value: str, path: str, key_name: str = "") -> str:
        """Redact a single string value.

        If the key name indicates a sensitive field (password, token, etc.),
        we prepend 'key=value' format so the PASSWORD pattern can match
        the value even though it appears standalone in JSON.
        """
        # For sensitive keys, simulate key=value format for pattern matching
        if key_name.lower() in self.SENSITIVE_KEYS:
            synthetic = f"{key_name}={value}"
            redacted, findings = self.redactor.redact_text(synthetic)
            # Extract just the redacted value (strip the key prefix)
            if redacted.startswith(key_name + "="):
                redacted = redacted[len(key_name) + 1:]
            for f in findings:
                f["json_path"] = path
                f["original_value"] = value
                f["key_name"] = key_name
            self._findings.extend(findings)
            return redacted

        # For non-sensitive keys, redact the value directly
        redacted, findings = self.redactor.redact_text(value)
        for f in findings:
            f["json_path"] = path
            f["original_value"] = value
        self._findings.extend(findings)
        return redacted


def detect_format(text: str) -> str:
    """Auto-detect log format.

    Returns: 'json', 'jsonl', or 'text'
    """
    text = text.strip()
    if not text:
        return "text"

    # Try parsing entire content as JSON
    try:
        json.loads(text)
        return "json"
    except json.JSONDecodeError:
        pass

    # Try first non-empty line as JSON
    for line in text.split("\n")[:5]:
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line)
            return "jsonl"
        except json.JSONDecodeError:
            break

    return "text"
