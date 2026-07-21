"""Configuration loading and defaults."""

import json
import os
from pathlib import Path
from typing import Optional


DEFAULT_CONFIG = {
    "salt": "log-redactor-default-salt-change-me",
    "categories": {
        "api_keys": True,
        "tokens": True,
        "passwords": True,
        "connection_strings": True,
        "pii": True,
        "private_keys": True,
        "network": False,
        "high_entropy": True,
    },
    "high_entropy_threshold": 4.5,
    "custom_patterns": {},
}


def load_config(config_path: Optional[str] = None) -> dict:
    """Load configuration from file, merging with defaults.

    Resolution order:
    1. Explicit config_path argument
    2. LOG_REDACTOR_CONFIG environment variable
    3. ./config.json in current directory
    4. Built-in defaults

    Returns:
        Merged configuration dict.
    """
    config = dict(DEFAULT_CONFIG)
    config["categories"] = dict(DEFAULT_CONFIG["categories"])
    config["custom_patterns"] = dict(DEFAULT_CONFIG["custom_patterns"])

    # Determine config file path
    if config_path is None:
        config_path = os.environ.get("LOG_REDACTOR_CONFIG")
    if config_path is None:
        local_config = Path("config.json")
        if local_config.exists():
            config_path = str(local_config)

    if config_path is None:
        return config

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path, "r", encoding="utf-8") as f:
        user_config = json.load(f)

    # Merge top-level keys
    for key, value in user_config.items():
        if key == "categories" and isinstance(value, dict):
            config["categories"].update(value)
        elif key == "custom_patterns" and isinstance(value, dict):
            config["custom_patterns"].update(value)
        else:
            config[key] = value

    return config


def save_config(config: dict, path: str) -> None:
    """Save configuration to a JSON file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
