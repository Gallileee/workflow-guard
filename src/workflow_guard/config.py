"""The repository's settings: ``.github/workflow-guard.yml``.

One file for the command line, the pre-commit hook and the GitHub Action, instead of repeating
the same options in three places::

    ignore: [WG006]
    min-severity: low
    fail-on: medium
    script-inputs:
      - my-org/deploy:commands

It is looked up from the current directory upwards, stopping at the repository root (the folder
with ``.git``); ``--config FILE`` names another file and ``--no-config`` skips it. Options given
on the command line win over the file; ``ignore`` and ``script-inputs`` from both are combined.
Unknown keys and wrong values are errors, so a typo doesn't silently turn a setting off.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .model import Severity
from .rules import RULE_IDS
from .scripts import parse_script_input

NAMES = ("workflow-guard.yml", "workflow-guard.yaml")
KEYS = ("ignore", "min-severity", "fail-on", "script-inputs")


class ConfigError(Exception):
    """The settings file can't be read or has a wrong key or value."""


@dataclass(frozen=True)
class Config:
    path: Path | None = None
    ignore: frozenset[str] = frozenset()
    min_severity: Severity | None = None
    fail_on: Severity | None = None
    script_inputs: tuple[str, ...] = field(default=())


def find_config(start: Path) -> Path | None:
    """``.github/workflow-guard.yml`` (or ``.yaml``) in ``start`` or the nearest folder above it,
    up to and including the repository root."""
    for folder in (start.resolve(), *start.resolve().parents):
        for name in NAMES:
            candidate = folder / ".github" / name
            if candidate.is_file():
                return candidate
        if (folder / ".git").exists():
            return None
    return None


def _strings(value: object, key: str) -> list[str]:
    """A list of strings, or one string with items separated by commas or whitespace."""
    if isinstance(value, str):
        return [part for part in value.replace(",", " ").split() if part]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [item.strip() for item in value if item.strip()]
    raise ConfigError(f"'{key}' must be a list of strings")


def _severity(value: object, key: str) -> Severity:
    try:
        return Severity.parse(str(value))
    except ValueError as e:
        raise ConfigError(f"'{key}': {e}") from None


def parse_config(text: str, path: Path | None = None) -> Config:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ConfigError(f"not valid YAML: {e}") from None
    if data is None:
        return Config(path)
    if not isinstance(data, dict):
        raise ConfigError("expected a mapping of settings (ignore, min-severity, fail-on, script-inputs)")
    unknown = sorted(str(key) for key in data if key not in KEYS)
    if unknown:
        raise ConfigError(f"unknown setting(s): {', '.join(unknown)}; known: {', '.join(KEYS)}")

    ignore = frozenset(rule.upper() for rule in _strings(data.get("ignore", []), "ignore"))
    if bad := sorted(ignore - RULE_IDS):
        raise ConfigError(f"'ignore': unknown rule(s): {', '.join(bad)}")
    script_inputs = tuple(_strings(data.get("script-inputs", []), "script-inputs"))
    for spec in script_inputs:
        try:
            parse_script_input(spec)
        except ValueError as e:
            raise ConfigError(f"'script-inputs': {e}") from None
    return Config(
        path,
        ignore,
        _severity(data["min-severity"], "min-severity") if "min-severity" in data else None,
        _severity(data["fail-on"], "fail-on") if "fail-on" in data else None,
        script_inputs,
    )


def load_config(path: Path) -> Config:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"cannot read: {e}") from None
    return parse_config(text, path)
