"""Findings and severities."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Severity(IntEnum):
    """How bad a finding is. Ordered, so ``--fail-on medium`` can compare."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, text: str) -> Severity:
        try:
            return cls[text.strip().upper()]
        except KeyError:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {text!r} (use one of: {choices})") from None

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True, order=True)
class Finding:
    """One problem at one place in one workflow file. Lines and columns start at 1."""

    path: str
    line: int
    column: int
    rule_id: str
    severity: Severity
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "rule": self.rule_id,
            "severity": str(self.severity),
            "message": self.message,
        }
