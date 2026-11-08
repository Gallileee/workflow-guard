"""SARIF 2.1.0 output, the format GitHub code scanning reads.

One run, one ``reportingDescriptor`` per rule, one ``result`` per finding. Files that couldn't be
checked become ``toolExecutionNotifications``, so a broken workflow doesn't silently vanish from
the report.

GitHub-specific choices (see README, "Code scanning"):

- ``level`` comes from each finding's own severity (WG001 and WG005 vary per finding), so no
  ``security-severity`` is set on the rules: that number is per rule, not per result.
- ``partialFingerprints`` are computed here from rule, file and message, without the line
  number, so an alert keeps its identity when lines above it move.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import quote

from . import __version__
from .model import Finding, Severity
from .rules import RULES, Rule

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/Gallileee/workflow-guard"
FINGERPRINT_KEY = "workflowGuard/v1"

LEVELS = {Severity.LOW: "note", Severity.MEDIUM: "warning", Severity.HIGH: "error"}


def artifact_location(path: str) -> dict[str, str]:
    """A relative path stays relative to the checkout (``%SRCROOT%``), which is what code
    scanning needs to link a result to a file. Absolute paths become ``file:`` URIs."""
    posix = path.replace("\\", "/")
    # Built by hand: PurePath.as_uri() is deprecated since Python 3.14.
    if PureWindowsPath(path).is_absolute() and PureWindowsPath(path).drive:
        return {"uri": "file:///" + quote(PureWindowsPath(path).as_posix(), safe="/:")}
    if PurePosixPath(posix).is_absolute():
        return {"uri": "file://" + quote(posix, safe="/")}
    while posix.startswith("./"):
        posix = posix[2:]
    return {"uri": quote(posix, safe="/"), "uriBaseId": "%SRCROOT%"}


def _rule_descriptor(rule: Rule) -> dict[str, object]:
    return {
        "id": rule.id,
        "name": rule.name,
        "shortDescription": {"text": rule.summary},
        "fullDescription": {"text": rule.summary},
        "help": {"text": rule.help or rule.summary},
        "helpUri": f"{INFORMATION_URI}#rules",
        "properties": {"tags": ["security", "github-actions"]},
    }


def _fingerprints(findings: Sequence[Finding]) -> list[str]:
    """A stable id per finding. Identical (rule, file, message) triples are told apart by their
    order in the file, so two equal problems still get two alerts."""
    seen: Counter[tuple[str, str, str]] = Counter()
    result = []
    for f in findings:
        key = (f.rule_id, f.path, f.message)
        seen[key] += 1
        raw = "\0".join((*key, str(seen[key])))
        result.append(hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32])
    return result


def _result(finding: Finding, rule_index: int, fingerprint: str) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": LEVELS[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": artifact_location(finding.path),
                    "region": {"startLine": finding.line, "startColumn": finding.column},
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: fingerprint},
        "properties": {"severity": str(finding.severity)},
    }


def to_sarif(findings: Sequence[Finding], errors: Iterable[tuple[str, str]] = ()) -> dict[str, object]:
    """Build the SARIF log. ``errors`` are ``(path, message)`` for files that couldn't be read."""
    index = {rule.id: i for i, rule in enumerate(RULES)}
    notifications = [
        {
            "level": "error",
            "message": {"text": message},
            "locations": [{"physicalLocation": {"artifactLocation": artifact_location(path)}}],
        }
        for path, message in errors
    ]
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "workflow-guard",
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule_descriptor(r) for r in RULES],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": not notifications,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": [
                    _result(f, index[f.rule_id], fp)
                    for f, fp in zip(findings, _fingerprints(findings), strict=True)
                ],
            }
        ],
    }
