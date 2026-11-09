"""``--format github``: GitHub Actions workflow commands that show findings as annotations.

A line like ``::warning file=ci.yml,line=3,col=7,title=WG002::message`` printed in a workflow
step becomes an annotation on that line of the pull request's "Files changed" tab and in the
run summary. Unlike code scanning (``--format sarif``) it needs no upload and no
``security-events: write`` permission, and it works in private repositories without GitHub
Advanced Security.

Reference: https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from .model import Finding, Severity
from .rules import RULES

# GitHub has three annotation levels; "notice" is the quiet one.
COMMAND = {Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "notice"}

_RULE_NAMES = {rule.id: rule.name for rule in RULES}


def escape_data(text: str) -> str:
    """Escape the message part (after ``::``). Without this, a newline in a message would end
    the command and the rest of the line would be read as a new one: a workflow file name or
    YAML value could then inject commands such as ``::add-mask::`` into the log."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    """Escape a ``key=value`` property: like data, plus ``:`` and ``,``, which separate the
    properties from each other and from the message."""
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def _command(kind: str, message: str, **properties: object) -> str:
    props = ",".join(f"{key}={escape_property(str(value))}" for key, value in properties.items())
    return f"::{kind} {props}::{escape_data(message)}"


def annotation(finding: Finding) -> str:
    name = _RULE_NAMES.get(finding.rule_id, "")
    title = f"{finding.rule_id} {name}".strip()
    return _command(
        COMMAND[finding.severity],
        f"[{finding.severity}] {finding.message}",
        file=finding.path,
        line=finding.line,
        col=finding.column,
        title=title,
    )


def to_annotations(findings: Sequence[Finding], errors: Iterable[tuple[str, str]] = ()) -> str:
    """One workflow command per finding, then one ``::error`` per file that couldn't be read."""
    lines = [annotation(f) for f in findings]
    lines += [
        _command(
            "error", f"workflow-guard could not check this file: {message}", file=path, title="workflow-guard"
        )
        for path, message in errors
    ]
    return "\n".join(lines)
