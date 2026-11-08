"""Command line: ``workflow-guard [PATH ...]``.

Exit codes: 0 = nothing at or above --fail-on, 1 = findings, 2 = a file couldn't be checked or
the arguments were wrong.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from . import __version__
from .fix import GitHubResolver, Resolver, pin_actions
from .model import Finding, Severity
from .rules import RULE_IDS, RULES, check
from .workflow import Workflow, WorkflowError

DEFAULT_DIR = Path(".github") / "workflows"


def find_workflows(paths: Sequence[Path]) -> list[Path]:
    """Files given directly, plus *.yml / *.yaml inside given directories (not recursive,
    like GitHub, which only reads .github/workflows itself)."""
    found: list[Path] = []
    for p in paths:
        if p.is_dir():
            found += sorted(f for f in p.iterdir() if f.suffix in (".yml", ".yaml") and f.is_file())
        else:
            found.append(p)
    return found


def _parse_ids(text: str) -> frozenset[str]:
    ids = frozenset(part.strip().upper() for part in text.split(",") if part.strip())
    unknown = ids - RULE_IDS
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown rule(s): {', '.join(sorted(unknown))}")
    return ids


def _severity(text: str) -> Severity:
    try:
        return Severity.parse(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workflow-guard",
        description="Find common security mistakes in GitHub Actions workflows.",
    )
    parser.add_argument(
        "paths", nargs="*", type=Path, help=f"workflow files or directories (default: {DEFAULT_DIR})"
    )
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument(
        "--ignore",
        type=_parse_ids,
        default=frozenset(),
        metavar="IDS",
        help="comma-separated rule ids to skip, e.g. WG006",
    )
    parser.add_argument(
        "--min-severity",
        type=_severity,
        default=Severity.LOW,
        metavar="LEVEL",
        help="only show findings at this level or above (low, medium, high)",
    )
    parser.add_argument(
        "--fail-on",
        type=_severity,
        default=Severity.LOW,
        metavar="LEVEL",
        help="exit with 1 if a shown finding is at this level or above (default: low)",
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="pin actions to the commit SHA of their tag (WG001), via the GitHub API; "
        "uses GITHUB_TOKEN or GH_TOKEN if set. Rewrites the files in place",
    )
    parser.add_argument("--list-rules", action="store_true", help="print the rules and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _load(path: Path, fix: Resolver | None, err: TextIO) -> Workflow:
    """Read one workflow; with a resolver, pin its actions first and save the file."""
    display = path.as_posix()
    if fix is None:
        return Workflow.load(path, display)
    try:
        # newline="" keeps \r\n as it is, so only the pinned lines change on Windows checkouts too.
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as e:
        raise WorkflowError(f"cannot read: {e}") from e
    result = pin_actions(text, fix, display)
    for pin in result.pinned:
        print(f"{display}:{pin.line}: pinned {pin.old} -> {pin.new}", file=err)
    for line, uses, reason in result.failed:
        print(f"{display}:{line}: could not pin {uses}: {reason}", file=err)
    if result.text != text:
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(result.text)
    return Workflow.parse(result.text, display)


def _token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


def run(
    argv: Sequence[str] | None = None,
    out: TextIO = sys.stdout,
    err: TextIO = sys.stderr,
    resolver: Resolver | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    fixer: Resolver | None = None
    if args.fix and "WG001" not in args.ignore:
        fixer = resolver or GitHubResolver(token=_token())

    if args.list_rules:
        for rule in RULES:
            print(f"{rule.id}  {rule.name:<22} {rule.summary}", file=out)
        return 0

    paths = args.paths or [DEFAULT_DIR]
    missing = [p for p in paths if not p.exists()]
    if missing and args.paths:
        for p in missing:
            print(f"workflow-guard: {p.as_posix()}: no such file or directory", file=err)
        return 2
    files = find_workflows([p for p in paths if p.exists()])
    if not files:
        print(f"workflow-guard: no workflow files found in {', '.join(map(str, paths))}", file=err)
        return 2

    findings: list[Finding] = []
    broken = 0
    for f in files:
        try:
            wf = _load(f, fixer, err)
        except WorkflowError as e:
            print(f"{f.as_posix()}: error: {e}", file=err)
            broken += 1
            continue
        findings += [x for x in check(wf, args.ignore) if x.severity >= args.min_severity]

    if args.format == "json":
        json.dump({"files": len(files), "findings": [x.to_dict() for x in findings]}, out, indent=2)
        out.write("\n")
    else:
        for x in findings:
            print(f"{x.path}:{x.line}:{x.column}: {x.rule_id} [{x.severity}] {x.message}", file=out)
        print(f"{len(findings)} finding(s) in {len(files)} file(s)", file=err)

    if broken:
        return 2
    return 1 if any(x.severity >= args.fail_on for x in findings) else 0


def main() -> None:
    sys.exit(run())
