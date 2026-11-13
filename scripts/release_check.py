"""Checks that a release of workflow-guard was finished, run by .github/workflows/release-check.yml.

A release here is five steps by hand: bump the version in pyproject.toml *and* __init__.py,
merge, tag the merge commit ``vX.Y.Z``, push the tag, publish a GitHub Release with notes. This
script catches a step that was forgotten:

- error: pyproject.toml and ``__version__`` disagree;
- error: the version is older than the newest ``v*`` tag (a bump was lost in a merge);
- error: a pushed tag (or a published release) doesn't match the version in the code;
- error: an older tag has no GitHub Release;
- warning: the version has no tag yet (normal in a pull request that bumps it, and between the
  merge and the tag), or the newest tag has no release yet (between the tag and the release).

Warnings don't fail the job. In GitHub Actions they become annotations on the run.

Usage: ``python scripts/release_check.py [--releases]``; ``--releases`` asks the GitHub CLI for
the published releases (needs ``GH_TOKEN``), without it releases aren't checked. Standard library
only, so it runs before anything is installed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
_PYPROJECT_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
_INIT_VERSION = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)

ERROR = "error"
WARNING = "warning"


@dataclass(frozen=True)
class Problem:
    level: str
    """``ERROR`` or ``WARNING``."""
    text: str


def parse_version(text: str) -> tuple[int, int, int]:
    """``"0.15.0"`` or ``"v0.15.0"`` -> ``(0, 15, 0)``."""
    match = _VERSION.match(text.strip())
    if match is None:
        raise ValueError(f"not a version: {text!r}")
    return int(match[1]), int(match[2]), int(match[3])


def read_version(text: str, pattern: re.Pattern[str], where: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise ValueError(f"no version found in {where}")
    return match[1]


def version_tags(tags: Iterable[str]) -> list[str]:
    """The ``vX.Y.Z`` tags, oldest first; other tags are ignored."""
    return sorted((t for t in tags if t.startswith("v") and _VERSION.match(t)), key=parse_version)


def check(
    version: str,
    init_version: str,
    tags: Iterable[str],
    releases: set[str] | None = None,
    ref: str | None = None,
) -> list[Problem]:
    """Everything wrong with the release state. ``releases``: tag names with a published
    GitHub Release (None = not checked). ``ref``: ``GITHUB_REF`` of the run."""
    problems: list[Problem] = []
    if version != init_version:
        problems.append(
            Problem(
                ERROR, f"pyproject.toml says {version} but src/workflow_guard/__init__.py says {init_version}"
            )
        )
    try:
        current = parse_version(version)
    except ValueError as e:
        return [*problems, Problem(ERROR, f"pyproject.toml: {e}")]
    tagged = version_tags(tags)
    expected_tag = f"v{version}"

    if ref is not None and ref.startswith("refs/tags/v"):
        pushed = ref.removeprefix("refs/tags/")
        if pushed != expected_tag:
            problems.append(Problem(ERROR, f"tag {pushed} doesn't match the version in the code ({version})"))

    if tagged:
        latest = tagged[-1]
        if current < parse_version(latest):
            problems.append(
                Problem(
                    ERROR,
                    f"version {version} is older than the newest tag {latest}; was a version bump lost?",
                )
            )
        elif expected_tag not in tagged:
            problems.append(
                Problem(
                    WARNING,
                    f"{expected_tag} isn't tagged yet: after the merge, tag the merge commit "
                    f"(git tag -a {expected_tag} <sha>) and push the tag",
                )
            )
    elif ref is None or not ref.startswith("refs/tags/"):
        problems.append(
            Problem(WARNING, f"no v* tags found (is this a shallow clone?); {expected_tag} isn't tagged")
        )

    if releases is not None and tagged:
        for tag in tagged[:-1]:
            if tag not in releases:
                problems.append(Problem(ERROR, f"tag {tag} has no GitHub Release"))
        if tagged[-1] not in releases:
            problems.append(
                Problem(WARNING, f"tag {tagged[-1]} has no GitHub Release yet: publish one with its notes")
            )
    return problems


# --- gathering the facts ----------------------------------------------------------------------


def git_tags(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "tag", "--list", "v*"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def published_releases(root: Path) -> set[str]:
    """Tag names of the published (not draft) releases, from the GitHub CLI."""
    out = subprocess.run(
        ["gh", "release", "list", "--limit", "1000", "--json", "tagName,isDraft"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {r["tagName"] for r in json.loads(out) if not r.get("isDraft")}


def report(problems: list[Problem], annotate: bool) -> str:
    lines = []
    for p in problems:
        lines.append(f"::{p.level}::{p.text}" if annotate else f"{p.level}: {p.text}")
    return "\n".join(lines)


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--releases", action="store_true", help="also check GitHub Releases (gh CLI)")
    args = parser.parse_args(argv)
    try:
        version = read_version(
            (root / "pyproject.toml").read_text(encoding="utf-8"), _PYPROJECT_VERSION, "pyproject.toml"
        )
        init = (root / "src" / "workflow_guard" / "__init__.py").read_text(encoding="utf-8")
        init_version = read_version(init, _INIT_VERSION, "__init__.py")
        tags = git_tags(root)
        releases = published_releases(root) if args.releases else None
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        detail = getattr(e, "stderr", "") or ""
        print(f"release check: cannot read the release state: {e} {detail}".strip(), file=sys.stderr)
        return 2
    problems = check(version, init_version, tags, releases, os.environ.get("GITHUB_REF"))
    if problems:
        print(report(problems, annotate=os.environ.get("GITHUB_ACTIONS") == "true"))
    errors = sum(p.level == ERROR for p in problems)
    print(
        f"release check: version {version}, {len(version_tags(tags))} tag(s), {errors} error(s)",
        file=sys.stderr,
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
