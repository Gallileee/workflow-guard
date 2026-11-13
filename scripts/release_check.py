"""Checks that a release of workflow-guard was finished, run by .github/workflows/release-check.yml.

A release here is five steps by hand: bump the version in pyproject.toml *and* __init__.py,
merge, tag the merge commit ``vX.Y.Z``, push the tag, publish a GitHub Release with notes. This
script catches a step that was forgotten:

- error: pyproject.toml and ``__version__`` disagree;
- error: the version is older than the newest ``v*`` tag (a bump was lost in a merge);
- error: a pushed tag (or a published release) doesn't match the version in the code;
- error: an older tag has no GitHub Release;
- warning: the version has no tag yet (normal in a pull request that bumps it, and between the
  merge and the tag), or the newest tag has no release yet (between the tag and the release);
- error: CHANGELOG.md has no section for the version in the code or for a tag, has a section
  for a version that is neither, or isn't newest first (see scripts/release_notes.py);
- error (with ``--releases``): a section's title or text differs from its GitHub Release;
  warning: its date differs.

Warnings don't fail the job. In GitHub Actions they become annotations on the run.

Usage: ``python scripts/release_check.py [--releases]``; ``--releases`` asks the GitHub CLI for
the published releases (needs ``GH_TOKEN``), without it releases aren't checked. Standard library
only, so it runs before anything is installed.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

if (_HERE := str(Path(__file__).resolve().parent)) not in sys.path:
    sys.path.insert(0, _HERE)  # release_notes.py lives next to this script

from release_notes import (  # noqa: E402
    CHANGELOG,
    Release,
    Section,
    fetch_releases,
    parse,
    section_text,
    tidy,
)

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


def check_changelog(
    sections: list[Section] | None,
    version: str,
    tags: Iterable[str],
    releases: Mapping[str, Release] | None = None,
) -> list[Problem]:
    """CHANGELOG.md against the version, the tags and (if given) the releases' text.
    ``sections`` is None when there is no CHANGELOG.md."""
    if sections is None:
        return [Problem(ERROR, f"{CHANGELOG} is missing; create it with scripts/release_notes.py sync")]
    problems: list[Problem] = []
    tagged = version_tags(tags)
    expected = f"v{version}"
    seen: dict[str, Section] = {}
    for s in sections:
        if s.tag in seen:
            problems.append(Problem(ERROR, f"{CHANGELOG}:{s.line}: a second section for {s.tag}"))
        seen.setdefault(s.tag, s)
    order = [parse_version(s.tag) for s in sections]
    if order != sorted(order, reverse=True):
        problems.append(Problem(ERROR, f"{CHANGELOG}: sections aren't newest first"))
    if expected not in seen:
        problems.append(
            Problem(
                ERROR,
                f"{CHANGELOG} has no section for {expected}: write its release notes there in the"
                " pull request that bumps the version",
            )
        )
    for tag in tagged:
        if tag not in seen and tag != expected:
            problems.append(Problem(ERROR, f"{CHANGELOG} has no section for tag {tag}"))
    for tag, s in seen.items():
        if tag not in tagged and tag != expected:
            problems.append(
                Problem(
                    ERROR,
                    f"{CHANGELOG}:{s.line}: section {tag} is neither tagged nor the version in the code"
                    f" ({version})",
                )
            )
    for tag, s in seen.items():
        if releases is None or (release := releases.get(tag)) is None:
            continue
        where = f"{CHANGELOG}:{s.line}"
        if s.title != (release.name.strip() or tag):
            problems.append(
                Problem(ERROR, f"{where}: title '{s.title}' differs from the release's '{release.name}'")
            )
        if tidy(s.text) != section_text(release):
            problems.append(
                Problem(
                    ERROR,
                    f"{where}: the text of {tag} differs from its GitHub Release; fix the one that's"
                    " wrong (scripts/release_notes.py sync copies the releases)",
                )
            )
        if s.date and release.date and s.date != release.date:
            problems.append(Problem(WARNING, f"{where}: {tag} was released on {release.date}, not {s.date}"))
    return problems


# --- gathering the facts ----------------------------------------------------------------------


def git_tags(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "tag", "--list", "v*"], cwd=root, check=True, capture_output=True, text=True
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def read_changelog(root: Path) -> list[Section] | None:
    path = root / CHANGELOG
    return parse(path.read_text(encoding="utf-8")) if path.exists() else None


def report(problems: list[Problem], annotate: bool) -> str:
    lines = []
    for p in problems:
        lines.append(f"::{p.level}::{p.text}" if annotate else f"{p.level}: {p.text}")
    return "\n".join(lines)


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--releases", action="store_true", help="also check GitHub Releases and their text (gh CLI)"
    )
    args = parser.parse_args(argv)
    try:
        version = read_version(
            (root / "pyproject.toml").read_text(encoding="utf-8"), _PYPROJECT_VERSION, "pyproject.toml"
        )
        init = (root / "src" / "workflow_guard" / "__init__.py").read_text(encoding="utf-8")
        init_version = read_version(init, _INIT_VERSION, "__init__.py")
        tags = git_tags(root)
        releases = fetch_releases(root) if args.releases else None
        sections = read_changelog(root)
    except (OSError, ValueError, subprocess.CalledProcessError) as e:
        detail = getattr(e, "stderr", "") or ""
        print(f"release check: cannot read the release state: {e} {detail}".strip(), file=sys.stderr)
        return 2
    released = set(releases) if releases is not None else None
    problems = check(version, init_version, tags, released, os.environ.get("GITHUB_REF"))
    problems += check_changelog(sections, version, tags, releases)
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
