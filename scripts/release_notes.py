"""CHANGELOG.md and the GitHub Releases, kept as the same text.

CHANGELOG.md has one section per version, newest first::

    ## v0.16.0 — WG009: workflow_run (2026-11-13)

    <the release notes>

The heading is the release's title and its date. Below it are the release's notes, with every
heading one level deeper (a ``##`` in the notes is ``###`` here) and without a first heading
that only repeats the title. A new version's section is written in the pull request that bumps
the version (the date can wait); the release is then published from it::

    gh release create v0.17.0 --verify-tag \\
      --title "$(python scripts/release_notes.py title v0.17.0)" \\
      --notes-file <(python scripts/release_notes.py notes v0.17.0)

Commands:

- ``notes vX.Y.Z``: a section as release notes, on standard output.
- ``title vX.Y.Z``: a section's title (its heading without the date).
- ``sync``: rewrite CHANGELOG.md's released sections from the GitHub Releases (gh CLI), keeping
  sections that have no release yet.

``scripts/release_check.py`` checks that every tag has a section and that each section says what
its release says. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = "CHANGELOG.md"
HEADER = (
    "# Changelog\n\n"
    "Every release of workflow-guard, newest first. Each section is the text of its\n"
    "[GitHub Release](https://github.com/Gallileee/workflow-guard/releases), with headings one\n"
    "level deeper; `scripts/release_check.py` checks that the two agree.\n"
)

_SECTION = re.compile(r"^## (v\d+\.\d+\.\d+)(?=\s|$)(.*)$")
_DATE = re.compile(r"\s*\((\d{4}-\d{2}-\d{2})\)\s*$")
_HEADING = re.compile(r"^(#{1,6})(\s.*)$")
_FENCE = re.compile(r"^\s*(```|~~~)")


@dataclass(frozen=True)
class Release:
    tag: str
    name: str
    body: str
    date: str = ""
    """``YYYY-MM-DD`` it was published."""


@dataclass(frozen=True)
class Section:
    tag: str
    title: str
    """The heading without ``## `` and the date: ``v0.16.0 — WG009: workflow_run``."""
    date: str
    text: str
    line: int = 0


def version_key(tag: str) -> tuple[int, ...]:
    return tuple(int(part) for part in tag.removeprefix("v").split("."))


def _lines_outside_fences(lines: list[str]) -> Iterable[tuple[int, str]]:
    fenced = False
    for i, line in enumerate(lines):
        if _FENCE.match(line):
            fenced = not fenced
        elif not fenced:
            yield i, line


def shift_headings(text: str, by: int) -> str:
    """Every Markdown heading (outside code blocks) ``by`` levels deeper, or shallower if < 0."""
    lines = text.splitlines()
    for i, line in _lines_outside_fences(lines):
        if match := _HEADING.match(line):
            lines[i] = "#" * max(1, min(6, len(match[1]) + by)) + match[2]
    return "\n".join(lines)


def tidy(text: str) -> str:
    """Line endings and trailing spaces don't count as a difference."""
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").split("\n")).strip()


def section_text(release: Release) -> str:
    """What CHANGELOG.md says under a release's heading."""
    lines = tidy(release.body).splitlines()
    first = _HEADING.match(lines[0]) if lines else None
    if first and first[2].strip().casefold() == release.name.strip().casefold():
        lines = lines[1:]
    return tidy(shift_headings("\n".join(lines), 1))


def notes(section: Section) -> str:
    """A section as release notes: its headings one level back up."""
    return tidy(shift_headings(section.text, -1)) + "\n"


def parse(text: str) -> list[Section]:
    lines = text.replace("\r\n", "\n").split("\n")
    starts = []
    for i, line in _lines_outside_fences(lines):
        if match := _SECTION.match(line):
            starts.append((i, match))
    sections = []
    for n, (i, match) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        heading = (match[1] + match[2]).rstrip()
        date = _DATE.search(heading)
        title = heading[: date.start()] if date else heading
        sections.append(
            Section(match[1], title, date[1] if date else "", tidy("\n".join(lines[i + 1 : end])), i + 1)
        )
    return sections


def render(sections: Iterable[Section]) -> str:
    parts = [HEADER]
    for s in sections:
        heading = f"## {s.title}" + (f" ({s.date})" if s.date else "")
        parts.append(f"{heading}\n\n{s.text}\n" if s.text else f"{heading}\n")
    return "\n".join(parts)


def from_release(release: Release) -> Section:
    return Section(release.tag, release.name.strip() or release.tag, release.date, section_text(release))


def sync(current: Iterable[Section], releases: Mapping[str, Release]) -> list[Section]:
    """Released sections rewritten from their releases, unreleased ones kept; newest first."""
    by_tag = {s.tag: s for s in current if s.tag not in releases}
    by_tag.update({tag: from_release(r) for tag, r in releases.items() if _SECTION.match(f"## {tag}")})
    return sorted(by_tag.values(), key=lambda s: version_key(s.tag), reverse=True)


def fetch_releases(root: Path) -> dict[str, Release]:
    """Published (not draft) GitHub Releases by tag, from the GitHub CLI (``GH_REPO``/``GH_TOKEN``
    are honoured)."""
    out = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            "repos/{owner}/{repo}/releases?per_page=100",
            "--jq",
            ".[] | select(.draft | not)"
            ' | {tag: .tag_name, name: (.name // ""), body: (.body // ""),'
            ' date: ((.published_at // "")[0:10])}',
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout
    releases = [Release(**json.loads(line)) for line in out.splitlines() if line.strip()]
    return {r.tag: r for r in releases}


def _find(sections: list[Section], tag: str) -> Section:
    for s in sections:
        if s.tag == tag:
            return s
    raise SystemExit(f"{CHANGELOG} has no section for {tag}")


def main(argv: list[str] | None = None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("notes", "title"):
        sub.add_parser(name).add_argument("tag")
    sub.add_parser("sync")
    args = parser.parse_args(argv)
    path = root / CHANGELOG
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    sections = parse(text)
    sys.stdout.reconfigure(encoding="utf-8")  # titles have dashes; Windows consoles default to cp1252
    if args.command == "notes":
        sys.stdout.write(notes(_find(sections, args.tag)))
    elif args.command == "title":
        print(_find(sections, args.tag).title)
    else:
        path.write_text(render(sync(sections, fetch_releases(root))), encoding="utf-8", newline="\n")
        print(f"{CHANGELOG}: {len(parse(path.read_text(encoding='utf-8')))} section(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
