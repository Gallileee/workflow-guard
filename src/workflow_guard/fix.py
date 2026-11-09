"""``--fix``: pin ``uses: owner/repo@v4`` to the commit the tag points to right now.

The tag is looked up through the GitHub API and the line becomes
``uses: owner/repo@<40-character sha>  # v4``, so the version stays readable (and tools like
Dependabot and Renovate can still update it). Only the ``uses`` value and the end of its line
change; every other byte of the file, including comments and line endings, stays as it was.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from yaml.nodes import ScalarNode

from .workflow import Workflow

SHA = re.compile(r"^[0-9a-f]{40}$")
# owner/repo, an optional path (sub-action or reusable workflow), then @ref.
# Owner and repo names are restricted to what GitHub allows, so they're safe in a URL path.
USES = re.compile(r"^(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?P<path>/[^@\s]*)?@(?P<ref>[^@\s]+)$")


class ResolveError(Exception):
    """A tag or branch couldn't be turned into a commit SHA."""


class Resolver(Protocol):
    def resolve(self, repo: str, ref: str) -> str: ...


class GitHubResolver:
    """Looks up ``owner/repo@ref`` with GET /repos/{repo}/commits/{ref}.

    With the ``application/vnd.github.sha`` media type the answer is just the 40-character SHA,
    for branches, lightweight tags and annotated tags alike (always the commit, not the tag
    object). Answers are cached, so ``actions/checkout@v4`` in ten files is one request.
    Without a token GitHub allows 60 requests an hour; set GITHUB_TOKEN or GH_TOKEN for more.
    """

    def __init__(
        self,
        token: str | None = None,
        api_url: str = "https://api.github.com",
        timeout: float = 10.0,
        opener: Callable[..., object] = urlopen,
    ) -> None:
        self._token = token
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout
        self._open = opener
        self._cache: dict[tuple[str, str], str] = {}

    def resolve(self, repo: str, ref: str) -> str:
        key = (repo, ref)
        if key not in self._cache:
            self._cache[key] = self._fetch(repo, ref)
        return self._cache[key]

    def _fetch(self, repo: str, ref: str) -> str:
        url = f"{self._api_url}/repos/{repo}/commits/{quote(ref, safe='')}"
        headers = {
            "Accept": "application/vnd.github.sha",
            "User-Agent": "workflow-guard",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            with self._open(Request(url, headers=headers), timeout=self._timeout) as response:
                body = response.read(200).decode("utf-8", "replace").strip()
        except HTTPError as e:
            with e:  # an HTTPError holds the open response; close it (ResourceWarning otherwise)
                raise ResolveError(_explain(e, repo, ref)) from None
        except (URLError, TimeoutError, OSError) as e:
            raise ResolveError(f"cannot reach the GitHub API ({getattr(e, 'reason', e)})") from None
        if not SHA.match(body):
            raise ResolveError(f"unexpected answer from the GitHub API for {repo}@{ref}")
        return body


def _explain(e: HTTPError, repo: str, ref: str) -> str:
    if e.code in (404, 422):
        return f"{repo}@{ref} not found (no such repository, tag or branch)"
    if e.code in (401, 403, 429):
        detail = ""
        try:
            detail = json.loads(e.read(500)).get("message", "")
        except (ValueError, AttributeError, OSError):
            pass
        hint = "" if "token" in detail.lower() else "; set GITHUB_TOKEN or GH_TOKEN"
        return f"GitHub API refused the request ({e.code} {detail}){hint}".replace(" )", ")")
    return f"GitHub API error {e.code} for {repo}@{ref}; try again later"


DEFAULT_COMMENT_GAP = "  "
"""Two spaces before ``#``: what yamllint (and PEP 8) expect, used when a file shows no habit."""
PRETTIER_COMMENT_GAP = " "
"""Prettier rewrites every end-of-line comment in YAML to one space before ``#``."""

# An end-of-line comment: something that isn't blank, whitespace, then "#" followed by a space or
# the end of the line. YAML only starts a comment at a "#" after whitespace, so "a#b" isn't one.
_INLINE_COMMENT = re.compile(r"\S([ \t]+)#(?=[ \t\r]|$)", re.M)


def comment_gap(text: str, fallback: str = DEFAULT_COMMENT_GAP) -> str:
    """The whitespace this file usually puts before an end-of-line comment.

    Prettier formats YAML with one space (``uses: x@sha # v4``), yamllint wants two; rewriting a
    file in the other style makes its formatter check fail. So the most common gap among the
    file's own comments wins (a tie goes to two spaces). A file without such comments gets
    ``fallback``.
    """
    counts = Counter(m.group(1) for m in _INLINE_COMMENT.finditer(text))
    if not counts:
        return fallback
    return max(counts, key=lambda gap: (counts[gap], gap == DEFAULT_COMMENT_GAP))


_PRETTIER_CONFIGS = (
    ".prettierrc",
    ".prettierrc.json",
    ".prettierrc.json5",
    ".prettierrc.yaml",
    ".prettierrc.yml",
    ".prettierrc.toml",
    ".prettierrc.js",
    ".prettierrc.cjs",
    ".prettierrc.mjs",
    ".prettierrc.ts",
    "prettier.config.js",
    "prettier.config.cjs",
    "prettier.config.mjs",
    "prettier.config.ts",
)


def repository_root(file: Path) -> Path | None:
    """The nearest directory above ``file`` that holds ``.git`` (a folder, or a file in a
    worktree), or None outside a repository."""
    for directory in file.resolve().parents:
        if (directory / ".git").exists():
            return directory
    return None


def uses_prettier(root: Path) -> bool:
    """True if the repository has a Prettier config file, or Prettier in package.json (as a
    dependency or a ``"prettier"`` key)."""
    if any((root / name).is_file() for name in _PRETTIER_CONFIGS):
        return True
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return False
    if not isinstance(package, dict):
        return False
    sections = [package, package.get("dependencies"), package.get("devDependencies")]
    return any(isinstance(section, dict) and "prettier" in section for section in sections)


def fallback_gap(file: Path) -> str:
    """The gap for a file without end-of-line comments of its own: Prettier's one space if its
    repository uses Prettier, else two."""
    root = repository_root(file)
    return PRETTIER_COMMENT_GAP if root is not None and uses_prettier(root) else DEFAULT_COMMENT_GAP


@dataclass(frozen=True)
class Pin:
    line: int
    old: str
    new: str


@dataclass
class FixResult:
    text: str
    pinned: list[Pin] = field(default_factory=list)
    failed: list[tuple[int, str, str]] = field(default_factory=list)  # (line, uses, reason)


def pin_actions(
    text: str,
    resolver: Resolver,
    path: str = "<string>",
    gap: str | None = None,
    fallback: str = DEFAULT_COMMENT_GAP,
) -> FixResult:
    """Pin every ``owner/repo@tag`` in one workflow's text. Raises WorkflowError if it isn't one.

    ``gap`` is the whitespace written before a new ``# v4`` comment. By default it is the
    file's own habit (``comment_gap``), or ``fallback`` if the file has no end-of-line comments."""
    wf = Workflow.parse(text, path)
    if gap is None:
        gap = comment_gap(text, fallback)
    result = FixResult(text)
    nodes = [n for n in wf.uses_nodes() if isinstance(n, ScalarNode)]
    lines_with_uses = [n.start_mark.line for n in nodes]
    edits: list[tuple[int, int, str]] = []  # (start, end, replacement), applied back to front

    for node in nodes:
        match = USES.match(node.value)
        if not match or SHA.match(match["ref"]):
            continue  # local, Docker, no version (nothing to resolve), or already pinned
        line = node.start_mark.line + 1
        if wf.is_ignored(line, "WG001"):
            continue
        try:
            sha = resolver.resolve(match["repo"], match["ref"])
        except ResolveError as e:
            result.failed.append((line, node.value, str(e)))
            continue

        new_value = f"{match['repo']}{match['path'] or ''}@{sha}"
        start, end = node.start_mark.index, node.end_mark.index
        raw = text[start:end]
        quote_char = raw[0] if raw[:1] in ("'", '"') else ""
        edits.append((start, end, f"{quote_char}{new_value}{quote_char}"))

        # Keep the version readable in a comment, unless two uses share the line (flow style).
        if lines_with_uses.count(node.start_mark.line) == 1:
            edits.append(_comment_edit(text, end, match["ref"], gap))
        result.pinned.append(Pin(line, node.value, new_value))

    out = text
    for start, end, replacement in sorted(edits, reverse=True):
        out = out[:start] + replacement + out[end:]
    result.text = out
    return result


def _comment_edit(text: str, after: int, version: str, gap: str) -> tuple[int, int, str]:
    """``<gap># v4`` at the end of the line, or ``# v4; existing comment`` if it has one."""
    line_end = text.find("\n", after)
    if line_end == -1:
        line_end = len(text)
    if line_end > after and text[line_end - 1] == "\r":
        line_end -= 1
    hash_at = text.find("#", after, line_end)
    if hash_at == -1:
        return (line_end, line_end, f"{gap}# {version}")
    body = hash_at + 1
    while body < line_end and text[body] == " ":
        body += 1
    return (hash_at, body, f"# {version}; ")
