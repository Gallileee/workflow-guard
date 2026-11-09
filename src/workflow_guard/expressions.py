"""A small reader for GitHub Actions expressions (``${{ ... }}``).

Regular expressions over the raw text miss spellings that GitHub accepts and flag text that
isn't an expression at all. This module reads expressions the way GitHub does, as far as the
rules need it:

- ``find_expressions`` finds every ``${{ ... }}`` in a string; a ``}}`` inside a quoted string
  doesn't end the expression.
- ``tokenize`` splits the inside into tokens (names, ``.``, ``[``, strings, numbers, operators).
- ``context_paths`` turns property accesses into normalized paths:
  ``GitHub.event['pull_request'].TITLE`` and ``github.event.pull_request.title`` both become
  ``("github", "event", "pull_request", "title")``. Names are case-insensitive in GitHub, so
  paths are lower-cased. ``commits[0]`` and ``commits.*`` both become the segment ``"*"``.

Reference: https://docs.github.com/en/actions/reference/workflows-and-actions/expressions
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

WILDCARD = "*"
"""A path segment standing for any array element (``[0]``, ``.*``, ``[*]``)."""


class ExpressionError(ValueError):
    """The text inside ``${{ }}`` isn't a valid expression (GitHub rejects the workflow then)."""


@dataclass(frozen=True)
class Token:
    kind: str  # NAME, STRING, NUMBER, or the punctuation/operator itself: . [ ] ( ) , * == ! ...
    value: str
    pos: int


@dataclass(frozen=True)
class Expression:
    start: int
    """Offset of ``${{`` in the searched text."""
    end: int
    """Offset just after ``}}``."""
    inner: str


@dataclass(frozen=True)
class ContextPath:
    """One property access such as ``github.event.issue.title``."""

    segments: tuple[str, ...]
    function: str | None
    """The innermost function call it is an argument of (lower case), e.g. ``"tojson"``."""

    def __str__(self) -> str:
        return ".".join(self.segments)


_OPERATORS = ("==", "!=", "<=", ">=", "&&", "||", "<", ">", "!")
_PUNCTUATION = ".[](),*"


def find_expressions(text: str) -> Iterator[Expression]:
    """Every ``${{ ... }}`` in ``text``. An unterminated one ends the search."""
    pos = 0
    while (start := text.find("${{", pos)) != -1:
        i = start + 3
        while i < len(text):
            if text[i] == "'":
                i = _end_of_string(text, i)
                if i == -1:
                    return  # an unterminated string: nothing after it is an expression
                continue
            if text.startswith("}}", i):
                yield Expression(start, i + 2, text[start + 3 : i])
                break
            i += 1
        else:
            return
        pos = i + 2


def _end_of_string(text: str, quote: int) -> int:
    """Offset after the string literal starting at ``quote``, or -1 if it never ends.
    ``''`` inside is an escaped quote."""
    i = quote + 1
    while i < len(text):
        if text[i] == "'":
            if text.startswith("''", i):
                i += 2
                continue
            return i + 1
        i += 1
    return -1


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isspace():
            i += 1
        elif ch == "'":
            end = _end_of_string(text, i)
            if end == -1:
                raise ExpressionError(f"unterminated string at {i}")
            tokens.append(Token("STRING", text[i + 1 : end - 1].replace("''", "'"), i))
            i = end
        elif ch.isalpha() or ch == "_":
            j = i + 1
            while j < len(text) and (text[j].isalnum() or text[j] in "_-"):
                j += 1
            tokens.append(Token("NAME", text[i:j], i))
            i = j
        elif ch.isdigit() or (ch == "-" and i + 1 < len(text) and text[i + 1].isdigit()):
            j = i + 1
            while j < len(text) and (text[j].isalnum() or text[j] in ".+-"):
                j += 1
            tokens.append(Token("NUMBER", text[i:j], i))
            i = j
        elif op := next((op for op in _OPERATORS if text.startswith(op, i)), None):
            tokens.append(Token(op, op, i))
            i += len(op)
        elif ch in _PUNCTUATION:
            tokens.append(Token(ch, ch, i))
            i += 1
        else:
            raise ExpressionError(f"unexpected {ch!r} at {i}")
    return tokens


_LITERALS = frozenset({"true", "false", "null"})


def context_paths(text: str) -> list[ContextPath]:
    """Property accesses in one expression (the text between ``${{`` and ``}}``)."""
    tokens = tokenize(text)
    paths: list[ContextPath] = []
    calls: list[str | None] = []  # one entry per open "(": the function's name, or None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok.kind == "(":
            calls.append(None)
            i += 1
        elif tok.kind == ")":
            if calls:
                calls.pop()
            i += 1
        elif tok.kind == "NAME" and nxt is not None and nxt.kind == "(":
            calls.append(tok.value.lower())  # a function call such as format( or toJSON(
            i += 2
        elif tok.kind == "NAME" and tok.value.lower() not in _LITERALS and not _after_dot(tokens, i):
            segments, i = _read_path(tokens, i)
            function = next((c for c in reversed(calls) if c is not None), None)
            paths.append(ContextPath(segments, function))
        else:
            i += 1
    return paths


def _after_dot(tokens: Sequence[Token], i: int) -> bool:
    return i > 0 and tokens[i - 1].kind == "."


def _read_path(tokens: Sequence[Token], i: int) -> tuple[tuple[str, ...], int]:
    """Read ``name(.name | .* | ['key'] | [0] | [*])*`` from ``tokens[i]``. A bracket with
    anything else inside (``[matrix.key]``) ends the path; its contents are read on their own."""
    segments = [tokens[i].value.lower()]
    i += 1
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if tok.kind == "." and nxt is not None and nxt.kind == "NAME":
            segments.append(nxt.value.lower())
            i += 2
        elif tok.kind == "." and nxt is not None and nxt.kind == "*":
            segments.append(WILDCARD)
            i += 2
        elif (
            tok.kind == "["
            and nxt is not None
            and nxt.kind in ("STRING", "NUMBER", "*")
            and i + 2 < len(tokens)
            and tokens[i + 2].kind == "]"
        ):
            segments.append(nxt.value.lower() if nxt.kind == "STRING" else WILDCARD)
            i += 3
        else:
            break
    return tuple(segments), i


def matches(path: Sequence[str], pattern: Sequence[str]) -> bool:
    """True if ``path`` starts with ``pattern``; ``*`` in the pattern matches any one segment."""
    if len(path) < len(pattern):
        return False
    return all(p == WILDCARD or p == s for s, p in zip(path, pattern, strict=False))


def is_ancestor(path: Sequence[str], pattern: Sequence[str]) -> bool:
    """True if ``path`` is a strict prefix of what ``pattern`` describes (``github.event`` for
    ``github.event.issue.title``): the object at ``path`` *contains* the matching value."""
    if len(path) >= len(pattern):
        return False
    return all(p == WILDCARD or s == WILDCARD or p == s for s, p in zip(path, pattern, strict=False))
