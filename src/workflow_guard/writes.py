"""Reading what a step writes to $GITHUB_OUTPUT, $GITHUB_ENV and $GITHUB_PATH.

Steps pass values on by appending lines to files the runner reads after the step:
``name=value`` for one line, or ``name<<DELIMITER`` / lines / ``DELIMITER`` for several. Scripts
write those lines in many ways; this module understands the common ones:

    echo "title=$TITLE" >> "$GITHUB_OUTPUT"            one line
    {                                                  a group: every line inside is written
      echo "body<<EOF"
      echo "$BODY"
      echo "EOF"
    } >> "$GITHUB_OUTPUT"
    { echo "a=1"; echo "b=2"; } >> "$GITHUB_OUTPUT"    a group on one line
    cat <<EOF >> "$GITHUB_ENV"                         a shell heredoc: its body is written
    NOTES<<END
    $NOTES
    END
    EOF

and, in ``actions/github-script``, ``core.setOutput(...)``, ``core.exportVariable(...)`` and
``core.addPath(...)``.

The result is plain data (``Write`` and ``Assignment``); deciding what is tainted is taint.py's
job. This is pattern matching on shell text, not a shell parser: see the README's limitations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

OUTPUT, ENV, PATH = "OUTPUT", "ENV", "PATH"

_REDIRECT = re.compile(r""">>\s*["']?\$\{?GITHUB_(?P<file>OUTPUT|ENV|PATH)\b\}?["']?""")
# A shell heredoc feeding a command whose output goes to the file: cat <<EOF >> "$GITHUB_ENV",
# cat >> "$GITHUB_ENV" <<'EOF', cat <<-EOF ...
_SHELL_HEREDOC = re.compile(r"""<<-?\s*(?P<q>["']?)(?P<delim>[A-Za-z_]\w*)(?P=q)""")
_ECHO = re.compile(r"""^(?:echo(?:\s+-[neE]+)*|printf\s+(?P<q>["'])%s\\n(?P=q))\s+""")
_ONE_LINE = re.compile(r"^(?P<name>[A-Za-z_][\w-]*)=(?P<value>.*)$", re.S)
_MULTI_START = re.compile(r"^(?P<name>[A-Za-z_][\w-]*)<<(?P<delim>[A-Za-z_]\w*)$")


@dataclass(frozen=True)
class Write:
    """One line of text a script appends to one of the files."""

    line: int
    """Index of the script line that produces it (0 = first)."""
    file: str
    """``OUTPUT``, ``ENV`` or ``PATH``."""
    source: str
    """The shell text producing it (``echo "x=$Y"``), for checking what it uses."""
    text: str
    """Best guess at the text that ends up in the file (``x=$Y``)."""


@dataclass(frozen=True)
class Assignment:
    """What a run of writes means for one file."""

    file: str
    name: str | None
    """The output or variable name; None for $GITHUB_PATH lines and lines without a name."""
    writes: tuple[Write, ...]
    """The lines that make up the value (for ``name<<D`` without the start and end lines)."""


@dataclass(frozen=True)
class ScriptCall:
    """``core.setOutput`` / ``core.exportVariable`` / ``core.addPath`` in a github-script."""

    line: int
    file: str
    name: str | None
    argument: str
    """The JavaScript text of the value."""


def payload(source: str) -> str:
    """``echo "x=$Y"`` -> ``x=$Y``: drop echo/printf and one pair of surrounding quotes."""
    text = _ECHO.sub("", source.strip(), count=1).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    return text


def shell_writes(script: str) -> list[Write]:
    """Every line the script appends to $GITHUB_OUTPUT / $GITHUB_ENV / $GITHUB_PATH, in order."""
    lines = script.splitlines()
    writes: list[Write] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == "{":
            end = next((j for j in range(i + 1, len(lines)) if lines[j].strip().startswith("}")), None)
            redirect = _REDIRECT.search(lines[end]) if end is not None else None
            if end is not None and redirect is not None:
                writes += [Write(k, redirect["file"], lines[k], payload(lines[k])) for k in range(i + 1, end)]
                i = end + 1
                continue
            i += 1
            continue
        redirect = _REDIRECT.search(line)
        if redirect is None:
            i += 1
            continue
        before = line[: redirect.start()]
        heredoc = _SHELL_HEREDOC.search(line)
        if heredoc is not None and re.match(r"\s*cat\b", line):
            # The body lines are written as they are, up to the delimiter line.
            j = i + 1
            while j < len(lines) and lines[j].strip() != heredoc["delim"]:
                writes.append(Write(j, redirect["file"], lines[j], lines[j].strip()))
                j += 1
            i = j + 1
            continue
        group = re.match(r"^\s*\{(?P<body>.*);?\s*\}\s*$", before)
        if group is not None:
            for part in group["body"].split(";"):
                if part.strip():
                    writes.append(Write(i, redirect["file"], part, payload(part)))
        else:
            writes.append(Write(i, redirect["file"], before, payload(before)))
        i += 1
    return writes


def assignments(writes: list[Write]) -> list[Assignment]:
    """Group writes into values: ``name=value`` lines, and ``name<<D`` ... ``D`` blocks (one
    open block per file; a block never closed runs to the end of the script)."""
    result: list[Assignment] = []
    open_blocks: dict[str, tuple[str, str, list[Write]]] = {}
    for write in writes:
        if write.file in open_blocks:
            name, delim, body = open_blocks[write.file]
            if write.text.strip() == delim:
                result.append(Assignment(write.file, name, tuple(body)))
                del open_blocks[write.file]
            else:
                body.append(write)
            continue
        text = write.text.strip()
        if write.file != PATH and (start := _MULTI_START.match(text)):
            open_blocks[write.file] = (start["name"], start["delim"], [])
        elif write.file != PATH and (one := _ONE_LINE.match(text)):
            result.append(Assignment(write.file, one["name"], (write,)))
        else:
            result.append(Assignment(write.file, None, (write,)))
    result += [Assignment(file, name, tuple(body)) for file, (name, _, body) in open_blocks.items()]
    return result


_CORE_CALL = re.compile(
    r"""core\.(?P<fn>setOutput|exportVariable)\(\s*(?P<q>['"`])(?P<name>[\w-]+)(?P=q)\s*,(?P<arg>.*)\)"""
)
_CORE_ADD_PATH = re.compile(r"core\.addPath\((?P<arg>.*)\)")


def github_script_calls(script: str) -> list[ScriptCall]:
    """``core.setOutput('name', value)`` and friends, one call per line."""
    calls: list[ScriptCall] = []
    for index, line in enumerate(script.splitlines()):
        if match := _CORE_CALL.search(line):
            file = OUTPUT if match["fn"] == "setOutput" else ENV
            calls.append(ScriptCall(index, file, match["name"], match["arg"].strip()))
        elif match := _CORE_ADD_PATH.search(line):
            calls.append(ScriptCall(index, PATH, None, match["arg"].strip()))
    return calls
