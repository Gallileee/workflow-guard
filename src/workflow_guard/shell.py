"""Does a shell script fail for a commenter who can't write? A small bash evaluator for WG010.

Some workflows check who commented in a ``run:`` script instead of an ``if:``::

    case "$AUTHOR_ASSOCIATION" in
      OWNER|MEMBER|COLLABORATOR) ;;
      *) echo "not allowed"; exit 1 ;;
    esac

``always_fails`` runs such a script on paper with the variables it is given (the commenter's
association, a stranger's login, ``issue_comment`` for the event...) and every other value
unknown. It follows every path through ``if``/``elif``/``else``, ``case``, ``&&``/``||``,
``!``, ``[ ]``/``[[ ]]``/``test`` (``=``, ``==``, ``!=``, ``=~``, ``-z``, ``-n``), plain
assignments, ``exit`` and ``set -e``/``set +e`` (GitHub runs bash with ``-e``, so a failing
test on its own line ends the script too). A test it can't decide goes both ways. A script
fails *certainly* only if every path ends in a non-zero exit.

Functions (``name() { ...; }``, ``function name { ...; }``) run where they're called, with
``$1``... set from the call, ``local`` variables put back afterwards and ``return``; ``{ ...; }``
groups run in place. In a condition, a negated command or before the last command of a
``&&``/``||`` list, ``set -e`` doesn't act inside them either (bash's rule).

Loops: ``for x in a b c`` runs its body once per word; over words it can't work out (``$LIST``,
``$(...)``, a glob) and for ``while``/``until`` the body runs again and again, from every state
the last round left, until no new state turns up (at most 8 rounds; otherwise the script is
unknown). ``break`` and ``continue`` end a round. Commands that set variables are followed:
``read`` (unknown values), ``export``/``declare``/``readonly`` with ``NAME=value``, ``unset``,
``printf -v``, ``mapfile``/``readarray`` (an unknown array), ``x+=text``. Arrays: ``a=(x y)``,
``a+=(z)``, ``"${a[@]}"`` and ``${a[*]}``, ``${a[0]}``, ``${#a[@]}``; ``<(cmd)`` and ``>(cmd)`` are a
file with unknown contents. ``eval``, ``source``, ``shift``, ``let`` and ``getopts`` make the script unknown,
as do ``((...))``, subshells, background jobs and heredocs: such a script doesn't count as a
check. Commands it doesn't know succeed or fail, it doesn't matter which: only an ``exit`` or a
failing test decides.

The permission API is known too, when it asks about the commenter (a stranger's login):
``P=$(gh api repos/.../collaborators/$USER/permission --jq .permission)`` gives ``none`` or
``read``, or the command fails (a non-collaborator can get a 404), which ends the script under
``-e`` (or takes the ``else`` of ``if P=$(...)``). ``|| echo X`` turns the failure into ``X``
(maybe after gh's error text); without ``--jq``/``jq`` the answer is JSON, equal to no word.
``gh api ... | grep -q PATTERN`` is followed the same way. ``api_fails`` tells whether such a
script exits for a stranger, and None when no such call was followed.

``P=$(f ...)``, where ``f`` is a function, runs ``f`` in a subshell (``set -e`` not inherited, its
variables its own, ``exit`` not followed) and keeps what it prints: ``echo``, ``printf '%s'``, and
a permission call about the commenter, which prints its answer on a line, or on a failure an
error body (a 404's) or nothing. ``gh "$@"`` in a function is the call its caller wrote, so a
wrapper (``gh_retry api .../permission``) is followed; a retried failure's body counts once.
Output sent elsewhere (``>&2``, ``> file``) isn't printed; anything else a command may print
(``2>&1`` included) makes the output unknown. An assignment's status is its command
substitution's (``$((...))`` succeeds).

``script_outputs`` gives what a script that succeeds writes to ``$GITHUB_OUTPUT`` on each path
(``echo "name=value" >> "$GITHUB_OUTPUT"``, ``printf 'name=%s\n' "$x" >> ...``, or ``echo`` in a
``{ ...; } >> "$GITHUB_OUTPUT"`` group): the step's outputs. Any other mention of
``$GITHUB_OUTPUT`` (``tee``, a copy in a variable, a multiline value) makes them unknown.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Callable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass

from .conditions import STRANGER, UNKNOWN

FAIL, PASS = "fail", "pass"
_ERREXIT = "\0errexit"
_COMMAND = "__WG_CMD"
_MAX_PATHS = 64
_OPS = ("&&", "||", ";;", "<<", ">>", ";", "|", "&", "(", ")", "<", ">", "\n")
_OP_CHARS = ";&|()<>\n"
_UNSUPPORTED = {"select", "(", "((", "do", "done"}
_BREAK = "\0break"  # set on a path that ran `break` (cleared when its loop ends)
_CONTINUE = "\0continue"  # set on a path that ran `continue` (cleared at the end of the round)
_LOOPS = "\0loops"  # how many loops deep
_MAX_ROUNDS = 8
_UNFOLLOWED = {"eval", "source", ".", "shift", "let", "getopts", "select", "coproc"}
_PROCESS_FILE = "/dev/fd/__WG_PROC"  # <(cmd): a file whose contents are unknown
_RETURNED = "\0return"  # set on a path that ran `return`: the status it returned
_DEPTH = "\0depth"  # how many function calls deep
_LOCALS = "\0locals"  # names declared `local` in the current call
_FUNCTION = "\0function:"
_MAX_DEPTH = 8
_STDOUT = "\0stdout"  # inside $(...): what the commands printed so far
_SUBSHELL = "\0subshell"  # inside $(...)
_ARGV = "\0argv"  # in a function: its arguments as written, and the values they read
_ARGV_NAME = "__WG_ARGV"
# What a failed `gh api` call prints: the error's JSON body (or nothing, when the request
# never got an answer). A 404 is what a non-collaborator can get.
_NOT_FOUND = '{"message":"Not Found","status":"404"}'
_SILENT = {"true", ":", "false", "sleep", "cd", "mkdir", "rm", "touch", "chmod", "cp", "mv"}
_POSITIONAL = tuple(str(i) for i in range(1, 10))
_SEPARATORS = (";", "\n")
_NAME = re.compile(r"\$(?:(\w+)|\{(\w+)\})")
_EXPANSION = re.compile(r"\$[\w{(@*#?!-]")
_ASSIGNMENT = re.compile(r"([A-Za-z_]\w*)(\+?)=(.*)", re.DOTALL)
_ARRAY_REF = re.compile(r"\$\{(#?)(\w+)\[([@*]|\d+)\]\}")


class _ArrayWord(str):
    """``name=(a b c)`` (or ``+=``) as one word: the element words are kept apart."""

    items: tuple[str, ...]


_GH_API = re.compile(r"\bgh\s+api\b")
_API_USER = re.compile(r"collaborators/([^/\s\"']+)/permission")
_JQ_FIELD = re.compile(
    r"(?:--jq|-q)[\s=]+['\"]?\.(\w+)['\"]?(?=\s|$)|\|\s*jq\s+(?:-r\s+)?['\"]?\.(\w+)['\"]?\s*$"
)
_ANY_JQ = re.compile(r"(?:--jq|-q)(?:\s|=)|\|\s*jq\b")
_FALLBACK = re.compile(r"\|\|\s*(?:echo\s+['\"]?([\w-]*)['\"]?|(true|:))\s*$")
_API_SEEN: ContextVar[bool] = ContextVar("api_seen", default=False)
_PASSED: ContextVar[list | None] = ContextVar("passed", default=None)  # envs where the script succeeds
_OUTPUT_FILE = re.compile(r"\$\{?GITHUB_OUTPUT\}?")
_OUT = "\0out:"  # an output the script wrote: _OUT + name
_OUT_UNKNOWN = "\0out?"  # a write the evaluator couldn't read
_TO_OUTPUT = "\0to_output"  # inside a { ...; } >> "$GITHUB_OUTPUT" group


@dataclass(frozen=True)
class _Sub:
    """A command substitution's text: its output is unknown unless it asks the permission API."""

    inner: str


class Unsupported(Exception):
    """The script uses something the evaluator doesn't follow."""


def always_fails(script: str, variables: Mapping[str, object]) -> bool:
    """True if ``script`` ends with a non-zero exit on every path, with ``variables`` (name ->
    a string, ``STRANGER`` or ``UNKNOWN``) and every other variable unknown. False when it may
    succeed, or when it uses something the evaluator doesn't follow."""
    result = _analyse(script, variables)
    return result is not None and result[0]


def api_fails(script: str, variables: Mapping[str, object]) -> bool | None:
    """Like ``always_fails`` for a script that asks the permission API about the commenter:
    None if the evaluator doesn't follow the script or followed no such call."""
    result = _analyse(script, variables)
    return result[0] if result is not None and result[1] else None


def script_outputs(script: str, variables: Mapping[str, object]) -> list[dict[str, object]] | None:
    """The outputs the script writes on each path where it succeeds (name -> a string,
    ``STRANGER`` or ``UNKNOWN``; an output it doesn't write is empty), or None if the evaluator
    doesn't follow the script or a write to ``$GITHUB_OUTPUT``. An empty list: it never
    succeeds."""
    passed: list[Env] = []
    if _analyse(script, variables, passed) is None:
        return None
    maps: list[dict[str, object]] = []
    for env in passed:
        if env.get(_OUT_UNKNOWN):
            return None
        written = {key[len(_OUT) :]: value for key, value in env.items() if key.startswith(_OUT)}
        if written not in maps:
            maps.append(written)
    return maps


def _analyse(
    script: str, variables: Mapping[str, object], passed: list | None = None
) -> tuple[bool, bool] | None:
    """(fails on every path, a permission API call was followed), or None if unsupported.
    ``passed`` collects the variables on every path where the script succeeds."""
    token, passed_token = _API_SEEN.set(False), _PASSED.set(passed)
    try:
        text, subs = _prepare(script)
        tokens = _tokens(text)
        parser = _Parser(tokens)
        tree = parser.program()
        # GitHub runs the script file without arguments: $1... are empty.
        env: dict[str, object] = {**dict.fromkeys(_POSITIONAL, ""), **variables, **subs, _ERREXIT: True}
        mentions = sum("GITHUB_OUTPUT" in t for t in tokens) + sum(
            "GITHUB_OUTPUT" in s.inner for s in subs.values()
        )
        if mentions != parser.output_targets:
            env[_OUT_UNKNOWN] = True  # written some other way: tee, a copy in a variable...
        ends, paths = _run_seq(tree, [env])
        if passed is not None:
            passed += paths
        return not paths and ends == {FAIL}, _API_SEEN.get()
    except Unsupported:
        return None
    finally:
        _API_SEEN.reset(token)
        _PASSED.reset(passed_token)


# --- reading the script ------------------------------------------------------------------------


def _close(text: str, start: int) -> int:
    """The index of the ``)`` that closes the ``(`` at ``start``."""
    depth, quote = 0, None
    for i in range(start, len(text)):
        c = text[i]
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
    raise Unsupported("unclosed $(")


def _prepare(script: str, prefix: str = _COMMAND) -> tuple[str, dict[str, _Sub]]:
    """Joins ``\\`` continuations, drops comments, and replaces each command substitution
    (``$(...)``, backticks, ``$((...))``) with a variable ``$__WG_CMD<n>`` (``prefix`` + n)
    holding its text."""
    text = script.replace("\\\n", " ")
    out: list[str] = []
    subs: dict[str, _Sub] = {}

    def substitute(inner: str) -> None:
        name = f"{prefix}{len(subs)}"
        subs[name] = _Sub(inner.strip())
        out.append("${" + name + "}")

    i, quote = 0, None
    while i < len(text):
        c = text[i]
        if quote != "'" and text.startswith("$(", i):
            end = _close(text, i + 1)
            substitute(text[i + 2 : end])
            i = end + 1
            continue
        if quote is None and (text.startswith("<(", i) or text.startswith(">(", i)):
            end = _close(text, i + 1)
            out.append(_PROCESS_FILE)
            i = end + 1
            continue
        if quote != "'" and c == "`":
            end = text.find("`", i + 1)
            if end < 0:
                raise Unsupported("unclosed backtick")
            substitute(text[i + 1 : end])
            i = end + 1
            continue
        if quote:
            if c == quote:
                quote = None
            elif c == "\\" and quote == '"' and i + 1 < len(text):
                out.append(c)
                i += 1
                c = text[i]
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or text[i - 1] in " \t\n;"):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        out.append(c)
        i += 1
    return "".join(out), subs


def _split_ops(run: str) -> list[str]:
    ops = []
    while run:
        op = next(o for o in _OPS if run.startswith(o))
        ops.append(op)
        run = run[len(op) :]
    return ops


def _tokens(text: str) -> list[str]:
    lexer = shlex.shlex(text, posix=True, punctuation_chars=_OP_CHARS)
    lexer.whitespace = " \t\r"
    lexer.commenters = ""
    lexer.wordchars += "$[]!{}@:%+,^#"
    tokens: list[str] = []
    try:
        for token in lexer:
            if token and all(c in _OP_CHARS for c in token):
                tokens.extend(_split_ops(token))
            else:
                tokens.append(token)
    except ValueError as err:  # an unclosed quote
        raise Unsupported(str(err)) from err
    if "<<" in tokens:
        raise Unsupported("heredoc")
    return tokens


# --- the tree ----------------------------------------------------------------------------------


@dataclass
class _Simple:
    words: list[str]
    output: bool = False  # redirected to $GITHUB_OUTPUT
    quiet: bool = False  # its output goes elsewhere (`>&2`, `> file`)
    merged: bool = False  # `2>&1`: what it writes to stderr is in its output


@dataclass
class _Redirected:
    """A compound command whose output goes elsewhere, or with ``2>&1``."""

    node: object
    quiet: bool
    merged: bool


@dataclass
class _If:
    branches: list[tuple[list, list]]  # (condition, body)
    otherwise: list | None


@dataclass
class _Case:
    word: str
    items: list[tuple[list[str], list]]  # (patterns, body)


@dataclass
class _Group:
    body: list
    output: bool = False  # `{ ...; } >> "$GITHUB_OUTPUT"`


@dataclass
class _For:
    name: str
    words: list[str] | None  # None: `for x; do` (the positional parameters)
    body: list
    output: bool = False


@dataclass
class _While:
    condition: list
    body: list
    until: bool = False
    output: bool = False


@dataclass
class _Define:
    name: str
    body: list


class _Function:
    """A defined function (compared and shown by identity: its body can be large)."""

    def __init__(self, body: list) -> None:
        self.body = body

    def __repr__(self) -> str:
        return f"<function {id(self)}>"


@dataclass
class _Pipe:
    negated: bool
    commands: list


@dataclass
class _AndOr:
    first: _Pipe
    rest: list[tuple[str, _Pipe]]


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.i = 0
        self.output_targets = 0  # redirections to $GITHUB_OUTPUT it understood
        self.last_redirect: tuple[str, bool, str] = ("", False, "")  # (operator, `&`, target)

    def peek(self) -> str | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None or (expected is not None and token != expected):
            raise Unsupported(f"expected {expected!r}, got {token!r}")
        self.i += 1
        return token

    def newlines(self) -> None:
        while self.peek() == "\n":
            self.i += 1

    def program(self) -> list:
        seq = self.seq(set())
        if self.peek() is not None:
            raise Unsupported(f"unexpected {self.peek()!r}")
        return seq

    def seq(self, stop: set[str]) -> list:
        commands: list[_AndOr] = []
        while True:
            while self.peek() in _SEPARATORS:
                self.i += 1
            token = self.peek()
            if token is None or token in stop or token == ";;":
                return commands
            commands.append(self.and_or())
            if self.peek() not in (*_SEPARATORS, None, ";;") and self.peek() not in stop:
                raise Unsupported(f"unexpected {self.peek()!r}")

    def and_or(self) -> _AndOr:
        first, rest = self.pipe(), []
        while self.peek() in ("&&", "||"):
            op = self.take()
            self.newlines()
            rest.append((op, self.pipe()))
        if self.peek() == "&":
            raise Unsupported("background job")
        return _AndOr(first, rest)

    def pipe(self) -> _Pipe:
        negated = self.peek() == "!"
        if negated:
            self.i += 1
        commands = [self.command()]
        while self.peek() == "|":
            self.i += 1
            self.newlines()
            commands.append(self.command())
        return _Pipe(negated, commands)

    def command(self) -> object:
        token = self.peek()
        if token == "(" and self.tokens[self.i + 1 : self.i + 2] == ["("]:
            return self.arithmetic()
        if token in _UNSUPPORTED:
            raise Unsupported(f"{token!r}")
        compound = {
            "if": self.if_,
            "case": self.case,
            "[[": self.double_test,
            "{": self.group,
            "for": self.for_,
            "while": self.while_,
            "until": self.while_,
        }
        if token in compound:
            node = compound[token]()
            output, quiet, merged = self.redirections()  # `} >> "$GITHUB_OUTPUT"`, `fi 2>&1`
            if output and isinstance(node, (_Group, _For, _While)):
                node.output = True
            elif output:
                self.output_targets -= 1  # `fi >> "$GITHUB_OUTPUT"`: not followed
            return _Redirected(node, quiet, merged) if quiet or merged else node
        if token == "function":
            self.i += 1
            name = self.take()
            if self.peek() == "(":
                self.take("(")
                self.take(")")
            return self.define(name)
        if token is not None and token not in _OPS and self.tokens[self.i + 1 : self.i + 3] == ["(", ")"]:
            name = self.take()
            self.take("(")
            self.take(")")
            return self.define(name)
        return self.simple()

    def redirections(self) -> tuple[bool, bool, bool]:
        """Skips redirections after a compound command: whether one goes to $GITHUB_OUTPUT,
        whether its output goes elsewhere, and whether stderr joins its output."""
        output = quiet = merged = False
        while self.peek() in ("<", ">", ">>") or (
            self.peek() not in (None, *_OPS)
            and self.tokens[self.i + 1 : self.i + 2] in (["<"], [">"], [">>"])
        ):
            fd = None
            if self.peek() not in ("<", ">", ">>"):
                fd = self.take()  # a file descriptor: 2>
            to_output = self.target()
            output |= to_output
            quiet, merged = self.stdout(fd, to_output, quiet, merged)
        return output, quiet, merged

    def stdout(self, fd: str | None, to_output: bool, quiet: bool, merged: bool) -> tuple[bool, bool]:
        """After the redirection just taken: whether stdout now goes elsewhere, and whether
        stderr goes where stdout went (``2>&1`` before stdout is sent elsewhere)."""
        op, dup, target = self.last_redirect
        if op in (">", ">>") and fd in (None, "1") and not to_output and not (dup and target == "1"):
            quiet = True
        if op == ">" and dup and fd == "2" and target == "1" and not quiet:
            merged = True
        return quiet, merged

    def target(self) -> bool:
        """Takes a redirection (the operator and its target); True if the target is
        $GITHUB_OUTPUT."""
        op = self.take()
        dup = self.peek() == "&"
        if dup:
            self.i += 1
        target = self.take()
        self.last_redirect = (op, dup, target)
        if _OUTPUT_FILE.fullmatch(target):
            self.output_targets += 1
            return True
        return False

    def for_(self) -> _For:
        self.take("for")
        name = self.take()
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            raise Unsupported(f"for {name!r}")  # for (( ... ))
        self.newlines()
        words: list[str] | None = None
        if self.peek() == "in":
            self.i += 1
            words = []
            while self.peek() not in (";", "\n", None):
                if self.peek() in _OPS:
                    raise Unsupported(f"for ... in {self.peek()!r}")
                words.append(self.take())
        while self.peek() in _SEPARATORS:
            self.i += 1
        return _For(name, words, self.do_done())

    def while_(self) -> _While:
        until = self.take() == "until"
        condition = self.seq({"do"})
        return _While(condition, self.do_done(), until)

    def do_done(self) -> list:
        self.take("do")
        body = self.seq({"done"})
        self.take("done")
        return body

    def group(self) -> _Group:
        self.take("{")
        body = self.seq({"}"})
        self.take("}")
        return _Group(body)

    def define(self, name: str) -> _Define:
        if not re.fullmatch(r"[A-Za-z_][\w-]*", name):
            raise Unsupported(f"function name {name!r}")
        self.newlines()
        if self.peek() != "{":
            raise Unsupported("function body that isn't { ...; }")
        return _Define(name, self.group().body)

    def simple(self) -> _Simple:
        words: list[str] = []
        output = quiet = merged = False
        while (token := self.peek()) is not None and token not in _OPS:
            self.i += 1
            fd = None
            if token.isdigit() and self.peek() in ("<", ">", ">>"):
                fd = token  # a file descriptor: 2>&1
            elif re.fullmatch(r"[A-Za-z_]\w*\+?=", token) and self.peek() == "(":
                words.append(self.array_literal(token))
            else:
                words.append(token)
            if self.peek() in ("<", ">", ">>"):  # a redirection: its target is no argument
                to_output = self.target()
                output |= to_output
                quiet, merged = self.stdout(fd, to_output, quiet, merged)
        if self.peek() in ("<", ">", ">>") and not words:
            to_output = self.target()
            quiet, merged = self.stdout(None, to_output, quiet, merged)
            node = self.simple()
            node.output |= output | to_output
            node.quiet |= quiet
            node.merged |= merged
            return node
        if self.peek() == "(":
            raise Unsupported("( after a word")
        if not words:
            raise Unsupported(f"unexpected {self.peek()!r}")
        return _Simple(words, output, quiet, merged)

    def arithmetic(self) -> _Simple:
        """``(( expr ))``: its words, after ``((``."""
        self.take("(")
        self.take("(")
        words, depth = ["(("], 0
        while True:
            token = self.peek()
            if token is None or token == "\n":
                raise Unsupported("unclosed ((")
            if token == ")" and depth == 0 and self.tokens[self.i + 1 : self.i + 2] == [")"]:
                self.i += 2
                return _Simple(words)
            depth += {"(": 1, ")": -1}.get(token, 0)
            words.append(self.take())

    def array_literal(self, head: str) -> _ArrayWord:
        """``name=( a b c )``, possibly over several lines."""
        self.take("(")
        items: list[str] = []
        while (token := self.peek()) != ")":
            if token is None:
                raise Unsupported("unclosed array")
            if token == "\n":
                self.i += 1
                continue
            if token in _OPS:
                raise Unsupported(f"{token!r} in an array")
            items.append(self.take())
        self.take(")")
        word = _ArrayWord(head + "(" + " ".join(items) + ")")
        word.items = tuple(items)
        return word

    def double_test(self) -> _Simple:
        """``[[ ... ]]``: operators inside it are part of the test."""
        words = [self.take("[[")]
        while (token := self.peek()) != "]]":
            if token is None or token == "\n":
                raise Unsupported("unclosed [[")
            words.append(self.take())
        words.append(self.take())
        return _Simple(words)

    def if_(self) -> _If:
        self.take("if")
        branches = []
        while True:
            condition = self.seq({"then"})
            self.take("then")
            body = self.seq({"elif", "else", "fi"})
            branches.append((condition, body))
            token = self.take()
            if token == "elif":
                continue
            if token == "else":
                otherwise = self.seq({"fi"})
                self.take("fi")
                return _If(branches, otherwise)
            return _If(branches, None)  # fi

    def case(self) -> _Case:
        self.take("case")
        word = self.take()
        self.take("in")
        items = []
        while True:
            self.newlines()
            if self.peek() == "esac":
                self.i += 1
                return _Case(word, items)
            if self.peek() == "(":
                self.i += 1
            patterns = [self.take()]
            while self.peek() == "|":
                self.i += 1
                patterns.append(self.take())
            self.take(")")
            body = self.seq({"esac"})
            if self.peek() == ";;":
                self.i += 1
            items.append((patterns, body))


# --- running it on paper -----------------------------------------------------------------------

Env = dict[str, object]
# A command's result on one path: (exit status True/False, whether `set -e` applies to it, env)
Result = tuple[bool, bool, Env]


def _array_ref(m: re.Match[str], env: Env) -> object:
    """``${a[@]}`` (the elements, as a tuple), ``${a[*]}`` (joined by spaces), ``${a[2]}``,
    ``${#a[@]}``."""
    length, name, index = m.groups()
    value = env.get(name, UNKNOWN)
    if isinstance(value, str):
        value = (value,)  # a plain variable is an array of one
    if not isinstance(value, tuple):
        return UNKNOWN
    if length:
        return str(len(value)) if index in "@*" else UNKNOWN
    if index == "@":
        return value
    if index == "*":
        return " ".join(value) if all(isinstance(v, str) for v in value) else UNKNOWN  # type: ignore[arg-type]
    return value[int(index)] if int(index) < len(value) else ""


def _value(word: str, env: Env) -> object:
    """A word's value: a string, STRANGER or UNKNOWN; ``"${a[@]}"`` alone gives the array's
    elements as a tuple."""
    whole = _NAME.fullmatch(word)
    if whole:
        value = env.get(whole.group(1) or whole.group(2), UNKNOWN)
        if isinstance(value, tuple):
            return value[0] if value else ""  # $a is the first element
        return UNKNOWN if isinstance(value, _Sub) else value
    if array := _ARRAY_REF.fullmatch(word):
        return _array_ref(array, env)
    parts, pos = [], 0
    for m in sorted([*_NAME.finditer(word), *_ARRAY_REF.finditer(word)], key=lambda m: m.start()):
        if m.start() < pos:
            continue
        if m.re is _ARRAY_REF:
            value = _array_ref(m, env)
            if isinstance(value, tuple):
                value = " ".join(value) if all(isinstance(v, str) for v in value) else UNKNOWN  # type: ignore[arg-type]
        else:
            value = env.get(m.group(1) or m.group(2), UNKNOWN)
            if isinstance(value, tuple):
                value = value[0] if value else ""
        if not isinstance(value, str):
            return UNKNOWN
        parts += [word[pos : m.start()], value]
        pos = m.end()
    # A `$` before nothing it could expand is just a `$` (`^(A|B)$`).
    return UNKNOWN if _EXPANSION.search(word[pos:]) else "".join(parts) + word[pos:]


def _equal(a: object, b: object) -> bool | None:
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if (a is STRANGER and isinstance(b, str)) or (b is STRANGER and isinstance(a, str)):
        return False  # a stranger's login is none of the names written down
    return None


def _not(value: bool | None) -> bool | None:
    return None if value is None else not value


def _compare(a: object, op: str, b: object, glob: bool) -> bool | None:
    if op in ("=", "=="):
        if glob and isinstance(b, str) and any(c in b for c in "*?["):
            return fnmatch.fnmatchcase(a, b) if isinstance(a, str) else None
        return _equal(a, b)
    if op == "!=":
        return _not(_compare(a, "=", b, glob))
    if op == "=~":
        if isinstance(a, str) and isinstance(b, str):
            try:
                return re.search(b, a) is not None
            except re.error:
                return None
        return None
    return None  # -eq, -lt, file tests...


class _Test:
    """``[ ... ]``, ``test ...`` (``glob`` False) or ``[[ ... ]]`` (``glob`` True)."""

    def __init__(self, words: list[str], env: Env, glob: bool) -> None:
        self.words, self.env, self.glob, self.i = words, env, glob, 0

    def peek(self) -> str | None:
        return self.words[self.i] if self.i < len(self.words) else None

    def take(self) -> str:
        if self.i >= len(self.words):
            raise Unsupported("test ends early")
        self.i += 1
        return self.words[self.i - 1]

    def run(self) -> bool | None:
        if not self.words:
            return False
        result = self.or_()
        if self.peek() is not None:
            raise Unsupported(f"test: unexpected {self.peek()!r}")
        return result

    def or_(self) -> bool | None:
        value = self.and_()
        while self.peek() in ("||", "-o"):
            self.i += 1
            right = self.and_()
            value = True if True in (value, right) else (False if value is False and right is False else None)
        return value

    def and_(self) -> bool | None:
        value = self.not_()
        while self.peek() in ("&&", "-a"):
            self.i += 1
            right = self.not_()
            value = False if False in (value, right) else (True if value and right else None)
        return value

    def not_(self) -> bool | None:
        if self.peek() == "!":
            self.i += 1
            return _not(self.not_())
        return self.primary()

    def primary(self) -> bool | None:
        if self.peek() == "(":
            self.i += 1
            value = self.or_()
            if self.take() != ")":
                raise Unsupported("test: expected ')'")
            return value
        if self.peek() in ("-z", "-n") and self.i + 1 < len(self.words):
            op = self.take()
            value = _value(self.take(), self.env)
            empty = (value == "") if isinstance(value, str) else (False if value is STRANGER else None)
            return empty if op == "-z" else _not(empty)
        left = self.take()
        op = self.peek()
        if op in ("=", "==", "!=", "=~") or (op or "").startswith("-") and op not in ("-a", "-o"):
            self.i += 1
            if op == "=~":
                right = self._regex()
            else:
                right = _value(self.take(), self.env)
            return _compare(_value(left, self.env), op, right, self.glob)
        value = _value(left, self.env)
        return (value != "") if isinstance(value, str) else (True if value is STRANGER else None)

    def _regex(self) -> object:
        """``[[ x =~ ^(A|B)$ ]]``: the tokenizer split the regex at ``(``, ``|`` and ``)``."""
        parts, depth = [], 0
        while (token := self.peek()) is not None and not (depth == 0 and token in ("&&", "||", ")")):
            depth += token == "("
            depth -= token == ")" and depth > 0
            parts.append(self.take())
        return _value("".join(parts), self.env) if parts else UNKNOWN


def _both(env: Env, errexit: bool) -> list[Result]:
    return [(True, errexit, env), (False, errexit, env)]


def _status(value: bool | None, env: Env) -> list[Result]:
    return _both(env, True) if value is None else [(value, True, env)]


def _assignment(word: str, env: Env) -> tuple[str, object]:
    """``name=value``, ``name+=value``, ``name=(a b)``, ``name+=(c)``: the name and its new
    value."""
    assign = _ASSIGNMENT.fullmatch(word)
    assert assign is not None
    name, append, text = assign.groups()
    old = env.get(name, UNKNOWN)
    if isinstance(word, _ArrayWord):
        items: list[object] = []
        for item in word.items:
            value = _value(item, env)
            if isinstance(value, tuple):
                items += value
            elif re.fullmatch(r"\[.*\]=.*", item):
                return name, UNKNOWN  # [key]=value: an associative array
            else:
                items.append(value)
        if append:
            if isinstance(old, str):
                old = (old,)
            return name, (*old, *items) if isinstance(old, tuple) else UNKNOWN
        return name, tuple(items)
    value = _value(text, env)
    if append:
        if isinstance(old, tuple):  # a+=x appends to the first element
            old = old[0] if old else ""
        value = old + value if isinstance(old, str) and isinstance(value, str) else UNKNOWN
    return name, value


def _api_answers(text: str, env: Env) -> list[tuple[bool, object]] | None:
    """What a permission API call (``gh api .../collaborators/<user>/permission``, maybe with
    ``--jq``, ``| jq``, ``|| echo X``) gives a stranger: (whether it succeeds, its output) for
    each case. None if ``text`` isn't such a call about the commenter."""
    user = _API_USER.search(text)
    if not _GH_API.search(text) or user is None or _value(user.group(1), env) is not STRANGER:
        return None
    fallback = _FALLBACK.search(text)
    call = text[: fallback.start()] if fallback else text
    field = _JQ_FIELD.search(call)
    if field is None and _ANY_JQ.search(call):
        return None  # another jq filter: its output is unknown
    if field is None:
        answers: list[tuple[bool, object]] = [(True, STRANGER)]  # JSON: equal to no word written
    elif (field.group(1) or field.group(2)) in ("permission", "role_name"):
        answers = [(True, "none"), (True, "read")]
    else:
        return None
    if fallback is None:
        answers.append((False, ""))
    else:
        # gh may print the error first: the output is the fallback, or something unlike any word.
        answers += [(True, fallback.group(1) or ""), (True, STRANGER)]
    _API_SEEN.set(True)
    return answers


def _grep(words: list[str], value: object) -> bool | None:
    """Whether ``grep [-qEiwxFs] PATTERN`` finds a line in ``value``."""
    flags, pattern = "", None
    for word in words[1:]:
        if pattern is None and word.startswith("-") and len(word) > 1:
            flags += word[1:]
        elif pattern is None:
            pattern = word
        else:
            return None  # a file to read
    if pattern is None or set(flags) - set("qEiwxFs"):
        return None
    if not isinstance(value, str):
        return None
    if "F" in flags:
        regex = re.escape(pattern)
    elif "E" in flags:
        regex = pattern
    else:  # basic regex: \| \( \) \+ \? are the operators, the bare ones are literal
        regex = re.sub(r"\\([|()+?{}])|([|()+?{}])", lambda m: m.group(1) or "\\" + m.group(2), pattern)
    if "w" in flags:
        regex = rf"\b(?:{regex})\b"
    try:
        compiled = re.compile(regex, re.IGNORECASE if "i" in flags else 0)
    except re.error:
        return None
    lines = value.split("\n")
    if "x" in flags:
        return any(compiled.fullmatch(line) for line in lines)
    return any(compiled.search(line) for line in lines)


def _api_pipe(commands: list, env: Env) -> list[Result] | None:
    """``gh api .../permission [--jq ...] [| jq -r .permission] | grep -q PATTERN``: its status
    for each answer (no pipefail: the last command's status, and grep reads nothing after a
    failed call). None for any other pipeline."""
    if not all(isinstance(c, _Simple) for c in commands) or commands[-1].words[0] != "grep":
        return None
    if _grep(commands[-1].words, "") is None:
        return None  # a grep it doesn't follow
    answers = _api_answers(" | ".join(" ".join(c.words) for c in commands[:-1]), env)
    if answers is None:
        return None
    results: list[Result] = []
    for _ok, output in answers:
        found = _grep(commands[-1].words, output)  # a failed call's output is empty
        results += _status(found, env)
    return results


def _simple(command: _Simple, env: Env) -> tuple[set[str], list[Result]]:
    words = command.words
    if len(words) == 1 and (assign := _ASSIGNMENT.fullmatch(words[0])) and not assign.group(2):
        name, _, value = assign.groups()
        whole = _NAME.fullmatch(value)
        sub = env.get(whole.group(1) or whole.group(2)) if whole else None
        answers = _api_answers(sub.inner, env) if isinstance(sub, _Sub) else None
        if answers is not None:  # the assignment's status is the command's
            return set(), [(ok, True, {**env, name: output}) for ok, output in answers]
        if isinstance(sub, _Sub) and whole is not None:
            captured = _captured(name, whole.group(1) or whole.group(2), sub, env)
            if captured is not None:
                return set(), captured
    if all(_ASSIGNMENT.fullmatch(word) for word in words):
        env = dict(env)
        for word in words:
            name, value = _assignment(word, env)
            env[name] = value
        # With a command substitution, the status is the command's: unknown ($((...)) succeeds).
        commands = [
            ref
            for word in words
            for ref in re.findall(r"\$\{(" + _COMMAND + r"\w*)\}", word)
            if isinstance(env.get(ref), _Sub) and not env[ref].inner.startswith("(")  # type: ignore[union-attr]
        ]
        return set(), _both(env, True) if commands else [(True, True, env)]
    while len(words) > 1 and _ASSIGNMENT.fullmatch(words[0]):
        words = words[1:]  # `IFS=, read -r a b`: the assignment only lasts for the command
    name, args = words[0], words[1:]
    if name in ("break", "continue"):
        if not env.get(_LOOPS) or args not in ([], ["1"]):
            raise Unsupported(f"{name} outside a loop or out of more than one")
        return set(), [(True, False, {**env, _BREAK if name == "break" else _CONTINUE: True})]
    changed = _sets(name, args, env)
    if changed is not None:
        return set(), _status(None, changed) if name == "read" else [(True, True, changed)]
    function = env.get(_FUNCTION + name)
    if isinstance(function, _Function):
        return _call(function, args, env)
    if name == "return":
        if not env.get(_DEPTH):
            raise Unsupported("return outside a function")
        code = _value(args[0], env) if args else UNKNOWN
        statuses = [int(code) % 256 == 0] if isinstance(code, str) and code.isdigit() else [True, False]
        return set(), [(ok, False, {**env, _RETURNED: ok}) for ok in statuses]
    if name == "local":
        if not env.get(_DEPTH):
            raise Unsupported("local outside a function")
        env = dict(env)
        for word in args:
            if word.startswith("-"):
                continue  # local -a, -r...
            assign = _ASSIGNMENT.fullmatch(word)
            local = assign.group(1) if assign else word
            if not re.fullmatch(r"[A-Za-z_]\w*", local):
                raise Unsupported(f"local {word!r}")
            env[_LOCALS] = (*env.get(_LOCALS, ()), local)
            env[local] = _assignment(word, env)[1] if assign else ""
        return set(), [(True, True, env)]
    if name == "exit":
        if env.get(_SUBSHELL):
            raise Unsupported("exit in $(...)")
        code = _value(args[0], env) if args else UNKNOWN
        ends = (
            {FAIL if int(code) % 256 else PASS}
            if isinstance(code, str) and code.lstrip("-").isdigit()
            else {FAIL, PASS}
        )
        passed = _PASSED.get()
        if PASS in ends and passed is not None:
            passed.append(env)
        return ends, []
    if name in ("echo", "printf") and (command.output or env.get(_TO_OUTPUT)):
        return set(), [(True, True, _write(name, args, env))]
    if name == "((":
        # Arithmetic: its status is unknown; if it assigns, its variables become unknown.
        text = " ".join(args)
        if re.search(r"\+\+|--|(?<![=!<>])=(?!=)|[-+*/%]=", text):
            env = {**env, **dict.fromkeys(re.findall(r"[A-Za-z_]\w*", text), UNKNOWN)}
        return set(), _both(env, True)
    if _STDOUT in env and name in ("echo", "printf"):
        return set(), [(True, True, _emit(env, _printed(name, args, env)))]
    if _STDOUT in env and name == "gh":
        answers = _api_answers(*_with_argv(words, env))
        if answers is not None:
            return set(), [
                (ok, True, _emit(env, piece))
                for ok, output in answers
                for piece in (_printed_answer(output) if ok else ["", _NOT_FOUND])
            ]
    if name in ("true", ":", "echo", "printf"):
        return set(), [(True, True, env)]
    if name == "false":
        return set(), [(False, True, env)]
    if name == "set":
        env = dict(env)
        for flag in args:
            if re.fullmatch(r"[-+][a-zA-Z]*e[a-zA-Z]*", flag):
                env[_ERREXIT] = flag[0] == "-"
        if "errexit" in args:
            env[_ERREXIT] = args[args.index("errexit") - 1] == "-o"
        return set(), [(True, True, env)]
    if name == "[":
        if not args or args[-1] != "]":
            raise Unsupported("[ without ]")
        return set(), _status(_Test(args[:-1], env, glob=False).run(), env)
    if name == "test":
        return set(), _status(_Test(args, env, glob=False).run(), env)
    if name == "[[":
        return set(), _status(_Test(args[:-1], env, glob=True).run(), env)
    if _STDOUT in env and not _silent(words):
        env = {**env, _STDOUT: UNKNOWN}  # it may print anything
    return set(), _both(env, True)


def _silent(words: list[str]) -> bool:
    """Whether the command prints nothing (``sleep``, ``grep -q``...)."""
    name = words[0]
    return name in _SILENT or (name == "grep" and any(re.fullmatch(r"-\w*q\w*", w) for w in words[1:]))


def _emit(env: Env, piece: object) -> Env:
    """Adds ``piece`` to what was printed inside ``$(...)``."""
    out = env[_STDOUT]
    if piece == "":
        return env
    if out == "":
        return {**env, _STDOUT: piece}
    if piece == _NOT_FOUND and isinstance(out, str) and out.endswith(_NOT_FOUND):
        return env  # a retried call: one error body stands for any number (the loop settles)
    if isinstance(out, str) and isinstance(piece, str):
        return {**env, _STDOUT: out + piece}
    return {**env, _STDOUT: UNKNOWN}


def _printed(name: str, args: list[str], env: Env) -> object:
    """What ``echo``/``printf`` prints: a string, STRANGER (a login alone) or UNKNOWN."""
    if name == "echo":
        words, newline, escapes = list(args), "\n", False
        while words and re.fullmatch(r"-[neE]+", words[0]):
            flags = words.pop(0)
            newline = "" if "n" in flags else newline
            escapes = escapes or "e" in flags
        values: list[object] = []
        for word in words:
            value = _value(word, env)
            values += value if isinstance(value, tuple) else [value]
        if values == [STRANGER]:
            return STRANGER
        if not all(isinstance(v, str) for v in values):
            return UNKNOWN
        text = " ".join(values) + newline  # type: ignore[arg-type]
        return UNKNOWN if escapes and "\\" in text else text
    fmt = _value(args[0], env) if args else ""
    rest = [_value(word, env) for word in args[1:]]
    if fmt in ("%s", "%s\\n") and len(rest) == 1:
        if rest == [STRANGER]:
            return STRANGER
        return rest[0] + ("\n" if fmt == "%s\\n" else "") if isinstance(rest[0], str) else UNKNOWN
    if isinstance(fmt, str) and not rest and "%" not in fmt and "\\" not in fmt.removesuffix("\\n"):
        return fmt.removesuffix("\\n") + ("\n" if fmt.endswith("\\n") else "")
    return UNKNOWN


def _printed_answer(output: object) -> list[object]:
    """What a permission call that succeeded prints: its answer on a line."""
    return [output + "\n" if isinstance(output, str) else output]


def _with_argv(words: list[str], env: Env) -> tuple[str, Env]:
    """A command's text with ``"$@"`` written out as the function's arguments were (a wrapper
    like ``gh_retry api ...`` that runs ``gh "$@"``), and the values those arguments read."""
    argv = env.get(_ARGV)
    if not isinstance(argv, tuple):
        return " ".join(words), env
    written, values = argv
    out: list[str] = []
    for word in words:
        out += list(written) if word in ("$@", "$*") else [word]
    return " ".join(out), {**env, **dict(values)}


def _captured(name: str, sub_name: str, sub: _Sub, env: Env) -> list[Result] | None:
    """``name=$(f ...)`` when ``f`` is a function: runs it in a subshell and keeps what it
    prints. None if the substitution starts with something else, or isn't followed."""
    try:
        text, subs = _prepare(sub.inner, sub_name + "_")
        tree = _Parser(_tokens(text)).program()
    except Unsupported:
        return None
    first = tree[0].first.commands[0] if tree else None
    if isinstance(first, _Redirected):
        first = first.node
    if not isinstance(first, _Simple):
        return None
    head = next((w for w in first.words if not _ASSIGNMENT.fullmatch(w)), None)
    if head is None or not isinstance(env.get(_FUNCTION + head), _Function):
        return None
    seen = _API_SEEN.get()
    # A subshell: `set -e` isn't inherited; only what it prints and writes to files comes back.
    inner = {**env, **subs, _STDOUT: "", _SUBSHELL: True, _ERREXIT: False, _TO_OUTPUT: None, _LOOPS: 0}
    try:
        ends, results = _seq_status(tree, inner)
    except Unsupported:
        _API_SEEN.set(seen)
        return None
    if ends:
        _API_SEEN.set(seen)
        return None
    out: list[Result] = []
    for status, _, after in results:
        value = after.get(_STDOUT, UNKNOWN)
        if isinstance(value, str):
            value = value.rstrip("\n")
        written = {k: v for k, v in after.items() if k.startswith(_OUT) or k == _OUT_UNKNOWN}
        out.append((status, True, {**env, **written, name: value}))
    return out


def _write(name: str, args: list[str], env: Env) -> Env:
    """``echo``/``printf`` to $GITHUB_OUTPUT: one ``name=value`` line becomes an output; anything
    else (several lines, ``name<<EOF``, a format it doesn't follow) makes the outputs unknown."""
    env = dict(env)
    if name == "echo":
        words = list(args)
        while words and re.fullmatch(r"-[neE]+", words[0]):
            words.pop(0)
        line = " ".join(words)
    else:
        fmt, rest = (args[0], args[1:]) if args else ("", [])
        named = re.fullmatch(r"([A-Za-z_][\w-]*)=%s(?:\\n)?", fmt)
        if named and len(rest) == 1:
            line = f"{named.group(1)}={rest[0]}"
        elif fmt in ("%s", "%s\\n") and len(rest) == 1:
            line = rest[0]
        elif "%" not in fmt and not rest:
            line = fmt.removesuffix("\\n")
        else:
            env[_OUT_UNKNOWN] = True
            return env
    assign = re.fullmatch(r"([A-Za-z_][\w-]*)=(.*)", line, re.DOTALL)
    if assign is None or "\n" in line or "\\n" in line:
        if line.strip():
            env[_OUT_UNKNOWN] = True
        return env
    env[_OUT + assign.group(1)] = _value(assign.group(2), env)
    return env


def _jumped(env: Env) -> bool:
    """The path ran ``return``, ``break`` or ``continue``: the rest of its block is skipped."""
    return _RETURNED in env or _BREAK in env or _CONTINUE in env


def _sets(name: str, args: list[str], env: Env) -> Env | None:
    """Commands that set variables: the new variables, or None for any other command."""
    if name in _UNFOLLOWED:
        raise Unsupported(name)
    if name == "read":
        env, names, i = dict(env), [], 0
        while i < len(args):
            word = args[i]
            if word.startswith("-") and len(word) > 1:
                if "a" in word:
                    raise Unsupported("read -a")
                if word[-1] in "pdtnNu":
                    i += 1  # the option's value
            else:
                names.append(word)
            i += 1
        for var in names or ["REPLY"]:
            env[var] = UNKNOWN
        return env
    if name in ("export", "declare", "typeset", "readonly"):
        env, plain = dict(env), True
        for word in args:
            if word.startswith("-"):
                if set(word[1:]) - set("xrgpa"):
                    plain = False  # -i, -l, -u... change the value; -A, -n make maps and refs
                continue
            if _ASSIGNMENT.fullmatch(word):
                name_, value = _assignment(word, env)
                env[name_] = value if plain else UNKNOWN
        return env
    if name == "unset":
        env = dict(env)
        functions = "-f" in args
        for word in args:
            if not word.startswith("-"):
                env.pop(_FUNCTION + word, None) if functions else env.update({word: ""})
        return env
    if name in ("mapfile", "readarray"):
        names, i = [], 0
        while i < len(args):
            if args[i].startswith("-") and len(args[i]) > 1:
                i += 2 if args[i][-1] in "dnOsuCc" else 1
                continue
            names.append(args[i])
            i += 1
        return {**env, (names[-1] if names else "MAPFILE"): UNKNOWN}
    if name == "printf" and len(args) > 1 and args[0] == "-v":
        return {**env, args[1]: UNKNOWN}
    return None


def _call(function: _Function, args: list[str], env: Env) -> tuple[set[str], list[Result]]:
    """Runs a function's body where it's called: ``$1``... from ``args``; afterwards ``$1``...
    and its ``local`` variables are put back. Its status is ``return``'s, or its last
    command's; ``set -e`` acts on it like on any command."""
    depth = int(env.get(_DEPTH) or 0)  # type: ignore[call-overload]
    if depth >= _MAX_DEPTH:
        raise Unsupported("functions too deep")
    inner = {**env, _DEPTH: depth + 1, _LOCALS: (), _ARGV: _argv(args, env, depth)}
    for i, name in enumerate(_POSITIONAL):
        inner[name] = _value(args[i], env) if i < len(args) else ""
    ends, results = _seq_status(function.body, inner)
    out: list[Result] = []
    for status, _, after in results:
        after = dict(after)
        status = after.pop(_RETURNED, status)  # type: ignore[assignment]
        for name in (*_POSITIONAL, *after.get(_LOCALS, ())):  # type: ignore[misc]
            if name in env:
                after[name] = env[name]
            else:
                after.pop(name, None)
        for key in (_DEPTH, _LOCALS, _ARGV):
            if key in env:
                after[key] = env[key]
            else:
                after.pop(key, None)
        out.append((bool(status), True, after))
    return ends, out


def _argv(args: list[str], env: Env, depth: int) -> tuple[tuple[str, ...], tuple[tuple[str, object], ...]]:
    """A call's arguments as written, for ``"$@"`` in the function: each variable they read is
    renamed (``$X`` -> ``$__WG_ARGV<depth>_X``) and its value kept, so the function's own
    variables can't change them."""
    outer = env.get(_ARGV)
    written: list[str] = []
    values: dict[str, object] = {}
    prefix = f"{_ARGV_NAME}{depth}_"

    def rename(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        values[prefix + name] = env.get(name, UNKNOWN)
        return "${" + prefix + name + "}"

    def rename_array(m: re.Match[str]) -> str:
        length, name, index = m.groups()
        values[prefix + name] = env.get(name, UNKNOWN)
        return "${" + length + prefix + name + "[" + index + "]}"

    for arg in args:
        if arg in ("$@", "$*"):
            if isinstance(outer, tuple):
                written += outer[0]
                values.update(outer[1])
            continue
        written.append(_NAME.sub(rename, _ARRAY_REF.sub(rename_array, arg)))
    return tuple(written), tuple(sorted(values.items(), key=lambda kv: kv[0]))


def _match(value: object, pattern: str) -> bool | None:
    if pattern == "*":
        return True
    pattern_value = _value(pattern, {})
    if not isinstance(pattern_value, str):
        return None
    if isinstance(value, str):
        return fnmatch.fnmatchcase(value, pattern_value)
    if value is STRANGER and not any(c in pattern_value for c in "*?["):
        return False
    return None


def _redirected(node: object, quiet: bool, merged: bool, env: Env) -> tuple[set[str], list[Result]]:
    """Inside ``$(...)``: a command whose output goes elsewhere prints nothing; with ``2>&1``
    its errors are printed too (unknown)."""
    out = UNKNOWN if merged else env[_STDOUT]
    ends, results = _command(node, env)
    return ends, [(status, flag, {**after, _STDOUT: out}) for status, flag, after in results]


def _command(command: object, env: Env) -> tuple[set[str], list[Result]]:
    if isinstance(command, _Redirected):
        if _STDOUT not in env:
            return _command(command.node, env)
        return _redirected(command.node, command.quiet, command.merged, env)
    if isinstance(command, _Simple):
        if (command.quiet or command.merged) and _STDOUT in env:
            plain = _Simple(command.words, command.output)
            return _redirected(plain, command.quiet, command.merged, env)
        return _simple(command, env)
    if isinstance(command, _If):
        return _if(command.branches, command.otherwise, env)
    if isinstance(command, _Case):
        return _case(command, env)
    if isinstance(command, _Group):
        inner = {**env, _TO_OUTPUT: True} if command.output else env
        ends, results = _seq_status(command.body, inner)
        if command.output:
            results = [
                (status, last, {**after, _TO_OUTPUT: env.get(_TO_OUTPUT)}) for status, last, after in results
            ]
        return ends, [(status, last and not _jumped(after), after) for status, last, after in results]
    if isinstance(command, _Define):
        return set(), [(True, True, {**env, _FUNCTION + command.name: _Function(command.body)})]
    if isinstance(command, (_For, _While)):
        inner = {**env, _LOOPS: int(env.get(_LOOPS) or 0) + 1}  # type: ignore[call-overload]
        if command.output:
            inner[_TO_OUTPUT] = True
        ends, paths = _for(command, inner) if isinstance(command, _For) else _while(command, inner)
        out = []
        for after in paths:
            after = {**after, _LOOPS: env.get(_LOOPS), _TO_OUTPUT: env.get(_TO_OUTPUT)}
            after.pop(_BREAK, None)
            out.append(after)
        return _after_compound(ends, _dedupe(out))
    raise Unsupported(type(command).__name__)


def _round(body: list, frontier: list[Env]) -> tuple[set[str], list[Env], list[Env]]:
    """Runs a loop's body once from each path: the exits, the paths that go round again, and the
    paths that leave the loop (``break``, or ``return`` from the function around it)."""
    ends, out = _run_seq(body, frontier)
    again, leave = [], []
    for after in out:
        if _BREAK in after or _RETURNED in after:
            leave.append(after)
        else:
            after = dict(after)
            after.pop(_CONTINUE, None)
            again.append(after)
    return ends, again, leave


def _for(node: _For, env: Env) -> tuple[set[str], list[Env]]:
    """``for``: once per word when the words are known (no `$`, no glob, nothing that splits);
    otherwise rounds with the variable unknown until no new state turns up."""
    values: list[object] | None = None
    if node.words is not None:
        values = []
        for word in node.words:
            value = _value(word, env)
            if isinstance(value, tuple):
                values += value  # "${a[@]}": the elements, as they are
            elif isinstance(value, str) and any(c in value for c in " \t\n*?["):
                values.append(UNKNOWN)  # it splits or globs into words of its own
            else:
                values.append(value)
    if values is not None and all(isinstance(v, str) for v in values):
        ends: set[str] = set()
        frontier, done = [env], []
        for value in values:
            more, frontier, leave = _round(node.body, [{**path, node.name: value} for path in frontier])
            ends |= more
            done += leave
            if not frontier:
                break
        return ends, done + frontier
    return _rounds(lambda path: ([{**path, node.name: UNKNOWN}], []), node.body, env, anytime=True)


def _while(node: _While, env: Env) -> tuple[set[str], list[Env]]:
    """``while``/``until``: the condition decides each round (``set -e`` doesn't act in it)."""
    ends: set[str] = set()

    def test(path: Env) -> tuple[list[Env], list[Env]]:
        more, results = _seq_status(node.condition, {**path, _ERREXIT: False})
        ends.update(more)
        go, stop = [], []
        for status, _, after in results:
            after = {**after, _ERREXIT: path[_ERREXIT]}
            (go if status != node.until else stop).append(after)
        return go, stop

    more, paths = _rounds(test, node.body, env)
    return ends | more, paths


def _rounds(
    start: Callable[[Env], tuple[list[Env], list[Env]]], body: list, env: Env, anytime: bool = False
) -> tuple[set[str], list[Env]]:
    """Runs a loop until no new state turns up: ``start`` turns a path into the paths that run
    the body and the paths that leave before it. ``anytime``: the loop may also end before any
    round (a ``for`` over words it can't count)."""
    ends: set[str] = set()
    seen = {_key(env)}
    frontier, done = [env], []
    for _ in range(_MAX_ROUNDS):
        go: list[Env] = []
        for path in frontier:
            if anytime:
                done.append(path)
            run, stop = start(path)
            go += run
            done += stop
        if not go:
            return ends, done
        more, again, leave = _round(body, _dedupe(go))
        ends |= more
        done += leave
        fresh = [path for path in _dedupe(again) if _key(path) not in seen]
        seen |= {_key(path) for path in fresh}
        frontier = fresh
        if not frontier:
            return ends, done
    raise Unsupported("a loop that doesn't settle")


def _after_compound(ends: set[str], paths: list[Env]) -> tuple[set[str], list[Result]]:
    """A compound command's status isn't followed: both, and `set -e` doesn't act on it."""
    return ends, [result for env in paths for result in _both(env, False)]


def _if(branches: list, otherwise: list | None, env: Env) -> tuple[set[str], list[Result]]:
    if not branches:
        if otherwise is None:
            return set(), [(True, False, env)]
        return _after_compound(*_run_seq(otherwise, [env]))
    condition, body = branches[0]
    quiet = {**env, _ERREXIT: False}  # `set -e` doesn't act inside a condition
    ends, results = _seq_status(condition, quiet)
    paths: list[Env] = []
    for status, _, after in results:
        after = {**after, _ERREXIT: env[_ERREXIT]}
        if status:
            more, out = _run_seq(body, [after])
            ends |= more
            paths += out
        else:
            more, rest = _if(branches[1:], otherwise, after)
            ends |= more
            paths += [r[2] for r in rest]
    return _after_compound(ends, paths)


def _case(command: _Case, env: Env) -> tuple[set[str], list[Result]]:
    value = _value(command.word, env)
    ends: set[str] = set()
    paths: list[Env] = []
    for patterns, body in command.items:
        matches = [_match(value, pattern) for pattern in patterns]
        if True in matches:
            more, out = _run_seq(body, [env])
            return _after_compound(ends | more, paths + out)
        if None in matches:
            more, out = _run_seq(body, [env])
            ends |= more
            paths += out
    return _after_compound(ends, paths + [env])


def _pipe(pipe: _Pipe, env: Env, last: bool = True) -> tuple[set[str], list[Result]]:
    """``last``: the pipeline is the last of its ``&&``/``||`` list. If not, or if negated,
    ``set -e`` doesn't act inside it (in a function or a group it runs)."""
    if (not last or pipe.negated) and env.get(_ERREXIT):
        ends, results = _pipe(_Pipe(pipe.negated, pipe.commands), {**env, _ERREXIT: False}, True)
        return ends, [(status, flag, {**after, _ERREXIT: True}) for status, flag, after in results]
    if len(pipe.commands) > 1:  # each part runs in a subshell: an exit there ends only that part
        ends, results = set(), _api_pipe(pipe.commands, env) or _both(env, True)
        last = pipe.commands[-1]
        if _STDOUT in env and not (isinstance(last, _Simple) and (last.quiet or _silent(last.words))):
            results = [(status, flag, {**after, _STDOUT: UNKNOWN}) for status, flag, after in results]
    else:
        ends, results = _command(pipe.commands[0], env)
    if pipe.negated:
        results = [(not status, False, after) for status, _, after in results]
    return ends, results


def _and_or(command: _AndOr, env: Env) -> tuple[set[str], list[Result]]:
    ends, results = _pipe(command.first, env, last=not command.rest)
    for i, (op, pipe) in enumerate(command.rest):
        nxt: list[Result] = []
        for status, _, after in results:
            if _jumped(after):
                nxt.append((status, False, after))
            elif status == (op == "&&"):
                more, out = _pipe(pipe, after, last=i == len(command.rest) - 1)
                ends |= more
                nxt += out
            else:
                nxt.append((status, False, after))  # `set -e` skips all but the last in a list
        results = nxt
    return ends, results


def _key(env: Env) -> tuple:
    return tuple(sorted((k, repr(v)) for k, v in env.items()))


def _dedupe(paths: list[Env]) -> list[Env]:
    seen, out = set(), []
    for env in paths:
        key = _key(env)
        if key not in seen:
            seen.add(key)
            out.append(env)
    if len(out) > _MAX_PATHS:
        raise Unsupported("too many paths")
    return out


def _run_seq(seq: list, paths: list[Env]) -> tuple[set[str], list[Env]]:
    """Runs ``seq`` from each of ``paths``: the exits it reaches and the paths that go on."""
    ends: set[str] = set()
    for command in seq:
        nxt: list[Env] = []
        for env in paths:
            if _jumped(env):  # return, break or continue: skip the rest of the block
                nxt.append(env)
                continue
            more, results = _and_or(command, env)
            ends |= more
            for status, errexit, after in results:
                if not status and errexit and after[_ERREXIT]:
                    ends.add(FAIL)
                else:
                    nxt.append(after)
        paths = _dedupe(nxt)
        if not paths:
            break
    return ends, paths


def _seq_status(seq: list, env: Env) -> tuple[set[str], list[Result]]:
    """Like ``_run_seq``, keeping the status of the last command (for an ``if`` condition)."""
    if not seq:
        return set(), [(True, False, env)]
    ends, paths = _run_seq(seq[:-1], [env])
    results: list[Result] = []
    for after in paths:
        if _jumped(after):
            # After break/continue the status is never read (the jumped path skips everything).
            results.append((bool(after.get(_RETURNED, True)), False, after))
            continue
        more, out = _and_or(seq[-1], after)
        ends |= more
        results += out
    return ends, results
