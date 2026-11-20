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

Anything else that changes the flow (loops, functions, subshells, background jobs, heredocs)
makes the script unknown: it doesn't count as a check. Commands it doesn't know succeed or
fail, it doesn't matter which: only an ``exit`` or a failing test decides.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass

from .conditions import STRANGER, UNKNOWN

FAIL, PASS = "fail", "pass"
_ERREXIT = "\0errexit"
_COMMAND = "__WG_CMD"
_MAX_PATHS = 64
_OPS = ("&&", "||", ";;", "<<", ">>", ";", "|", "&", "(", ")", "<", ">", "\n")
_OP_CHARS = ";&|()<>\n"
_UNSUPPORTED = {"for", "while", "until", "select", "function", "{", "(", "((", "do", "done", "return"}
_SEPARATORS = (";", "\n")
_NAME = re.compile(r"\$(?:(\w+)|\{(\w+)\})")
_EXPANSION = re.compile(r"\$[\w{(@*#?!-]")
_ASSIGNMENT = re.compile(r"([A-Za-z_]\w*)=(.*)", re.DOTALL)


class Unsupported(Exception):
    """The script uses something the evaluator doesn't follow."""


def always_fails(script: str, variables: Mapping[str, object]) -> bool:
    """True if ``script`` ends with a non-zero exit on every path, with ``variables`` (name ->
    a string, ``STRANGER`` or ``UNKNOWN``) and every other variable unknown. False when it may
    succeed, or when it uses something the evaluator doesn't follow."""
    try:
        tree = _Parser(_tokens(_prepare(script))).program()
        env: dict[str, object] = {**variables, _COMMAND: UNKNOWN, _ERREXIT: True}
        ends, paths = _run_seq(tree, [env])
    except Unsupported:
        return False
    return not paths and ends == {FAIL}


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


def _prepare(script: str) -> str:
    """Joins ``\\`` continuations, drops comments, and replaces command substitutions
    (``$(...)``, backticks, ``$((...))``) with ``$__WG_CMD``: their output is unknown."""
    text = script.replace("\\\n", " ")
    out: list[str] = []
    i, quote = 0, None
    while i < len(text):
        c = text[i]
        if quote != "'" and text.startswith("$(", i):
            i = _close(text, i + 1) + 1
            out.append("$" + _COMMAND)
            continue
        if quote != "'" and c == "`":
            end = text.find("`", i + 1)
            if end < 0:
                raise Unsupported("unclosed backtick")
            i = end + 1
            out.append("$" + _COMMAND)
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
    return "".join(out)


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


@dataclass
class _If:
    branches: list[tuple[list, list]]  # (condition, body)
    otherwise: list | None


@dataclass
class _Case:
    word: str
    items: list[tuple[list[str], list]]  # (patterns, body)


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
        if token in _UNSUPPORTED:
            raise Unsupported(f"{token!r}")
        if token == "if":
            return self.if_()
        if token == "case":
            return self.case()
        if token == "[[":
            return self.double_test()
        return self.simple()

    def simple(self) -> _Simple:
        words: list[str] = []
        while (token := self.peek()) is not None and token not in _OPS:
            words.append(token)
            self.i += 1
            if self.peek() in ("<", ">", ">>"):  # a redirection: skip it and its target
                self.i += 1
                if self.peek() == "&":
                    self.i += 1
                self.take()
        if self.peek() in ("<", ">", ">>") and not words:
            self.i += 1
            self.take()
            return self.simple()
        if self.peek() == "(":
            raise Unsupported("function definition")
        if not words:
            raise Unsupported(f"unexpected {self.peek()!r}")
        return _Simple(words)

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


def _value(word: str, env: Env) -> object:
    """A word's value: a string, STRANGER or UNKNOWN."""
    whole = _NAME.fullmatch(word)
    if whole:
        return env.get(whole.group(1) or whole.group(2), UNKNOWN)
    parts, pos = [], 0
    for m in _NAME.finditer(word):
        value = env.get(m.group(1) or m.group(2), UNKNOWN)
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


def _simple(command: _Simple, env: Env) -> tuple[set[str], list[Result]]:
    words = command.words
    if all(_ASSIGNMENT.fullmatch(word) for word in words):
        env = dict(env)
        for word in words:
            name, value = _ASSIGNMENT.fullmatch(word).groups()  # type: ignore[union-attr]
            env[name] = _value(value, env)
        return set(), [(True, True, env)]
    name, args = words[0], words[1:]
    if name == "exit":
        code = _value(args[0], env) if args else UNKNOWN
        if isinstance(code, str) and code.lstrip("-").isdigit():
            return {FAIL if int(code) % 256 else PASS}, []
        return {FAIL, PASS}, []
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
    return set(), _both(env, True)


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


def _command(command: object, env: Env) -> tuple[set[str], list[Result]]:
    if isinstance(command, _Simple):
        return _simple(command, env)
    if isinstance(command, _If):
        return _if(command.branches, command.otherwise, env)
    if isinstance(command, _Case):
        return _case(command, env)
    raise Unsupported(type(command).__name__)


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


def _pipe(pipe: _Pipe, env: Env) -> tuple[set[str], list[Result]]:
    if len(pipe.commands) > 1:  # each part runs in a subshell: an exit there ends only that part
        ends, results = set(), _both(env, True)
    else:
        ends, results = _command(pipe.commands[0], env)
    if pipe.negated:
        results = [(not status, False, after) for status, _, after in results]
    return ends, results


def _and_or(command: _AndOr, env: Env) -> tuple[set[str], list[Result]]:
    ends, results = _pipe(command.first, env)
    for op, pipe in command.rest:
        nxt: list[Result] = []
        for status, _, after in results:
            if status == (op == "&&"):
                more, out = _pipe(pipe, after)
                ends |= more
                nxt += out
            else:
                nxt.append((status, False, after))  # `set -e` skips all but the last in a list
        results = nxt
    return ends, results


def _dedupe(paths: list[Env]) -> list[Env]:
    seen, out = set(), []
    for env in paths:
        key = tuple(sorted((k, repr(v)) for k, v in env.items()))
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
        more, out = _and_or(seq[-1], after)
        ends |= more
        results += out
    return ends, results
