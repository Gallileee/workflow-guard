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

Anything else that changes the flow (loops, subshells, background jobs, heredocs) makes the
script unknown: it doesn't count as a check. Commands it doesn't know succeed or
fail, it doesn't matter which: only an ``exit`` or a failing test decides.

The permission API is known too, when it asks about the commenter (a stranger's login):
``P=$(gh api repos/.../collaborators/$USER/permission --jq .permission)`` gives ``none`` or
``read``, or the command fails (a non-collaborator can get a 404), which ends the script under
``-e`` (or takes the ``else`` of ``if P=$(...)``). ``|| echo X`` turns the failure into ``X``
(maybe after gh's error text); without ``--jq``/``jq`` the answer is JSON, equal to no word.
``gh api ... | grep -q PATTERN`` is followed the same way. ``api_fails`` tells whether such a
script exits for a stranger, and None when no such call was followed.
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass

from .conditions import STRANGER, UNKNOWN

FAIL, PASS = "fail", "pass"
_ERREXIT = "\0errexit"
_COMMAND = "__WG_CMD"
_MAX_PATHS = 64
_OPS = ("&&", "||", ";;", "<<", ">>", ";", "|", "&", "(", ")", "<", ">", "\n")
_OP_CHARS = ";&|()<>\n"
_UNSUPPORTED = {"for", "while", "until", "select", "(", "((", "do", "done"}
_RETURNED = "\0return"  # set on a path that ran `return`: the status it returned
_DEPTH = "\0depth"  # how many function calls deep
_LOCALS = "\0locals"  # names declared `local` in the current call
_FUNCTION = "\0function:"
_MAX_DEPTH = 8
_POSITIONAL = tuple(str(i) for i in range(1, 10))
_SEPARATORS = (";", "\n")
_NAME = re.compile(r"\$(?:(\w+)|\{(\w+)\})")
_EXPANSION = re.compile(r"\$[\w{(@*#?!-]")
_ASSIGNMENT = re.compile(r"([A-Za-z_]\w*)=(.*)", re.DOTALL)
_GH_API = re.compile(r"\bgh\s+api\b")
_API_USER = re.compile(r"collaborators/([^/\s\"']+)/permission")
_JQ_FIELD = re.compile(
    r"(?:--jq|-q)[\s=]+['\"]?\.(\w+)['\"]?(?=\s|$)|\|\s*jq\s+(?:-r\s+)?['\"]?\.(\w+)['\"]?\s*$"
)
_ANY_JQ = re.compile(r"(?:--jq|-q)(?:\s|=)|\|\s*jq\b")
_FALLBACK = re.compile(r"\|\|\s*(?:echo\s+['\"]?([\w-]*)['\"]?|(true|:))\s*$")
_API_SEEN: ContextVar[bool] = ContextVar("api_seen", default=False)


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


def _analyse(script: str, variables: Mapping[str, object]) -> tuple[bool, bool] | None:
    """(fails on every path, a permission API call was followed), or None if unsupported."""
    token = _API_SEEN.set(False)
    try:
        text, subs = _prepare(script)
        tree = _Parser(_tokens(text)).program()
        # GitHub runs the script file without arguments: $1... are empty.
        env: dict[str, object] = {**dict.fromkeys(_POSITIONAL, ""), **variables, **subs, _ERREXIT: True}
        ends, paths = _run_seq(tree, [env])
        return not paths and ends == {FAIL}, _API_SEEN.get()
    except Unsupported:
        return None
    finally:
        _API_SEEN.reset(token)


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


def _prepare(script: str) -> tuple[str, dict[str, _Sub]]:
    """Joins ``\\`` continuations, drops comments, and replaces each command substitution
    (``$(...)``, backticks, ``$((...))``) with a variable ``$__WG_CMD<n>`` holding its text."""
    text = script.replace("\\\n", " ")
    out: list[str] = []
    subs: dict[str, _Sub] = {}

    def substitute(inner: str) -> None:
        name = f"{_COMMAND}{len(subs)}"
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
        compound = {"if": self.if_, "case": self.case, "[[": self.double_test, "{": self.group}
        if token in compound:
            node = compound[token]()
            self.redirections()  # `} >> "$GITHUB_OUTPUT"`, `fi 2>&1`
            return node
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

    def redirections(self) -> None:
        """Skips redirections after a compound command (their target is only written)."""
        while self.peek() in (">", ">>") or (
            self.peek() not in (None, *_OPS) and self.tokens[self.i + 1 : self.i + 2] in ([">"], [">>"])
        ):
            if self.peek() not in (">", ">>"):
                self.i += 1  # a file descriptor: 2>
            self.i += 1
            if self.peek() == "&":
                self.i += 1
            self.take()

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
            raise Unsupported("( after a word")
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
        value = env.get(whole.group(1) or whole.group(2), UNKNOWN)
        return UNKNOWN if isinstance(value, _Sub) else value
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
    if len(words) == 1 and (assign := _ASSIGNMENT.fullmatch(words[0])):
        name, value = assign.groups()
        whole = _NAME.fullmatch(value)
        sub = env.get(whole.group(1) or whole.group(2)) if whole else None
        answers = _api_answers(sub.inner, env) if isinstance(sub, _Sub) else None
        if answers is not None:  # the assignment's status is the command's
            return set(), [(ok, True, {**env, name: output}) for ok, output in answers]
    if all(_ASSIGNMENT.fullmatch(word) for word in words):
        env = dict(env)
        for word in words:
            name, value = _ASSIGNMENT.fullmatch(word).groups()  # type: ignore[union-attr]
            env[name] = _value(value, env)
        return set(), [(True, True, env)]
    name, args = words[0], words[1:]
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
            assign = _ASSIGNMENT.fullmatch(word)
            local = assign.group(1) if assign else word
            if not re.fullmatch(r"[A-Za-z_]\w*", local):
                raise Unsupported(f"local {word!r}")
            env[_LOCALS] = (*env.get(_LOCALS, ()), local)
            env[local] = _value(assign.group(2), env) if assign else ""
        return set(), [(True, True, env)]
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


def _call(function: _Function, args: list[str], env: Env) -> tuple[set[str], list[Result]]:
    """Runs a function's body where it's called: ``$1``... from ``args``; afterwards ``$1``...
    and its ``local`` variables are put back. Its status is ``return``'s, or its last
    command's; ``set -e`` acts on it like on any command."""
    depth = int(env.get(_DEPTH) or 0)  # type: ignore[call-overload]
    if depth >= _MAX_DEPTH:
        raise Unsupported("functions too deep")
    inner = {**env, _DEPTH: depth + 1, _LOCALS: ()}
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
        for key in (_DEPTH, _LOCALS):
            if key in env:
                after[key] = env[key]
            else:
                after.pop(key, None)
        out.append((bool(status), True, after))
    return ends, out


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
    if isinstance(command, _Group):
        ends, results = _seq_status(command.body, env)
        return ends, [(status, last and _RETURNED not in after, after) for status, last, after in results]
    if isinstance(command, _Define):
        return set(), [(True, True, {**env, _FUNCTION + command.name: _Function(command.body)})]
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


def _pipe(pipe: _Pipe, env: Env, last: bool = True) -> tuple[set[str], list[Result]]:
    """``last``: the pipeline is the last of its ``&&``/``||`` list. If not, or if negated,
    ``set -e`` doesn't act inside it (in a function or a group it runs)."""
    if (not last or pipe.negated) and env.get(_ERREXIT):
        ends, results = _pipe(_Pipe(pipe.negated, pipe.commands), {**env, _ERREXIT: False}, True)
        return ends, [(status, flag, {**after, _ERREXIT: True}) for status, flag, after in results]
    if len(pipe.commands) > 1:  # each part runs in a subshell: an exit there ends only that part
        ends, results = set(), _api_pipe(pipe.commands, env) or _both(env, True)
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
            if _RETURNED in after:
                nxt.append((status, False, after))
            elif status == (op == "&&"):
                more, out = _pipe(pipe, after, last=i == len(command.rest) - 1)
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
            if _RETURNED in env:  # the function has returned: skip the rest of its body
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
        if _RETURNED in after:
            results.append((bool(after[_RETURNED]), False, after))
            continue
        more, out = _and_or(seq[-1], after)
        ends |= more
        results += out
    return ends, results
