"""Does an ``actions/github-script`` step fail for a commenter who can't write? (WG010)

A permission check is often written in JavaScript::

    const { data } = await github.rest.repos.getCollaboratorPermissionLevel({
      ...context.repo,
      username: context.actor,
    });
    if (!['admin', 'write'].includes(data.permission)) {
      core.setFailed(`${context.actor} may not do this`);
    }

``run`` follows such a script on paper for a commenter who can't write: ``context.actor`` and
the commenter's login are a stranger (equal to no name written down), ``author_association``
is the association given, ``context.eventName`` is ``issue_comment`` and everything else in
``context`` is unknown. ``getCollaboratorPermissionLevel`` about the stranger answers
``permission``/``role_name`` ``none`` or ``read`` (``user.permissions`` all false but ``pull``)
or throws (a 404 for someone who isn't a collaborator); any other call answers something
unknown and may throw. It follows ``const``/``let``/``var`` (with ``{ a, b: { c } }``
patterns), assignments, ``if``/``else``, ``return``, ``throw``, ``try``/``catch``/``finally``,
``core.setFailed`` (the step fails at the end), ``core.setOutput``, ``process.exit``, and the
expressions around them: ``!``, ``&&``, ``||``, ``??``, ``? :``, ``===``/``!==``/``==``/``!=``,
``+``, template strings, ``.includes``/``.indexOf``/``.toLowerCase``/``.trim``/``.startsWith``/
``.endsWith``, ``String``/``Boolean``/``JSON.stringify``. A condition it can't decide goes both
ways. Functions, arrow functions, loops, ``switch`` and classes make the script unknown.

``${{ }}`` in the script is pasted in before it runs; its value (see
``conditions.stranger_text``) is put where it stands, inside a string or not.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from .conditions import STRANGER, UNKNOWN


class Unsupported(Exception):
    """The script uses something this evaluator doesn't follow."""


class _Undefined:
    def __repr__(self) -> str:
        return "undefined"


UNDEFINED = _Undefined()
_MARK = "\x01"  # around the number of a ${{ }} pasted into the script
_MAX_PATHS = 64
_PERMISSION_CALL = re.compile(r"getCollaboratorPermissionLevel")


@dataclass
class Result:
    """How the script ends for a stranger, over every path."""

    fails: bool
    """Every path fails the step (an uncaught throw, ``core.setFailed``, ``process.exit(1)``)."""
    asked: bool
    """A permission API call about the commenter was followed."""
    outputs: list[dict[str, object]] = field(default_factory=list)
    """The step's outputs on each path where it succeeds (``core.setOutput``, and ``result``
    from ``return``)."""


def run(script: str, values: Mapping[int, object], association: str, encoding: str = "json") -> Result | None:
    """Follows ``script`` with ``values[n]`` for the n-th ``${{ }}`` (see ``paste``); None if
    it uses something the evaluator doesn't follow."""
    try:
        program = _Parser(_tokens(script, values)).program()
        env = _Env({"context": _context(association)}, {}, False, False)
        ends = _block(program, [env])
    except (Unsupported, RecursionError):
        return None
    successes: list[dict[str, object]] = []
    for end in ends:
        if end.kind in ("throw", "exit_fail") or end.env.failed:
            continue
        outputs = dict(end.env.outputs)
        if end.kind == "return":
            outputs["result"] = _result_text(end.value, encoding)
        elif end.kind == "normal":
            outputs.setdefault("result", "")
        if outputs not in successes:
            successes.append(outputs)
    return Result(not successes, any(end.env.asked for end in ends), successes)


def paste(script: str, expressions: list[tuple[int, int]]) -> str:
    """The script with each ``${{ }}`` (given as (start, end) offsets) replaced by a mark with
    its number, for ``run``."""
    parts, pos = [], 0
    for n, (start, end) in enumerate(expressions):
        parts += [script[pos:start], f"{_MARK}{n}{_MARK}"]
        pos = end
    return "".join(parts) + script[pos:]


# --- tokens ----------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Token:
    kind: str  # name, num, str, tmpl, regex, op, mark
    value: object
    newline: bool = field(default=False, compare=False)  # a line break before it


_PUNCT = sorted(
    [
        "===", "!==", "...", "**=", "<<=", ">>=", "=>", "==", "!=", "<=", ">=", "&&", "||", "??",
        "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "**", "<<", ">>",
        "{", "}", "(", ")", "[", "]", ";", ",", ".", "<", ">", "+", "-", "*", "/", "%", "!",
        "?", ":", "=", "&", "|", "^", "~",
    ],
    key=len,
    reverse=True,
)  # fmt: skip
_REGEX_AFTER = {
    "(",
    ",",
    "=",
    ":",
    "[",
    "!",
    "&",
    "|",
    "?",
    "{",
    "}",
    ";",
    "&&",
    "||",
    "??",
    "return",
    "typeof",
}
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "b": "\b", "f": "\f", "v": "\v"}


def _tokens(text: str, values: Mapping[int, object]) -> list[_Token]:
    """The tokens; each knows whether a line break came before it (for ``return``)."""
    count = 0
    tokens: list[_Token] = []
    i = 0
    newline = False
    while i < len(text):
        c = text[i]
        if tokens and len(tokens) > count:
            last = tokens[-1]
            tokens[-1] = _Token(last.kind, last.value, newline)
            newline = False
        count = len(tokens)
        if c.isspace():
            newline |= c == "\n"
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                raise Unsupported("unclosed comment")
            newline |= "\n" in text[i:end]
            i = end + 2
        elif c == _MARK:
            end = text.index(_MARK, i + 1)
            tokens.append(_Token("mark", values.get(int(text[i + 1 : end]), UNKNOWN)))
            i = end + 1
        elif c in "'\"":
            value, i = _string(text, i, values)
            tokens.append(_Token("str", value))
        elif c == "`":
            parts, i = _template(text, i, values)
            tokens.append(_Token("tmpl", parts))
        elif c.isdigit() or (c == "." and i + 1 < len(text) and text[i + 1].isdigit()):
            m = re.match(
                r"0[xX][0-9a-fA-F_]+|\d[\d_]*(?:\.\d*)?(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?", text[i:]
            )
            assert m is not None
            number = m.group(0).replace("_", "")
            tokens.append(
                _Token("num", float(int(number, 16)) if number[:2].lower() == "0x" else float(number))
            )
            i += len(m.group(0))
        elif c.isalpha() or c in "_$":
            m = re.match(r"[\w$]+", text[i:])
            assert m is not None
            tokens.append(_Token("name", m.group(0)))
            i += len(m.group(0))
        elif c == "/" and (not tokens or _regex_may_start(tokens[-1])):
            i = _skip_regex(text, i)
            tokens.append(_Token("regex", UNKNOWN))
        else:
            op = next((p for p in _PUNCT if text.startswith(p, i)), None)
            if op is None:
                raise Unsupported(f"unexpected {c!r}")
            tokens.append(_Token("op", op))
            i += len(op)
    return tokens


def _regex_may_start(prev: _Token) -> bool:
    return (prev.kind == "op" and prev.value in _REGEX_AFTER) or (
        prev.kind == "name" and prev.value in _REGEX_AFTER
    )


def _skip_regex(text: str, i: int) -> int:
    i += 1
    in_class = False
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "\n":
            break
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            i += 1
            while i < len(text) and text[i].isalpha():
                i += 1
            return i
        i += 1
    raise Unsupported("unclosed regex")


def _string(text: str, i: int, values: Mapping[int, object]) -> tuple[object, int]:
    quote = text[i]
    i += 1
    parts: list[object] = [""]
    while i < len(text) and text[i] != quote:
        c = text[i]
        if c == "\n":
            raise Unsupported("newline in a string")
        if c == "\\":
            nxt = text[i + 1 : i + 2]
            if nxt in ("x", "u"):
                raise Unsupported("escape")
            parts.append(_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        if c == _MARK:
            end = text.index(_MARK, i + 1)
            parts.append(values.get(int(text[i + 1 : end]), UNKNOWN))
            i = end + 1
            continue
        parts.append(c)
        i += 1
    if i >= len(text):
        raise Unsupported("unclosed string")
    return _join(parts), i + 1


def _join(parts: list[object]) -> object:
    """Strings and pasted values side by side: a string, a pasted value standing alone, or
    UNKNOWN."""
    pieces = [p for p in parts if p != ""]
    if len(pieces) == 1 and not isinstance(pieces[0], str):
        return pieces[0]
    if all(isinstance(p, str) for p in pieces):
        return "".join(pieces)  # type: ignore[arg-type]
    return UNKNOWN


def _template(text: str, i: int, values: Mapping[int, object]) -> tuple[list[object], int]:
    """A template string as a list of strings and expression sources (in tuples)."""
    i += 1
    parts: list[object] = []
    current: list[object] = [""]
    while i < len(text) and text[i] != "`":
        c = text[i]
        if c == "\\":
            current.append(_ESCAPES.get(text[i + 1 : i + 2], text[i + 1 : i + 2]))
            i += 2
        elif text.startswith("${", i):
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            if depth:
                raise Unsupported("unclosed ${")
            parts += [_join(current), (text[i + 2 : j - 1],)]
            current = [""]
            i = j
        elif c == _MARK:
            end = text.index(_MARK, i + 1)
            current.append(values.get(int(text[i + 1 : end]), UNKNOWN))
            i = end + 1
        else:
            current.append(c)
            i += 1
    if i >= len(text):
        raise Unsupported("unclosed template")
    parts.append(_join(current))
    return [
        _Parser(_tokens(p[0], values)).expression_only() if isinstance(p, tuple) else p for p in parts
    ], i + 1


# --- the tree ----------------------------------------------------------------------------------------


@dataclass
class _Node:
    kind: str
    value: object = None
    children: tuple = ()


class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens, self.i = tokens, 0

    def peek(self, ahead: int = 0) -> _Token | None:
        j = self.i + ahead
        return self.tokens[j] if j < len(self.tokens) else None

    def is_op(self, *ops: str) -> bool:
        tok = self.peek()
        return tok is not None and tok.kind == "op" and tok.value in ops

    def is_name(self, *names: str) -> bool:
        tok = self.peek()
        return tok is not None and tok.kind == "name" and tok.value in names

    def take(self, op: str | None = None) -> _Token:
        tok = self.peek()
        if tok is None or (op is not None and not (tok.kind in ("op", "name") and tok.value == op)):
            raise Unsupported(f"expected {op!r}, got {tok!r}")
        self.i += 1
        return tok

    def program(self) -> list[_Node]:
        body = []
        while self.peek() is not None:
            body.append(self.statement())
        return body

    def expression_only(self) -> _Node:
        node = self.expression()
        if self.peek() is not None:
            raise Unsupported("extra tokens in ${}")
        return node

    def block(self) -> list[_Node]:
        self.take("{")
        body = []
        while not self.is_op("}"):
            if self.peek() is None:
                raise Unsupported("unclosed block")
            body.append(self.statement())
        self.take("}")
        return body

    def body(self) -> list[_Node]:
        return self.block() if self.is_op("{") else [self.statement()]

    def end(self) -> None:
        if self.is_op(";"):
            self.i += 1

    def statement(self) -> _Node:
        tok = self.peek()
        assert tok is not None
        if tok.kind == "op" and tok.value == "{":
            return _Node("block", self.block())
        if tok.kind == "op" and tok.value == ";":
            self.i += 1
            return _Node("block", [])
        if tok.kind == "name":
            word = tok.value
            if word in ("const", "let", "var"):
                self.i += 1
                decls = [self.declarator()]
                while self.is_op(","):
                    self.i += 1
                    decls.append(self.declarator())
                self.end()
                return _Node("block", decls)
            if word == "if":
                self.i += 1
                self.take("(")
                cond = self.expression()
                self.take(")")
                then = self.body()
                otherwise: list[_Node] = []
                if self.is_name("else"):
                    self.i += 1
                    otherwise = self.body()
                return _Node("if", cond, (then, otherwise))
            if word == "return":
                self.i += 1
                nxt = self.peek()
                # `return` then a line break returns undefined (a semicolon goes in there).
                bare = nxt is None or nxt.newline or self.is_op(";", "}")
                value = None if bare else self.expression()
                self.end()
                return _Node("return", value)
            if word == "throw":
                self.i += 1
                value = self.expression()
                self.end()
                return _Node("throw", value)
            if word == "try":
                self.i += 1
                attempt = self.block()
                name, handler, final = None, None, None
                if self.is_name("catch"):
                    self.i += 1
                    if self.is_op("("):
                        self.i += 1
                        name = self.take().value
                        self.take(")")
                    handler = self.block()
                if self.is_name("finally"):
                    self.i += 1
                    final = self.block()
                return _Node("try", name, (attempt, handler, final))
            if word in (
                "function",
                "for",
                "while",
                "do",
                "switch",
                "class",
                "async",
                "with",
                "yield",
                "import",
            ):
                raise Unsupported(word)
        node = self.expression()
        self.end()
        return _Node("expr", node)

    def declarator(self) -> _Node:
        if self.is_op("{"):
            target = self.pattern()
        elif self.is_op("["):
            raise Unsupported("array pattern")
        else:
            target = _Node("name", self.take().value)
        value = None
        if self.is_op("="):
            self.i += 1
            value = self.assignment()
        return _Node("declare", value, (target,))

    def pattern(self) -> _Node:
        """``{ a, b: c, d: { e } }``: (key, target) pairs."""
        self.take("{")
        pairs = []
        while not self.is_op("}"):
            if self.is_op("..."):
                raise Unsupported("rest pattern")
            key = self.take().value
            target = _Node("name", key)
            if self.is_op(":"):
                self.i += 1
                target = self.pattern() if self.is_op("{") else _Node("name", self.take().value)
            if self.is_op("="):
                raise Unsupported("default in a pattern")
            pairs.append((key, target))
            if not self.is_op("}"):
                self.take(",")
        self.take("}")
        return _Node("pattern", pairs)

    # expressions, lowest precedence first
    def expression(self) -> _Node:
        node = self.assignment()
        while self.is_op(","):
            self.i += 1
            node = _Node("seq", None, (node, self.assignment()))
        return node

    def assignment(self) -> _Node:
        start = self.i
        if self.is_op("(") or (self.peek() is not None and self.peek().kind == "name"):  # type: ignore[union-attr]
            if self._arrow_ahead():
                raise Unsupported("arrow function")
        self.i = start
        left = self.conditional()
        if self.is_op("=", "+=", "-=", "*=", "/=", "%=", "||=", "&&=", "??="):
            op = self.take().value
            right = self.assignment()
            return _Node("assign", op, (left, right))
        return left

    def _arrow_ahead(self) -> bool:
        tok = self.peek()
        if tok is not None and tok.kind == "name" and self.peek(1) == _Token("op", "=>"):
            return True  # (tokens compare by kind and value only)
        if not self.is_op("("):
            return False
        depth, j = 0, self.i
        while j < len(self.tokens):
            t = self.tokens[j]
            if t.kind == "op" and t.value in ("(", "[", "{"):
                depth += 1
            elif t.kind == "op" and t.value in (")", "]", "}"):
                depth -= 1
                if depth == 0:
                    return j + 1 < len(self.tokens) and self.tokens[j + 1] == _Token("op", "=>")
            j += 1
        return False

    def conditional(self) -> _Node:
        cond = self.binary(0)
        if self.is_op("?"):
            self.i += 1
            then = self.assignment()
            self.take(":")
            otherwise = self.assignment()
            return _Node("cond", None, (cond, then, otherwise))
        return cond

    _LEVELS = (
        ("??",),
        ("||",),
        ("&&",),
        ("|",),
        ("^",),
        ("&",),
        ("===", "!==", "==", "!="),
        ("<", ">", "<=", ">=", "instanceof", "in"),
        ("<<", ">>"),
        ("+", "-"),
        ("*", "/", "%"),
    )

    def binary(self, level: int) -> _Node:
        if level == len(self._LEVELS):
            return self.unary()
        node = self.binary(level + 1)
        ops = self._LEVELS[level]
        while (tok := self.peek()) is not None and tok.kind in ("op", "name") and tok.value in ops:
            self.i += 1
            node = _Node("binary", tok.value, (node, self.binary(level + 1)))
        return node

    def unary(self) -> _Node:
        if self.is_op("!", "-", "+", "~") or self.is_name("typeof", "void", "await", "delete"):
            op = self.take().value
            return _Node("unary", op, (self.unary(),))
        if self.is_op("++", "--"):
            raise Unsupported("++")
        node = self.postfix(self.primary())
        if self.is_op("++", "--"):
            self.i += 1
            return _Node("unary", "++", (node,))
        return node

    def postfix(self, node: _Node) -> _Node:
        while True:
            if self.is_op(".", "?."):
                optional = self.take().value == "?."
                if self.is_op("("):
                    node = _Node("call", None, (node, *self.arguments()))
                    continue
                if self.is_op("["):
                    self.i += 1
                    key = self.expression()
                    self.take("]")
                    node = _Node("index", optional, (node, key))
                    continue
                node = _Node("optmember" if optional else "member", self.take().value, (node,))
            elif self.is_op("["):
                self.i += 1
                key = self.expression()
                self.take("]")
                node = _Node("index", False, (node, key))
            elif self.is_op("("):
                node = _Node("call", None, (node, *self.arguments()))
            elif (tok := self.peek()) is not None and tok.kind == "tmpl":
                raise Unsupported("tagged template")
            else:
                return node

    def arguments(self) -> list[_Node]:
        self.take("(")
        args = []
        while not self.is_op(")"):
            if self.is_op("..."):
                self.i += 1
                args.append(_Node("spread", None, (self.assignment(),)))
            else:
                args.append(self.assignment())
            if not self.is_op(")"):
                self.take(",")
        self.take(")")
        return args

    def primary(self) -> _Node:
        tok = self.take()
        if tok.kind in ("num", "str", "mark", "regex"):
            return _Node("literal", tok.value)
        if tok.kind == "tmpl":
            return _Node("template", tok.value)
        if tok.kind == "name":
            if tok.value in ("true", "false"):
                return _Node("literal", tok.value == "true")
            if tok.value == "null":
                return _Node("literal", None)
            if tok.value == "undefined":
                return _Node("literal", UNDEFINED)
            if tok.value == "new":
                callee = self.postfix_member(self.primary())
                args = self.arguments() if self.is_op("(") else []
                return _Node("new", None, (callee, *args))
            if tok.value in ("function", "class", "this", "super", "async", "yield"):
                raise Unsupported(str(tok.value))
            return _Node("name", tok.value)
        if tok.value == "(":
            node = self.expression()
            self.take(")")
            return node
        if tok.value == "[":
            items = []
            while not self.is_op("]"):
                if self.is_op("..."):
                    self.i += 1
                    items.append(_Node("spread", None, (self.assignment(),)))
                else:
                    items.append(self.assignment())
                if not self.is_op("]"):
                    self.take(",")
            self.take("]")
            return _Node("array", None, tuple(items))
        if tok.value == "{":
            pairs = []
            while not self.is_op("}"):
                if self.is_op("..."):
                    self.i += 1
                    pairs.append((None, self.assignment()))
                else:
                    key_tok = self.take()
                    if key_tok.kind == "op" and key_tok.value == "[":
                        raise Unsupported("computed key")
                    key = str(key_tok.value) if key_tok.kind != "num" else str(int(key_tok.value))  # type: ignore[arg-type]
                    if self.is_op(":"):
                        self.i += 1
                        pairs.append((key, self.assignment()))
                    elif self.is_op("("):
                        raise Unsupported("method")
                    else:
                        pairs.append((key, _Node("name", key)))
                if not self.is_op("}"):
                    self.take(",")
            self.take("}")
            return _Node("object", pairs)
        raise Unsupported(f"unexpected {tok.value!r}")

    def postfix_member(self, node: _Node) -> _Node:
        while self.is_op("."):
            self.i += 1
            node = _Node("member", self.take().value, (node,))
        return node


# --- running it on paper -------------------------------------------------------------------------


@dataclass
class _Env:
    names: dict[str, object]
    outputs: dict[str, object]
    failed: bool  # core.setFailed was called
    asked: bool  # the permission API was asked about the commenter

    def with_name(self, name: str, value: object) -> _Env:
        return _Env({**self.names, name: value}, self.outputs, self.failed, self.asked)

    def key(self) -> str:
        return repr(
            (
                sorted((k, repr(v)) for k, v in self.names.items()),
                sorted(self.outputs.items(), key=str),
                self.failed,
                self.asked,
            )
        )


@dataclass
class _End:
    kind: str  # normal, return, throw, exit_fail, exit_ok
    env: _Env
    value: object = None


class _Context(dict):
    """``context``: known parts, and UNKNOWN for anything else."""


def _context(association: str) -> object:
    comment = _Context(user=_Context(login=STRANGER), author_association=association)
    sender = _Context(login=STRANGER)
    return _Context(
        actor=STRANGER,
        triggering_actor=STRANGER,
        eventName="issue_comment",
        payload=_Context(comment=comment, sender=sender),
    )


def _truthy(value: object) -> bool | None:
    if value is UNKNOWN:
        return None
    if value is STRANGER:
        return True
    if value is UNDEFINED or value is None or value is False or value == "":
        return False
    if isinstance(value, float):
        return value != 0 and not math.isnan(value)
    return True


def _text(value: object) -> object:
    """``String(value)``."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if value is UNDEFINED:
        return "undefined"
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    return UNKNOWN


def _json(value: object) -> object:
    """``JSON.stringify(value)``."""
    if value is UNDEFINED:
        return UNDEFINED
    if isinstance(value, str):
        return json.dumps(value)
    if value is None or isinstance(value, (bool, float)):
        return _text(value)
    if isinstance(value, list):
        items = [_json(v) for v in value]
        return UNKNOWN if any(not isinstance(i, str) for i in items) else "[" + ",".join(items) + "]"  # type: ignore[arg-type]
    if isinstance(value, dict) and not isinstance(value, _Context):
        items = [(k, _json(v)) for k, v in value.items() if _json(v) is not UNDEFINED]
        if any(not isinstance(v, str) for _, v in items):
            return UNKNOWN
        return "{" + ",".join(f"{json.dumps(k)}:{v}" for k, v in items) + "}"
    return UNKNOWN


def _result_text(value: object, encoding: str) -> object:
    """The ``result`` output for a returned value: JSON unless ``result-encoding: string``."""
    if value is UNDEFINED:
        return ""
    text = _text(value) if encoding == "string" else _json(value)
    return text if isinstance(text, str) else UNKNOWN


def _output_text(value: object) -> object:
    """What ``core.setOutput`` writes: a string as it is, anything else as JSON."""
    if isinstance(value, str) or value is STRANGER:
        return value
    if value is UNDEFINED or value is None:
        return ""
    text = _json(value)
    return text if isinstance(text, str) else UNKNOWN


def _equal(a: object, b: object, strict: bool) -> bool | None:
    if a is UNKNOWN or b is UNKNOWN:
        return None
    if a is STRANGER or b is STRANGER:
        other = b if a is STRANGER else a
        return None if other is STRANGER else False
    if strict and type(a) is not type(b):
        return False
    if not strict and {type(a), type(b)} <= {type(None), _Undefined}:
        return True
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return a is b
    return a == b


def _member(obj: object, key: object) -> object:
    if obj is UNKNOWN or key is UNKNOWN:
        return UNKNOWN
    if isinstance(obj, _Context):
        return obj.get(key, UNKNOWN)  # type: ignore[call-overload]
    if isinstance(obj, dict):
        return obj.get(key, UNDEFINED)  # type: ignore[call-overload]
    if isinstance(obj, (list, str)) and key == "length":
        return float(len(obj))
    if isinstance(obj, list) and isinstance(key, float) and key.is_integer():
        return obj[int(key)] if 0 <= key < len(obj) else UNDEFINED
    if obj is STRANGER and key == "length":
        return UNKNOWN
    if obj is None or obj is UNDEFINED:
        raise _Throw  # reading a property of null
    return UNKNOWN if obj is STRANGER else UNDEFINED


class _Throw(Exception):
    """The expression throws (in this path)."""


_STRING_METHODS = {"toLowerCase", "toUpperCase", "trim", "toString", "trimStart", "trimEnd"}


def _method(obj: object, name: str, args: list[object]) -> object:
    """A known method on a known value, or UNKNOWN."""
    if name in _STRING_METHODS and not args:
        if obj is STRANGER:
            return STRANGER
        if isinstance(obj, str):
            return {
                "toLowerCase": obj.lower(),
                "toUpperCase": obj.upper(),
                "trim": obj.strip(),
                "trimStart": obj.lstrip(),
                "trimEnd": obj.rstrip(),
                "toString": obj,
            }[name]
        if name == "toString":
            return _text(obj)
        return UNKNOWN
    if name in ("includes", "indexOf") and args:
        item = args[0]
        if isinstance(obj, list):
            found = [_equal(v, item, True) for v in obj]
            if True in found:
                return True if name == "includes" else float(found.index(True))
            if None in found:
                return UNKNOWN
            return False if name == "includes" else -1.0
        if isinstance(obj, str) and isinstance(item, str):
            return (item in obj) if name == "includes" else float(obj.find(item))
        if obj is STRANGER and isinstance(item, str) and name == "includes":
            return UNKNOWN
        return UNKNOWN
    if name in ("startsWith", "endsWith") and args and isinstance(obj, str) and isinstance(args[0], str):
        return obj.startswith(args[0]) if name == "startsWith" else obj.endswith(args[0])
    return UNKNOWN


def _stranger_permission() -> list[object]:
    """What ``getCollaboratorPermissionLevel`` answers about a stranger (it may also throw a
    404: ``_call_known`` adds that path)."""
    answers: list[object] = []
    for level in ("none", "read"):
        permissions = {
            "admin": False,
            "maintain": False,
            "push": False,
            "triage": False,
            "pull": level == "read",
        }
        user = {"login": STRANGER, "permissions": permissions}
        answers.append({"data": {"permission": level, "role_name": level, "user": user}})
    return answers


# A list of (env, value) on the paths where the expression has a value, and the envs where it
# throws.
Values = tuple[list[tuple[_Env, object]], list[_Env]]


def _eval(node: _Node, env: _Env) -> Values:
    kind = node.kind
    if kind == "literal":
        return [(env, node.value)], []
    if kind == "template":
        return _template_value(node.value, env)  # type: ignore[arg-type]
    if kind == "name":
        name = str(node.value)
        if name in env.names:
            return [(env, env.names[name])], []
        return [(env, UNKNOWN)], []  # github, core, process, require... or an unknown global
    if kind == "member":
        return _map1(node.children[0], env, lambda v: _member(v, node.value))
    if kind == "optmember":
        return _map1(
            node.children[0],
            env,
            lambda v: UNDEFINED if v is None or v is UNDEFINED else _member(v, node.value),
        )
    if kind == "index":
        return _map2(node.children[0], node.children[1], env, lambda o, k: _member(o, _key(k)))
    if kind == "array":
        return _seq(list(node.children), env, lambda items: items, spread=True)
    if kind == "object":
        pairs = node.value  # type: ignore[assignment]
        return _seq(
            [v for _, v in pairs],  # type: ignore[misc]
            env,
            lambda vals: _make_object([k for k, _ in pairs], vals),  # type: ignore[misc]
        )
    if kind == "unary":
        return _unary(node, env)
    if kind == "binary":
        return _binary(node, env)
    if kind == "cond":
        out, thrown = _eval(node.children[0], env)
        values: list[tuple[_Env, object]] = []
        for e, cond in out:
            test = _truthy(cond)
            for branch, take in ((node.children[1], test is not False), (node.children[2], test is not True)):
                if take:
                    more, err = _eval(branch, e)
                    values += more
                    thrown += err
        return values, thrown
    if kind == "assign":
        return _assign(node, env)
    if kind == "seq":
        out, thrown = _eval(node.children[0], env)
        values = []
        for e, _ in out:
            more, err = _eval(node.children[1], e)
            values += more
            thrown += err
        return values, thrown
    if kind == "call":
        return _call(node, env)
    if kind == "new":
        out, thrown = _seq(list(node.children[1:]), env, lambda _: UNKNOWN)
        return out, thrown
    if kind == "spread":
        return _eval(node.children[0], env)
    raise Unsupported(kind)


def _key(value: object) -> object:
    return value if isinstance(value, (str, float)) or value is UNKNOWN else UNKNOWN


def _make_object(keys: list[str | None], values: list[object]) -> object:
    """An object literal; after ``...unknown`` (``...context.repo``) the keys written later are
    still known and the others unknown."""
    result: dict[str, object] = {}
    partial = False
    for key, value in zip(keys, values, strict=True):
        if key is None:
            if isinstance(value, dict):
                result.update(value)
                partial |= isinstance(value, _Context)
            elif value is not None and value is not UNDEFINED:
                result, partial = {}, True  # unknown keys, which may hide the ones before
        else:
            result[key] = value
    return _Context(result) if partial else result


def _map1(child: _Node, env: _Env, fn) -> Values:  # noqa: ANN001
    out, thrown = _eval(child, env)
    values = []
    for e, v in out:
        try:
            values.append((e, fn(v)))
        except _Throw:
            thrown.append(e)
    return values, thrown


def _map2(left: _Node, right: _Node, env: _Env, fn) -> Values:  # noqa: ANN001
    out, thrown = _eval(left, env)
    values = []
    for e, a in out:
        more, err = _eval(right, e)
        thrown += err
        for e2, b in more:
            try:
                values.append((e2, fn(a, b)))
            except _Throw:
                thrown.append(e2)
    return values, thrown


def _seq(nodes: list[_Node], env: _Env, fn, spread: bool = False) -> Values:  # noqa: ANN001
    """Evaluates ``nodes`` left to right on every path; ``fn`` makes one value of them."""
    states: list[tuple[_Env, list[object]]] = [(env, [])]
    thrown: list[_Env] = []
    for node in nodes:
        nxt = []
        for e, vals in states:
            out, err = _eval(node, e)
            thrown += err
            for e2, v in out:
                if spread and node.kind == "spread":
                    if not isinstance(v, list):
                        nxt.append((e2, [*vals, UNKNOWN, UNKNOWN]))  # unknown length: not a known list
                        continue
                    nxt.append((e2, vals + v))
                else:
                    nxt.append((e2, [*vals, v]))
        states = _cap(nxt)
    if spread and any(n.kind == "spread" for n in nodes):
        return [(e, UNKNOWN) for e, _ in states], thrown  # an array with a spread: not followed
    return [(e, fn(vals)) for e, vals in states], thrown


def _cap(items: list) -> list:
    if len(items) > _MAX_PATHS:
        raise Unsupported("too many paths")
    return items


def _template_value(parts: list[object], env: _Env) -> Values:
    nodes = [p if isinstance(p, _Node) else _Node("literal", p) for p in parts]

    def join(vals: list[object]) -> object:
        filled = [v for v in vals if v != ""]
        if len(filled) == 1 and filled[0] is STRANGER:
            return STRANGER  # `${login}` alone is the login
        texts = [_text(v) if not isinstance(v, str) else v for v in vals]
        return "".join(texts) if all(isinstance(t, str) for t in texts) else UNKNOWN  # type: ignore[arg-type]

    return _seq(nodes, env, join)


def _unary(node: _Node, env: _Env) -> Values:
    op = node.value
    if op == "await":
        return _eval(node.children[0], env)
    if op == "++":
        raise Unsupported("++")

    def apply(v: object) -> object:
        if op == "!":
            t = _truthy(v)
            return UNKNOWN if t is None else not t
        if op == "typeof":
            return UNKNOWN
        if op == "void":
            return UNDEFINED
        if op in ("-", "+") and isinstance(v, float):
            return -v if op == "-" else v
        return UNKNOWN

    return _map1(node.children[0], env, apply)


def _binary(node: _Node, env: _Env) -> Values:
    op = node.value
    if op in ("&&", "||", "??"):
        out, thrown = _eval(node.children[0], env)
        values: list[tuple[_Env, object]] = []
        for e, left in out:
            if op == "??":
                stop = None if left is UNKNOWN else (left is not None and left is not UNDEFINED)
            else:
                t = _truthy(left)
                stop = None if t is None else (t if op == "||" else not t)
            if stop is not False:
                values.append((e, left))  # the left side is the value
            if stop is not True:
                more, err = _eval(node.children[1], e)
                values += more
                thrown += err
        return values, thrown

    def apply(a: object, b: object) -> object:
        if op in ("===", "!==", "==", "!="):
            eq = _equal(a, b, op in ("===", "!=="))
            if eq is None:
                return UNKNOWN
            return eq if op in ("===", "==") else not eq
        if op == "+":
            if isinstance(a, float) and isinstance(b, float):
                return a + b
            if isinstance(a, str) or isinstance(b, str):
                ta, tb = _text(a), _text(b)
                return ta + tb if isinstance(ta, str) and isinstance(tb, str) else UNKNOWN
            return UNKNOWN
        return UNKNOWN

    return _map2(node.children[0], node.children[1], env, apply)


def _assign(node: _Node, env: _Env) -> Values:
    target, value = node.children
    out, thrown = _eval(value, env)
    if node.value != "=":
        out = [(e, UNKNOWN) for e, _ in out]
    if target.kind == "name":
        return [(e.with_name(str(target.value), v), v) for e, v in out], thrown
    if target.kind in ("member", "index"):
        # obj.x = v: the object isn't followed after that.
        root = target
        while root.kind in ("member", "index"):
            root = root.children[0]
        if root.kind == "name":
            return [(e.with_name(str(root.value), UNKNOWN), v) for e, v in out], thrown
    raise Unsupported("assignment target")


def _callee_path(node: _Node) -> list[str] | None:
    parts = []
    while node.kind == "member":
        parts.append(str(node.value))
        node = node.children[0]
    if node.kind != "name":
        return None
    parts.append(str(node.value))
    return parts[::-1]


def _call(node: _Node, env: _Env) -> Values:
    callee, *arg_nodes = node.children
    path = _callee_path(callee)
    if (
        path
        and path[-1] in _STRING_METHODS | {"includes", "indexOf", "startsWith", "endsWith"}
        and len(path) > 1
    ):
        obj_node = callee.children[0]
        return _seq([obj_node, *arg_nodes], env, lambda vals: _method(vals[0], path[-1], vals[1:]))
    if callee.kind == "member" and path is None:
        # (expr).method(...): the object is an expression
        name = str(callee.value)
        if name in _STRING_METHODS | {"includes", "indexOf", "startsWith", "endsWith"}:
            return _seq([callee.children[0], *arg_nodes], env, lambda vals: _method(vals[0], name, vals[1:]))
    values, thrown = _seq(list(arg_nodes), env, lambda vals: vals)
    results: list[tuple[_Env, object]] = []
    for e, args in values:
        out, err = _call_known(path, args, e)  # type: ignore[arg-type]
        results += out
        thrown += err
    return _cap(results), thrown


def _call_known(path: list[str] | None, args: list[object], env: _Env) -> Values:
    if path in (["core", "setFailed"],):
        return [(_Env(env.names, env.outputs, True, env.asked), UNDEFINED)], []
    if path == ["core", "setOutput"] and len(args) >= 2:
        name = args[0]
        if not isinstance(name, str):
            raise Unsupported("setOutput with an unknown name")
        outputs = {**env.outputs, name: _output_text(args[1])}
        return [(_Env(env.names, outputs, env.failed, env.asked), UNDEFINED)], []
    if path and path[0] in ("core", "console") and path[-1] in (
        "info", "debug", "warning", "notice", "error", "log", "warn", "startGroup", "endGroup",
    ):  # fmt: skip
        return [(env, UNDEFINED)], []
    if path == ["process", "exit"]:
        raise Unsupported("process.exit inside an expression")
    if path in (["String"],):
        return [(env, _text(args[0]) if args else "")], []
    if path in (["Boolean"],):
        t = _truthy(args[0]) if args else False
        return [(env, UNKNOWN if t is None else t)], []
    if path == ["JSON", "stringify"] and args:
        return [(env, _json(args[0]))], []
    if path and path[-1] == "getCollaboratorPermissionLevel" and path[0] == "github":
        request = args[0] if args else UNKNOWN
        user = request.get("username", UNKNOWN) if isinstance(request, dict) else UNKNOWN
        if user is STRANGER:
            asked = _Env(env.names, env.outputs, env.failed, True)
            values = [(asked, value) for value in _stranger_permission()]
            return values, [asked]
        return [(env, UNKNOWN)], [env]
    # Any other call (github.rest..., require, exec): an unknown answer, and it may throw.
    return [(env, UNKNOWN)], [env]


def _exit(node: _Node, env: _Env) -> list[_End] | None:
    """``process.exit(code)`` as a statement of its own."""
    call = node.children[0] if node.kind == "unary" and node.value == "await" else node
    if call.kind != "call" or _callee_path(call.children[0]) != ["process", "exit"]:
        return None
    out, thrown = _seq(list(call.children[1:]), env, lambda vals: vals[0] if vals else 0.0)
    ends = [_End("throw", e) for e in thrown]
    for e, code in out:
        if isinstance(code, float):
            ends.append(_End("exit_ok" if code == 0 else "exit_fail", e))
        else:
            ends += [_End("exit_ok", e), _End("exit_fail", e)]
    return ends


def _dedupe(ends: list[_End]) -> list[_End]:
    seen, out = set(), []
    for end in ends:
        key = (end.kind, end.env.key(), repr(end.value))
        if key not in seen:
            seen.add(key)
            out.append(end)
    return _cap(out)


def _block(body: list[_Node], envs: list[_Env]) -> list[_End]:
    """Runs statements from each env: how each path ends (``normal`` if it falls through)."""
    ends: list[_End] = []
    current = envs
    for stmt in body:
        nxt: list[_Env] = []
        for env in current:
            for end in _statement(stmt, env):
                if end.kind == "normal":
                    nxt.append(end.env)
                else:
                    ends.append(end)
        current = [end.env for end in _dedupe([_End("normal", e) for e in nxt])]
        if not current:
            break
    return _dedupe(ends + [_End("normal", e) for e in current])


def _statement(stmt: _Node, env: _Env) -> list[_End]:
    if stmt.kind == "expr":
        ends = _exit(stmt.value, env)  # type: ignore[arg-type]
        if ends is not None:
            return ends
    return _statement_inner(stmt, env)


def _statement_inner(stmt: _Node, env: _Env) -> list[_End]:
    kind = stmt.kind
    if kind == "block":
        return _block(stmt.value, [env])  # type: ignore[arg-type]
    if kind == "expr":
        out, thrown = _eval(stmt.value, env)  # type: ignore[arg-type]
        return [_End("normal", e) for e, _ in out] + [_End("throw", e) for e in thrown]
    if kind == "declare":
        (target,) = stmt.children
        if stmt.value is None:
            return [_End("normal", _bind(target, UNDEFINED, env))]
        out, thrown = _eval(stmt.value, env)  # type: ignore[arg-type]
        ends = [_End("throw", e) for e in thrown]
        for e, v in out:
            try:
                ends.append(_End("normal", _bind(target, v, e)))
            except _Throw:
                ends.append(_End("throw", e))
        return ends
    if kind == "if":
        out, thrown = _eval(stmt.value, env)  # type: ignore[arg-type]
        then, otherwise = stmt.children
        ends = [_End("throw", e) for e in thrown]
        for e, cond in out:
            test = _truthy(cond)
            if test is not False:
                ends += _block(then, [e])
            if test is not True:
                ends += _block(otherwise, [e])
        return ends
    if kind == "return":
        if stmt.value is None:
            return [_End("return", env, UNDEFINED)]
        out, thrown = _eval(stmt.value, env)  # type: ignore[arg-type]
        return [_End("return", e, v) for e, v in out] + [_End("throw", e) for e in thrown]
    if kind == "throw":
        out, thrown = _eval(stmt.value, env)  # type: ignore[arg-type]
        return [_End("throw", e) for e, _ in out] + [_End("throw", e) for e in thrown]
    if kind == "try":
        name, (attempt, handler, final) = stmt.value, stmt.children
        ends = _block(attempt, [env])
        if handler is not None:
            caught = [end.env for end in ends if end.kind == "throw"]
            ends = [end for end in ends if end.kind != "throw"]
            if caught:
                start = [e.with_name(str(name), UNKNOWN) if name else e for e in caught]
                ends += _block(handler, start)
        if final is not None:
            finished: list[_End] = []
            for end in ends:
                after = _block(final, [end.env])
                for f in after:
                    # finally falls through: the earlier end stands, with the new state
                    finished.append(_End(end.kind, f.env, end.value) if f.kind == "normal" else f)
            ends = finished
        return _dedupe(ends)
    raise Unsupported(kind)


def _bind(target: _Node, value: object, env: _Env) -> _Env:
    if target.kind == "name":
        return env.with_name(str(target.value), value)
    for key, sub in target.value:  # type: ignore[attr-defined]
        env = _bind(sub, _member(value, key), env)
    return env
