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
unknown and may throw. It follows ``const``/``let``/``var`` (with object and array patterns:
``{ a, b: { c } = {}, ...rest }``, ``[a, , b = 1, ...rest]``; also in parameters and
``for...of``), assignments, ``if``/``else``, ``return``, ``throw``, ``try``/``catch``/``finally``,
``core.setFailed`` (the step fails at the end), ``core.setOutput``, ``process.exit``, and the
expressions around them: ``!``, ``&&``, ``||``, ``??``, ``? :``, ``===``/``!==``/``==``/``!=``,
``+``, template strings, ``.includes``/``.indexOf``/``.toLowerCase``/``.trim``/``.startsWith``/
``.endsWith``, ``String``/``Boolean``/``JSON.stringify``, ``Promise.all`` (the list it's given),
``Object.keys``/``values``/``entries``. A condition it can't decide goes both
ways. Functions (``function f(a, b = 1) {}``, ``async function``, arrow functions with an
expression or a block) run where they are called, with their own parameters and declarations
(``async``/``await`` change nothing here); ``.some``, ``.every``, ``.find``, ``.findIndex``,
``.filter``, ``.map`` and ``.forEach`` call their callback for each element of a known list (on
an unknown one: zero or one call, and an unknown result). ``for (const x of list)`` runs once
per element of a known list (a string, a Map's entries, a Set), and round after round on an
unknown one until no new state turns up (at most 8); ``break`` and ``continue`` work in it.
Other loops, ``switch``, classes, recursion past 8 calls, patterns on the left of an assignment
and a default that may throw or change something make the script unknown.

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
        if any(end.kind in ("break", "continue") for end in ends):
            raise Unsupported("break outside a loop")
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
                m = re.match(r"x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\}", text[i + 1 :])
                if m is None:
                    raise Unsupported("escape")
                parts.append(chr(int(m.group(1) or m.group(2) or m.group(3), 16)))
                i += 1 + len(m.group(0))
                continue
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
            if word == "function" or (word == "async" and self.peek(1) == _Token("name", "function")):
                node = self.function()
                if node.value is None:
                    raise Unsupported("a function statement without a name")
                return _Node("fundecl", node.value, node.children)
            if word == "for":
                return self.for_of()
            if word in ("break", "continue"):
                self.i += 1
                nxt = self.peek()
                if nxt is not None and nxt.kind == "name" and not nxt.newline:
                    raise Unsupported(f"{word} with a label")
                self.end()
                return _Node(word)
            if word in ("while", "do", "switch", "class", "with", "yield", "import"):
                raise Unsupported(word)
        node = self.expression()
        self.end()
        return _Node("expr", node)

    def for_of(self) -> _Node:
        self.take("for")
        self.take("(")
        if not self.is_name("const", "let", "var"):
            raise Unsupported("for loop")
        self.i += 1
        target = self.binding()
        if not self.is_name("of"):
            raise Unsupported("for loop that isn't for...of")
        self.i += 1
        iterable = self.expression()
        self.take(")")
        return _Node("forof", target, (iterable, self.body()))

    def function(self) -> _Node:
        """``[async] function [name](params) { body }``: a node with the name (or None) and
        (params, body, is_block)."""
        if self.is_name("async"):
            self.i += 1
        self.take("function")
        name = None
        if (tok := self.peek()) is not None and tok.kind == "name":
            name = self.take().value
        params = self.params()
        return _Node("function", name, (params, self.block(), True))

    def params(self) -> _Node:
        """``(a, { b } = {}, ...rest)``: an array pattern the arguments are bound to."""
        self.take("(")
        return self.elements(")")

    def elements(self, close: str) -> _Node:
        """The inside of ``[a, , b = 1, ...rest]`` (or a parameter list) up to ``close``: an
        ``apattern`` node with ((target, default) or None for a hole, ...) and the rest target."""
        items: list[tuple[_Node, _Node | None] | None] = []
        rest = None
        while not self.is_op(close):
            if self.is_op(",") and close == "]":
                self.i += 1
                items.append(None)
                continue
            if self.is_op("..."):
                self.i += 1
                rest = self.binding()
                break
            items.append((self.binding(), self.default()))
            if not self.is_op(close):
                self.take(",")
        self.take(close)
        return _Node("apattern", (items, rest))

    def binding(self) -> _Node:
        """What a declaration, parameter or ``for...of`` binds: a name, ``{ ... }`` or
        ``[ ... ]``."""
        if self.is_op("{"):
            return self.pattern()
        if self.is_op("["):
            self.i += 1
            return self.elements("]")
        tok = self.take()
        if tok.kind != "name":
            raise Unsupported(f"unexpected {tok.value!r} in a binding")
        return _Node("name", tok.value)

    def default(self) -> _Node | None:
        if self.is_op("="):
            self.i += 1
            return self.assignment()
        return None

    def arrow(self) -> _Node:
        """``[async] x => body`` or ``[async] (a, b) => body``."""
        if self.is_name("async"):
            self.i += 1
        if self.is_op("("):
            params = self.params()
        else:
            params = _Node("apattern", ([(_Node("name", self.take().value), None)], None))
        self.take("=>")
        if self.is_op("{"):
            return _Node("function", None, (params, self.block(), True))
        return _Node("function", None, (params, self.assignment(), False))

    def declarator(self) -> _Node:
        target = self.binding()
        return _Node("declare", self.default(), (target,))

    def pattern(self) -> _Node:
        """``{ a, b: c, d: { e } = {}, 'f-g': h, ...rest }``: (key, target, default) triples
        and the rest name."""
        self.take("{")
        pairs: list[tuple[object, _Node, _Node | None]] = []
        rest = None
        while not self.is_op("}"):
            if self.is_op("..."):
                self.i += 1
                rest = self.binding()
                if rest.kind != "name":
                    raise Unsupported("a pattern after ... in an object pattern")
                break
            tok = self.take()
            if tok.kind == "op":
                raise Unsupported("computed key")
            target = _Node("name", tok.value)
            if self.is_op(":"):
                self.i += 1
                target = self.binding()
            elif tok.kind != "name":
                raise Unsupported(f"{tok.value!r} without a name")
            pairs.append((tok.value, target, self.default()))
            if not self.is_op("}"):
                self.take(",")
        self.take("}")
        return _Node("pattern", (pairs, rest))

    # expressions, lowest precedence first
    def expression(self) -> _Node:
        node = self.assignment()
        while self.is_op(","):
            self.i += 1
            node = _Node("seq", None, (node, self.assignment()))
        return node

    def assignment(self) -> _Node:
        start = self.i
        if self.is_name("async") and (nxt := self.peek(1)) is not None and not nxt.newline:
            self.i += 1
            arrow = self._arrow_ahead()
            self.i = start
            if arrow:
                return self.arrow()
        if self.is_op("(") or (self.peek() is not None and self.peek().kind == "name"):  # type: ignore[union-attr]
            if self._arrow_ahead():
                return self.arrow()
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
            if tok.value == "function" or (tok.value == "async" and self.is_name("function")):
                self.i -= 1
                return self.function()
            if tok.value in ("class", "this", "super", "yield"):
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


class _Fn:
    """A function value (compared and shown by identity)."""

    def __init__(self, params: list, body: object, block: bool) -> None:
        self.params, self.body, self.block = params, body, block

    def __repr__(self) -> str:
        return f"<function {id(self)}>"


_DEPTH: list[int] = [0]  # how many calls deep (one run at a time)
_MAX_DEPTH = 8
_MAX_ROUNDS = 8
_CALLBACKS = {"some", "every", "find", "findIndex", "filter", "map", "forEach"}


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


class _Collection:
    """A ``Map`` (``pairs``) or ``Set`` (keys with no value), kept as an immutable list of
    entries in insertion order; ``set``/``add`` make a new one."""

    def __init__(self, kind: str, pairs: tuple[tuple[object, object], ...] = ()) -> None:
        self.kind, self.pairs = kind, pairs

    def __repr__(self) -> str:
        return f"{self.kind}({self.pairs!r})"

    def find(self, key: object) -> tuple[bool | None, object]:
        """Whether ``key`` is in it (None: may be) and its value (UNKNOWN if not sure)."""
        maybe = False
        for k, v in self.pairs:
            same = _equal(k, key, True)
            if same is True:
                return (None, UNKNOWN) if maybe else (True, v)
            if same is None:
                maybe = True
        return (None, UNKNOWN) if maybe else (False, UNDEFINED)

    def put(self, key: object, value: object) -> object:
        """A new one with ``key`` set; UNKNOWN when it may or may not be there already."""
        found, _ = self.find(key)
        if found is None:
            return UNKNOWN
        pairs = tuple((k, value if _equal(k, key, True) else v) for k, v in self.pairs)
        return _Collection(self.kind, pairs if found else (*pairs, (key, value)))


def _construct(callee: list[str] | None, args: list[object]) -> object:
    """``new Map()``, ``new Map([[k, v]])``, ``new Set([...])``; anything else is unknown."""
    items = args[0] if args else []
    if callee == ["Set"] and isinstance(items, list):
        return _Collection("Set", tuple((item, True) for item in items))
    if (
        callee == ["Map"]
        and isinstance(items, list)
        and all(isinstance(i, list) and len(i) == 2 for i in items)
    ):
        return _Collection("Map", tuple((i[0], i[1]) for i in items))  # type: ignore[index]
    return UNKNOWN


def _method(obj: object, name: str, args: list[object]) -> object:
    """A known method on a known value, or UNKNOWN."""
    if isinstance(obj, _Collection) and args and name in ("has", "get"):
        found, value = obj.find(args[0])
        if name == "has":
            return UNKNOWN if found is None else found
        return value
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
        callee = _callee_path(node.children[0])
        return _seq(list(node.children[1:]), env, lambda args: _construct(callee, args))
    if kind == "spread":
        return _eval(node.children[0], env)
    if kind == "function":
        params, body, block = node.children
        return [(env, _Fn(params, body, block))], []
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


def _names(target: _Node) -> list[str]:
    """The names a binding target (a name, ``pattern`` or ``apattern``) declares."""
    if target.kind == "name":
        return [str(target.value)]
    if target.kind == "pattern":
        pairs, rest = target.value  # type: ignore[misc]
        subs = [sub for _, sub, _ in pairs]
    else:
        items, rest = target.value  # type: ignore[misc]
        subs = [item[0] for item in items if item is not None]
    if rest is not None:
        subs.append(rest)
    return [name for sub in subs for name in _names(sub)]


def _locals(body: object, params: _Node) -> set[str]:
    """The names a function declares itself (parameters, const/let/var, inner functions):
    they don't change the caller's names."""
    names = set(_names(params))
    todo = list(body) if isinstance(body, list) else []
    while todo:
        node = todo.pop()
        if not isinstance(node, _Node) or node.kind == "function":
            continue  # a nested function's names are its own
        if node.kind == "declare":
            names.update(_names(node.children[0]))
        elif node.kind == "fundecl":
            names.add(str(node.value))
            continue
        elif node.kind == "forof":
            names.update(_names(node.value))  # type: ignore[arg-type]
        for child in node.children:
            if isinstance(child, list):
                todo += child
            elif isinstance(child, tuple):
                todo += [c for c in child if isinstance(c, (_Node, list))]
            else:
                todo.append(child)
        if isinstance(node.value, list):
            todo += node.value
    return names


def _invoke(fn: _Fn, args: list[object], env: _Env) -> Values:
    """Calls ``fn``: its body runs with the parameters bound; afterwards the caller's names are
    back, but changes to names the function doesn't declare stay (they're the caller's)."""
    if _DEPTH[0] >= _MAX_DEPTH:
        raise Unsupported("calls too deep")
    _DEPTH[0] += 1
    try:
        try:
            inner = _bind(fn.params, list(args), env)
        except _Throw:
            return [], [env]  # a parameter pattern on undefined or null
        local = _locals(fn.body, fn.params)
        values: list[tuple[_Env, object]] = []
        thrown: list[_Env] = []
        if fn.block:
            for end in _block(fn.body, [inner]):  # type: ignore[arg-type]
                if end.kind in ("exit_ok", "exit_fail", "break", "continue"):
                    raise Unsupported(f"{end.kind} inside a function")
                if end.kind == "throw":
                    thrown.append(_back(end.env, env, local))
                else:
                    values.append(
                        (_back(end.env, env, local), end.value if end.kind == "return" else UNDEFINED)
                    )
        else:
            out, err = _eval(fn.body, inner)  # type: ignore[arg-type]
            values = [(_back(e, env, local), v) for e, v in out]
            thrown = [_back(e, env, local) for e in err]
        return values, thrown
    finally:
        _DEPTH[0] -= 1


def _back(after: _Env, before: _Env, local: set[str]) -> _Env:
    names = {k: v for k, v in after.names.items() if k not in local}
    names.update({k: v for k, v in before.names.items() if k in local})
    return _Env(names, after.outputs, after.failed, after.asked)


def _callback(method: str, items: object, fn: _Fn, env: _Env) -> Values:
    """``items.some(fn)`` and the like: ``fn(item, index)`` for each element of a known list,
    in order; on anything else zero or one call (for what it may change) and an unknown
    result."""
    if not isinstance(items, list):
        out, thrown = _invoke(fn, [UNKNOWN, UNKNOWN, items], env)
        return [(env, UNKNOWN)] + [(e, UNKNOWN) for e, _ in out], thrown
    states: list[tuple[_Env, list[object]]] = [(env, [])]
    thrown: list[_Env] = []
    for index, item in enumerate(items):
        nxt = []
        for e, results in states:
            out, err = _invoke(fn, [item, float(index), items], e)
            thrown += err
            nxt += [(e2, [*results, v]) for e2, v in out]
        states = _cap(nxt)
    return [(e, _combine(method, items, results)) for e, results in states], thrown


def _collection_call(name: str, method: str, arg_nodes: list[_Node], env: _Env) -> Values:
    """``cache.has(k)``, ``cache.get(k)``, ``cache.set(k, v)``, ``seen.add(k)`` on a Map or Set
    held in a name: ``set``/``add`` put the new one back under that name."""

    def apply(args: list[object]) -> object:
        return args

    out, thrown = _seq(list(arg_nodes), env, apply)
    values: list[tuple[_Env, object]] = []
    for e, args in out:
        held = e.names[name]
        assert isinstance(held, _Collection)
        if method in ("has", "get"):
            values.append((e, _method(held, method, args)))  # type: ignore[arg-type]
        elif method in ("set", "add") and args:
            value = args[1] if method == "set" and len(args) > 1 else True  # type: ignore[index]
            new = held.put(args[0], value if held.kind == "Map" else True)  # type: ignore[index]
            values.append((e.with_name(name, new), new))
        else:
            raise Unsupported(f"{held.kind}.{method}")
    return values, thrown


def _combine(method: str, items: list[object], results: list[object]) -> object:
    tests = [_truthy(r) for r in results]
    if method == "some":
        return True if True in tests else (UNKNOWN if None in tests else False)
    if method == "every":
        return False if False in tests else (UNKNOWN if None in tests else True)
    if method in ("find", "findIndex"):
        for index, (item, test) in enumerate(zip(items, tests, strict=True)):
            if test is None:
                return UNKNOWN
            if test:
                return item if method == "find" else float(index)
        return UNDEFINED if method == "find" else -1.0
    if method == "filter":
        return UNKNOWN if None in tests else [item for item, test in zip(items, tests, strict=True) if test]
    if method == "map":
        return list(results)
    return UNDEFINED  # forEach


def _call(node: _Node, env: _Env) -> Values:
    callee, *arg_nodes = node.children
    if callee.kind == "member" and str(callee.value) in _CALLBACKS and len(arg_nodes) == 1:
        method = str(callee.value)

        def apply(vals: list[object]) -> object:
            return vals

        pairs, thrown = _seq([callee.children[0], arg_nodes[0]], env, apply)
        values: list[tuple[_Env, object]] = []
        for e, (items, fn) in pairs:  # type: ignore[misc]
            if isinstance(fn, _Fn):
                out, err = _callback(method, items, fn, e)
                values += out
                thrown += err
            else:
                values.append((e, UNKNOWN))
                thrown.append(e)
        return _cap(values), thrown
    if callee.kind not in ("name", "member") or (
        callee.kind == "name" and isinstance(env.names.get(str(callee.value)), _Fn)
    ):
        fns, thrown = _eval(callee, env)
        values = []
        for e, fn in fns:
            args_out, err = _seq(list(arg_nodes), e, lambda vals: vals)
            thrown += err
            for e2, args in args_out:
                if not isinstance(fn, _Fn):
                    values.append((e2, UNKNOWN))
                    thrown.append(e2)
                    continue
                out, err2 = _invoke(fn, args, e2)  # type: ignore[arg-type]
                values += out
                thrown += err2
        return _cap(values), thrown
    path = _callee_path(callee)
    if path and len(path) == 2 and isinstance(env.names.get(path[0]), _Collection):
        return _collection_call(path[0], path[1], arg_nodes, env)
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
        if name in _STRING_METHODS | {"includes", "indexOf", "startsWith", "endsWith", "has", "get"}:
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
    if path == ["Promise", "all"] and args and isinstance(args[0], list):
        # `await` changes nothing here: the calls in the list already ran (and may have thrown)
        return [(env, args[0])], []
    if path and len(path) == 2 and path[0] == "Object" and path[1] in ("keys", "values", "entries"):
        obj = args[0] if args else UNDEFINED
        if isinstance(obj, dict) and not isinstance(obj, _Context):
            pairs = list(obj.items())
            listed = {
                "keys": [k for k, _ in pairs],
                "values": [v for _, v in pairs],
                "entries": [[k, v] for k, v in pairs],
            }[path[1]]
            return [(env, listed)], []
        if isinstance(obj, _Context):
            return [(env, UNKNOWN)], []
        if obj is None or obj is UNDEFINED:
            return [], [env]
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
    """Runs statements from each env: how each path ends (``normal`` if it falls through).
    Function statements are bound first (JavaScript hoists them)."""
    ends: list[_End] = []
    current = envs
    for stmt in body:
        if stmt.kind == "fundecl":
            params, fbody, block = stmt.children
            current = [e.with_name(str(stmt.value), _Fn(params, fbody, block)) for e in current]
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
    if kind == "fundecl":
        return [_End("normal", env)]  # bound when its block started
    if kind in ("break", "continue"):
        return [_End(kind, env)]
    if kind == "forof":
        return _for_of(stmt, env)
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


def _for_of(stmt: _Node, env: _Env) -> list[_End]:
    """``for (const x of items)``: once per element of a known list; otherwise round after
    round with ``x`` unknown until no new state turns up (the loop may end before any round)."""
    target = stmt.value
    iterable, body = stmt.children
    out, thrown = _eval(iterable, env)
    ends = [_End("throw", e) for e in thrown]

    def bound(envs: list[_Env], item: object) -> list[_Env]:
        result = []
        for e in envs:
            try:
                result.append(_bind(target, item, e))  # type: ignore[arg-type]
            except _Throw:
                ends.append(_End("throw", e))
        return result

    for start, value in out:
        try:
            items = _iterate(value)
        except _Throw:
            ends.append(_End("throw", start))
            continue
        if isinstance(items, list):
            current = [start]
            for item in items:
                again: list[_Env] = []
                for end in _block(body, bound(current, item)):
                    if end.kind in ("normal", "continue"):
                        again.append(end.env)
                    elif end.kind == "break":
                        ends.append(_End("normal", end.env))
                    else:
                        ends.append(end)
                current = [e.env for e in _dedupe([_End("normal", e) for e in again])]
            ends += [_End("normal", e) for e in current]
            continue
        seen = {start.key()}
        current = [start]
        ends.append(_End("normal", start))
        for _ in range(_MAX_ROUNDS):
            fresh: list[_Env] = []
            for end in _block(body, bound(current, UNKNOWN)):
                if end.kind in ("normal", "continue"):
                    ends.append(_End("normal", end.env))
                    if end.env.key() not in seen:
                        seen.add(end.env.key())
                        fresh.append(end.env)
                elif end.kind == "break":
                    ends.append(_End("normal", end.env))
                else:
                    ends.append(end)
            current = fresh
            if not current:
                break
        else:
            raise Unsupported("a loop that doesn't settle")
    return _dedupe(ends)


def _bind(target: _Node, value: object, env: _Env) -> _Env:
    """``target = value`` for a name or a pattern; raises _Throw where JavaScript throws (an
    object pattern on undefined or null, an array pattern on something not iterable)."""
    if target.kind == "name":
        return env.with_name(str(target.value), value)
    if target.kind == "pattern":
        pairs, rest = target.value  # type: ignore[misc]
        if value is None or value is UNDEFINED:
            raise _Throw
        for key, sub, default in pairs:
            env = _bind(sub, _default(_member(value, key), default, env), env)
        if rest is not None:
            env = _bind(rest, _object_rest(value, {key for key, _, _ in pairs}), env)
        return env
    items, rest = target.value  # type: ignore[misc]
    elements = _iterate(value)
    for i, item in enumerate(items):
        if item is None:
            continue
        sub, default = item
        if isinstance(elements, list):
            element = elements[i] if i < len(elements) else UNDEFINED
        else:
            element = UNKNOWN
        env = _bind(sub, _default(element, default, env), env)
    if rest is not None:
        env = _bind(rest, elements[len(items) :] if isinstance(elements, list) else UNKNOWN, env)
    return env


def _default(value: object, default: _Node | None, env: _Env) -> object:
    """``value`` or, where it is undefined, the default; a default that may throw or change
    anything isn't followed."""
    if default is None or (value is not UNDEFINED and value is not UNKNOWN):
        return value
    out, thrown = _eval(default, env)
    if thrown or any(e.key() != env.key() for e, _ in out):
        raise Unsupported("a default that may throw or change something")
    if value is UNKNOWN or len(out) != 1:
        return UNKNOWN
    return out[0][1]


def _iterate(value: object) -> object:
    """The elements ``for...of`` and an array pattern go through: a list, or UNKNOWN; raises
    _Throw for something that isn't iterable."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return list(value)
    if isinstance(value, _Collection):
        if value.kind == "Map":
            return [[k, v] for k, v in value.pairs]
        return [k for k, _ in value.pairs]
    if value is UNKNOWN or value is STRANGER:
        return UNKNOWN
    raise _Throw  # undefined, null, a number, a plain object, a function


def _object_rest(value: object, taken: set[object]) -> object:
    """``...rest`` in an object pattern: the other keys of a known object."""
    if isinstance(value, dict) and not isinstance(value, _Context):
        return {k: v for k, v in value.items() if k not in taken}
    return UNKNOWN
