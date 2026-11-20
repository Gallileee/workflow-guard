"""Does an ``if:`` keep strangers out? Evaluating a condition for the people it should stop.

WG010 needs to know whether a job's ``if:`` stops commenters who can't write to the
repository. Mentioning ``github.event.comment.author_association`` isn't enough:
``author_association != 'NONE'`` still lets in everyone who once had a pull request merged
(``CONTRIBUTOR``) or opened one (``FIRST_TIME_CONTRIBUTOR``).

So the condition is evaluated, once for each association that can't write, with:

- ``github.event.comment.author_association`` set to that association;
- the commenter's login (``github.actor``, ``github.triggering_actor``,
  ``github.event.comment.user.login``, ``github.event.sender.login``) set to a stranger: an
  account that equals no login written in the workflow, but whose name is otherwise unknown;
- ``vars.*`` and ``secrets.*`` to a list the owners keep: a stranger isn't on it, so
  ``contains(fromJSON(vars.MAINTAINERS), github.actor)`` and ``github.actor == vars.DEPLOYER``
  are false for them;
- ``github.event_name`` to ``issue_comment`` (a workflow with more triggers often has
  ``github.event_name == 'workflow_dispatch' || (...)``);
- everything else (the comment's text, the issue, ``success()``...) unknown.

Values are three-valued: a result is known only when it holds whatever the unknowns are
(``x && false`` is false for every ``x``). A condition keeps a stranger out only if it is
*certainly* false for them; anything else (true or unknown) lets them in.

Reference: https://docs.github.com/en/actions/reference/workflows-and-actions/expressions
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from .expressions import ExpressionError, Token, tokenize


class _Unknown:
    def __repr__(self) -> str:
        return "UNKNOWN"


class _Stranger:
    """A login no one wrote down: not equal to any login in the workflow."""

    def __repr__(self) -> str:
        return "STRANGER"


class _OwnersList:
    """A value from ``vars`` or ``secrets``: set by the repository's owners, unknown to us,
    but never naming a stranger."""

    def __repr__(self) -> str:
        return "OWNERS_LIST"


UNKNOWN = _Unknown()
STRANGER = _Stranger()
OWNERS_LIST = _OwnersList()

TRUSTED_ASSOCIATIONS = ("OWNER", "MEMBER", "COLLABORATOR")
"""Associations of people who can write to the repository (or own it)."""
UNTRUSTED_ASSOCIATIONS = ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN", "NONE")
"""Every other value GitHub gives ``author_association``."""

ASSOCIATION = ("github", "event", "comment", "author_association")
EVENT_NAME = ("github", "event_name")
LOGINS = (
    ("github", "actor"),
    ("github", "triggering_actor"),
    ("github", "event", "comment", "user", "login"),
    ("github", "event", "sender", "login"),
)


# --- parsing -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Node:
    kind: str  # literal, path, call, not, and, or, compare, unknown
    value: object = None
    children: tuple[Node, ...] = ()


_COMPARE = ("==", "!=", "<", "<=", ">", ">=")


class _Parser:
    """Recursive descent with GitHub's precedence: ``!`` > comparisons > ``&&`` > ``||``."""

    def __init__(self, tokens: Sequence[Token]) -> None:
        self.tokens = tokens
        self.i = 0

    def peek(self) -> Token | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self, kind: str) -> Token:
        tok = self.peek()
        if tok is None or tok.kind != kind:
            raise ExpressionError(f"expected {kind!r} at token {self.i}")
        self.i += 1
        return tok

    def accept(self, *kinds: str) -> Token | None:
        tok = self.peek()
        if tok is not None and tok.kind in kinds:
            self.i += 1
            return tok
        return None

    def parse(self) -> Node:
        node = self.or_()
        if self.peek() is not None:
            raise ExpressionError(f"unexpected {self.peek().value!r}")
        return node

    def or_(self) -> Node:
        node = self.and_()
        while self.accept("||"):
            node = Node("or", children=(node, self.and_()))
        return node

    def and_(self) -> Node:
        node = self.compare()
        while self.accept("&&"):
            node = Node("and", children=(node, self.compare()))
        return node

    def compare(self) -> Node:
        node = self.unary()
        while op := self.accept(*_COMPARE):
            node = Node("compare", op.kind, (node, self.unary()))
        return node

    def unary(self) -> Node:
        if self.accept("!"):
            return Node("not", children=(self.unary(),))
        return self.postfix(self.primary())

    def primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise ExpressionError("expression ends early")
        self.i += 1
        if tok.kind == "(":
            node = self.or_()
            self.take(")")
            return node
        if tok.kind == "STRING":
            return Node("literal", tok.value)
        if tok.kind == "NUMBER":
            return Node("literal", _number(tok.value))
        if tok.kind == "NAME":
            name = tok.value.lower()
            if self.accept("("):
                args: list[Node] = []
                if not self.accept(")"):
                    args.append(self.or_())
                    while self.accept(","):
                        args.append(self.or_())
                    self.take(")")
                return Node("call", name, tuple(args))
            if name in ("true", "false"):
                return Node("literal", name == "true")
            if name == "null":
                return Node("literal", None)
            return Node("path", (name,))
        raise ExpressionError(f"unexpected {tok.value!r}")

    def postfix(self, node: Node) -> Node:
        """``.name``, ``.*``, ``['key']``, ``[0]``, ``[expr]`` after a value."""
        while True:
            if self.accept("."):
                tok = self.accept("NAME", "*")
                if tok is None:
                    raise ExpressionError("expected a name after '.'")
                node = _extend(node, tok.value.lower() if tok.kind == "NAME" else "*")
            elif self.accept("["):
                if self.accept("*"):
                    self.take("]")
                    node = _extend(node, "*")
                    continue
                index = self.or_()
                self.take("]")
                key = index.value if index.kind == "literal" and isinstance(index.value, str) else "*"
                node = _extend(node, key.lower())
            else:
                return node


def _extend(node: Node, segment: str) -> Node:
    if node.kind == "path":
        return Node("path", (*node.value, segment))
    return Node("unknown")  # a property of a function's result, e.g. fromJSON(x).y


def _number(text: str) -> float:
    try:
        return float(int(text, 16)) if text.lower().startswith(("0x", "-0x")) else float(text)
    except ValueError as err:
        raise ExpressionError(f"bad number {text!r}") from err


def parse(text: str) -> Node:
    """Parse the inside of ``${{ }}`` (or a bare ``if:``). Raises ``ExpressionError``."""
    return _Parser(tokenize(text)).parse()


STATUS_FUNCTIONS = ("success", "failure", "cancelled", "always")
"""Functions that make an ``if:`` look at how the earlier steps (or the needed jobs) ended.
An ``if:`` that calls none of them gets ``success() &&`` in front of it, so it never runs after
a failure. ``evaluate`` asks ``lookup`` for ``("success()",)``, ``("failure()",)`` and
``("cancelled()",)``; ``always()`` is true."""


def status_functions(text: str) -> tuple[str, ...]:
    """The status functions ``text`` calls, in order of first use (``("always",)``); empty if
    none, so the implicit ``success()`` applies. Raises ``ExpressionError``."""
    found: list[str] = []

    def walk(node: Node) -> None:
        if node.kind == "call" and node.value in STATUS_FUNCTIONS and not node.children:
            if node.value not in found:
                found.append(str(node.value))
        for child in node.children:
            walk(child)

    walk(parse(text))
    return tuple(found)


# --- evaluating ----------------------------------------------------------------------------------


def truthy(value: object) -> bool | _Unknown:
    if value is UNKNOWN or value is OWNERS_LIST:
        return UNKNOWN
    if value is STRANGER:
        return True  # a login is never empty
    if value is None or value is False or value == "":
        return False
    if isinstance(value, float):
        return value != 0 and not math.isnan(value)
    return True


def _to_number(value: object) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, float):
        return value
    if isinstance(value, str):
        try:
            return float(value.strip()) if value.strip() else 0.0
        except ValueError:
            return math.nan
    return math.nan  # arrays and objects


def _equal(a: object, b: object) -> bool | _Unknown:
    if a is UNKNOWN or b is UNKNOWN:
        return UNKNOWN
    if {id(a), id(b)} == {id(STRANGER), id(OWNERS_LIST)}:
        return False
    if a is OWNERS_LIST or b is OWNERS_LIST:
        return UNKNOWN
    if a is STRANGER or b is STRANGER:
        other = b if a is STRANGER else a
        return UNKNOWN if other is STRANGER else False
    if isinstance(a, str) and isinstance(b, str):
        return a.casefold() == b.casefold()
    if isinstance(a, (list, dict)) or isinstance(b, (list, dict)):
        return a is b
    if type(a) is type(b):
        return a == b
    return _to_number(a) == _to_number(b)  # NaN equals nothing


def _compare(op: str, a: object, b: object) -> object:
    if op in ("==", "!="):
        eq = _equal(a, b)
        return eq if eq is UNKNOWN or op == "==" else not eq
    if any(v is UNKNOWN or v is STRANGER or v is OWNERS_LIST for v in (a, b)):
        return UNKNOWN
    if isinstance(a, str) and isinstance(b, str):
        x, y = a.casefold(), b.casefold()
    else:
        x, y = _to_number(a), _to_number(b)
        if math.isnan(x) or math.isnan(y):
            return False
    return {"<": x < y, "<=": x <= y, ">": x > y, ">=": x >= y}[op]


def _contains(search: object, item: object) -> object:
    if search is OWNERS_LIST:
        return False if item is STRANGER else UNKNOWN
    if search is UNKNOWN or item is UNKNOWN or search is STRANGER or item is OWNERS_LIST:
        return UNKNOWN
    if isinstance(search, list):
        results = [_equal(element, item) for element in search]
        if True in results:
            return True
        return UNKNOWN if UNKNOWN in results else False
    if item is STRANGER:
        return UNKNOWN  # a stranger may pick a login that is part of the text
    return _text(item).casefold() in _text(search).casefold()


def _affix(text: object, part: object, starts: bool) -> object:
    if any(v is UNKNOWN or v is STRANGER or v is OWNERS_LIST for v in (text, part)):
        return UNKNOWN
    whole, piece = _text(text).casefold(), _text(part).casefold()
    return whole.startswith(piece) if starts else whole.endswith(piece)


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else str(value)
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _from_json(value: object) -> object:
    if value is OWNERS_LIST:
        return OWNERS_LIST
    if not isinstance(value, str):
        return UNKNOWN
    try:
        loaded = json.loads(value)
    except ValueError:
        return UNKNOWN
    return _normalize(loaded)


def _normalize(value: object) -> object:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, dict):
        return {str(k).lower(): _normalize(v) for k, v in value.items()}
    return UNKNOWN


def evaluate(node: Node, lookup: Callable[[tuple[str, ...]], object]) -> object:
    """The value of ``node``; context values come from ``lookup``."""
    if node.kind == "literal":
        return node.value
    if node.kind == "path":
        return lookup(node.value)
    if node.kind == "not":
        value = truthy(evaluate(node.children[0], lookup))
        return value if value is UNKNOWN else not value
    if node.kind in ("and", "or"):
        left = evaluate(node.children[0], lookup)
        decided = truthy(left)
        stop = False if node.kind == "and" else True
        if decided is stop:
            return left
        right = evaluate(node.children[1], lookup)
        if decided is not UNKNOWN:
            return right
        # The left side is unknown: the result is known only if the right side decides it.
        return stop if truthy(right) is stop else UNKNOWN
    if node.kind == "compare":
        a, b = (evaluate(child, lookup) for child in node.children)
        return _compare(node.value, a, b)
    if node.kind == "call":
        args = [evaluate(child, lookup) for child in node.children]
        name = node.value
        if name == "contains" and len(args) == 2:
            return _contains(*args)
        if name in ("startswith", "endswith") and len(args) == 2:
            return _affix(args[0], args[1], name == "startswith")
        if name == "fromjson" and len(args) == 1:
            return _from_json(args[0])
        if name == "always" and not args:
            return True
        if name in STATUS_FUNCTIONS and not args:
            return lookup((f"{name}()",))  # success(), failure(), cancelled()
        return UNKNOWN  # format(), toJSON(), hashFiles()...
    return UNKNOWN


# --- the question WG010 asks ---------------------------------------------------------------------


def _stranger_lookup(association: str) -> Callable[[tuple[str, ...]], object]:
    def lookup(path: tuple[str, ...]) -> object:
        if path == ASSOCIATION:
            return association
        if path == EVENT_NAME:
            return "issue_comment"
        if path in LOGINS:
            return STRANGER
        if path[0] in ("vars", "secrets") and len(path) > 1:
            return OWNERS_LIST
        return UNKNOWN

    return lookup


def lets_in(condition: str) -> tuple[str, ...]:
    """The associations without write access for which ``condition`` may be true.

    An empty result means the condition keeps every such commenter out (whatever their login
    and whatever the comment says). Raises ``ExpressionError`` for text that isn't an
    expression."""
    tree = parse(condition)
    return tuple(
        association
        for association in UNTRUSTED_ASSOCIATIONS
        if truthy(evaluate(tree, _stranger_lookup(association))) is not False
    )


# --- the answer of a permission step that only reports ------------------------------------------

NO_ANSWERS = ("", "false", "none", "read")
"""What a permission step that only reports may put in its outputs for a commenter who can't
write: nothing (the step didn't set it), ``false`` (a yes/no output), or the permission level
GitHub gives them (``none``, or ``read`` on a public repository)."""


def _for_strangers(condition: str, lookup: Callable[[tuple[str, ...]], object]) -> list[object]:
    """How ``condition`` comes out (True, False or UNKNOWN) for each association that can't
    write, with ``lookup`` for every value the stranger doesn't set."""
    tree = parse(condition)
    results = []
    for association in UNTRUSTED_ASSOCIATIONS:
        stranger = _stranger_lookup(association)

        def both(path: tuple[str, ...], stranger: Callable[[tuple[str, ...]], object] = stranger) -> object:
            value = stranger(path)
            return lookup(path) if value is UNKNOWN else value

        results.append(truthy(evaluate(tree, both)))
    return results


def may_pass(condition: str, lookup: Callable[[tuple[str, ...]], object]) -> bool:
    """Whether ``condition`` may be true for a commenter who can't write. The commenter's
    association, login, ``vars`` and ``secrets`` are set as for ``lets_in``; ``lookup`` gives
    every other value (UNKNOWN for none). Raises ``ExpressionError``."""
    return any(result is not False for result in _for_strangers(condition, lookup))


def must_pass(condition: str, lookup: Callable[[tuple[str, ...]], object]) -> bool:
    """Whether ``condition`` is certainly true for every commenter who can't write (values set
    as for ``may_pass``). Raises ``ExpressionError``."""
    return all(result is True for result in _for_strangers(condition, lookup))


def text_value(expression: str, lookup: Callable[[tuple[str, ...]], object]) -> object:
    """The text ``${{ expression }}`` puts in its place, or UNKNOWN. Raises ``ExpressionError``."""
    value = evaluate(parse(expression), lookup)
    if value is UNKNOWN or value is STRANGER or value is OWNERS_LIST:
        return UNKNOWN
    return _text(value)
