"""conditions.py: evaluating an if: for commenters who can't write to the repository."""

import pytest

from workflow_guard.conditions import (
    STRANGER,
    UNKNOWN,
    UNTRUSTED_ASSOCIATIONS,
    evaluate,
    lets_in,
    parse,
    truthy,
)
from workflow_guard.expressions import ExpressionError

ASSOC = "github.event.comment.author_association"
EVERYONE = UNTRUSTED_ASSOCIATIONS


def value(text: str, **context):
    """Evaluate ``text``; ``github__actor=...`` sets ``github.actor``, the rest is unknown."""
    known = {tuple(k.split("__")): v for k, v in context.items()}
    return evaluate(parse(text), lambda path: known.get(path, UNKNOWN))


# --- the evaluator -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("'a' == 'A'", True),  # strings compare ignoring case
        ("1 == '1'", True),  # different types compare as numbers
        ("null == 0", True),
        ("true == 1", True),
        ("'x' == 0", False),  # 'x' is NaN as a number
        ("0x10 == 16", True),
        ("!('a' != 'a')", True),
        ("2 < 10", True),
        ("'b' > 'a'", True),
        ("contains('Hello', 'ELL')", True),
        ("contains(fromJSON('[\"a\", \"b\"]'), 'B')", True),
        ("contains(fromJSON('[\"a\", \"b\"]'), 'c')", False),
        ("startsWith('/deploy now', '/DEPLOY')", True),
        ("endsWith('abc', 'b')", False),
        ("always()", True),
        ("'' || 'b'", "b"),
        ("'a' && ''", ""),
    ],
)
def test_known_values(text, expected):
    assert value(text) == expected


@pytest.mark.parametrize(
    "text",
    ["success()", "format('{0}', 'x') == 'x'", "fromJSON('{\"A\": 1}').a", "hashFiles('x')"],
)
def test_functions_we_dont_evaluate_are_unknown(text):
    assert value(text) is UNKNOWN


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("x && false", False),
        ("false && x", False),
        ("x || true", True),
        ("x && true", UNKNOWN),
        ("x || false", UNKNOWN),
        ("!x", UNKNOWN),
        ("x == 'a'", UNKNOWN),
        ("x < 1", UNKNOWN),
    ],
)
def test_unknowns_decide_nothing_unless_the_other_side_does(text, expected):
    assert truthy(value(text)) is expected


def test_precedence_and_paths():
    assert value("true || false && false") is True  # && binds tighter than ||
    assert value("!false == true") is True  # ! binds tighter than ==
    path = {"github__event__comment__author_association": "none"}
    assert value("github['event'].Comment.author_association == 'NONE'", **path) is True
    assert value("github.event.comment.*.x", **path) is UNKNOWN
    assert value("github.event.comment[*].x", **path) is UNKNOWN


def test_a_stranger_equals_no_written_login_but_may_contain_one():
    assert value("github.actor == 'me'", github__actor=STRANGER) is False
    assert value("github.actor != 'me'", github__actor=STRANGER) is True
    assert value("contains(fromJSON('[\"me\"]'), github.actor)", github__actor=STRANGER) is False
    assert value("contains('me,you', github.actor)", github__actor=STRANGER) is UNKNOWN
    assert value("startsWith(github.actor, 'dependabot')", github__actor=STRANGER) is UNKNOWN
    assert value("github.actor == github.triggering_actor", github__actor=STRANGER) is UNKNOWN


@pytest.mark.parametrize("text", ["a ==", "(a", "a b", "f(a,", "a.", "'x' = 1", ""])
def test_invalid_expressions_raise(text):
    with pytest.raises(ExpressionError):
        parse(text)


# --- lets_in -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cond",
    [
        f"{ASSOC} == 'OWNER'",
        f"{ASSOC} == 'OWNER' || {ASSOC} == 'MEMBER' || {ASSOC} == 'COLLABORATOR'",
        f'contains(fromJSON(\'["OWNER", "MEMBER", "COLLABORATOR"]\'), {ASSOC})',
        f"contains('OWNER,MEMBER,COLLABORATOR', {ASSOC})",
        f"github.event.issue.pull_request && contains(github.event.comment.body, '/t')"
        f" && {ASSOC} == 'MEMBER'",
        f"!({ASSOC} != 'OWNER')",
        "github.actor == 'maintainer'",
        "github.event.comment.user.login == 'a' || github.triggering_actor == 'b'",
        "contains(fromJSON(vars.MAINTAINERS), github.actor)",
        "github.actor == vars.DEPLOYER",
        f"{ASSOC} == 'OWNER' || github.actor == 'dependabot[bot]'",
    ],
)
def test_allow_lists_let_no_one_in(cond):
    assert lets_in(cond) == ()


@pytest.mark.parametrize(
    ("cond", "who"),
    [
        (f"{ASSOC} != 'NONE'", ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN")),
        (
            f"{ASSOC} != 'NONE' && {ASSOC} != 'FIRST_TIME_CONTRIBUTOR' && {ASSOC} != 'FIRST_TIMER'",
            ("CONTRIBUTOR", "MANNEQUIN"),
        ),
        (f'contains(fromJSON(\'["OWNER", "CONTRIBUTOR"]\'), {ASSOC})', ("CONTRIBUTOR",)),
        (
            f'!contains(fromJSON(\'["NONE", "FIRST_TIMER"]\'), {ASSOC})',
            ("CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN"),
        ),
        (f"{ASSOC} == 'OWNER' || contains(github.event.comment.body, '/force')", EVERYONE),
        ("github.actor != 'dependabot[bot]'", EVERYONE),
        ("contains('alice,bob', github.actor)", EVERYONE),
        ("startsWith(github.actor, 'team-')", EVERYONE),
        (f"{ASSOC} == 'OWNER' || always()", EVERYONE),
        (f"{ASSOC}", EVERYONE),
        (f"contains(vars.ROLES, {ASSOC})", EVERYONE),
        ("github.actor == 'me' || !vars.LOCKED", EVERYONE),  # a variable may be empty
    ],
)
def test_weak_checks_name_who_gets_in(cond, who):
    assert lets_in(cond) == who
