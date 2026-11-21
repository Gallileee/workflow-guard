"""conditions.py: evaluating an if: for commenters who can't write to the repository."""

import pytest

from workflow_guard.conditions import (
    OWNERS_LIST,
    STRANGER,
    UNKNOWN,
    UNTRUSTED_ASSOCIATIONS,
    evaluate,
    lets_in,
    may_pass,
    must_pass,
    parse,
    status_functions,
    stranger_text,
    text_value,
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


# --- may_pass and text_value ---------------------------------------------------------------------


def _answer(value: str):
    def lookup(path):
        if path == ("steps", "perm", "outputs", "ok"):
            return value
        if path == ("github", "actor"):
            return STRANGER
        if path[0] == "vars":
            return OWNERS_LIST
        return UNKNOWN

    return lookup


@pytest.mark.parametrize(
    ("condition", "answer", "passes"),
    [
        ("steps.perm.outputs.ok == 'true'", "false", False),
        ("steps.perm.outputs.ok", "false", True),
        ("steps.perm.outputs.ok", "", False),
        ("steps.perm.outputs.ok != 'false'", "", True),
        ("steps.perm.outputs.ok != 'false'", "false", False),
        ("steps.perm.outputs.ok == 'true' || github.event.comment.author_association == 'OWNER'", "", False),
        ("steps.perm.outputs.ok == 'true' || github.event.comment.author_association != 'NONE'", "", True),
        ("steps.perm.outputs.ok == 'true' || success()", "", True),
        ("steps.other.outputs.ok == 'true'", "", True),
    ],
)
def test_may_pass(condition, answer, passes):
    assert may_pass(condition, _answer(answer)) is passes


@pytest.mark.parametrize(
    ("expression", "value"),
    [
        ("steps.perm.outputs.ok", "read"),
        ("steps.perm.outputs.ok == 'read'", "true"),
        ("steps.perm.outputs.ok == 'true' && 'yes' || 'no'", "no"),
        ("1", "1"),
        ("github.actor", UNKNOWN),
        ("vars.X", UNKNOWN),
        ("steps.perm.outputs.ok && format('{0}', 1)", UNKNOWN),
    ],
)
def test_text_value(expression, value):
    assert text_value(expression, _answer("read")) == value


def test_text_value_rejects_bad_expressions():
    with pytest.raises(ExpressionError):
        text_value("steps.perm.outputs.ok ==", _answer(""))


# --- status functions ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"{ASSOC} == 'OWNER'", ()),
        ("always()", ("always",)),
        ("!cancelled() && (failure() || SUCCESS())", ("cancelled", "failure", "success")),
        ("always() || always()", ("always",)),
        ("format('{0}', success())", ("success",)),
        ("success('x')", ()),
    ],
)
def test_status_functions_are_found(text, expected):
    assert status_functions(text) == expected


def test_status_functions_need_an_expression():
    with pytest.raises(ExpressionError):
        status_functions("always(")


def test_status_functions_come_from_the_lookup():
    status = {("success()",): False, ("failure()",): True, ("cancelled()",): UNKNOWN}

    def lookup(path):
        return status.get(path, UNKNOWN)

    assert evaluate(parse("success()"), lookup) is False
    assert evaluate(parse("failure() && always()"), lookup) is True
    assert evaluate(parse("!cancelled()"), lookup) is UNKNOWN
    assert evaluate(parse("success() && x"), lookup) is False


# --- the event, and conditions that must pass -----------------------------------------------------


def test_the_event_name_is_issue_comment():
    assert lets_in("github.event_name == 'push'") == ()
    assert lets_in(f"github.event_name == 'workflow_dispatch' || {ASSOC} == 'OWNER'") == ()
    assert lets_in("github.event_name == 'issue_comment'") == EVERYONE


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("steps.p.outputs.ok != 'true'", True),
        ("steps.p.outputs.ok == 'false'", False),  # '' and 'none' aren't 'false'
        (f"{ASSOC} != 'OWNER'", True),
        (f"{ASSOC} == 'NONE'", False),
        ("github.event.issue.locked", False),
    ],
)
def test_must_pass(text, expected):
    def answering(answer):
        return lambda path: answer if path[0] == "steps" else UNKNOWN

    assert all(must_pass(text, answering(answer)) for answer in ("", "false", "none")) is expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("${{ github.event.comment.author_association }}", "NONE"),
        ("x-${{ github.event.comment.author_association }}", "x-NONE"),
        ("${{ github.actor }}", STRANGER),
        (" ${{ github.actor }} ", STRANGER),
        ("@${{ github.actor }}", UNKNOWN),
        ("${{ github.event_name }}", "issue_comment"),
        ("${{ github.event.comment.body }}", UNKNOWN),
        ("${{ vars.ADMINS }}", UNKNOWN),
        ("${{ github.event_name == 'push' }}", "false"),
        ("${{ 1 + }}", UNKNOWN),
        ("plain", "plain"),
    ],
)
def test_stranger_text(text, expected):
    value = stranger_text(text, "NONE")
    assert value == expected if isinstance(expected, str) else value is expected


@pytest.mark.parametrize(
    ("text", "condition", "as_value"),
    [
        # Truthy for sure, but which value is it?
        ("x || 'push'", True, UNKNOWN),
        ("x && false", False, UNKNOWN),
        ("x || ''", UNKNOWN, UNKNOWN),
        ("'a' || x", "a", "a"),
        ("false && x", False, False),
    ],
)
def test_and_or_as_a_condition_and_as_a_value(text, condition, as_value):
    tree = parse(text)
    assert (
        evaluate(tree, lambda path: UNKNOWN) == condition or evaluate(tree, lambda path: UNKNOWN) is condition
    )
    value = evaluate(tree, lambda path: UNKNOWN, as_value=True)
    assert value == as_value or value is as_value


def test_a_compared_or_is_a_value():
    # (x || 'push') may be x, so it may not be 'push'.
    assert evaluate(parse("(x || 'push') == 'push'"), lambda path: UNKNOWN) is UNKNOWN
    assert text_value("x || 'push'", lambda path: UNKNOWN) is UNKNOWN
    assert stranger_text("${{ steps.r.outputs.e || github.event_name }}", "NONE") is UNKNOWN


def test_an_or_passed_to_a_function_is_a_value():
    # x || 'abc' is x or 'abc', not the text 'true'.
    assert evaluate(parse("contains(x || 'abc', 'true')"), lambda path: UNKNOWN) is UNKNOWN
