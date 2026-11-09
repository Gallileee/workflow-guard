import textwrap

import pytest

from workflow_guard.expressions import (
    ExpressionError,
    context_paths,
    find_expressions,
    is_ancestor,
    matches,
    tokenize,
)
from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow


def paths(text):
    return [str(p) for p in context_paths(text)]


# --- find_expressions ----------------------------------------------------------------------------


def test_finds_every_expression_with_offsets():
    text = "a ${{ x }} b ${{y}}"
    assert [(e.start, e.end, e.inner) for e in find_expressions(text)] == [(2, 10, " x "), (13, 19, "y")]


def test_closing_braces_inside_a_string_do_not_end_the_expression():
    (expr,) = find_expressions("${{ format('}}{0}', github.head_ref) }} tail")
    assert expr.inner == " format('}}{0}', github.head_ref) "


def test_unterminated_expressions_are_ignored():
    assert list(find_expressions("echo ${{ github.head_ref")) == []
    assert list(find_expressions("echo ${{ 'open }}")) == []


# --- tokenize ------------------------------------------------------------------------------------


def test_tokens():
    kinds = [t.kind for t in tokenize("a.b['c'] == 1 && !f(x, -2.5)")]
    assert kinds == [
        "NAME", ".", "NAME", "[", "STRING", "]", "==", "NUMBER", "&&", "!",
        "NAME", "(", "NAME", ",", "NUMBER", ")",
    ]  # fmt: skip


def test_doubled_quotes_escape_a_quote():
    (tok,) = tokenize("'it''s'")
    assert (tok.kind, tok.value) == ("STRING", "it's")


@pytest.mark.parametrize("bad", ["'open", "a ; b", "a # b"])
def test_invalid_expressions(bad):
    with pytest.raises(ExpressionError):
        tokenize(bad)


# --- context_paths -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "github.event.pull_request.title",
        "github.event['pull_request']['title']",
        "github['event'].pull_request['title']",
        "GitHub.Event.Pull_Request.TITLE",
        "  github . event . pull_request . title  ",
    ],
)
def test_spellings_of_the_same_path(text):
    assert paths(text) == ["github.event.pull_request.title"]


def test_array_elements_become_wildcards():
    assert paths("github.event.commits[0].message") == ["github.event.commits.*.message"]
    assert paths("github.event.commits.*.message") == ["github.event.commits.*.message"]
    assert paths("github.event.commits[*].message") == ["github.event.commits.*.message"]


def test_function_arguments_and_operators():
    found = context_paths("format('{0} {1}', github.head_ref, toJSON(github.event)) == env.X")
    assert [(str(p), p.function) for p in found] == [
        ("github.head_ref", "format"),
        ("github.event", "tojson"),
        ("env.x", None),
    ]


def test_string_literals_and_keywords_are_not_paths():
    assert paths("'github.head_ref'") == []
    assert paths("true && false || null") == []
    assert paths("success() && !cancelled()") == []


def test_hyphenated_names():
    assert paths("steps.my-step.outputs.value") == ["steps.my-step.outputs.value"]


def test_a_computed_key_ends_the_path_and_is_read_on_its_own():
    assert paths("github.event[matrix.key].title") == ["github.event", "matrix.key"]


def test_matches_and_is_ancestor():
    pattern = ("github", "event", "commits", "*", "message")
    assert matches(("github", "event", "commits", "*", "message"), pattern)
    assert matches(("github", "event", "commits", "*", "message", "x"), pattern)
    assert not matches(("github", "event", "commits"), pattern)
    assert is_ancestor(("github", "event"), pattern)
    assert is_ancestor(("github", "event", "commits", "*"), pattern)
    assert not is_ancestor(("github", "event", "issue"), pattern)
    assert not is_ancestor(pattern, pattern)


# --- the rules on top of it ----------------------------------------------------------------------


def run_findings(expr: str, on: str = "pull_request"):
    text = textwrap.dedent(f"""
    on: {on}
    permissions: {{}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{{{ {expr} }}}}"
    """)
    return [(f.rule_id, f.severity) for f in check(Workflow.parse(text, "wf.yml"))]


@pytest.mark.parametrize(
    "expr",
    [
        # Spellings the regular expressions missed:
        "github.event['pull_request']['title']",
        "github['head_ref']",
        "GITHUB.EVENT.ISSUE.BODY",
        "github.event.commits[0]['message']",
        "toJSON(github.event)",
        "toJSON(github.event.pull_request)",
        "toJSON(github.event.commits)",
        "format('}}{0}', github.head_ref)",
    ],
)
def test_bypasses_of_the_old_regex_are_caught(expr):
    assert run_findings(expr) == [("WG004", Severity.HIGH)]


@pytest.mark.parametrize(
    "expr",
    [
        # Text the regular expressions reported although nothing outsider-controlled is used:
        "'github.head_ref'",
        "format('see github.event.issue.title in {0}', github.sha)",
        # Safe values and objects without outsider text:
        "toJSON(github.event.pull_request.head.sha)",
        "toJSON(steps)",
        "github.event.pull_request.number",
        "github.event",  # an object in a string is just "Object"
        "github.event.issue.title_length",  # not a real field, but not 'title' either
    ],
)
def test_false_positives_of_the_old_regex_are_gone(expr):
    assert run_findings(expr) == []


def test_tojson_message_names_an_example_field():
    text = textwrap.dedent("""
    on: issues
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - run: echo '${{ toJSON(github.event) }}'
    """)
    (f,) = check(Workflow.parse(text, "wf.yml"))
    assert f.message.startswith("toJSON(github.event) includes values outsiders can set, such as '")


def test_an_invalid_expression_is_skipped_but_later_ones_are_checked():
    text = textwrap.dedent("""
    on: issues
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - run: |
              echo "${{ a ; b }}"
              echo "${{ github.event.issue.title }}"
    """)
    assert [(f.rule_id, f.line) for f in check(Workflow.parse(text, "wf.yml"))] == [("WG004", 10)]


@pytest.mark.parametrize(
    "ref",
    [
        "${{ github.event.pull_request.head.sha }}",
        "${{ github.event['pull_request']['head']['ref'] }}",
        "${{ GITHUB.HEAD_REF }}",
        "refs/pull/${{ github.event.number }}/merge",
    ],
)
def test_pull_request_target_checkouts_of_pr_code(ref):
    text = textwrap.dedent(f"""
    on: pull_request_target
    permissions: {{}}
    jobs:
      a:
        runs-on: x
        steps:
          - uses: actions/checkout@{"a" * 40}
            with:
              persist-credentials: false
              ref: "{ref}"
    """)
    assert [(f.rule_id, f.severity) for f in check(Workflow.parse(text, "wf.yml"))] == [
        ("WG005", Severity.HIGH)
    ]
