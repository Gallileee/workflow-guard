"""A finding inside a reusable workflow or action names every caller that passes untrusted text."""

import textwrap

from workflow_guard.calls import link_local_calls
from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.taint import INPUT, OUTSIDER, Taint, merge_callers
from workflow_guard.workflow import Workflow

PR_TITLE = "${{ github.event.pull_request.title }}"
ISSUE_TITLE = "${{ github.event.issue.title }}"

CALLEE = """
on:
  workflow_call:
    inputs:
      title: {type: string}
permissions: {}
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.title }}"
"""

ACTION = """
inputs:
  title: {}
runs:
  using: composite
  steps:
    - shell: bash
      run: echo "T=${{ inputs.title }}" >> "$GITHUB_ENV"
"""


def caller(name: str, value: str) -> Workflow:
    text = f"""
on: pull_request_target
permissions: {{}}
jobs:
  call:
    uses: ./.github/workflows/greet.yml
    with:
      title: {value}
"""
    return Workflow.parse(textwrap.dedent(text), f".github/workflows/{name}")


def step_caller(name: str, value: str) -> Workflow:
    text = f"""
on: issues
permissions: {{}}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/greet
        with:
          title: {value}
"""
    return Workflow.parse(textwrap.dedent(text), f".github/workflows/{name}")


def findings(rule: str, callee: Workflow, *callers: Workflow):
    link_local_calls([callee, *callers])
    return [f for f in check(callee) if f.rule_id == rule]


def callee() -> Workflow:
    return Workflow.parse(textwrap.dedent(CALLEE), ".github/workflows/greet.yml")


def test_one_tainted_caller_has_no_list():
    (f,) = findings("WG004", callee(), caller("a.yml", PR_TITLE), caller("b.yml", "hello"))
    assert "other callers" not in f.message


def test_every_other_tainted_caller_is_listed():
    (f,) = findings(
        "WG004",
        callee(),
        caller("a.yml", PR_TITLE),
        caller("b.yml", "hello"),
        caller("c.yml", ISSUE_TITLE),
        caller("d.yml", f"x {PR_TITLE}"),
    )
    assert f.severity == Severity.HIGH
    assert "(via with.title in .github/workflows/a.yml (job 'call'))" in f.message
    assert f.message.endswith(
        "; other callers pass untrusted text too: "
        "with.title in .github/workflows/c.yml (job 'call') ('github.event.issue.title'); "
        "with.title in .github/workflows/d.yml (job 'call') ('github.event.pull_request.title')"
    )
    assert "b.yml" not in f.message


def test_the_worst_caller_leads_and_medium_ones_follow():
    middle = Workflow.parse(
        textwrap.dedent("""
        on: workflow_call
        permissions: {}
        jobs:
          call:
            uses: ./.github/workflows/greet.yml
            with:
              title: ${{ inputs.name }}
        """),
        ".github/workflows/middle.yml",
    )
    (f,) = findings("WG004", callee(), middle, caller("z.yml", PR_TITLE))
    assert f.severity == Severity.HIGH
    assert "(via with.title in .github/workflows/z.yml (job 'call'))" in f.message
    assert "other callers pass untrusted text too: with.title in .github/workflows/middle.yml" in f.message
    assert "('inputs.name')" in f.message


def test_step_callers_of_an_action_are_listed_in_wg007():
    action = Workflow.parse(textwrap.dedent(ACTION), ".github/actions/greet/action.yml")
    (f,) = findings("WG007", action, step_caller("a.yml", ISSUE_TITLE), step_caller("b.yml", ISSUE_TITLE))
    assert f.severity == Severity.HIGH
    assert "with.title in .github/workflows/a.yml:8" in f.message
    assert f.message.endswith(
        "; other callers pass untrusted text too: "
        "with.title in .github/workflows/b.yml:8 ('github.event.issue.title')"
    )


def test_merge_callers_keeps_file_order_and_drops_duplicates():
    a = Taint(OUTSIDER, "github.head_ref", Severity.HIGH, via=("with.x in a",))
    b = Taint(INPUT, "inputs.y", Severity.MEDIUM, via=("with.x in b",))
    c = Taint(
        OUTSIDER, "github.head_ref", Severity.HIGH, via=("with.x in c",), callers=("with.x in d ('q')",)
    )
    merged = merge_callers([b, a, c])
    assert merged.via == ("with.x in a",)
    assert merged.callers == (
        "with.x in c ('github.head_ref')",
        "with.x in d ('q')",
        "with.x in b ('inputs.y')",
    )
    assert merge_callers([a]) == a
    assert merge_callers([c, c]).callers == ("with.x in d ('q')", "with.x in c ('github.head_ref')")


def test_the_list_follows_the_value_through_env_in_the_callee():
    text = CALLEE.replace(
        '      - run: echo "${{ inputs.title }}"',
        '      - env:\n          T: ${{ inputs.title }}\n        run: echo "${{ env.T }}"',
    )
    wf = Workflow.parse(textwrap.dedent(text), ".github/workflows/greet.yml")
    (f,) = findings("WG004", wf, caller("a.yml", PR_TITLE), caller("b.yml", ISSUE_TITLE))
    assert "env.T (step 1 of job 'greet')" in f.message
    assert f.message.endswith(
        "with.title in .github/workflows/b.yml (job 'call') ('github.event.issue.title')"
    )
