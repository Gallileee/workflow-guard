"""WG007: untrusted text appended to $GITHUB_ENV or $GITHUB_PATH."""

import textwrap

import pytest

from workflow_guard.model import Severity
from workflow_guard.rules import RULE_IDS, RULES, check
from workflow_guard.sarif import to_sarif
from workflow_guard.workflow import Workflow


def findings(text: str, rule="WG007"):
    found = check(Workflow.parse(textwrap.dedent(text), "wf.yml"))
    return [f for f in found if f.rule_id == rule]


def workflow(script: str, env: str = "TITLE: ${{ github.event.pull_request.title }}") -> str:
    # Indented to sit under "run: |" once the template below is dedented by 4.
    lines = "\n".join(f"              {line}" for line in script.splitlines())
    return f"""
    on: pull_request_target
    permissions: {{}}
    jobs:
      label:
        runs-on: x
        steps:
          - env:
              {env}
            run: |
{lines}
    """


@pytest.mark.parametrize(
    "script",
    [
        'echo "PR_TITLE=$TITLE" >> "$GITHUB_ENV"',
        "echo PR_TITLE=${TITLE} >>$GITHUB_ENV",
        'echo "$TITLE" >> "$GITHUB_ENV"',  # no NAME= at all: the whole line is the sender's
        "printf '%s\\n' \"X=$TITLE\" >> ${GITHUB_ENV}",
    ],
)
def test_tainted_text_into_github_env(script):
    (f,) = findings(workflow(script))
    assert (f.severity, f.line) == (Severity.HIGH, 11)
    assert f.message.startswith(
        "'github.event.pull_request.title', which outsiders can set (via env.TITLE (step 1 of job 'label'))"
        " is written to $GITHUB_ENV; a line break in it can set any variable for the later steps"
    )


def test_github_path():
    (f,) = findings(workflow('echo "$TITLE" >> "$GITHUB_PATH"'))
    assert "is written to $GITHUB_PATH; it can put a directory of the sender's choosing first" in f.message


def test_the_line_of_the_write_is_reported():
    (f,) = findings(workflow('echo start\necho "safe=1" >> "$GITHUB_ENV"\necho "T=$TITLE" >> "$GITHUB_ENV"'))
    assert f.line == 13


@pytest.mark.parametrize(
    "script",
    [
        'echo "SHA=$GITHUB_SHA" >> "$GITHUB_ENV"',  # runner variables aren't tainted
        'echo "title=$TITLE" >> "$GITHUB_OUTPUT"',  # outputs are WG004's business when used
        'echo "$TITLE" > title.txt',  # a file of its own is the recommended alternative
        'echo "N=${{ github.event.pull_request.number }}" >> "$GITHUB_ENV"',
    ],
)
def test_harmless_writes(script):
    assert findings(workflow(script)) == []


def test_a_direct_expression_is_both_wg004_and_wg007():
    text = workflow('echo "T=${{ github.head_ref }}" >> "$GITHUB_ENV"', env="X: y")
    found = check(Workflow.parse(textwrap.dedent(text), "wf.yml"))
    assert [f.rule_id for f in found if f.rule_id != "WG005"] == [
        "WG004",
        "WG007",
    ]


def test_taint_from_an_earlier_github_env_write_counts_too():
    text = """
    on: issues
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - env:
              BODY: ${{ github.event.issue.body }}
            run: echo "B=$BODY" >> "$GITHUB_ENV"
          - run: echo "C=$B" >> "$GITHUB_ENV"
    """
    found = findings(text)
    assert [f.line for f in found] == [10, 11]
    assert "$B written to $GITHUB_ENV in step 1 of job 'a'" in found[1].message


def test_composite_action_inputs_are_medium():
    text = """
    runs:
      using: composite
      steps:
        - shell: bash
          env:
            V: ${{ inputs.version }}
          run: echo "TOOL_VERSION=$V" >> "$GITHUB_ENV"
    """
    (f,) = findings(text)
    assert f.severity == Severity.MEDIUM
    assert f.message.startswith("'inputs.version' from the calling workflow, which may be untrusted")


def test_inline_ignore():
    text = workflow('echo "T=$TITLE" >> "$GITHUB_ENV"  # workflow-guard: ignore[WG007]')
    assert findings(text) == []


def test_rule_ids_are_unique_and_in_sarif():
    assert len(RULE_IDS) == len(RULES)
    rules = to_sarif([])["runs"][0]["tool"]["driver"]["rules"]
    wg007 = next(r for r in rules if r["id"] == "WG007")
    assert "BASH_ENV" in wg007["help"]["text"]
