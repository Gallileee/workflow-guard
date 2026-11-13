"""Outputs of local actions and reusable workflows, followed back to the caller."""

import io
import json
import textwrap
from pathlib import Path

from workflow_guard.calls import link_local_calls
from workflow_guard.cli import run
from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

TITLE = "${{ github.event.pull_request.title }}"

# An action that hands its input back as an output, and one whose output is its own text.
ECHO_ACTION = """
inputs:
  text: {}
outputs:
  result:
    value: ${{ steps.copy.outputs.result }}
  fixed:
    value: ${{ steps.copy.outputs.fixed }}
runs:
  using: composite
  steps:
    - id: copy
      shell: bash
      env:
        TEXT: ${{ inputs.text }}
      run: |
        echo "result=$TEXT" >> "$GITHUB_OUTPUT"
        echo "fixed=done" >> "$GITHUB_OUTPUT"
"""

READ_ACTION = """
outputs:
  title:
    value: ${{ steps.read.outputs.title }}
runs:
  using: composite
  steps:
    - id: read
      shell: bash
      env:
        T: ${{ github.event.pull_request.title }}
      run: echo "title=$T" >> "$GITHUB_OUTPUT"
"""


def action(text: str, folder: str = ".github/actions/echo") -> Workflow:
    return Workflow.parse(textwrap.dedent(text), f"{folder}/action.yml")


def caller(steps: str, name: str = "ci.yml") -> Workflow:
    text = (
        "on: pull_request_target\npermissions: {}\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        + textwrap.indent(textwrap.dedent(steps).strip("\n"), "      ")
        + "\n"
    )
    return Workflow.parse(text, f".github/workflows/{name}")


def wg004(wf: Workflow):
    return [f for f in check(wf) if f.rule_id == "WG004"]


def checked(*files: Workflow) -> None:
    link_local_calls(list(files))


# --- local actions --------------------------------------------------------------------------------


def test_an_output_carrying_the_input_back_is_tainted():
    ci = caller(f"""
        - id: echo
          uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - run: echo "${{{{ steps.echo.outputs.result }}}}"
    """)
    checked(ci, action(ECHO_ACTION))
    (f,) = wg004(ci)
    assert f.severity == Severity.HIGH
    assert f.line == 11
    assert (
        "with.text in .github/workflows/ci.yml:8 -> env.TEXT (step 'copy') -> steps.copy.outputs.result"
        in (f.message)
    )
    assert f.message.endswith(
        "-> steps.echo.outputs.result) and is pasted into a script; pass it through 'env:'"
        " and use the variable instead"
    )


def test_a_fixed_output_and_a_clean_input_stay_clean():
    ci = caller(f"""
        - id: tainted
          uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - id: clean
          uses: ./.github/actions/echo
          with:
            text: ${{{{ github.sha }}}}
        - run: echo "${{{{ steps.tainted.outputs.fixed }}}} ${{{{ steps.clean.outputs.result }}}}"
    """)
    checked(ci, action(ECHO_ACTION))
    assert wg004(ci) == []


def test_each_call_is_worked_out_with_its_own_inputs():
    # The action's input_taints merge all callers (the tainted one wins), but the clean call's
    # output must not inherit the other call's title.
    ci = caller(f"""
        - id: a
          uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - id: b
          uses: ./.github/actions/echo
          with:
            text: hello
        - run: echo "${{{{ steps.b.outputs.result }}}}"
    """)
    echo = action(ECHO_ACTION)
    checked(ci, echo)
    assert echo.input_taints is not None and "text" in echo.input_taints
    assert wg004(ci) == []


def test_an_action_reading_the_event_itself():
    ci = caller("""
        - id: read
          uses: ./.github/actions/read
        - run: echo "${{ steps.read.outputs.title }}"
    """)
    checked(ci, action(READ_ACTION, ".github/actions/read"))
    (f,) = wg004(ci)
    assert f.severity == Severity.HIGH
    assert (
        "env.T (step 'read') -> steps.read.outputs.title -> outputs.title of "
        ".github/actions/read/action.yml -> steps.read.outputs.title" in f.message
    )


def test_output_names_ignore_case_and_need_a_step_id():
    ci = caller(f"""
        - uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - id: Echo
          uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - run: echo "${{{{ steps.echo.outputs.RESULT }}}}"
    """)
    checked(ci, action(ECHO_ACTION))
    (f,) = wg004(ci)
    assert f.severity == Severity.HIGH


def test_outputs_also_feed_wg007():
    ci = caller(f"""
        - id: echo
          uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - run: echo "T=${{{{ steps.echo.outputs.result }}}}" >> "$GITHUB_ENV"
    """)
    checked(ci, action(ECHO_ACTION))
    assert {f.rule_id for f in check(ci)} >= {"WG004", "WG007"}


def test_an_action_without_known_callers_has_medium_outputs_from_inputs():
    # Checking the action on its own: its input could be anything, and so could the output
    # of an outer action that passes its own input through.
    outer = action(
        """
        inputs:
          name: {}
        outputs:
          out:
            value: ${{ steps.e.outputs.result }}
        runs:
          using: composite
          steps:
            - id: e
              uses: ./.github/actions/echo
              with:
                text: ${{ inputs.name }}
            - shell: bash
              run: echo "${{ steps.e.outputs.result }}"
        """,
        ".github/actions/outer",
    )
    checked(outer, action(ECHO_ACTION))
    (f,) = wg004(outer)
    assert f.severity == Severity.MEDIUM


def test_a_loop_of_actions_terminates():
    loop = action(
        """
        outputs:
          out:
            value: ${{ steps.me.outputs.out }}
        runs:
          using: composite
          steps:
            - id: me
              uses: ./.github/actions/loop
            - shell: bash
              run: echo "${{ steps.me.outputs.out }}"
        """,
        ".github/actions/loop",
    )
    checked(loop)
    assert wg004(loop) == []


def test_without_linking_outputs_are_unknown_and_trusted():
    ci = caller(f"""
        - id: echo
          uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - run: echo "${{{{ steps.echo.outputs.result }}}}"
    """)
    assert wg004(ci) == []  # never linked: the action isn't known


# --- reusable workflows ---------------------------------------------------------------------------

REUSABLE = """
on:
  workflow_call:
    inputs:
      title: {type: string}
    outputs:
      echoed:
        value: ${{ jobs.copy.outputs.title }}
      fixed:
        value: done
permissions: {}
jobs:
  copy:
    runs-on: ubuntu-latest
    outputs:
      title: ${{ steps.c.outputs.title }}
    steps:
      - id: c
        env:
          T: ${{ inputs.title }}
        run: echo "title=$T" >> "$GITHUB_OUTPUT"
"""


def top(value: str, use: str = "echoed") -> Workflow:
    text = f"""
on: pull_request_target
permissions: {{}}
jobs:
  call:
    uses: ./.github/workflows/reusable.yml
    with:
      title: {value}
  after:
    needs: call
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{{{ needs.call.outputs.{use} }}}}"
"""
    return Workflow.parse(textwrap.dedent(text), ".github/workflows/top.yml")


def reusable() -> Workflow:
    return Workflow.parse(textwrap.dedent(REUSABLE), ".github/workflows/reusable.yml")


def test_reusable_workflow_outputs_reach_needs_of_the_caller():
    caller_wf = top(TITLE)
    checked(caller_wf, reusable())
    (f,) = wg004(caller_wf)
    assert f.severity == Severity.HIGH
    assert (
        "needs.copy.outputs.title -> outputs.echoed of .github/workflows/reusable.yml"
        " -> needs.call.outputs.echoed" in f.message
    )
    assert "with.title in .github/workflows/top.yml (job 'call')" in f.message


def test_reusable_workflow_clean_outputs():
    for wf, other in ((top(TITLE, use="fixed"), reusable()), (top("hello"), reusable())):
        checked(wf, other)
        assert wg004(wf) == []


# --- command line ---------------------------------------------------------------------------------


def test_cli_follows_action_outputs(tmp_path, monkeypatch):
    (tmp_path / ".github/actions/echo").mkdir(parents=True)
    (tmp_path / ".github/workflows").mkdir(parents=True)
    (tmp_path / ".github/actions/echo/action.yml").write_text(textwrap.dedent(ECHO_ACTION), encoding="utf-8")
    ci = caller(f"""
        - id: echo
          uses: ./.github/actions/echo
          with:
            text: {TITLE}
        - run: echo "${{{{ steps.echo.outputs.result }}}}"
    """)
    Path(tmp_path / ".github/workflows/ci.yml").write_text("\n".join(ci.lines) + "\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    out = io.StringIO()
    run(["--format", "json", "--ignore", "WG001,WG005"], out, io.StringIO())
    found = {(f["path"], f["rule"], f["severity"]) for f in json.loads(out.getvalue())["findings"]}
    assert (".github/workflows/ci.yml", "WG004", "high") in found
