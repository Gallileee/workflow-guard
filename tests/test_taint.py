"""WG004 through detours: env:, $GITHUB_ENV, $GITHUB_OUTPUT, job outputs."""

import textwrap

import pytest

from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

TITLE = "${{ github.event.pull_request.title }}"


def wg004(text: str):
    found = check(Workflow.parse(textwrap.dedent(text), "wf.yml"))
    return [f for f in found if f.rule_id == "WG004"]


def one(text: str):
    (f,) = wg004(text)
    return f


# --- env: ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("level", ["workflow", "job", "step"])
def test_env_at_every_level(level):
    env = f"      env:\n        TITLE: {TITLE}\n"
    text = (
        "on: pull_request\npermissions: {}\n"
        + (f"env:\n  TITLE: {TITLE}\n" if level == "workflow" else "")
        + "jobs:\n  test:\n    runs-on: x\n"
        + (f"    env:\n      TITLE: {TITLE}\n" if level == "job" else "")
        + '    steps:\n      - run: echo "${{ env.TITLE }}"\n'
        + (
            env.replace("      env", "        env").replace("        TITLE", "          TITLE")
            if level == "step"
            else ""
        )
    )
    f = one(text)
    assert f.severity == Severity.HIGH
    assert f.message.startswith(
        "'env.title' carries 'github.event.pull_request.title', which outsiders can set"
    )
    assert 'use the shell variable "$TITLE" instead' in f.message


def test_the_message_names_the_detour():
    f = one(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        env:
          TITLE: {TITLE}
        steps:
          - run: echo "${{{{ env.TITLE }}}}"
    """)
    assert "(via env.TITLE (job 'test'))" in f.message
    assert f.line == 10


def test_using_the_shell_variable_is_fine():
    assert (
        wg004(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        env:
          TITLE: {TITLE}
        steps:
          - run: echo "$TITLE"
    """)
        == []
    )


def test_a_clean_value_at_a_lower_level_removes_the_taint():
    assert (
        wg004(f"""
    on: pull_request
    permissions: {{}}
    env:
      TITLE: {TITLE}
    jobs:
      test:
        runs-on: x
        env:
          TITLE: fixed text
        steps:
          - run: echo "${{{{ env.TITLE }}}}"
    """)
        == []
    )


def test_env_names_ignore_case_in_expressions():
    assert (
        len(
            wg004(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        env:
          Title: {TITLE}
        steps:
          - run: echo "${{{{ env.TITLE }}}}"
    """)
        )
        == 1
    )


def test_step_env_only_applies_to_its_own_step():
    assert (
        wg004(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        steps:
          - env:
              TITLE: {TITLE}
            run: echo "$TITLE"
          - run: echo "${{{{ env.TITLE }}}}"
    """)
        == []
    )


def test_env_values_built_from_other_text_are_still_tainted():
    f = one("""
    on: issues
    permissions: {}
    jobs:
      test:
        runs-on: x
        env:
          MSG: "New issue: ${{ github.event.issue.title }} (#${{ github.event.issue.number }})"
        steps:
          - run: echo "${{ env.MSG }}"
    """)
    assert "'github.event.issue.title'" in f.message


# --- $GITHUB_ENV and $GITHUB_OUTPUT --------------------------------------------------------------


def test_step_output_written_from_a_tainted_env_variable():
    f = one(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        steps:
          - id: meta
            env:
              TITLE: {TITLE}
            run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"
          - run: echo "${{{{ steps.meta.outputs.title }}}}"
    """)
    assert f.message.startswith(
        "'steps.meta.outputs.title' carries 'github.event.pull_request.title', which outsiders can set"
        " (via env.TITLE (step 'meta') -> steps.meta.outputs.title)"
    )
    assert f.message.endswith("pass it through 'env:' and use the variable instead")


@pytest.mark.parametrize(
    "write",
    [
        'echo "title=$TITLE" >> "$GITHUB_OUTPUT"',
        "echo title=${TITLE} >>$GITHUB_OUTPUT",
        "echo 'title=${{ github.event.pull_request.title }}' >> ${GITHUB_OUTPUT}",
    ],
)
def test_spellings_of_an_output_write(write):
    found = wg004(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        steps:
          - id: meta
            env:
              TITLE: {TITLE}
            run: {write!r}
          - run: echo "${{{{ steps.meta.outputs.title }}}}"
    """)
    # The last spelling is also reported directly, on the writing line itself.
    assert found[-1].message.startswith("'steps.meta.outputs.title' carries")


def test_github_env_reaches_later_steps_only():
    found = wg004(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        steps:
          - env:
              RAW: {TITLE}
            run: |
              echo "SAFE_LOOKING=$RAW" >> "$GITHUB_ENV"
              echo "${{{{ env.SAFE_LOOKING }}}}"
          - run: echo "${{{{ env.SAFE_LOOKING }}}}"
    """)
    # Within the writing step the new variable doesn't exist yet; the next step has it.
    assert [f.line for f in found] == [13]
    assert "$SAFE_LOOKING written to $GITHUB_ENV in step 1 of job 'test'" in found[0].message


def test_overwriting_an_output_with_clean_text_clears_it():
    assert (
        wg004(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        steps:
          - id: meta
            env:
              TITLE: {TITLE}
            run: |
              echo "title=$TITLE" >> "$GITHUB_OUTPUT"
              echo "title=fixed" >> "$GITHUB_OUTPUT"
          - run: echo "${{{{ steps.meta.outputs.title }}}}"
    """)
        == []
    )


def test_outputs_of_a_step_without_id_cannot_be_read():
    assert (
        wg004(f"""
    on: pull_request
    permissions: {{}}
    jobs:
      test:
        runs-on: x
        steps:
          - env:
              TITLE: {TITLE}
            run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"
          - run: echo "${{{{ steps.meta.outputs.title }}}}"
    """)
        == []
    )


# --- job outputs ---------------------------------------------------------------------------------

JOBS = f"""
on: pull_request
permissions: {{}}
jobs:
  meta:
    runs-on: x
    outputs:
      title: ${{{{ steps.read.outputs.title }}}}
      sha: ${{{{ github.sha }}}}
    steps:
      - id: read
        env:
          TITLE: {TITLE}
        run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"
  use:
    needs: meta
    runs-on: x
    steps:
      - run: echo "${{{{ needs.meta.outputs.title }}}} ${{{{ needs.meta.outputs.sha }}}}"
"""


def test_job_outputs_through_needs():
    f = one(JOBS)
    assert f.line == 19
    assert (
        "(via env.TITLE (step 'read') -> steps.read.outputs.title -> needs.meta.outputs.title)" in f.message
    )


def test_job_order_in_the_file_does_not_matter():
    # "use" comes first in the file; its needs: still sees the other job's outputs.
    text = JOBS.replace("  meta:", "  zzz:").replace("needs: meta", "needs: zzz")
    text = text.replace("needs.meta.", "needs.zzz.")
    head, jobs = text.split("jobs:\n")
    meta, use = jobs.split("  use:\n")
    assert len(wg004(head + "jobs:\n  use:\n" + use + meta)) == 1


def test_a_needs_loop_does_not_hang():
    assert (
        wg004("""
    on: pull_request
    permissions: {}
    jobs:
      a:
        needs: b
        runs-on: x
        outputs:
          v: ${{ needs.b.outputs.v }}
        steps:
          - run: echo "${{ needs.b.outputs.v }}"
      b:
        needs: a
        runs-on: x
        outputs:
          v: ${{ needs.a.outputs.v }}
        steps:
          - run: echo "${{ needs.a.outputs.v }}"
    """)
        == []
    )


# --- composite actions ---------------------------------------------------------------------------


def test_action_inputs_through_env_are_medium():
    f = one("""
    runs:
      using: composite
      steps:
        - id: x
          shell: bash
          env:
            NAME: ${{ inputs.name }}
          run: echo "out=$NAME" >> "$GITHUB_OUTPUT"
        - shell: bash
          run: echo "${{ steps.x.outputs.out }}"
    """)
    assert f.severity == Severity.MEDIUM
    assert "'inputs.name' from the calling workflow, which may be untrusted" in f.message
    assert "step 'x'" in f.message


def test_clean_values_stay_clean():
    assert (
        wg004("""
    on: push
    permissions: {}
    env:
      SHA: ${{ github.sha }}
    jobs:
      test:
        runs-on: x
        steps:
          - id: v
            run: echo "version=$(cat VERSION)" >> "$GITHUB_OUTPUT"
          - run: echo "${{ env.SHA }} ${{ steps.v.outputs.version }}"
    """)
        == []
    )
