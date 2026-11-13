"""Local composite actions (uses: ./dir) and the steps that run them."""

import io
import json
import textwrap
from pathlib import Path

from workflow_guard.calls import link_local_calls
from workflow_guard.cli import run
from workflow_guard.model import Severity
from workflow_guard.project import repo_root
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

TITLE = "${{ github.event.pull_request.title }}"

ACTION = """
inputs:
  title:
    description: what to greet
runs:
  using: composite
  steps:
    - run: echo "${{ inputs.title }}"
      shell: bash
"""


def action(text: str = ACTION, folder: str = ".github/actions/greet", name: str = "action.yml") -> Workflow:
    return Workflow.parse(textwrap.dedent(text), f"{folder}/{name}")


def workflow(
    value: str,
    uses: str = "./.github/actions/greet",
    name: str = "ci.yml",
    before: str = "",
    key: str = "title",
) -> Workflow:
    text = f"""
on: pull_request_target
permissions: {{}}
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:{before}
      - uses: {uses}
        with:
          {key}: {value}
"""
    return Workflow.parse(textwrap.dedent(text), f".github/workflows/{name}")


def wg004(wf: Workflow):
    return [f for f in check(wf) if f.rule_id == "WG004"]


def linked(callee: Workflow, *callers: Workflow) -> Workflow:
    link_local_calls([callee, *callers])
    return callee


def test_without_a_known_caller_inputs_stay_medium():
    (f,) = wg004(action())
    assert f.severity == Severity.MEDIUM
    assert f.message.startswith("'inputs.title' comes from the calling workflow")


def test_a_step_passing_a_pr_title_makes_it_high():
    (f,) = wg004(linked(action(), workflow(TITLE)))
    assert f.severity == Severity.HIGH
    assert f.path == ".github/actions/greet/action.yml"
    assert f.line == 8
    assert "(via with.title in .github/workflows/ci.yml:8)" in f.message


def test_clean_callers_make_it_clean():
    callee = linked(action(), workflow("${{ github.sha }}"), workflow("hi", name="b.yml"))
    assert callee.input_taints == {}
    assert wg004(callee) == []


def test_the_step_scope_is_used():
    # The with: value reads env and a step output at that point of the job.
    before = f"""
      - id: meta
        run: echo "title=$T" >> "$GITHUB_OUTPUT"
        env:
          T: {TITLE}"""
    (f,) = wg004(linked(action(), workflow("${{ steps.meta.outputs.title }}", before=before)))
    assert f.severity == Severity.HIGH
    assert "steps.meta.outputs.title -> with.title in .github/workflows/ci.yml" in f.message


def test_step_env_counts_for_its_own_with():
    caller = Workflow.parse(
        textwrap.dedent(f"""
        on: pull_request_target
        permissions: {{}}
        jobs:
          greet:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/greet
                env:
                  T: {TITLE}
                with:
                  title: ${{{{ env.T }}}}
        """),
        ".github/workflows/ci.yml",
    )
    (f,) = wg004(linked(action(), caller))
    assert f.severity == Severity.HIGH


def test_action_yaml_works_too():
    (f,) = wg004(linked(action(name="action.yaml"), workflow(TITLE)))
    assert f.severity == Severity.HIGH


def test_uses_dot_slash_runs_the_repository_root_action(tmp_path):
    # A repository that *is* an action runs its own action.yml with "uses: ./" (like this one).
    root_action = Workflow.parse(textwrap.dedent(ACTION), str(tmp_path / "action.yml"))
    lines = workflow(TITLE, uses="./").lines
    caller = Workflow.parse("\n".join(lines), str(tmp_path / ".github/workflows/ci.yml"))
    link_local_calls([root_action, caller])
    (f,) = wg004(root_action)
    assert f.severity == Severity.HIGH


def test_a_composite_action_passing_its_input_on():
    outer = action(
        """
        inputs:
          name: {}
        runs:
          using: composite
          steps:
            - uses: ./.github/actions/greet
              with:
                title: hello ${{ inputs.name }}
        """,
        folder=".github/actions/outer",
    )
    inner = action()
    link_local_calls([inner, outer, workflow(TITLE, uses="./.github/actions/outer", key="name")])
    (f,) = wg004(inner)
    assert f.severity == Severity.HIGH
    assert (
        "with.name in .github/workflows/ci.yml:8 -> with.title in .github/actions/outer/action.yml:7"
        in f.message
    )


def test_an_outer_action_without_callers_passes_medium_on():
    outer = action(
        """
        runs:
          using: composite
          steps:
            - uses: ./.github/actions/greet
              with:
                title: ${{ inputs.name }}
        """,
        folder=".github/actions/outer",
    )
    inner = linked(action(), outer)
    (f,) = wg004(inner)
    assert f.severity == Severity.MEDIUM


def test_a_reusable_workflow_step_passing_its_input_to_an_action():
    reusable = Workflow.parse(
        textwrap.dedent("""
        on:
          workflow_call:
            inputs:
              t: {type: string}
        permissions: {}
        jobs:
          greet:
            runs-on: ubuntu-latest
            steps:
              - uses: ./.github/actions/greet
                with:
                  title: ${{ inputs.t }}
        """),
        ".github/workflows/reusable.yml",
    )
    top = Workflow.parse(
        textwrap.dedent("""
        on: issues
        permissions: {}
        jobs:
          call:
            uses: ./.github/workflows/reusable.yml
            with:
              t: ${{ github.event.issue.title }}
        """),
        ".github/workflows/top.yml",
    )
    inner = action()
    link_local_calls([inner, reusable, top])
    (f,) = wg004(inner)
    assert f.severity == Severity.HIGH
    assert "'github.event.issue.title'" in f.message


def test_remote_actions_and_workflow_files_are_not_action_calls():
    callee = linked(
        action(),
        workflow(TITLE, uses="octo/greet@v1"),
        workflow(TITLE, uses="./.github/actions/other"),
    )
    assert callee.input_taints is None


def test_repo_root_from_an_action_folder():
    assert repo_root(Path("r/.github/actions/x/action.yml")) == Path("r").resolve()
    assert repo_root(Path("r/.github/workflows/ci.yml")) == Path("r").resolve()


# --- command line ---------------------------------------------------------------------------------


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def test_cli_default_paths_link_local_actions(tmp_path, monkeypatch):
    write(tmp_path, ".github/actions/greet/action.yml", ACTION)
    write(tmp_path, ".github/workflows/ci.yml", "\n".join(workflow(TITLE).lines))
    monkeypatch.chdir(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    code = run(["--format", "json", "--ignore", "WG001,WG005"], out, err)
    (f,) = json.loads(out.getvalue())["findings"]
    assert code == 1
    assert (f["path"], f["severity"]) == (".github/actions/greet/action.yml", "high")
