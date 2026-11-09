"""Action metadata files (action.yml): composite and Docker actions."""

import io
import re
import textwrap
from pathlib import Path

import pytest
import yaml

from workflow_guard.cli import run
from workflow_guard.fix import pin_actions
from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import ACTION, ACTION_JOB, WORKFLOW, Workflow, WorkflowError

SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"
ROOT = Path(__file__).parent.parent


def parse(text: str) -> Workflow:
    return Workflow.parse(textwrap.dedent(text), "action.yml")


def findings(text: str):
    return check(parse(text))


COMPOSITE = f"""
name: example
inputs:
  name:
    description: who to greet
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@{SHA}  # v5
      with:
        python-version: ${{{{ inputs.name }}}}
    - shell: bash
      env:
        NAME: ${{{{ inputs.name }}}}
      run: echo "Hello $NAME"
"""


def test_a_file_with_runs_is_an_action_and_with_jobs_a_workflow():
    assert parse(COMPOSITE).kind == ACTION
    assert parse("on: push\njobs: {}\n").kind == WORKFLOW


def test_neither_jobs_nor_runs_is_an_error():
    with pytest.raises(WorkflowError, match="no 'jobs' or 'runs'"):
        parse("name: x\ndescription: y\n")


def test_composite_steps_are_steps_without_a_job():
    steps = list(parse(COMPOSITE).steps())
    assert [s.job_id for s in steps] == [ACTION_JOB] * 3
    assert [s.uses for s in steps][:2] == ["actions/checkout@v4", f"actions/setup-python@{SHA}"]


def test_composite_action_rules():
    found = findings(COMPOSITE)
    # The checkout tag (WG001) and its persisted token (WG006); inputs in with:/env: are fine,
    # and actions have no permissions, so WG002 doesn't apply.
    assert [(f.rule_id, f.line) for f in found] == [("WG001", 9), ("WG006", 9)]


def test_inputs_pasted_into_run_are_template_injection_in_an_action():
    text = """
    runs:
      using: composite
      steps:
        - shell: bash
          run: |
            echo start
            echo "${{ inputs.title }}"
    """
    (f,) = findings(text)
    assert (f.rule_id, f.severity, f.line) == ("WG004", Severity.MEDIUM, 8)
    assert "'inputs.title' comes from the calling workflow" in f.message


def test_inputs_in_a_workflow_run_are_not_reported():
    # workflow_dispatch / workflow_call inputs are set by people with write access (or the
    # caller's own code), so in a workflow they stay unreported, as before.
    text = """
    on: workflow_dispatch
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - run: echo "${{ inputs.title }}"
    """
    assert findings(text) == []


def test_outsider_controlled_context_in_an_action_is_still_high():
    text = """
    runs:
      using: composite
      steps:
        - shell: bash
          run: echo "${{ github.event.pull_request.title }}"
    """
    (f,) = findings(text)
    assert (f.rule_id, f.severity) == ("WG004", Severity.HIGH)


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("docker://alpine:3.20", [("WG001", Severity.MEDIUM)]),
        ("docker://alpine@sha256:" + "a" * 64, []),
        ("Dockerfile", []),  # built from the action's own repository
    ],
)
def test_docker_action_image(image, expected):
    text = f"runs:\n  using: docker\n  image: {image}\n"
    assert [(f.rule_id, f.severity) for f in findings(text)] == expected


def test_javascript_action_has_nothing_to_check():
    assert findings("runs:\n  using: node24\n  main: dist/index.js\n") == []


def test_inline_ignore_works_in_actions():
    text = """
    runs:
      using: composite
      steps:
        - uses: actions/checkout@v4  # workflow-guard: ignore[WG001,WG006]
    """
    assert findings(text) == []


def test_fix_pins_composite_steps():
    text = "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n"
    result = pin_actions(text, FixedResolver(), "action.yml")
    assert result.text == f"runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@{SHA}  # v4\n"


class FixedResolver:
    def resolve(self, repo: str, ref: str) -> str:
        return SHA


# --- discovery -----------------------------------------------------------------------------------


def call(*args):
    out, err = io.StringIO(), io.StringIO()
    code = run(list(args), out, err)
    return code, out.getvalue(), err.getvalue()


def test_default_paths_include_root_and_local_actions(tmp_path, monkeypatch):
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: hi\n"
    )
    (tmp_path / "action.yml").write_text("runs:\n  using: node24\n  main: index.js\n")
    local = tmp_path / ".github" / "actions" / "setup"
    local.mkdir(parents=True)
    (local / "action.yaml").write_text("runs:\n  using: composite\n  steps:\n    - uses: actions/cache@v4\n")
    (local / "README.yml").write_text("not: an action\n")  # only action.y(a)ml files count
    monkeypatch.chdir(tmp_path)

    code, out, err = call()
    assert code == 1
    assert out.splitlines() == [
        ".github/actions/setup/action.yaml:4:13: WG001 [low] 'actions/cache@v4' points to a tag or"
        " branch that can be moved; pin it to a full commit SHA"
    ]
    assert "1 finding(s) in 3 file(s)" in err


def test_a_repository_with_only_an_action(tmp_path, monkeypatch):
    (tmp_path / "action.yml").write_text("runs:\n  using: node24\n  main: index.js\n")
    monkeypatch.chdir(tmp_path)
    assert call()[0] == 0


def test_this_repositorys_own_action_is_clean():
    code, out, _ = call((ROOT / "action.yml").as_posix())
    assert (code, out) == (0, "")


def test_pre_commit_pattern_matches_actions():
    files = re.compile(yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())[0]["files"])
    assert files.search("action.yml")
    assert files.search(".github/actions/setup/action.yaml")
    assert files.search(".github/actions/a/b/action.yml")
    assert not files.search("docs/action.yml")
    assert not files.search(".github/actions/setup/README.yml")
