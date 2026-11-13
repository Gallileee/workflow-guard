"""Reusable workflows (on: workflow_call) and the local workflows that call them."""

import io
import json
import textwrap
from pathlib import Path

from workflow_guard.calls import link_local_calls, local_calls
from workflow_guard.cli import run
from workflow_guard.model import Severity
from workflow_guard.project import repo_root
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

TITLE = "${{ github.event.pull_request.title }}"

CALLEE = """
on:
  workflow_call:
    inputs:
      title:
        type: string
      verbose:
        type: boolean
      count:
        type: number
permissions: {}
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ inputs.title }}"
"""


def wf(name: str, text: str) -> Workflow:
    return Workflow.parse(textwrap.dedent(text), f".github/workflows/{name}")


def caller(value: str, target: str = "./.github/workflows/greet.yml", extra: str = "") -> str:
    return f"""
on: pull_request
permissions: {{}}
jobs:{extra}
  call:
    uses: {target}
    with:
      title: {value}
"""


def wg(rule: str, workflow: Workflow):
    return [f for f in check(workflow) if f.rule_id == rule]


def linked(callee_text: str, *callers: str) -> Workflow:
    callee = wf("greet.yml", callee_text)
    link_local_calls([callee, *(wf(f"ci{i}.yml", text) for i, text in enumerate(callers))])
    return callee


# --- a reusable workflow on its own ---------------------------------------------------------------


def test_inputs_without_a_known_caller_are_medium():
    (f,) = wg("WG004", wf("greet.yml", CALLEE))
    assert f.severity == Severity.MEDIUM
    assert f.line == 16
    assert f.message.startswith("'inputs.title' comes from the calling workflow")


def test_boolean_and_number_inputs_cannot_carry_text():
    text = CALLEE.replace("inputs.title", "inputs.verbose }} ${{ inputs.COUNT")
    assert wg("WG004", wf("greet.yml", text)) == []


def test_undeclared_inputs_are_still_medium():
    text = CALLEE.replace("inputs.title", "inputs.other")
    (f,) = wg("WG004", wf("greet.yml", text))
    assert f.severity == Severity.MEDIUM


def test_inputs_of_an_ordinary_workflow_are_trusted():
    # workflow_dispatch inputs come from people with write access to the repository.
    text = CALLEE.replace("workflow_call:", "workflow_dispatch:")
    assert wg("WG004", wf("greet.yml", text)) == []


def test_inputs_follow_env_detours_in_the_callee():
    text = CALLEE.replace(
        '      - run: echo "${{ inputs.title }}"',
        '      - run: echo "title=$T" >> "$GITHUB_ENV"\n        env:\n          T: ${{ inputs.title }}',
    )
    (f,) = wg("WG007", wf("greet.yml", text))
    assert f.severity == Severity.MEDIUM


# --- with a local caller --------------------------------------------------------------------------


def test_a_caller_passing_a_pr_title_makes_it_high():
    callee = linked(CALLEE, caller(TITLE))
    (f,) = wg("WG004", callee)
    assert f.severity == Severity.HIGH
    assert f.path == ".github/workflows/greet.yml"
    assert f.message == (
        "'inputs.title' carries 'github.event.pull_request.title', which outsiders can set "
        "(via with.title in .github/workflows/ci0.yml (job 'call')) and is pasted into a script; "
        "pass it through 'env:' and use the variable instead"
    )


def test_callers_passing_clean_values_make_it_clean():
    callee = linked(CALLEE, caller("${{ github.sha }}"), caller("hello"))
    assert callee.input_taints == {}
    assert wg("WG004", callee) == []


def test_the_worst_caller_wins():
    callee = linked(CALLEE, caller("hello"), caller(TITLE))
    (f,) = wg("WG004", callee)
    assert f.severity == Severity.HIGH
    assert "ci1.yml" in f.message


def test_input_names_ignore_case():
    callee = linked(CALLEE.replace("inputs.title", "inputs.TITLE"), caller(TITLE).replace("title:", "Title:"))
    (f,) = wg("WG004", callee)
    assert f.severity == Severity.HIGH


def test_needs_outputs_of_the_caller_are_followed():
    extra = f"""
  meta:
    runs-on: ubuntu-latest
    outputs:
      title: ${{{{ steps.t.outputs.title }}}}
    steps:
      - id: t
        run: echo "title=$T" >> "$GITHUB_OUTPUT"
        env:
          T: {TITLE}"""
    text = caller("${{ needs.meta.outputs.title }}", extra=extra).replace(
        "  call:\n", "  call:\n    needs: meta\n"
    )
    (f,) = wg("WG004", linked(CALLEE, text))
    assert f.severity == Severity.HIGH
    assert "needs.meta.outputs.title -> with.title in .github/workflows/ci0.yml" in f.message


def test_a_chain_of_reusable_workflows():
    middle = """
on:
  workflow_call:
    inputs:
      name: {type: string}
permissions: {}
jobs:
  pass-on:
    uses: ./.github/workflows/greet.yml
    with:
      title: prefix ${{ inputs.name }}
"""
    top = caller(TITLE, target="./.github/workflows/middle.yml").replace("title:", "name:")
    callee = wf("greet.yml", CALLEE)
    files = [callee, wf("middle.yml", middle), wf("top.yml", top)]
    link_local_calls(files)
    (f,) = wg("WG004", callee)
    assert f.severity == Severity.HIGH
    hops = "with.name in .github/workflows/top.yml (job 'call') -> with.title in .github/workflows/middle.yml"
    assert hops in f.message


def test_a_middle_workflow_without_callers_passes_medium_on():
    middle = """
on:
  workflow_call:
permissions: {}
jobs:
  pass-on:
    uses: ./.github/workflows/greet.yml
    with:
      title: ${{ inputs.name }}
"""
    callee = wf("greet.yml", CALLEE)
    link_local_calls([callee, wf("middle.yml", middle)])
    (f,) = wg("WG004", callee)
    assert f.severity == Severity.MEDIUM
    assert "'inputs.name' from the calling workflow, which may be untrusted" in f.message


def test_a_loop_of_calls_does_not_hang():
    a = CALLEE.replace("jobs:\n", "jobs:\n  again:\n    uses: ./.github/workflows/b.yml\n", 1)
    b = caller("${{ inputs.title }}").replace("on: pull_request", "on: workflow_call")
    first, second = wf("greet.yml", a), wf("b.yml", b)
    link_local_calls([first, second])
    assert first.input_taints is not None


def test_remote_and_missing_targets_are_not_callers():
    callee = linked(
        CALLEE,
        caller(TITLE, target="octo/repo/.github/workflows/greet.yml@v1"),
        caller(TITLE, target="./.github/workflows/other.yml"),
    )
    assert callee.input_taints is None
    (f,) = wg("WG004", callee)
    assert f.severity == Severity.MEDIUM


def test_only_files_under_dot_github_workflows_have_a_repository():
    assert repo_root(Path("repo/.github/workflows/ci.yml")) == Path("repo").resolve()
    assert repo_root(Path("repo/ci.yml")) is None
    files = [Workflow.parse(textwrap.dedent(caller(TITLE)), "ci.yml"), wf("greet.yml", CALLEE)]
    assert local_calls(files) == {}


# --- command line ---------------------------------------------------------------------------------


def write(root: Path, name: str, text: str) -> None:
    folder = root / ".github" / "workflows"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / name).write_text(textwrap.dedent(text), encoding="utf-8")


def run_json(*argv: str):
    out, err = io.StringIO(), io.StringIO()
    code = run([*argv, "--format", "json", "--ignore", "WG001"], out, err)
    return code, json.loads(out.getvalue())["findings"]


def test_cli_links_the_files_it_checks(tmp_path):
    write(tmp_path, "greet.yml", CALLEE)
    write(tmp_path, "ci.yml", caller(TITLE))
    folder = tmp_path / ".github" / "workflows"
    code, findings = run_json(str(folder))
    assert code == 1
    (f,) = findings
    assert (f["rule"], f["severity"]) == ("WG004", "high")
    assert f["path"].endswith(".github/workflows/greet.yml")
    assert "(job 'call')" in f["message"]


def test_cli_with_only_the_callee_reports_medium(tmp_path):
    write(tmp_path, "greet.yml", CALLEE)
    write(tmp_path, "ci.yml", caller("${{ github.sha }}"))
    folder = tmp_path / ".github" / "workflows"
    _, alone = run_json(str(folder / "greet.yml"))
    assert [f["severity"] for f in alone] == ["medium"]
    _, together = run_json(str(folder))
    assert together == []
