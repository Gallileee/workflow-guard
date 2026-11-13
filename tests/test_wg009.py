"""WG009: workflow_run workflows that check out or download artifacts of the triggering run."""

import textwrap
from pathlib import Path

import pytest

from workflow_guard.calls import link_local_calls
from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

SHA = "a" * 40
RUN_ID = "${{ github.event.workflow_run.id }}"


def wg009(text: str, path: str = "wf.yml", others=()):
    wf = Workflow.parse(textwrap.dedent(text), path)
    if others:
        link_local_calls([wf, *others])
    return [(f.line, f.severity, f.message) for f in check(wf) if f.rule_id == "WG009"]


def on_run(*lines: str, trigger: str = "workflow_run:\n    workflows: [CI]\n    types: [completed]") -> str:
    body = "\n".join(f"      {line}" for line in lines)
    return f"on:\n  {trigger}\npermissions: {{}}\njobs:\n  a:\n    runs-on: x\n    steps:\n{body}\n"


# --- checking out the triggering run's code ------------------------------------------------------


@pytest.mark.parametrize(
    "expr",
    [
        "github.event.workflow_run.head_sha",
        "github.event.workflow_run.head_branch",
        "github.event.workflow_run.head_commit.id",
        "github.event.workflow_run.pull_requests[0].head.sha",
    ],
)
def test_checking_out_the_triggering_commit_is_high(expr):
    text = on_run(f"- uses: actions/checkout@{SHA}", "  with:", f"    ref: ${{{{ {expr} }}}}")
    ((line, severity, message),) = wg009(text)
    assert (line, severity) == (10, Severity.HIGH)
    assert message.startswith("checks out the triggering run's code under 'workflow_run'")
    assert "the triggering run can be a pull request from a fork" in message


def test_checking_out_the_fork_repository_is_high():
    text = on_run(
        f"- uses: actions/checkout@{SHA}",
        "  with:",
        "    repository: ${{ github.event.workflow_run.head_repository.full_name }}",
    )
    assert [s for _, s, _ in wg009(text)] == [Severity.HIGH]


def test_checking_out_the_default_branch_is_fine():
    assert wg009(on_run(f"- uses: actions/checkout@{SHA}", "- run: make")) == []
    text = on_run(f"- uses: actions/checkout@{SHA}", "  with:", "    ref: ${{ github.sha }}")
    assert wg009(text) == []


# --- downloading the triggering run's artifacts --------------------------------------------------


def test_download_into_the_workspace_then_run_is_high():
    text = on_run(
        f"- uses: actions/checkout@{SHA}",
        f"- uses: actions/download-artifact@{SHA}",
        "  with:",
        f"    run-id: {RUN_ID}",
        "    github-token: ${{ github.token }}",
        "- run: npm ci && npm run report",
    )
    ((line, severity, message),) = wg009(text)
    assert (line, severity) == (11, Severity.HIGH)
    assert "unpacks the triggering run's artifacts into the workspace" in message
    assert "the step at line 15 runs commands there with secrets" in message
    assert "${{ runner.temp }}" in message


@pytest.mark.parametrize("path", [".", "./", "${{ github.workspace }}", "${{github.workspace}}/"])
def test_workspace_spellings(path):
    text = on_run(
        f"- uses: actions/download-artifact@{SHA}",
        "  with:",
        f"    run-id: {RUN_ID}",
        f"    path: {path!r}" if path.startswith("$") else f"    path: {path}",
        "- run: ./report.sh",
    )
    assert [s for _, s, _ in wg009(text)] == [Severity.HIGH]


def test_download_elsewhere_is_medium():
    text = on_run(
        f"- uses: actions/download-artifact@{SHA}",
        "  with:",
        f"    run-id: {RUN_ID}",
        "    path: ${{ runner.temp }}/artifact",
        '- run: cat "$RUNNER_TEMP/artifact/pr-number.txt"',
    )
    ((line, severity, message),) = wg009(text)
    assert (line, severity) == (10, Severity.MEDIUM)
    assert message.startswith("downloads the triggering run's artifacts under 'workflow_run'")
    assert "don't run or source them" in message


def test_download_with_nothing_run_afterwards_is_medium():
    text = on_run(f"- uses: actions/download-artifact@{SHA}", "  with:", f"    run-id: {RUN_ID}")
    assert [s for _, s, _ in wg009(text)] == [Severity.MEDIUM]


def test_a_later_step_in_another_job_doesnt_count():
    text = on_run(f"- uses: actions/download-artifact@{SHA}", "  with:", f"    run-id: {RUN_ID}")
    text += "  b:\n    runs-on: x\n    steps:\n      - run: make\n"
    assert [s for _, s, _ in wg009(text)] == [Severity.MEDIUM]


def test_a_local_action_counts_as_running_workspace_code():
    text = on_run(
        f"- uses: actions/download-artifact@{SHA}",
        "  with:",
        f"    run-id: {RUN_ID}",
        "- uses: ./.github/actions/report",
    )
    assert [s for _, s, _ in wg009(text)] == [Severity.HIGH]


def test_this_runs_own_artifacts_are_fine():
    text = on_run(f"- uses: actions/download-artifact@{SHA}", "  with:", "    name: dist", "- run: make")
    assert wg009(text) == []


def test_dawidd6_download_defaults_to_the_workspace():
    text = on_run(
        f"- uses: dawidd6/action-download-artifact@{SHA}",
        "  with:",
        f"    run_id: {RUN_ID}",
        "- run: bash coverage.sh",
    )
    assert [s for _, s, _ in wg009(text)] == [Severity.HIGH]


def test_gh_run_download():
    high = on_run(f"- run: gh run download {RUN_ID} -n coverage", "- run: ./upload.sh")
    medium = on_run(f'- run: gh run download {RUN_ID} -n coverage -D "$RUNNER_TEMP/cov"', "- run: x")
    assert [s for _, s, _ in wg009(high)] == [Severity.HIGH]
    assert [s for _, s, _ in wg009(medium)] == [Severity.MEDIUM]


def test_github_script_download_is_medium():
    text = on_run(
        f"- uses: actions/github-script@{SHA}",
        "  with:",
        "    script: |",
        "      const zip = await github.rest.actions.downloadArtifact({owner, repo, artifact_id: id,"
        " archive_format: 'zip'});",
        "- run: unzip pr.zip",
    )
    assert [s for _, s, _ in wg009(text)] == [Severity.MEDIUM]


# --- which workflows it applies to ---------------------------------------------------------------


def test_other_triggers_are_not_checked():
    text = on_run(
        f"- uses: actions/checkout@{SHA}",
        "  with:",
        "    ref: ${{ github.event.workflow_run.head_sha }}",
        trigger="push",
    )
    assert wg009(text) == []


def test_ignore_comment():
    text = on_run(
        f"- uses: actions/checkout@{SHA}  # workflow-guard: ignore[WG009]",
        "  with:",
        "    ref: ${{ github.event.workflow_run.head_sha }}",
    )
    # The finding is on the step's first line, which holds the comment.
    assert wg009(text) == []


# --- the triggering workflows among the checked files --------------------------------------------

ROOT = Path("repo").resolve()
CHECKOUT_HEAD = (
    f"- uses: actions/checkout@{SHA}",
    "  with:",
    "    ref: ${{ github.event.workflow_run.head_sha }}",
)


def triggering(name: str | None, on: str, file: str = "ci.yml") -> Workflow:
    head = f"name: {name}\n" if name else ""
    text = f"{head}on: {on}\npermissions: {{}}\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: make\n"
    return Workflow.parse(text, str(ROOT / ".github" / "workflows" / file))


def report(workflows: str, *others: Workflow):
    text = on_run(*CHECKOUT_HEAD, trigger=f"workflow_run:\n    workflows: {workflows}")
    return wg009(text, str(ROOT / ".github" / "workflows" / "report.yml"), others)


def test_triggered_only_by_pushes_is_fine():
    assert report("[CI]", triggering("CI", "push")) == []


def test_triggered_by_pull_requests_names_the_workflow():
    ((_, severity, message),) = report("[CI]", triggering("CI", "[push, pull_request]"))
    assert severity == Severity.HIGH
    assert "'CI' runs on pull_request, so the triggering run can be a pull request from a fork" in message


def test_one_untrusted_workflow_is_enough():
    found = report("[CI, Lint]", triggering("CI", "push"), triggering("Lint", "pull_request", "lint.yml"))
    assert ["'Lint' runs on pull_request" in m for _, _, m in found] == [True]


def test_a_chain_of_workflow_run_counts_as_untrusted():
    assert len(report("[Build]", triggering("Build", "workflow_run"))) == 1


def test_an_unnamed_workflow_is_known_by_its_path():
    assert report("[.github/workflows/ci.yml]", triggering(None, "push")) == []


def test_an_unknown_workflow_is_assumed_untrusted():
    ((_, _, message),) = report("[Deploy]", triggering("CI", "push"))
    assert message.endswith("can be a pull request from a fork, and its code then runs here")


def test_pull_request_target_builds_the_base_branch():
    assert report("CI", triggering("CI", "pull_request_target")) == []


def test_a_step_before_the_download_doesnt_count():
    text = on_run(
        "- run: make", f"- uses: actions/download-artifact@{SHA}", "  with:", f"    run-id: {RUN_ID}"
    )
    assert [s for _, s, _ in wg009(text)] == [Severity.MEDIUM]


def test_a_workflow_of_another_repository_doesnt_count():
    elsewhere = Workflow.parse(
        "name: CI\non: push\npermissions: {}\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: make\n",
        str(Path("other").resolve() / ".github" / "workflows" / "ci.yml"),
    )
    assert len(report("[CI]", elsewhere)) == 1
