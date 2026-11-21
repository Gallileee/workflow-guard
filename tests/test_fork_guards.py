"""WG005 and WG009: an if: that keeps a fork's pull request out guards the step or job."""

import pytest

from workflow_guard.conditions import FORK_PR, FORK_RUN, UNTRUSTED_ASSOCIATIONS, lets_in
from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

SHA = "a" * 40


def found(text: str, rule: str):
    return [(f.line, f.severity) for f in check(Workflow.parse(text, "wf.yml")) if f.rule_id == rule]


def prt(job_if: str = "", step_if: str = "", extra_jobs: str = "", needs: str = "") -> str:
    job_cond = f"    if: {job_if}\n" if job_if else ""
    step_cond = f"        if: {step_if}\n" if step_if else ""
    need = f"    needs: {needs}\n" if needs else ""
    return (
        "on: [pull_request_target]\npermissions: {}\njobs:\n" + extra_jobs + "  build:\n" + need + job_cond
        + "    runs-on: x\n    steps:\n"
        f"      - uses: actions/checkout@{SHA}\n" + step_cond
        + "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
        "          persist-credentials: false\n"
    )  # fmt: skip


def run_wf(job_if: str = "", extra_jobs: str = "", needs: str = "") -> str:
    job_cond = f"    if: {job_if}\n" if job_if else ""
    need = f"    needs: {needs}\n" if needs else ""
    return (
        "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\npermissions: {}\njobs:\n"
        + extra_jobs + "  deploy:\n" + need + job_cond + "    runs-on: x\n    steps:\n"
        f"      - uses: actions/checkout@{SHA}\n"
        "        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n"
        "          persist-credentials: false\n"
    )  # fmt: skip


# --- conditions.py: the fork's stranger ----------------------------------------------------------


@pytest.mark.parametrize(
    "condition",
    [
        "github.event.pull_request.head.repo.full_name == github.repository",
        "github.event.pull_request.head.repo.full_name == github.event.pull_request.base.repo.full_name",
        "!github.event.pull_request.head.repo.fork",
        "github.event.pull_request.head.repo.fork == false",
        "github.event.pull_request.head.repo.owner.login == github.repository_owner",
        'contains(fromJSON(\'["OWNER","MEMBER"]\'), github.event.pull_request.author_association)',
        "github.event.pull_request.user.login == 'dependabot[bot]'",
        "github.actor == 'renovate[bot]' || github.actor == 'octocat'",
        "github.event_name == 'push'",
    ],
)
def test_conditions_that_keep_a_forks_pr_out(condition):
    assert lets_in(condition, FORK_PR) == ()


@pytest.mark.parametrize(
    ("condition", "passing"),
    [
        ("github.event.pull_request.author_association != 'NONE'", 4),
        ("github.event.pull_request.head.repo.full_name != github.repository", 5),
        (
            "contains(github.event.pull_request.labels.*.name, 'safe to test')",
            5,
        ),  # a label stays on new pushes
        ("github.actor != 'renovate[bot]'", 5),
        ("github.event_name == 'pull_request_target'", 5),
    ],
)
def test_conditions_that_let_a_fork_in(condition, passing):
    assert len(lets_in(condition, FORK_PR)) == passing


@pytest.mark.parametrize(
    "condition",
    [
        "github.event.workflow_run.head_repository.full_name == github.repository",
        "github.event.workflow_run.head_repository.fork == false",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.event != 'pull_request'",
        "github.event.workflow_run.actor.login == 'octocat'",
        "github.event.workflow_run.head_repository.owner.login == github.repository_owner",
    ],
)
def test_conditions_that_keep_a_forks_run_out(condition):
    assert lets_in(condition, FORK_RUN) == ()


@pytest.mark.parametrize(
    "condition",
    ["github.event.workflow_run.conclusion == 'success'", "github.event.workflow_run.head_branch == 'main'"],
)
def test_conditions_that_let_a_forks_run_in(condition):
    assert lets_in(condition, FORK_RUN) == UNTRUSTED_ASSOCIATIONS


def test_the_comment_profile_is_unchanged():
    # A pull request's head means nothing for a comment.
    assert len(lets_in("github.event.pull_request.head.repo.full_name == github.repository")) == 5


# --- WG005 ---------------------------------------------------------------------------------------

SAME_REPO = "github.event.pull_request.head.repo.full_name == github.repository"


def test_a_pr_head_checkout_without_a_guard_is_high():
    assert found(prt(), "WG005") == [(7, Severity.HIGH)]


@pytest.mark.parametrize(
    ("job_if", "step_if"),
    [
        (SAME_REPO, ""),
        ("", SAME_REPO),
        ("${{ github.event.pull_request.author_association == 'MEMBER' }}", ""),
        (f"github.event_name == 'workflow_dispatch' || {SAME_REPO}", ""),
    ],
)
def test_a_guarded_checkout_is_fine(job_if, step_if):
    # A step-level guard leaves the reminder: the job itself still runs for forks.
    assert Severity.HIGH not in [s for _, s in found(prt(job_if, step_if), "WG005")]


@pytest.mark.parametrize(
    "job_if",
    [
        "github.event.pull_request.author_association != 'NONE'",
        "contains(github.event.pull_request.labels.*.name, 'ok')",
    ],
)
def test_a_weak_guard_is_no_guard(job_if):
    assert found(prt(job_if), "WG005") == [(8, Severity.HIGH)]


GUARD_JOB = f"  guard:\n    if: {SAME_REPO}\n    runs-on: x\n    steps:\n      - run: echo ok\n"


def test_a_guard_in_a_needed_job():
    assert found(prt(extra_jobs=GUARD_JOB, needs="guard"), "WG005") == []


@pytest.mark.parametrize(
    "job_if", ["always()", "${{ !cancelled() }}", "always() && needs.guard.result != 'failure'"]
)
def test_a_job_that_runs_after_a_skipped_guard_is_high(job_if):
    assert [s for _, s in found(prt(job_if, extra_jobs=GUARD_JOB, needs="guard"), "WG005")] == [Severity.HIGH]


def test_always_with_the_guards_result_is_fine():
    text = prt("always() && needs.guard.result == 'success'", extra_jobs=GUARD_JOB, needs="guard")
    assert found(text, "WG005") == []


def test_the_reminder_goes_when_every_job_keeps_forks_out():
    text = (
        "on: [pull_request_target]\npermissions: {}\njobs:\n"
        f"  label:\n    if: {SAME_REPO}\n    runs-on: x\n    steps: []\n"
    )
    assert found(text, "WG005") == []
    assert found(text.replace(f"    if: {SAME_REPO}\n", ""), "WG005") == [(1, Severity.LOW)]


# --- WG009 ---------------------------------------------------------------------------------------


def test_a_triggering_commit_checkout_without_a_guard_is_high():
    assert found(run_wf(), "WG009") == [(10, Severity.HIGH)]


@pytest.mark.parametrize(
    "job_if",
    [
        "github.event.workflow_run.head_repository.full_name == github.repository",
        "github.event.workflow_run.conclusion == 'success' && github.event.workflow_run.event == 'push'",
        "${{ github.event.workflow_run.head_repository.fork == false }}",
    ],
)
def test_a_guarded_workflow_run_job_is_fine(job_if):
    assert found(run_wf(job_if), "WG009") == []


def test_a_conclusion_check_is_no_guard():
    assert len(found(run_wf("github.event.workflow_run.conclusion == 'success'"), "WG009")) == 1


def test_a_workflow_run_guard_in_a_needed_job():
    guard = (
        "  guard:\n    if: github.event.workflow_run.event == 'push'\n    runs-on: x\n"
        "    steps:\n      - run: echo ok\n"
    )
    assert found(run_wf(extra_jobs=guard, needs="guard"), "WG009") == []
    assert len(found(run_wf("always()", extra_jobs=guard, needs="guard"), "WG009")) == 1


def test_a_guarded_artifact_download():
    text = (
        "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\npermissions: {}\njobs:\n"
        "  a:\n    runs-on: x\n    steps:\n"
        f"      - uses: actions/download-artifact@{SHA}\n"
        "        with:\n          run-id: ${{ github.event.workflow_run.id }}\n"
    )
    assert len(found(text, "WG009")) == 1
    guarded = text.replace(
        "    runs-on: x\n", "    if: github.event.workflow_run.event == 'push'\n    runs-on: x\n"
    )
    assert found(guarded, "WG009") == []


def test_the_repository_owner_is_no_stranger():
    assert lets_in("github.actor == github.repository_owner") == ()
    assert lets_in("github.actor == github.repository_owner", FORK_PR) == ()


def test_running_anyway_is_judged_for_a_fork():
    # always(): the job may run after the skipped guard, but then its own fork check decides.
    job_if = (
        "always() && (needs.guard.result == 'success' || github.event.pull_request.head.repo.fork == false)"
    )
    assert found(prt(job_if, extra_jobs=GUARD_JOB, needs="guard"), "WG005") == []
