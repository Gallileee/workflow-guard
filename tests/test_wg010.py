"""WG010: issue_comment jobs that check out the PR or use secrets without checking the commenter."""

import textwrap

import pytest

from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

SHA = "a" * 40
CHECKOUT_PR = (
    f"- uses: actions/checkout@{SHA}",
    "  with:",
    "    ref: refs/pull/${{ github.event.issue.number }}/head",
    "    persist-credentials: false",
)


def wg010(text: str):
    found = check(Workflow.parse(textwrap.dedent(text), "wf.yml"))
    return [(f.line, f.severity, f.message) for f in found if f.rule_id == "WG010"]


def on_comment(*lines: str, job_if: str = "", trigger: str = "issue_comment:\n    types: [created]") -> str:
    body = "\n".join(f"      {line}" for line in lines)
    cond = f"    if: {job_if}\n" if job_if else ""
    return f"on:\n  {trigger}\npermissions: {{}}\njobs:\n  test:\n{cond}    runs-on: x\n    steps:\n{body}\n"


# --- checking out the pull request ---------------------------------------------------------------


@pytest.mark.parametrize(
    "ref",
    [
        "refs/pull/${{ github.event.issue.number }}/head",
        "refs/pull/${{ github.event.issue.number }}/merge",
        "${{ steps.pr.outputs.head_sha }}",
        "${{ needs.lookup.outputs.sha }}",
        "${{ github.event.issue.pull_request.head.sha }}",
        "refs/pull/${{ env.PR }}/merge",
    ],
)
def test_checking_out_the_pr_without_a_check_is_high(ref):
    text = on_comment(f"- uses: actions/checkout@{SHA}", "  with:", f"    ref: {ref}", "- run: npm test")
    ((line, severity, message),) = wg010(text)
    assert (line, severity) == (9, Severity.HIGH)
    assert message.startswith("checks out the pull request's code in a job that anyone who can comment")
    assert message.endswith("in the job's 'if:', or the commenter's permission in a first step")


@pytest.mark.parametrize(
    "script",
    [
        "gh pr checkout ${{ github.event.issue.number }}",
        'gh pr checkout "$NUMBER"',
        "git fetch origin pull/${{ github.event.issue.number }}/head:pr && git checkout pr",
        "git fetch origin refs/pull/7/merge",
    ],
)
def test_checking_out_the_pr_in_a_script_is_high(script):
    assert [s for _, s, _ in wg010(on_comment(f"- run: {script}"))] == [Severity.HIGH]


def test_the_default_branch_is_not_the_pr():
    assert wg010(on_comment(f"- uses: actions/checkout@{SHA}", "- run: ./label.sh")) == []
    text = on_comment(f"- uses: actions/checkout@{SHA}", "  with:", "    ref: ${{ github.sha }}")
    assert wg010(text) == []


def test_a_body_match_is_named_as_no_check():
    text = on_comment(*CHECKOUT_PR, job_if="contains(github.event.comment.body, '/test')")
    ((_, _, message),) = wg010(text)
    assert "(its 'if:' only looks at the comment's text, which anyone can write)" in message


def test_a_body_match_in_the_step_if_is_named_too():
    text = on_comment(*CHECKOUT_PR, "  if: startsWith(github.event.comment.body, '/test')")
    ((_, _, message),) = wg010(text)
    assert "only looks at the comment's text" in message


# --- what counts as a check ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "cond",
    [
        'contains(fromJSON(\'["OWNER", "MEMBER"]\'), github.event.comment.author_association)',
        "${{ github.event.comment.author_association == 'OWNER' }}",
        "github.actor == 'maintainer'",
        "contains(fromJSON(vars.MAINTAINERS), github.triggering_actor)",
        "github.event.comment.user.login == 'bot-owner'",
    ],
)
def test_a_job_if_on_the_commenter_is_a_check(cond):
    assert wg010(on_comment(*CHECKOUT_PR, job_if=cond)) == []


def test_a_step_if_on_the_commenter_covers_that_step():
    text = on_comment(*CHECKOUT_PR, "  if: github.event.comment.author_association == 'MEMBER'")
    assert wg010(text) == []


@pytest.mark.parametrize(
    "step",
    [
        (f"- uses: actions-cool/check-user-permission@{SHA}", "  with:", "    require: write"),
        (f"- uses: xt0rted/slash-command-action@{SHA}", "  with:", "    command: test"),
        (
            f"- uses: actions/github-script@{SHA}",
            "  with:",
            "    script: |",
            "      const r = await github.rest.repos.getCollaboratorPermissionLevel({...context.repo,"
            " username: context.actor});",
            "      if (r.data.permission !== 'admin') core.setFailed('no');",
        ),
        ("- run: gh api repos/$GITHUB_REPOSITORY/collaborators/$ACTOR/permission --jq .permission",),
    ],
)
def test_a_permission_step_is_a_check(step):
    assert wg010(on_comment(*step, *CHECKOUT_PR)) == []


def test_a_check_in_a_needed_job_counts():
    text = on_comment(*CHECKOUT_PR).replace(
        "jobs:\n  test:\n",
        "jobs:\n  gate:\n    if: github.event.comment.author_association == 'OWNER'\n    runs-on: x\n"
        "    steps:\n      - run: echo ok\n  middle:\n    needs: gate\n    runs-on: x\n    steps:\n"
        "      - run: echo ok\n  test:\n    needs: [middle]\n",
    )
    assert wg010(text) == []


def test_needs_without_a_check_doesnt_count_and_loops_end():
    text = on_comment(*CHECKOUT_PR).replace(
        "jobs:\n  test:\n",
        "jobs:\n  a:\n    needs: test\n    runs-on: x\n    steps:\n      - run: echo\n"
        "  test:\n    needs: a\n",
    )
    assert [s for _, s, _ in wg010(text)] == [Severity.HIGH]


# --- secrets -------------------------------------------------------------------------------------


def test_secrets_without_a_check_are_medium():
    text = on_comment("- run: ./deploy.sh", "  env:", "    TOKEN: ${{ secrets.DEPLOY_TOKEN }}")
    ((line, severity, message),) = wg010(text)
    assert (line, severity) == (6, Severity.MEDIUM)
    assert message.startswith("job 'test' uses secrets and anyone who can comment can start it")


def test_the_github_token_alone_is_not_reported():
    text = on_comment(
        "- run: gh issue edit --add-label triage", "  env:", "    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"
    )
    assert wg010(text) == []


def test_secrets_with_a_check_are_fine():
    text = on_comment(
        "- run: ./deploy.sh", "  env:", "    T: ${{ secrets.X }}", job_if="github.actor == 'me'"
    )
    assert wg010(text) == []


def test_a_checkout_finding_replaces_the_secrets_finding():
    text = on_comment(*CHECKOUT_PR, "- run: make", "  env:", "    T: ${{ secrets.X }}")
    assert [s for _, s, _ in wg010(text)] == [Severity.HIGH]


# --- other workflows -----------------------------------------------------------------------------


@pytest.mark.parametrize("trigger", ["pull_request", "push", "pull_request_review_comment"])
def test_other_triggers_are_not_checked(trigger):
    assert wg010(on_comment(*CHECKOUT_PR, trigger=trigger)) == []


def test_ignore_comment():
    text = on_comment(
        f"- uses: actions/checkout@{SHA}  # workflow-guard: ignore[WG010]",
        "  with:",
        "    ref: refs/pull/${{ github.event.issue.number }}/head",
    )
    assert wg010(text) == []
