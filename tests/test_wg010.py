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
    ("cond", "who"),
    [
        (
            "github.event.comment.author_association != 'NONE'",
            "CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR, FIRST_TIMER and MANNEQUIN",
        ),
        (
            'contains(fromJSON(\'["OWNER", "CONTRIBUTOR"]\'), github.event.comment.author_association)',
            "CONTRIBUTOR",
        ),
    ],
)
def test_a_weak_association_check_is_named(cond, who):
    ((_, severity, message),) = wg010(on_comment(*CHECKOUT_PR, job_if=cond))
    assert severity == Severity.HIGH
    assert f"(its 'if:' looks at who commented but still lets {who} in: author_association" in message


def test_a_weak_login_check_is_named():
    text = on_comment(
        "- run: ./deploy.sh", "  env:", "    T: ${{ secrets.X }}", job_if="github.actor != 'renovate[bot]'"
    )
    ((_, severity, message),) = wg010(text)
    assert severity == Severity.MEDIUM
    assert "(its 'if:' looks at who commented but still lets in every account it doesn't name)" in message


def test_a_weak_step_if_doesnt_cover_the_step():
    text = on_comment(*CHECKOUT_PR, "  if: github.event.comment.author_association != 'NONE'")
    ((_, _, message),) = wg010(text)
    assert "still lets CONTRIBUTOR" in message


def test_a_weak_check_with_a_body_match_names_the_weak_check():
    cond = "contains(github.event.comment.body, '/test') && github.event.comment.author_association != 'NONE'"
    ((_, _, message),) = wg010(on_comment(*CHECKOUT_PR, job_if=cond))
    assert "still lets CONTRIBUTOR" in message
    assert "only looks at the comment's text" not in message


def test_an_if_that_isnt_an_expression_is_no_check():
    text = on_comment(*CHECKOUT_PR, job_if="github.actor == 'me' &&")
    assert [s for _, s, _ in wg010(text)] == [Severity.HIGH]


def test_a_weak_check_in_a_needed_job_doesnt_count():
    text = on_comment(*CHECKOUT_PR).replace(
        "jobs:\n  test:\n",
        "jobs:\n  gate:\n    if: github.event.comment.author_association != 'NONE'\n    runs-on: x\n"
        "    steps:\n      - run: echo ok\n  test:\n    needs: gate\n",
    )
    ((_, severity, message),) = wg010(text)
    assert severity == Severity.HIGH
    assert (
        "(the 'if:' of job 'gate', which it needs, looks at who commented but still lets"
        " CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR, FIRST_TIMER and MANNEQUIN in" in message
    )


def test_a_weak_job_if_with_a_strong_step_if_is_covered():
    text = on_comment(
        *CHECKOUT_PR,
        "  if: github.event.comment.author_association == 'MEMBER'",
        job_if="github.event.comment.author_association != 'NONE'",
    )
    assert wg010(text) == []


@pytest.mark.parametrize(
    "step",
    [
        (
            f"- uses: actions-cool/check-user-permission@{SHA}",
            "  with:",
            "    require: write",
            "    error-if-missing: true",
        ),
        (
            f"- uses: sushichop/action-repository-permission@{SHA}",
            "  with:",
            "    required-permission: write",
        ),
        (f"- uses: xt0rted/slash-command-action@{SHA}", "  with:", "    command: test"),
        (
            f"- uses: actions/github-script@{SHA}",
            "  with:",
            "    script: |",
            "      const r = await github.rest.repos.getCollaboratorPermissionLevel({...context.repo,"
            " username: context.actor});",
            "      if (r.data.permission !== 'admin') core.setFailed('no');",
        ),
        ("- run: gh api repos/$R/collaborators/$U/permission --jq .permission | grep -qE 'admin|write'",),
        (
            "- run: |",
            "    p=$(gh api repos/$GITHUB_REPOSITORY/collaborators/$ACTOR/permission --jq .permission)",
            '    if [ "$p" != admin ]; then exit 1; fi',
        ),
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


# --- a permission step whose answer nothing acts on ----------------------------------------------

ASK_ONLY = (
    f"- uses: actions-cool/check-user-permission@{SHA}",
    "  id: perm",
    "  with:",
    "    require: write",
)
CONTINUING_ASK = (f"- uses: xt0rted/slash-command-action@{SHA}", "  id: perm", "  continue-on-error: true")
GITHUB_SCRIPT_ASK = (
    f"- uses: actions/github-script@{SHA}",
    "  id: perm",
    "  with:",
    "    script: |",
    "      const r = await github.rest.repos.getCollaboratorPermissionLevel({...context.repo,"
    " username: context.actor});",
    "      return ['admin', 'write'].includes(r.data.permission);",
)


@pytest.mark.parametrize(
    "step",
    [
        ASK_ONLY,
        GITHUB_SCRIPT_ASK,
        (
            f"- uses: sushichop/action-repository-permission@{SHA}",
            "  with:",
            "    required-permission: write",
            "    relax: true",
        ),
        (f"- uses: xt0rted/slash-command-action@{SHA}", "  continue-on-error: true"),
        (
            "- run: |",
            "    if gh api repos/$R/collaborators/$U/permission --jq .permission | grep -q admin; then",
            '      echo "ok=true" >> "$GITHUB_OUTPUT"',
            "    fi",
        ),
        ("- run: gh api repos/$R/collaborators/$U/permission --jq .permission | grep -q admin || true",),
    ],
)
def test_a_permission_step_that_doesnt_fail_is_no_check(step):
    ((line, severity, message),) = wg010(on_comment(*step, *CHECKOUT_PR))
    assert severity == Severity.HIGH
    assert (
        "(the step at line 9 asks for the commenter's permission but doesn't fail on a no,"
        " and this step's 'if:' doesn't check its answer)" in message
    )


@pytest.mark.parametrize(
    ("ask", "cond"),
    [
        (ASK_ONLY, "steps.perm.outputs.require-result == 'true'"),
        (GITHUB_SCRIPT_ASK, "${{ steps.perm.outputs.result == 'true' }}"),
        (GITHUB_SCRIPT_ASK, "contains(fromJSON('[\"true\"]'), steps.perm.outputs.result)"),
        # A step that would fail but continues on error: its outcome is the answer.
        (CONTINUING_ASK, "steps.Perm.outcome == 'success'"),
        (CONTINUING_ASK, "${{ success() && steps.perm.outcome != 'failure' }}"),
    ],
)
def test_a_step_if_on_the_answer_covers_that_step(ask, cond):
    assert wg010(on_comment(*ask, *CHECKOUT_PR, f"  if: {cond}")) == []


def test_the_answer_covers_only_the_steps_that_check_it():
    text = on_comment(
        *ASK_ONLY,
        *CHECKOUT_PR,
        "  if: steps.perm.outputs.require-result == 'true'",
        "- run: gh pr checkout ${{ github.event.issue.number }}",
    )
    assert [line for line, _, _ in wg010(text)] == [18]


def test_an_answer_without_an_id_cant_be_checked():
    step = tuple(line for line in ASK_ONLY if "id:" not in line)
    text = on_comment(*step, *CHECKOUT_PR, "  if: steps.perm.outputs.require-result == 'true'")
    assert [s for _, s, _ in wg010(text)] == [Severity.HIGH]


def test_secrets_only_in_steps_that_wait_for_the_answer_are_fine():
    gated = (
        "- run: ./deploy.sh",
        "  if: steps.perm.outputs.require-result == 'true'",
        "  env:",
        "    T: ${{ secrets.X }}",
    )
    assert wg010(on_comment(*ASK_ONLY, *gated)) == []
    ungated = ("- run: ./deploy.sh", "  env:", "    T: ${{ secrets.X }}")
    ((_, severity, message),) = wg010(on_comment(*ASK_ONLY, *ungated))
    assert severity == Severity.MEDIUM
    assert "doesn't fail on a no, and this job's 'if:' doesn't check its answer)" in message


def gated_by(job_if: str, output: str = "${{ steps.perm.outputs.require-result }}") -> str:
    gate = "\n".join(f"      {line}" for line in ASK_ONLY)
    return on_comment(*CHECKOUT_PR, job_if=job_if).replace(
        "jobs:\n  test:\n",
        f"jobs:\n  gate:\n    runs-on: x\n    outputs:\n      allowed: {output}\n    steps:\n{gate}\n"
        "  test:\n    needs: gate\n",
    )


def test_a_job_if_on_a_needed_jobs_answer_is_a_check():
    assert wg010(gated_by("needs.gate.outputs.allowed == 'true'")) == []


@pytest.mark.parametrize(
    ("job_if", "output"),
    [
        ("", "${{ steps.perm.outputs.require-result }}"),
        ("needs.gate.outputs.other == 'true'", "${{ steps.perm.outputs.require-result }}"),
        ("needs.gate.outputs.allowed == 'true'", "${{ steps.other.outputs.x }}"),
    ],
)
def test_a_needed_jobs_answer_the_job_doesnt_check_is_named(job_if, output):
    ((line, severity, message),) = wg010(gated_by(job_if, output))
    assert severity == Severity.HIGH
    assert (
        "(the step at line 11 in job 'gate', which it needs, asks for the commenter's permission" in message
    )
    assert "this job's 'if:' doesn't check the answer in needs.gate.outputs)" in message


def test_secrets_in_a_step_with_a_strong_if_are_fine():
    step = ("- run: ./deploy.sh", "  if: github.actor == 'me'", "  env:", "    T: ${{ secrets.X }}")
    assert wg010(on_comment(*step)) == []


def test_step_ids_dont_depend_on_case():
    ask = tuple(line.replace("id: perm", "id: CheckPerm") for line in ASK_ONLY)
    assert (
        wg010(on_comment(*ask, *CHECKOUT_PR, "  if: steps.checkperm.outputs.require-result == 'true'")) == []
    )


# --- an if: that reads the answer but lets a no through ------------------------------------------


@pytest.mark.parametrize(
    ("ask", "cond", "who"),
    [
        # The string 'false' is true in an if:.
        (ASK_ONLY, "steps.perm.outputs.require-result", "'false', 'none' or 'read'"),
        # A misspelt output name is empty: != fails open, == fails closed.
        (ASK_ONLY, "steps.perm.outputs.require-result != 'false'", "nothing, 'none' or 'read'"),
        (GITHUB_SCRIPT_ASK, "steps.perm.outputs.result != 'none'", "nothing, 'false' or 'read'"),
        # A step that never fails always succeeds.
        (GITHUB_SCRIPT_ASK, "steps.perm.outcome == 'success'", "anything"),
        (GITHUB_SCRIPT_ASK, "steps.perm.conclusion == 'success'", "anything"),
        (
            ASK_ONLY,
            "steps.perm.outputs.require-result == 'true' || startsWith(github.event.comment.body, '/test')",
            "anything",
        ),
        (ASK_ONLY, "${{ steps.perm.outputs.require-result == 'true' || always() }}", "anything"),
        # Not an expression GitHub accepts.
        (ASK_ONLY, "steps.perm.outputs.require-result ==", "anything"),
    ],
)
def test_an_if_that_lets_a_no_through_is_named(ask, cond, who):
    ((_, severity, message),) = wg010(on_comment(*ask, *CHECKOUT_PR, f"  if: {cond}"))
    assert severity == Severity.HIGH
    assert f"and this step's 'if:' is still true when it answers {who})" in message


def test_an_if_on_the_answer_and_a_strong_commenter_check_is_covered():
    cond = (
        "steps.perm.outputs.require-result != 'false' && github.event.comment.author_association == 'OWNER'"
    )
    assert wg010(on_comment(*ASK_ONLY, *CHECKOUT_PR, f"  if: {cond}")) == []


def test_secrets_in_a_step_that_lets_a_no_through_are_medium():
    step = (
        "- run: ./deploy.sh",
        "  if: steps.perm.outputs.require-result",
        "  env:",
        "    T: ${{ secrets.X }}",
    )
    ((_, severity, message),) = wg010(on_comment(*ASK_ONLY, *step))
    assert severity == Severity.MEDIUM
    assert "doesn't fail on a no, and this job's 'if:' doesn't check its answer)" in message


@pytest.mark.parametrize(
    ("job_if", "output", "who"),
    [
        (
            "needs.gate.outputs.allowed != 'false'",
            "${{ steps.perm.outputs.require-result }}",
            "nothing, 'none' or 'read'",
        ),
        ("needs.gate.outputs.allowed", "${{ steps.perm.outputs.require-result == 'true' }}", "anything"),
        # Part of the output is unknown, so the whole of it is.
        (
            "contains(needs.gate.outputs.allowed, 'true')",
            "${{ github.run_id }}-${{ steps.perm.outputs.require-result }}",
            "anything",
        ),
        (
            "needs.gate.outputs.allowed == 'yes'",
            "${{ steps.perm.outputs.require-result && 'yes' }}",
            "'false', 'none' or 'read'",
        ),
    ],
)
def test_a_job_if_that_lets_a_needed_jobs_no_through_is_named(job_if, output, who):
    ((_, severity, message),) = wg010(gated_by(job_if, output))
    assert severity == Severity.HIGH
    assert (
        f"this job's 'if:' reads the answer in needs.gate.outputs but is still true when it answers {who})"
        in message
    )


@pytest.mark.parametrize(
    ("job_if", "output"),
    [
        ("needs.gate.outputs.allowed == 'true'", "${{ steps.perm.outputs.require-result == 'true' }}"),
        ("needs.gate.outputs.allowed == 'ok-true'", "ok-${{ steps.perm.outputs.require-result }}"),
        ("needs.gate.outputs.allowed != 'ok-false'", "ok-${{ steps.perm.outputs.require-result == 'true' }}"),
        ("needs.gate.outputs.allowed", "${{ steps.perm.outputs.require-result == 'true' && 'yes' || '' }}"),
    ],
)
def test_a_job_if_that_keeps_a_needed_jobs_no_out_is_a_check(job_if, output):
    assert wg010(gated_by(job_if, output)) == []


# --- a permission step that comes too late -------------------------------------------------------

STOP = (f"- uses: xt0rted/slash-command-action@{SHA}", "  with:", "    command: test")


def test_a_checkout_before_the_permission_step_is_high():
    ((line, severity, message),) = wg010(on_comment(*CHECKOUT_PR, *STOP))
    assert (line, severity) == (9, Severity.HIGH)
    assert (
        "(the step at line 13 fails unless the commenter may write, but this step runs before it)" in message
    )


def test_only_the_steps_before_the_permission_step_are_open():
    text = on_comment(
        "- run: gh pr checkout ${{ github.event.issue.number }}", *STOP, "- run: gh pr checkout 1"
    )
    assert [line for line, _, _ in wg010(text)] == [9]


def test_a_gated_step_before_the_permission_step_is_covered():
    text = on_comment(*CHECKOUT_PR, "  if: github.event.comment.author_association == 'MEMBER'", *STOP)
    assert wg010(text) == []


def test_secrets_before_the_permission_step_are_medium():
    secret = ("- run: ./notify.sh", "  env:", "    T: ${{ secrets.X }}")
    ((_, severity, message),) = wg010(on_comment(*secret, *STOP))
    assert severity == Severity.MEDIUM
    assert (
        "(the step at line 12 fails unless the commenter may write,"
        " but the steps that use secrets run before it)" in message
    )
    assert wg010(on_comment(*STOP, *secret)) == []


def test_job_env_secrets_with_a_permission_step_first_are_fine():
    text = on_comment(*STOP, "- run: ./deploy.sh").replace(
        "    runs-on: x\n", "    runs-on: x\n    env:\n      T: ${{ secrets.X }}\n"
    )
    assert wg010(text) == []


def test_order_in_a_needed_job_doesnt_matter_for_the_jobs_that_need_it():
    gate = "\n".join(f"      {line}" for line in ("- run: echo hi", *STOP))
    text = on_comment(*CHECKOUT_PR).replace(
        "jobs:\n  test:\n", f"jobs:\n  gate:\n    runs-on: x\n    steps:\n{gate}\n  test:\n    needs: gate\n"
    )
    assert wg010(text) == []
