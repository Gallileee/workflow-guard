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
        # The string 'false' is true in an if:. With `require:` set, require-result is never
        # empty, so 'false' is the only answer a no gets.
        (ASK_ONLY, "steps.perm.outputs.require-result", "'false'"),
        (ASK_ONLY, "steps.perm.outputs.user-permission", "'none' or 'read'"),
        # Without `require:` it isn't set at all.
        (ASK_ONLY[:2], "steps.perm.outputs.require-result != 'false'", "nothing, 'none' or 'read'"),
        # A misspelt output name is empty: != fails open, == fails closed.
        (ASK_ONLY, "steps.perm.outputs.require-reslut != 'false'", "nothing, 'none' or 'read'"),
        (GITHUB_SCRIPT_ASK, "steps.perm.outputs.result != 'none'", "nothing, 'false' or 'read'"),
        # A step that never fails always succeeds.
        (GITHUB_SCRIPT_ASK, "steps.perm.outcome == 'success'", "anything"),
        (GITHUB_SCRIPT_ASK, "steps.perm.conclusion == 'success'", "anything"),
        (
            ASK_ONLY,
            "steps.perm.outputs.require-result == 'true' || startsWith(github.event.comment.body, '/test')",
            "'false'",
        ),
        (ASK_ONLY, "${{ steps.perm.outputs.require-result == 'true' || always() }}", "'false'"),
        (GITHUB_SCRIPT_ASK, "${{ steps.perm.outputs.result == 'true' || always() }}", "anything"),
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
            "${{ steps.perm.outputs.user-permission }}",
            "'none' or 'read'",
        ),
        ("needs.gate.outputs.allowed", "${{ steps.perm.outputs.require-result == 'true' }}", "'false'"),
        # Part of the output is unknown, so the whole of it is.
        (
            "contains(needs.gate.outputs.allowed, 'true')",
            "${{ github.run_id }}-${{ steps.perm.outputs.require-result }}",
            "anything",
        ),
        (
            "needs.gate.outputs.allowed == 'yes'",
            "${{ steps.perm.outputs.require-result && 'yes' }}",
            "'false'",
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


# --- running anyway: always(), failure(), !cancelled() ---------------------------------------------

STATUS_IFS = ["always()", "failure()", "${{ !cancelled() }}", "success() || failure()", "${{ always() }}"]


def needing(gate_lines: tuple[str, ...], job_if: str = "", gate_if: str = "") -> str:
    gate = "\n".join(f"      {line}" for line in gate_lines)
    cond = f"    if: {gate_if}\n" if gate_if else ""
    return on_comment(*CHECKOUT_PR, job_if=job_if).replace(
        "jobs:\n  test:\n",
        f"jobs:\n  gate:\n{cond}    runs-on: x\n    steps:\n{gate}\n  test:\n    needs: gate\n",
    )


OWNER_ONLY = "github.event.comment.author_association == 'OWNER'"


@pytest.mark.parametrize("job_if", STATUS_IFS)
def test_a_job_that_runs_after_a_failed_check_is_open(job_if):
    ((_, severity, message),) = wg010(needing(STOP, job_if))
    assert severity == Severity.HIGH
    assert (
        "(job 'gate', which it needs, fails for commenters who can't write, but this job's 'if:' uses"
        in message
    )
    assert "so it runs anyway); check github.event" in message


def test_the_message_names_every_status_function():
    ((_, _, message),) = wg010(needing(STOP, "success() || failure()"))
    assert "this job's 'if:' uses success() and failure(), so it runs anyway)" in message
    ((_, _, message),) = wg010(needing(STOP, "${{ !cancelled() }}"))
    assert "this job's 'if:' uses cancelled(), so it runs anyway)" in message


@pytest.mark.parametrize(
    "job_if",
    ["success()", "success() && always()", "${{ !failure() }}", "always() && needs.gate.result == 'success'"],
)
def test_a_job_that_doesnt_run_after_a_failed_check_is_covered(job_if):
    assert wg010(needing(STOP, job_if)) == []


@pytest.mark.parametrize(
    "job_if",
    ["always()", "${{ !failure() }}", "${{ !cancelled() }}", "always() && needs.gate.result != 'failure'"],
)
def test_a_job_that_runs_after_a_skipped_check_is_open(job_if):
    ((_, severity, message),) = wg010(needing(("- run: echo ok",), job_if, OWNER_ONLY))
    assert severity == Severity.HIGH
    assert "(job 'gate', which it needs, is skipped for commenters who can't write" in message


@pytest.mark.parametrize(
    "job_if",
    [
        "failure()",
        "always() && needs.gate.result == 'success'",
        "${{ !cancelled() && needs.gate.outputs.ok == 'true' }}",
        "always() && github.event.comment.author_association == 'MEMBER'",
    ],
)
def test_a_job_that_doesnt_run_after_a_skipped_check_is_covered(job_if):
    assert wg010(needing(("- run: echo ok",), job_if, OWNER_ONLY)) == []


def test_without_a_status_function_a_skipped_or_failed_check_still_counts():
    assert wg010(needing(STOP, "github.event.issue.pull_request")) == []
    assert wg010(needing(("- run: echo ok",), "contains(github.event.comment.body, '/t')", OWNER_ONLY)) == []


def test_running_anyway_breaks_the_chain_further_up():
    text = on_comment(*CHECKOUT_PR).replace(
        "jobs:\n  test:\n",
        f"jobs:\n  gate:\n    if: {OWNER_ONLY}\n    runs-on: x\n"
        "    steps:\n      - run: echo ok\n  middle:\n    needs: gate\n    if: always()\n    runs-on: x\n"
        "    steps:\n      - run: echo ok\n  test:\n    needs: [middle]\n",
    )
    assert [s for _, s, _ in wg010(text)] == [Severity.HIGH]
    # without always() in 'middle' it is skipped too, and so is 'test'
    assert wg010(text.replace("    if: always()\n", "")) == []


def test_one_needed_check_that_holds_is_enough():
    text = (
        needing(STOP, "always()")
        .replace("    needs: gate\n", "    needs: [gate, owner]\n")
        .replace(
            "jobs:\n",
            f"jobs:\n  owner:\n    if: {OWNER_ONLY}\n    runs-on: x\n    steps:\n      - run: echo ok\n",
        )
    )
    assert len(wg010(text)) == 1
    covered = text.replace("    if: always()\n", "    if: always() && needs.owner.result == 'success'\n")
    assert wg010(covered) == []


@pytest.mark.parametrize("step_if", STATUS_IFS)
def test_a_step_that_runs_after_the_permission_step_fails_is_open(step_if):
    ((line, severity, message),) = wg010(on_comment(*STOP, *CHECKOUT_PR, f"  if: {step_if}"))
    assert (line, severity) == (12, Severity.HIGH)
    assert "(the step at line 9 fails unless the commenter may write, but this step's 'if:' uses" in message
    assert "so it runs even when that step fails); check github.event" in message


@pytest.mark.parametrize(
    "step_if",
    [
        "success()",
        "${{ !failure() }}",
        "always() && false",
        f"failure() && {OWNER_ONLY}",
        "always(",
    ],
)
def test_a_step_that_doesnt_run_after_the_permission_step_fails_is_covered(step_if):
    assert wg010(on_comment(*STOP, *CHECKOUT_PR, f"  if: {step_if}")) == []


def test_a_step_that_runs_anyway_but_checks_the_answer_is_covered():
    text = on_comment(
        *ASK_ONLY, *STOP, *CHECKOUT_PR, "  if: always() && steps.perm.outputs.require-result == 'true'"
    )
    assert wg010(text) == []


def test_secrets_in_a_step_that_runs_after_the_permission_step_fails_are_medium():
    secret = ("- run: ./report.sh", "  if: always()", "  env:", "    T: ${{ secrets.X }}")
    ((_, severity, message),) = wg010(on_comment(*STOP, *secret))
    assert severity == Severity.MEDIUM
    assert (
        "(the step at line 9 fails unless the commenter may write, but the 'if:' of a step that"
        " uses secrets uses always(), so it runs even when that step fails)" in message
    )


def test_secrets_before_and_after_name_the_early_ones():
    early = ("- run: ./notify.sh", "  env:", "    T: ${{ secrets.X }}")
    late = ("- run: ./report.sh", "  if: always()", "  env:", "    T: ${{ secrets.Y }}")
    ((_, _, message),) = wg010(on_comment(*early, *STOP, *late))
    assert "but the steps that use secrets run before it)" in message


def test_failure_after_a_skipped_check_is_open_when_another_job_can_fail():
    text = (
        needing(("- run: echo ok",), "failure()", OWNER_ONLY)
        .replace("    needs: gate\n", "    needs: [gate, build]\n")
        .replace("jobs:\n", "jobs:\n  build:\n    runs-on: x\n    steps:\n      - run: make\n")
    )
    ((_, _, message),) = wg010(text)
    assert "is skipped for commenters who can't write, but this job's 'if:' uses failure()" in message


def test_failure_after_a_skipped_check_is_open_when_a_job_before_it_can_fail():
    text = needing(("- run: echo ok",), "failure()", OWNER_ONLY).replace(
        "  gate:\n", "  build:\n    runs-on: x\n    steps:\n      - run: make\n  gate:\n    needs: build\n"
    )
    assert len(wg010(text)) == 1


def test_cancelled_counts_as_running_anyway():
    # Another comment can cancel the run (concurrency: cancel-in-progress), and then it runs.
    ((_, _, message),) = wg010(on_comment(*STOP, *CHECKOUT_PR, "  if: cancelled()"))
    assert "this step's 'if:' uses cancelled(), so it runs even when that step fails)" in message


# --- false positives found on public workflows (2026-11-20) --------------------------------------


@pytest.mark.parametrize(
    "job_if",
    [
        # Workflows with more triggers: a comment's run is always 'issue_comment'.
        f"github.event_name == 'workflow_dispatch' || (github.event_name == 'issue_comment' && {OWNER_ONLY})",
        f"github.event_name != 'issue_comment' || {OWNER_ONLY}",
        # A job that never runs for a comment.
        "github.event_name == 'push'",
        "github.event_name == 'schedule' && contains(github.event.comment.body, '/x')",
    ],
)
def test_the_event_name_is_issue_comment(job_if):
    assert wg010(on_comment(*CHECKOUT_PR, job_if=job_if)) == []


def test_the_event_name_alone_is_no_check():
    ((_, _, message),) = wg010(on_comment(*CHECKOUT_PR, job_if="github.event_name == 'issue_comment'"))
    assert "without checking who commented;" in message


DENY = ("- run: exit 1", "  if: steps.perm.outputs.require-result != 'true'")


def test_a_step_that_exits_on_a_reported_no_stops_the_job():
    assert wg010(on_comment(*ASK_ONLY, *DENY, *CHECKOUT_PR)) == []
    secret = ("- run: ./deploy.sh", "  env:", "    T: ${{ secrets.X }}")
    assert wg010(on_comment(*ASK_ONLY, *DENY, *secret)) == []


@pytest.mark.parametrize(
    "deny",
    [
        ("- run: exit 1", "  if: steps.perm.outputs.require-result == 'false'"),
        (
            "- run: |",
            '    echo "$ACTOR may not run this"',
            "    exit 1",
            "  if: ${{ steps.perm.outputs.user-permission != 'write' }}",
        ),
        (
            f"- uses: actions/github-script@{SHA}",
            "  if: steps.perm.outputs.require-result != 'true'",
            "  with:",
            "    script: core.setFailed('no')",
        ),
    ],
)
def test_ways_to_exit_on_a_reported_no(deny):
    assert wg010(on_comment(*ASK_ONLY, *deny, *CHECKOUT_PR)) == []


@pytest.mark.parametrize(
    ("ask", "deny"),
    [
        # Not every no: require-result is empty without `require:`.
        (ASK_ONLY[:2], ("- run: exit 1", "  if: steps.perm.outputs.require-result == 'false'")),
        # Only some of the no answers.
        (ASK_ONLY, ("- run: exit 1", "  if: steps.perm.outputs.user-permission == 'none'")),
        # Maybe: it depends on something else too.
        (ASK_ONLY, ("- run: exit 1", f"  {DENY[1].strip()} && github.event.issue.locked")),
        # Doesn't fail.
        (ASK_ONLY, ("- run: echo no", "  if: steps.perm.outputs.require-result != 'true'")),
        (ASK_ONLY, (*DENY, "  continue-on-error: true")),
        # Doesn't read the answer.
        (ASK_ONLY, ("- run: exit 1", "  if: github.event.issue.locked")),
    ],
)
def test_a_step_that_doesnt_exit_on_every_reported_no_is_no_stop(ask, deny):
    ((_, severity, _),) = wg010(on_comment(*ask, *deny, *CHECKOUT_PR))
    assert severity == Severity.HIGH


def test_steps_between_the_answer_and_the_exit_are_open():
    ((line, _, message),) = wg010(on_comment(*ASK_ONLY, *CHECKOUT_PR, *DENY))
    assert line == 13
    assert (
        "(the step at line 17 fails unless the commenter may write, but this step runs before it)" in message
    )


def test_a_job_with_more_needs_knows_how_each_ends():
    # One needed job checks, the other only runs for workflow_dispatch: both don't succeed.
    text = needing(
        STOP, "(needs.gate.result == 'success' || needs.manual.result == 'success') && !cancelled()"
    )
    text = text.replace("    needs: gate\n", "    needs: [gate, manual]\n").replace(
        "jobs:\n",
        "jobs:\n  manual:\n    if: github.event_name == 'workflow_dispatch'\n    runs-on: x\n"
        "    steps:\n      - run: echo ok\n",
    )
    assert wg010(text.replace("&& !cancelled()", "&& always()")) == []
    open_ = text.replace("needs.manual.result == 'success'", "needs.manual.result == 'skipped'")
    assert len(wg010(open_.replace("&& !cancelled()", "&& always()"))) == 1


def test_a_failing_permission_step_that_also_writes_its_answer():
    gate = (
        f"- uses: actions/github-script@{SHA}",
        "  id: perm",
        "  with:",
        "    script: |",
        "      const r = await github.rest.repos.getCollaboratorPermissionLevel({...context.repo,"
        " username: context.actor});",
        "      core.setOutput('ok', r.data.permission === 'admin');",
        "      if (r.data.permission === 'none') core.setFailed('no');",
    )
    text = needing(gate, "${{ !cancelled() && needs.gate.outputs.ok == 'true' }}").replace(
        "    runs-on: x\n    steps:\n      - uses: actions/github",
        "    runs-on: x\n    outputs:\n      ok: ${{ steps.perm.outputs.ok }}\n"
        "    steps:\n      - uses: actions/github",
    )
    assert wg010(text) == []
    assert (
        len(wg010(text.replace("needs.gate.outputs.ok == 'true'", "needs.gate.outputs.ok != 'false'"))) == 1
    )


@pytest.mark.parametrize(
    "script",
    [
        'echo "REF=refs/pull/${{ github.event.issue.number }}/merge" >> "$GITHUB_ENV"',
        "echo ref=refs/pull/1/head >> $GITHUB_OUTPUT",
        "gh api repos/$R/pulls/1 --jq .head.sha  # not refs/pull/1/head",
    ],
)
def test_a_pr_ref_that_is_only_saved_is_no_checkout(script):
    assert wg010(on_comment(f"- run: {script}")) == []


def test_a_git_command_split_over_lines_is_a_checkout():
    text = on_comment(
        "- run: |", "    git fetch origin \\", "      refs/pull/${{ github.event.issue.number }}/head"
    )
    assert [s for _, s, _ in wg010(text)] == [Severity.HIGH]


# --- a script that checks who commented --------------------------------------------------------

SCRIPT_GATE = (
    "- run: |",
    '    case "$ASSOC" in',
    "      OWNER|MEMBER|COLLABORATOR) ;;",
    '      *) echo "not allowed"; exit 1 ;;',
    "    esac",
    "  env:",
    "    ASSOC: ${{ github.event.comment.author_association }}",
)


def test_a_script_that_exits_for_strangers_stops_the_job():
    assert wg010(on_comment(*SCRIPT_GATE, *CHECKOUT_PR)) == []
    secret = ("- run: ./deploy.sh", "  env:", "    T: ${{ secrets.X }}")
    assert wg010(on_comment(*SCRIPT_GATE, *secret)) == []


@pytest.mark.parametrize(
    "gate",
    [
        (
            "- run: |",
            '    if [ "${{ github.event.comment.author_association }}" != "OWNER" ]; then',
            "      exit 1",
            "    fi",
        ),
        ('- run: \'[[ "${{ github.actor }}" == "octocat" ]] || exit 1\'',),
        (
            "- run: |",
            "    ok=false",
            '    case "$A" in OWNER|MEMBER) ok=true ;; esac',
            '    [ "$ok" = true ] || exit 1',
            "  if: github.event_name == 'issue_comment'",
            "  shell: bash",
            "  env:",
            "    A: ${{ github.event.comment.author_association }}",
        ),
    ],
)
def test_ways_to_check_in_a_script(gate):
    assert wg010(on_comment(*gate, *CHECKOUT_PR)) == []


def test_a_script_check_in_a_needed_job_counts():
    assert wg010(needing(SCRIPT_GATE)) == []


def test_a_checkout_before_the_script_check_is_open():
    ((line, _, message),) = wg010(on_comment(*CHECKOUT_PR, *SCRIPT_GATE))
    assert line == 9
    assert (
        "(the step at line 13 fails unless the commenter may write, but this step runs before it)" in message
    )


@pytest.mark.parametrize(
    ("gate", "who"),
    [
        (
            (
                "- run: '[ \"$A\" = NONE ] && exit 1 || true'",
                "  env:",
                "    A: ${{ github.event.comment.author_association }}",
            ),
            "CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR, FIRST_TIMER and MANNEQUIN in: author_association values",
        ),
        (
            ("- run: |", '    if [ "${{ github.actor }}" = "spam-bot" ]; then exit 1; fi'),
            "in every account it doesn't name",
        ),
    ],
)
def test_a_script_that_lets_some_through_is_named(gate, who):
    ((_, _, message),) = wg010(on_comment(*gate, *CHECKOUT_PR))
    assert f"(the script at line 9 looks at who commented but still lets {who}" in message


def test_a_weak_script_in_a_needed_job_is_named():
    gate = ("- run: |", '    if [ "${{ github.actor }}" = "spam-bot" ]; then exit 1; fi')
    ((_, _, message),) = wg010(needing(gate))
    assert (
        "(the script at line 9 in job 'gate', which it needs, looks at who commented but still lets in"
        in message
    )


@pytest.mark.parametrize(
    "extra",
    [
        ("  continue-on-error: true",),
        ("  if: contains(github.event.comment.body, '/deploy')",),  # may not run
        ("  shell: pwsh",),
        ("  shell: python",),
    ],
)
def test_a_script_check_that_may_not_stop_the_job(extra):
    assert [s for _, s, _ in wg010(on_comment(*SCRIPT_GATE, *extra, *CHECKOUT_PR))] == [Severity.HIGH]


def test_a_windows_runner_runs_pwsh_unless_told_otherwise():
    text = on_comment(*SCRIPT_GATE, *CHECKOUT_PR).replace("runs-on: x", "runs-on: windows-latest")
    assert len(wg010(text)) == 1
    bash = text.replace("    steps:\n", "    defaults:\n      run:\n        shell: bash\n    steps:\n")
    assert wg010(bash) == []


def test_a_script_that_doesnt_use_the_variable_is_no_check_and_not_named():
    text = on_comment("- run: ./build.sh || exit 1", *CHECKOUT_PR).replace(
        "permissions: {}\n",
        "permissions: {}\nenv:\n  ASSOC: ${{ github.event.comment.author_association }}\n",
    )
    ((_, _, message),) = wg010(text)
    assert "the script at" not in message


def test_a_permission_api_call_with_an_expression_in_the_url():
    step = (
        "- run: |",
        '    U="${{ github.event.comment.user.login }}"',
        '    P=$(gh api "repos/${{ github.repository }}/collaborators/${{ github.actor }}/permission")',
        '    if [[ "$P" != "admin" ]]; then exit 1; fi',
    )
    assert wg010(on_comment(*step, *CHECKOUT_PR)) == []


def test_a_script_that_tries_to_stop_no_one_is_not_named():
    # It looks at who commented but has no exit: it isn't meant as a check.
    ((_, _, message),) = wg010(on_comment('- run: echo "hello ${{ github.actor }}"', *CHECKOUT_PR))
    assert "the script at" not in message


# --- permission API scripts run on paper ---------------------------------------------------------

PERM = 'P=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$GITHUB_ACTOR/permission" --jq .permission'


def test_a_script_that_exits_only_on_an_api_error_is_no_stop():
    # `exit 1` is there, but a no (none, read) only goes to an output.
    step = ("- run: |", f"    {PERM} || exit 1)", '    echo "permission=$P" >> "$GITHUB_OUTPUT"')
    ((line, severity, message),) = wg010(on_comment(*step, *CHECKOUT_PR))
    assert (line, severity) == (12, Severity.HIGH)
    assert "(the step at line 9 asks for the commenter's permission but doesn't fail on a no" in message


@pytest.mark.parametrize(
    "check",
    [
        f'    {PERM} 2>/dev/null || echo none)\n    case "$P" in admin|write) ;; *) exit 1 ;; esac',
        f'    {PERM})\n    [[ "$P" == "admin" || "$P" == "write" ]] || exit 1',
        '    gh api "repos/$R/collaborators/$U/permission" -q .permission | grep -qE "admin|write" || exit 1',
    ],
)
def test_a_script_that_exits_on_a_no_is_a_stop(check):
    step = ("- run: |", *check.split("\n"), "  env:", "    U: ${{ github.event.comment.user.login }}")
    assert wg010(on_comment(*step, *CHECKOUT_PR)) == []


def test_an_api_script_that_reports_covers_what_reads_its_answer():
    step = (
        "- id: perm",
        "  run: |",
        f"    if {PERM}); then",
        '      echo "ok=$([ "$P" = admin ] && echo true || echo false)" >> "$GITHUB_OUTPUT"',
        "    else",
        "      exit 1",
        "    fi",
    )
    assert wg010(on_comment(*step, *CHECKOUT_PR, "  if: steps.perm.outputs.ok == 'true'")) == []
    assert len(wg010(on_comment(*step, *CHECKOUT_PR))) == 1


@pytest.mark.parametrize(
    "step",
    [
        # Not about the commenter: the text decides, as before.
        (
            "- run: |",
            '    P=$(gh api "repos/$R/collaborators/$PR_AUTHOR/permission" --jq .permission)',
            "    exit 1",
        ),
        # Something the evaluator doesn't follow.
        ("- run: |", f"    for i in 1 2; do {PERM}) && break; done", '    [ "$P" = admin ] || exit 1'),
        # Another shell.
        ("- run: |", f"    {PERM} || exit 1)", "  shell: pwsh"),
    ],
)
def test_api_scripts_it_cant_run_are_guessed_from_the_text(step):
    assert wg010(on_comment(*step, *CHECKOUT_PR)) == []


# --- a permission step that may be skipped -----------------------------------------------------

MAYBE = "  if: contains(github.event.comment.body, '/test')"


def test_a_check_that_may_be_skipped_doesnt_cover_the_steps_after_it():
    ((line, severity, message),) = wg010(on_comment(*STOP, MAYBE, *CHECKOUT_PR))
    assert (line, severity) == (13, Severity.HIGH)
    assert (
        "(the step at line 9 fails unless the commenter may write, but its 'if:' may skip it,"
        " and this step doesn't have the same condition)" in message
    )


@pytest.mark.parametrize(
    "step_if",
    [
        "contains(github.event.comment.body, '/test')",
        "${{ contains(github.event.comment.body, '/test') }}",
        "github.event.issue.pull_request && contains(github.event.comment.body, '/test')",
        "contains(github.event.comment.body, '/test') && (github.event.issue.pull_request || false)",
    ],
)
def test_a_step_with_the_checks_condition_is_covered(step_if):
    assert wg010(on_comment(*STOP, MAYBE, *CHECKOUT_PR, f"  if: {step_if}")) == []


@pytest.mark.parametrize(
    "step_if",
    [
        "github.event.issue.pull_request",
        "contains(github.event.comment.body, '/test') || github.event.issue.pull_request",
        "contains(github.event.comment.body, '/other')",
    ],
)
def test_a_step_without_the_checks_condition_is_open(step_if):
    assert len(wg010(on_comment(*STOP, MAYBE, *CHECKOUT_PR, f"  if: {step_if}"))) == 1


def test_a_check_whose_if_always_holds_covers_everything():
    assert wg010(on_comment(*STOP, "  if: github.event_name == 'issue_comment'", *CHECKOUT_PR)) == []
    assert wg010(on_comment(*STOP, "  if: '!cancelled() || true'", *CHECKOUT_PR)) == []


def test_a_later_check_that_always_runs_covers_what_follows_it():
    assert wg010(on_comment(*STOP, MAYBE, *STOP, *CHECKOUT_PR)) == []


def test_secrets_after_a_check_that_may_be_skipped_are_medium():
    secret = ("- run: ./deploy.sh", "  env:", "    T: ${{ secrets.X }}")
    ((_, severity, message),) = wg010(on_comment(*STOP, MAYBE, *secret))
    assert severity == Severity.MEDIUM
    assert (
        "but its 'if:' may skip it, and a step that uses secrets doesn't have the same condition)" in message
    )
    assert wg010(on_comment(*STOP, MAYBE, *secret, MAYBE)) == []


def test_a_script_check_that_may_be_skipped_covers_steps_with_its_condition():
    gate = (*SCRIPT_GATE, MAYBE)
    assert len(wg010(on_comment(*gate, *CHECKOUT_PR))) == 1
    assert wg010(on_comment(*gate, *CHECKOUT_PR, MAYBE)) == []


# --- ... in a needed job ------------------------------------------------------------------------


def needing_maybe(job_if: str, output: str = "${{ steps.cmd.outputs.go }}") -> str:
    gate = "\n".join(
        f"      {line}"
        for line in (
            "- id: cmd",
            "  run: echo go=true >> $GITHUB_OUTPUT",
            *STOP,
            "  if: steps.cmd.outputs.go == 'true'",
        )
    )
    cond = f"    if: {job_if}\n" if job_if else ""
    return on_comment(*CHECKOUT_PR).replace(
        "jobs:\n  test:\n",
        f"jobs:\n  gate:\n    runs-on: x\n    outputs:\n      go: {output}\n    steps:\n{gate}\n"
        f"  test:\n    needs: gate\n{cond}",
    )


def test_a_needed_check_that_may_be_skipped_doesnt_cover_the_job():
    assert len(wg010(needing_maybe(""))) == 1


@pytest.mark.parametrize(
    "job_if", ["needs.gate.outputs.go == 'true'", "${{ needs.gate.outputs.go == 'true' && true }}"]
)
def test_a_job_with_the_needed_checks_condition_is_covered(job_if):
    assert wg010(needing_maybe(job_if)) == []


@pytest.mark.parametrize(
    ("job_if", "output"),
    [
        ("needs.gate.outputs.go != 'true'", "${{ steps.cmd.outputs.go }}"),
        # The output carries more than the value.
        ("needs.gate.outputs.go == 'true'", "x${{ steps.cmd.outputs.go }}"),
        ("needs.gate.outputs.go == 'true'", "${{ steps.other.outputs.go }}"),
        ("needs.gate.outputs.go == 'true'", "${{ steps.cmd.outputs.go || 'true' }}"),
    ],
)
def test_a_job_without_the_needed_checks_condition_is_open(job_if, output):
    assert len(wg010(needing_maybe(job_if, output))) == 1


# --- a script that reports who commented through $GITHUB_OUTPUT ----------------------------------

TRUST = (
    "- id: trust",
    "  run: |",
    '    case "${{ github.event.comment.author_association }}" in',
    '      OWNER|MEMBER|COLLABORATOR) echo "trusted=true" >> "$GITHUB_OUTPUT" ;;',
    '      *) echo "trusted=false" >> "$GITHUB_OUTPUT" ;;',
    "    esac",
)


@pytest.mark.parametrize(
    "cond",
    [
        "steps.trust.outputs.trusted == 'true'",
        "steps.trust.outputs.trusted != 'false'",
        "${{ !contains(steps.trust.outputs.trusted, 'f') }}",
    ],
)
def test_a_step_if_on_a_scripts_output_covers_that_step(cond):
    assert wg010(on_comment(*TRUST, *CHECKOUT_PR, f"  if: {cond}")) == []


def test_a_step_if_that_lets_the_scripts_no_through_is_named():
    ((_, _, message),) = wg010(on_comment(*TRUST, *CHECKOUT_PR, "  if: steps.trust.outputs.trusted != 'yes'"))
    assert (
        "(the step at line 9 looks at who commented but doesn't fail on a no, and this step's 'if:'"
        " is still true when it answers 'trusted=false')" in message
    )


def test_a_step_that_doesnt_read_the_scripts_output_is_named():
    ((_, _, message),) = wg010(on_comment(*TRUST, *CHECKOUT_PR))
    assert (
        "(the step at line 9 looks at who commented but doesn't fail on a no,"
        " and this step's 'if:' doesn't check" in message
    )


def test_an_exit_on_the_scripts_no_stops_the_job():
    deny = ("- if: steps.trust.outputs.trusted != 'true'", "  run: exit 1")
    assert wg010(on_comment(*TRUST, *deny, *CHECKOUT_PR)) == []


def test_a_job_if_on_a_needed_scripts_output():
    gate = "\n".join(f"      {line}" for line in TRUST)
    text = on_comment(*CHECKOUT_PR, job_if="needs.gate.outputs.trusted == 'true'").replace(
        "jobs:\n  test:\n",
        "jobs:\n  gate:\n    runs-on: x\n    outputs:\n      trusted: ${{ steps.trust.outputs.trusted }}\n"
        f"    steps:\n{gate}\n  test:\n    needs: gate\n",
    )
    assert wg010(text) == []
    assert len(wg010(text.replace("== 'true'", "!= 'yes'"))) == 1


@pytest.mark.parametrize(
    "script",
    [
        # An output it can't work out.
        '    echo "trusted=$(./check.sh)" >> "$GITHUB_OUTPUT"',
        # Written some way it doesn't follow.
        '    echo "trusted=false" | tee -a "$GITHUB_OUTPUT"',
    ],
)
def test_a_script_output_it_cant_work_out_is_no_check(script):
    step = ("- id: trust", "  run: |", '    A="${{ github.event.comment.author_association }}"', script)
    assert len(wg010(on_comment(*step, *CHECKOUT_PR, "  if: steps.trust.outputs.trusted == 'true'"))) == 1


def test_a_script_that_writes_the_api_answer():
    step = (
        "- id: perm",
        "  run: |",
        '    P=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$GITHUB_ACTOR/permission" --jq .permission)',
        '    if [ "$P" = admin ]; then ok=yes; else ok=no; fi',
        '    echo "ok=$ok" >> "$GITHUB_OUTPUT"',
    )
    assert wg010(on_comment(*step, *CHECKOUT_PR, "  if: steps.perm.outputs.ok == 'yes'")) == []
    ((_, _, message),) = wg010(on_comment(*step, *CHECKOUT_PR, "  if: steps.perm.outputs.ok != 'false'"))
    assert "asks for the commenter's permission but doesn't fail on a no" in message
    assert "is still true when it answers 'ok=no')" in message


def test_a_script_that_doesnt_look_at_the_commenter_is_no_answer():
    step = ("- id: trust", "  run: echo trusted=false >> $GITHUB_OUTPUT")
    ((_, _, message),) = wg010(on_comment(*step, *CHECKOUT_PR, "  if: steps.trust.outputs.trusted == 'true'"))
    assert "looks at who commented" not in message


def test_a_script_with_continue_on_error_is_no_answer():
    text = on_comment(
        *TRUST, "  continue-on-error: true", *CHECKOUT_PR, "  if: steps.trust.outputs.trusted == 'true'"
    )
    assert len(wg010(text)) == 1


def test_a_script_that_writes_nothing_is_no_answer():
    step = ("- id: hello", '  run: echo "hello ${{ github.actor }}"')
    ((_, _, message),) = wg010(on_comment(*step, *CHECKOUT_PR))
    assert "looks at who commented" not in message


def test_the_permission_step_may_use_a_secret_token():
    # It needs a token to ask the API; the steps after it are what it guards.
    ask = (*ASK_ONLY[:2], "  with:", "    require: write", "    token: ${{ secrets.BOT_TOKEN }}")
    assert wg010(on_comment(*ask, "- run: echo hi")) == []
    secret = ("- run: ./deploy.sh", "  env:", "    T: ${{ secrets.X }}")
    assert [s for _, s, _ in wg010(on_comment(*ask, *secret))] == [Severity.MEDIUM]
