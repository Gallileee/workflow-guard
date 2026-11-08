import textwrap

import pytest

from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow, WorkflowError

SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def findings(yaml_text: str, ignore=frozenset()):
    return check(Workflow.parse(textwrap.dedent(yaml_text), "wf.yml"), frozenset(ignore))


def ids(yaml_text: str, ignore=frozenset()):
    return [f.rule_id for f in findings(yaml_text, ignore)]


SAFE = f"""
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}  # v4
        with:
          persist-credentials: false
      - run: echo "${{{{ github.sha }}}}"
"""


def test_a_hardened_workflow_has_no_findings():
    assert findings(SAFE) == []


# --- WG001 ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uses", "severity"),
    [
        ("actions/checkout@v4", Severity.LOW),
        ("github/codeql-action/init@v3", Severity.LOW),
        ("some-org/deploy-action@v1", Severity.HIGH),
        ("some-org/deploy-action@main", Severity.HIGH),
        ("some-org/deploy-action", Severity.HIGH),
        (f"some-org/deploy-action@{SHA[:7]}", Severity.HIGH),  # a short SHA can collide
        ("docker://alpine:3.20", Severity.MEDIUM),
    ],
)
def test_unpinned_uses_are_reported_with_a_severity_by_owner(uses, severity):
    result = findings(
        f"""
    on: push
    permissions: {{}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: {uses}
    """,
        ignore={"WG006"},
    )
    assert [(f.rule_id, f.severity, f.line, f.column) for f in result] == [("WG001", severity, 8, 15)]


@pytest.mark.parametrize(
    "uses", [f"some-org/x@{SHA}", "./.github/actions/local", "docker://alpine@sha256:" + "a" * 64]
)
def test_pinned_and_local_uses_are_fine(uses):
    assert (
        ids(f"""
    on: push
    permissions: {{}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: {uses}
    """)
        == []
    )


def test_reusable_workflow_calls_are_checked_too():
    result = findings("""
    on: push
    permissions: {}
    jobs:
      call:
        uses: some-org/shared/.github/workflows/build.yml@main
    """)
    assert [(f.rule_id, f.severity) for f in result] == [("WG001", Severity.HIGH)]


# --- WG002 / WG003 -------------------------------------------------------------------------------


def test_missing_permissions_names_the_jobs_and_points_at_jobs_key():
    result = findings("""
    on: push
    jobs:
      build:
        runs-on: ubuntu-latest
        steps: []
      deploy:
        runs-on: ubuntu-latest
        permissions:
          contents: write
        steps: []
    """)
    assert [(f.rule_id, f.line) for f in result] == [("WG002", 3)]
    assert "build" in result[0].message and "deploy" not in result[0].message


def test_permissions_on_every_job_are_enough():
    assert (
        ids("""
    on: push
    jobs:
      build:
        runs-on: ubuntu-latest
        permissions:
          contents: read
        steps: []
    """)
        == []
    )


def test_write_all_is_high_at_both_levels():
    result = findings("""
    on: push
    permissions: write-all
    jobs:
      build:
        runs-on: ubuntu-latest
        permissions: write-all
        steps: []
    """)
    assert [(f.rule_id, f.severity, f.line) for f in result] == [
        ("WG003", Severity.HIGH, 3),
        ("WG003", Severity.HIGH, 7),
    ]


# --- WG004 ---------------------------------------------------------------------------------------


def test_a_pr_title_in_a_run_script_is_reported_on_its_own_line():
    result = findings("""
    on: pull_request
    permissions: {}
    jobs:
      greet:
        runs-on: ubuntu-latest
        steps:
          - run: |
              echo "Checking..."
              echo "${{ github.event.pull_request.title }}"
    """)
    assert [(f.rule_id, f.severity, f.line) for f in result] == [("WG004", Severity.HIGH, 10)]
    assert "github.event.pull_request.title" in result[0].message


@pytest.mark.parametrize(
    "expr",
    [
        "github.head_ref",
        "github.event.issue.body",
        "github.event.comment.body",
        "github.event.head_commit.message",
        "github.event.commits[0].author.email",
        "github.event.workflow_run.head_branch",
        "format('x {0}', github.event.issue.title)",
    ],
)
def test_untrusted_contexts(expr):
    assert ids(f"""
    on: issues
    permissions: {{}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: echo "${{{{ {expr} }}}}"
    """) == ["WG004"]


def test_trusted_contexts_and_env_indirection_are_fine():
    assert (
        ids("""
    on: pull_request
    permissions: {}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - env:
              TITLE: ${{ github.event.pull_request.title }}
            run: |
              echo "$TITLE"
              echo "${{ github.sha }} ${{ github.event.pull_request.number }}"
    """)
        == []
    )


def test_github_script_is_checked_but_other_actions_inputs_are_not():
    result = ids(f"""
    on: issue_comment
    permissions: {{}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/github-script@{SHA}
            with:
              script: console.log("${{{{ github.event.comment.body }}}}")
          - uses: some-org/x@{SHA}
            with:
              text: ${{{{ github.event.comment.body }}}}
    """)
    assert result == ["WG004"]


# --- WG005 ---------------------------------------------------------------------------------------


def test_pull_request_target_alone_is_a_low_reminder():
    result = findings("""
    on:
      pull_request_target:
        types: [opened]
    permissions: {}
    jobs:
      label:
        runs-on: ubuntu-latest
        steps: []
    """)
    assert [(f.rule_id, f.severity, f.line) for f in result] == [("WG005", Severity.LOW, 2)]


def test_checking_out_the_pr_head_under_pull_request_target_is_high():
    result = findings(f"""
    on: [pull_request_target]
    permissions: {{}}
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@{SHA}
            with:
              ref: ${{{{ github.event.pull_request.head.sha }}}}
              persist-credentials: false
    """)
    assert [(f.rule_id, f.severity, f.line) for f in result] == [("WG005", Severity.HIGH, 8)]


# --- WG006 ---------------------------------------------------------------------------------------


def test_checkout_without_persist_credentials_false():
    result = findings(f"""
    on: push
    permissions: {{}}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@{SHA}
          - uses: actions/checkout@{SHA}
            with:
              persist-credentials: true
    """)
    assert [(f.rule_id, f.line) for f in result] == [("WG006", 8), ("WG006", 9)]


# --- ignoring and parsing ------------------------------------------------------------------------


def test_inline_and_global_ignores():
    text = """
    on: push
    permissions: {}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4  # workflow-guard: ignore[WG001, WG006]
          - uses: actions/checkout@v4
    """
    assert ids(text) == ["WG001", "WG006"]  # only the second step
    assert ids(text, ignore={"WG006"}) == ["WG001"]


def test_ignore_marker_must_be_in_a_comment():
    assert ids("""
    on: push
    permissions: {}
    jobs:
      a:
        runs-on: ubuntu-latest
        steps:
          - run: 'echo "workflow-guard: ignore[WG004] ${{ github.head_ref }}"'
    """) == ["WG004"]


def test_the_on_key_is_not_read_as_a_boolean():
    wf = Workflow.parse("on:\n  push:\n  pull_request_target:\njobs: {}\n")
    assert wf.triggers() == {"push", "pull_request_target"}


@pytest.mark.parametrize("text", ["jobs: [", "- just\n- a list\n", "name: no jobs\n", ""])
def test_files_that_are_not_workflows_are_rejected(text):
    with pytest.raises(WorkflowError):
        Workflow.parse(text)
