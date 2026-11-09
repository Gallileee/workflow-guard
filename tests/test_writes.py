"""writes.py on its own, then the forms it adds to WG004 / WG007."""

import textwrap

import pytest

from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow
from workflow_guard.writes import (
    ENV,
    OUTPUT,
    PATH,
    assignments,
    github_script_calls,
    payload,
    shell_writes,
)


def script(text: str) -> str:
    return textwrap.dedent(text).strip("\n")


def summary(text: str):
    """(file, name, [lines]) per assignment."""
    return [(a.file, a.name, [w.line for w in a.writes]) for a in assignments(shell_writes(script(text)))]


# --- payload / shell_writes ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ('echo "a=$B"', "a=$B"),
        ("echo 'a=1'", "a=1"),
        ("echo -n a=1", "a=1"),
        ("printf '%s\\n' \"a=$B\"", "a=$B"),
        ("a=1", "a=1"),
    ],
)
def test_payload(source, expected):
    assert payload(source) == expected


def test_single_lines():
    assert summary("""
        echo "a=1" >> "$GITHUB_OUTPUT"
        echo B=2 >>$GITHUB_ENV
        echo "/opt/tool/bin" >> ${GITHUB_PATH}
        echo "not written"
    """) == [(OUTPUT, "a", [0]), (ENV, "B", [1]), (PATH, None, [2])]


def test_a_group_on_several_lines_with_a_multiline_value():
    assert summary("""
        {
          echo "title=$TITLE"
          echo "body<<EOF"
          echo "$BODY"
          echo "second line"
          echo "EOF"
        } >> "$GITHUB_OUTPUT"
        echo done
    """) == [(OUTPUT, "title", [1]), (OUTPUT, "body", [3, 4])]


def test_a_group_on_one_line():
    assert summary("""{ echo "a=1"; echo "b=$X"; } >> "$GITHUB_OUTPUT\"""") == [
        (OUTPUT, "a", [0]),
        (OUTPUT, "b", [0]),
    ]


def test_separate_echo_lines_build_one_multiline_value():
    assert summary("""
        echo "notes<<END" >> "$GITHUB_ENV"
        echo "$NOTES" >> "$GITHUB_ENV"
        echo "END" >> "$GITHUB_ENV"
    """) == [(ENV, "notes", [1])]


@pytest.mark.parametrize(
    "first_line",
    ['cat <<EOF >> "$GITHUB_ENV"', "cat >> $GITHUB_ENV <<'EOF'", 'cat <<-EOF >> "$GITHUB_ENV"'],
)
def test_a_shell_heredoc(first_line):
    assert summary(f"""
        {first_line}
        NOTES<<DELIM
        $NOTES
        DELIM
        EOF
        echo after
    """) == [(ENV, "NOTES", [2])]


def test_a_block_never_closed_runs_to_the_end():
    assert summary("""
        echo "x<<EOF" >> "$GITHUB_OUTPUT"
        echo "$A" >> "$GITHUB_OUTPUT"
    """) == [(OUTPUT, "x", [1])]


def test_github_script_calls():
    calls = github_script_calls(
        script("""
        const t = context.payload.pull_request.title;
        core.setOutput('title', t);
        core.exportVariable("NAME", process.env.X)
        core.addPath(`${dir}/bin`);
        core.info('nothing')
    """)
    )
    assert [(c.line, c.file, c.name, c.argument) for c in calls] == [
        (1, OUTPUT, "title", "t"),
        (2, ENV, "NAME", "process.env.X"),
        (3, PATH, None, "`${dir}/bin`"),
    ]


# --- through the rules ---------------------------------------------------------------------------


def findings(text: str):
    return [(f.rule_id, f.line) for f in check(Workflow.parse(textwrap.dedent(text), "wf.yml"))]


def test_multiline_output_from_an_issue_body_is_followed():
    found = check(
        Workflow.parse(
            textwrap.dedent("""
    on: issues
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - id: read
            env:
              BODY: ${{ github.event.issue.body }}
            run: |
              {
                echo "body<<EOF"
                echo "$BODY"
                echo "EOF"
              } >> "$GITHUB_OUTPUT"
          - run: echo "${{ steps.read.outputs.body }}"
    """),
            "wf.yml",
        )
    )
    (f,) = found
    assert (f.rule_id, f.line) == ("WG004", 17)
    assert "steps.read.outputs.body" in f.message


def test_a_shell_heredoc_into_github_env_is_wg007_on_the_body_line():
    assert findings("""
    on: issues
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - env:
              BODY: ${{ github.event.issue.body }}
            run: |
              cat <<EOF >> "$GITHUB_ENV"
              ISSUE<<END
              $BODY
              END
              EOF
    """) == [("WG007", 13)]


def test_github_script_payload_into_an_output_then_into_run():
    text = """
    on: pull_request_target
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - id: meta
            uses: actions/github-script@%s
            with:
              script: |
                const title = context.payload.pull_request.title;
                core.setOutput('title', context.payload.pull_request.title);
          - run: echo "${{ steps.meta.outputs.title }}"
    """ % ("a" * 40)
    found = [f for f in check(Workflow.parse(textwrap.dedent(text), "wf.yml")) if f.rule_id == "WG004"]
    (f,) = found
    assert f.line == 14
    assert "'github.event.pull_request.title', which outsiders can set" in f.message


def test_github_script_export_variable_is_wg007_in_the_script():
    text = """
    on: issue_comment
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - uses: actions/github-script@%s
            env:
              COMMENT: ${{ github.event.comment.body }}
            with:
              script: |
                core.info('reading');
                core.exportVariable('C', process.env.COMMENT);
                core.addPath(context.payload['comment']['body']);
    """ % ("a" * 40)
    found = [(f.rule_id, f.line, f.severity) for f in check(Workflow.parse(textwrap.dedent(text), "wf.yml"))]
    assert found == [("WG007", 14, Severity.HIGH), ("WG007", 15, Severity.HIGH)]


def test_clean_multiline_values_stay_clean():
    assert (
        findings("""
    on: push
    permissions: {}
    jobs:
      a:
        runs-on: x
        steps:
          - id: log
            run: |
              {
                echo "changes<<EOF"
                git log --oneline -5
                echo "EOF"
              } >> "$GITHUB_OUTPUT"
          - run: echo "${{ steps.log.outputs.changes }}"
    """)
        == []
    )
