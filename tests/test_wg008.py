"""WG008: secrets pasted into scripts, toJSON(secrets), secrets: inherit to another repository."""

import textwrap

import pytest

from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.workflow import Workflow

SHA = "a" * 40


def wg008(text: str):
    found = check(Workflow.parse(textwrap.dedent(text), "wf.yml"))
    return [(f.line, f.severity, f.message) for f in found if f.rule_id == "WG008"]


def steps(*lines: str) -> str:
    body = "\n".join(f"      {line}" for line in lines)
    return f"on: push\npermissions: {{}}\njobs:\n  a:\n    runs-on: x\n    steps:\n{body}\n"


# --- secrets in scripts --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "expr",
    [
        "secrets.DEPLOY_KEY",
        "secrets['DEPLOY_KEY']",
        "SECRETS.deploy_key",
        "format('{0}', secrets.DEPLOY_KEY)",
    ],
)
def test_a_secret_pasted_into_run(expr):
    ((line, severity, message),) = wg008(steps(f'- run: ./deploy "${{{{ {expr} }}}}"'))
    assert (line, severity) == (7, Severity.MEDIUM)
    assert message.startswith("'secrets.deploy_key' is pasted into the script text")


def test_the_line_inside_a_block_script():
    text = steps("- run: |", "    echo start", '    curl -H "Authorization: ${{ secrets.TOKEN }}" x')
    assert [line for line, _, _ in wg008(text)] == [9]


def test_a_computed_secret_name():
    ((_, _, message),) = wg008(steps('- run: echo "${{ secrets[matrix.name] }}"'))
    assert message.startswith("'secrets[...]' is pasted")


def test_github_script():
    text = steps(
        f"- uses: actions/github-script@{SHA}",
        "  with:",
        "    script: |",
        "      const t = '${{ secrets.NPM_TOKEN }}';",
    )
    assert [line for line, _, _ in wg008(text)] == [10]


@pytest.mark.parametrize(
    "lines",
    [
        # The recommended way: env: and a shell variable.
        ("- env:", "    TOKEN: ${{ secrets.TOKEN }}", '  run: ./deploy "$TOKEN"'),
        # Inputs of other actions are how secrets are meant to be passed.
        (f"- uses: some-org/deploy@{SHA}", "  with:", "    token: ${{ secrets.TOKEN }}"),
        # Only the text matters, not a string that mentions secrets.
        ("- run: echo \"${{ 'secrets.TOKEN' }}\"",),
        ('- run: echo "${{ github.sha }}"',),
    ],
)
def test_fine(lines):
    assert wg008(steps(*lines)) == []


# --- toJSON(secrets) -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lines", "line"),
    [
        (("- env:", "    ALL: ${{ toJSON(secrets) }}", "  run: ./x"), 8),
        (("- run: echo '${{ toJSON(secrets) }}' > s.json",), 7),
        ((f"- uses: some-org/x@{SHA}", "  with:", "    all: ${{ toJson(secrets) }}"), 9),
    ],
)
def test_tojson_secrets_anywhere(lines, line):
    ((found_line, severity, message),) = wg008(steps(*lines))
    assert (found_line, severity) == (line, Severity.HIGH)
    assert message.startswith("toJSON(secrets) puts every secret")


def test_tojson_of_one_secret_is_the_script_case():
    ((_, severity, _),) = wg008(steps('- run: echo "${{ toJSON(secrets.X) }}"'))
    assert severity == Severity.MEDIUM


# --- secrets: inherit ----------------------------------------------------------------------------

CALLS = f"""
on: push
permissions: {{}}
jobs:
  remote:
    uses: some-org/shared/.github/workflows/deploy.yml@{SHA}
    secrets: inherit
  local:
    uses: ./.github/workflows/build.yml
    secrets: inherit
  listed:
    uses: some-org/shared/.github/workflows/deploy.yml@{SHA}
    secrets:
      token: ${{{{ secrets.TOKEN }}}}
"""


def test_secrets_inherit_only_for_other_repositories():
    ((line, severity, message),) = wg008(CALLS)
    assert (line, severity) == (7, Severity.MEDIUM)
    assert message.startswith("job 'remote' passes all of this repository's secrets ('secrets: inherit')")


def test_inline_ignore():
    assert wg008(steps('- run: ./deploy "${{ secrets.KEY }}"  # workflow-guard: ignore[WG008]')) == []


def test_actions_are_checked_too():
    text = """
    runs:
      using: composite
      steps:
        - shell: bash
          run: echo "${{ secrets.X }}"
    """
    # Composite actions can't read secrets (the caller has to pass them as inputs), but pasting
    # them is still the same mistake if someone tries.
    assert len(wg008(text)) == 1
