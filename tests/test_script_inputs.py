"""Actions that run one of their inputs as a script: WG004 and WG008 look there too."""

import textwrap

import pytest

from workflow_guard.model import Severity
from workflow_guard.rules import check
from workflow_guard.scripts import SCRIPT_INPUTS, action_name, scripts
from workflow_guard.workflow import Workflow

SHA = "a" * 40
TITLE = "${{ github.event.pull_request.title }}"


def findings(text: str, rule: str):
    found = check(Workflow.parse(textwrap.dedent(text), "wf.yml"))
    return [(f.line, f.severity, f.message) for f in found if f.rule_id == rule]


def step(uses: str, *with_lines: str, on: str = "pull_request") -> str:
    body = "\n".join(f"          {line}" for line in with_lines)
    return (
        f"on: {on}\npermissions: {{}}\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        f"      - uses: {uses}\n        with:\n{body}\n"
    )


ALL_INPUTS = [(action, name) for action, (inputs, _) in SCRIPT_INPUTS.items() for name in inputs]


@pytest.mark.parametrize(("action", "name"), ALL_INPUTS)
def test_every_listed_input_is_checked(action, name):
    ((line, severity, message),) = findings(step(f"{action}@{SHA}", f'{name}: echo "{TITLE}"'), "WG004")
    assert (line, severity) == (9, Severity.HIGH)
    assert message.startswith("'github.event.pull_request.title' can be set by outsiders and is pasted")
    assert f"({action} runs its '{name}' input as a script" in message


def test_the_ssh_action_says_how_to_pass_a_variable():
    text = step(
        f"appleboy/ssh-action@{SHA}", "host: example.com", "script: |", f'  cd app && git log -1 "{TITLE}"'
    )
    ((line, _, message),) = findings(text, "WG004")
    assert line == 11
    assert message.endswith(
        "(appleboy/ssh-action runs its 'script' input as a script; on the server, pass it with the"
        " action's 'envs:' input)"
    )


def test_an_action_without_a_note_ends_after_the_action():
    ((_, _, message),) = findings(
        step(f"azure/cli@{SHA}", f"inlineScript: az group show -n {TITLE}"), "WG004"
    )
    assert message.endswith("(azure/cli runs its 'inlineScript' input as a script)")


def test_names_are_matched_without_case():
    text = step(f"Azure/CLI@{SHA}", f"INLINESCRIPT: echo {TITLE}")
    assert len(findings(text, "WG004")) == 1


def test_other_inputs_of_the_same_action_are_data():
    text = step(f"appleboy/ssh-action@{SHA}", f"host: {TITLE}", "script: echo hi")
    assert findings(text, "WG004") == []


def test_unlisted_actions_are_not_checked():
    assert findings(step(f"some/action@{SHA}", f"script: echo {TITLE}"), "WG004") == []


def test_github_script_keeps_its_message():
    ((_, _, message),) = findings(
        step(f"actions/github-script@{SHA}", f"script: console.log('{TITLE}')"), "WG004"
    )
    assert message.endswith("pass it through 'env:' and use the variable instead")


def test_a_detour_through_env_is_followed_into_an_action_input():
    text = step(f"nick-fields/retry@{SHA}", "command: ./notify.sh ${{ env.T }}", "max_attempts: 3")
    text = text.replace("    runs-on: x\n", f"    runs-on: x\n    env:\n      T: {TITLE}\n")
    ((_, severity, message),) = findings(text, "WG004")
    assert severity == Severity.HIGH
    assert "'env.t' carries" in message and "(nick-fields/retry runs its 'command' input" in message


def test_trusted_values_are_fine():
    assert findings(step(f"azure/cli@{SHA}", "inlineScript: echo ${{ github.sha }}"), "WG004") == []


def test_a_secret_pasted_into_an_action_script_is_wg008():
    text = step(f"appleboy/ssh-action@{SHA}", "script: deploy --token ${{ secrets.DEPLOY_TOKEN }}", on="push")
    ((line, severity, message),) = findings(text, "WG008")
    assert (line, severity) == (9, Severity.MEDIUM)
    assert message.startswith("'secrets.deploy_token' is pasted into the script text")
    assert message.endswith(
        "(appleboy/ssh-action runs its 'script' input as a script; on the server, pass it"
        " with the action's 'envs:' input)"
    )


def test_a_secret_in_an_ordinary_input_is_fine():
    text = step(f"appleboy/ssh-action@{SHA}", "key: ${{ secrets.SSH_KEY }}", "script: ./deploy.sh", on="push")
    assert findings(text, "WG008") == []


def test_inline_ignore():
    text = step(f"azure/cli@{SHA}", f"inlineScript: echo {TITLE}  # workflow-guard: ignore[WG004]")
    assert findings(text, "WG004") == []


@pytest.mark.parametrize(
    ("uses", "name"),
    [
        ("appleboy/ssh-action@v1", "appleboy/ssh-action"),
        ("Azure/CLI@" + SHA, "azure/cli"),
        ("./local-action", ""),
        ("docker://alpine:3", ""),
        ("docker://alpine@sha256:" + "0" * 64, ""),
        (None, ""),
        ("no-ref", ""),
    ],
)
def test_action_name(uses, name):
    assert action_name(uses) == name


def test_scripts_lists_run_and_inputs_in_order():
    wf = Workflow.parse(
        step(f"cypress-io/github-action@{SHA}", "build: npm run build", "browser: chrome", "start: npm start")
    )
    (st,) = wf.steps()
    assert [s.where for s in scripts(st)] == ["with.build", "with.start"]
