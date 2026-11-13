"""Where a step's script text is: ``run:``, and the inputs of actions that run an input as code.

``${{ }}`` in any of these is pasted into the code before it runs (WG004, WG008). Besides
``run:`` and ``actions/github-script``'s ``script``, a few widely used actions take a shell (or
PowerShell, Python) script as an input and run it on the runner, in a container or on a server
over SSH. The table lists them; input names are matched without case, as GitHub does.
"""

from __future__ import annotations

from dataclasses import dataclass

from yaml.nodes import ScalarNode

from .workflow import Step, get, items

_NO_ENV_ON_SERVER = "the step's env: doesn't reach the server by itself"

# action (owner/repo, lower case) -> (inputs that run as code, how to get a variable there)
SCRIPT_INPUTS: dict[str, tuple[tuple[str, ...], str]] = {
    "appleboy/ssh-action": (("script",), "on the server, pass it with the action's 'envs:' input"),
    "garygrossgarten/github-action-ssh": (("command",), _NO_ENV_ON_SERVER),
    "google-github-actions/ssh-compute": (("command",), _NO_ENV_ON_SERVER),
    "addnab/docker-run-action": (("run",), "pass it into the container with 'options: -e NAME'"),
    "uraimo/run-on-arch-action": (
        ("run", "install", "setup"),
        "pass it into the container with the action's 'env:' input",
    ),
    "nick-fields/retry": (("command", "on_retry_command", "new_command_on_retry"), ""),
    "nick-invision/retry": (("command", "on_retry_command", "new_command_on_retry"), ""),
    "wandalen/wretry.action": (("command",), ""),
    "azure/cli": (("inlinescript",), ""),
    "azure/powershell": (("inlinescript",), ""),
    "cypress-io/github-action": (("build", "start", "command", "install-command"), ""),
    "mathiasvr/command-output": (("run",), ""),
    "jannekem/run-python-script-action": (("script",), ""),
}
GITHUB_SCRIPT = "actions/github-script"


@dataclass(frozen=True)
class Script:
    node: ScalarNode
    where: str
    """``run`` or ``with.<input>``."""
    action: str = ""
    """For an action's input from SCRIPT_INPUTS: the action (``appleboy/ssh-action``)."""
    note: str = ""
    """How to get a variable to where that script runs, if ``env:`` alone doesn't."""

    def hint(self) -> str:
        """The end of a message for a value pasted into this script."""
        if not self.action:
            return ""
        input_name = self.where.removeprefix("with.")
        note = f"; {self.note}" if self.note else ""
        return f" ({self.action} runs its '{input_name}' input as a script{note})"


def action_name(uses: str | None) -> str:
    """``owner/repo`` (lower case) of a step's ``uses: owner/repo@ref``; "" for local and Docker."""
    if not uses or "@" not in uses or uses.startswith(("./", "docker://")):
        return ""
    return uses.split("@", 1)[0].lower()


def scripts(step: Step) -> list[Script]:
    """The step's script texts, in file order: ``run:`` or the action's script inputs."""
    found = []
    if isinstance(run := get(step.node, "run"), ScalarNode):
        found.append(Script(run, "run"))
    action = action_name(step.uses)
    if action == GITHUB_SCRIPT:
        inputs, note, label = ("script",), "", ""
    elif action in SCRIPT_INPUTS:
        (inputs, note), label = SCRIPT_INPUTS[action], action
    else:
        return found
    for key, value in items(get(step.node, "with")):
        if key.lower() in inputs and isinstance(value, ScalarNode):
            found.append(Script(value, f"with.{key}", label, note))
    return found
