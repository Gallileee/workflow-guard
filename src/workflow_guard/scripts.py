"""Where a step's script text is: ``run:``, and the inputs of actions that run an input as code.

``${{ }}`` in any of these is pasted into the code before it runs (WG004, WG008). Besides
``run:`` and ``actions/github-script``'s ``script``, a few widely used actions take a shell (or
PowerShell, Python) script as an input and run it on the runner, in a container or on a server
over SSH. The table lists them; input names are matched without case, as GitHub does.
Users add their own (in-house actions) with ``--script-input owner/repo:input,input``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
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

_ACTION = re.compile(r"^[A-Za-z0-9_-][\w.-]*/[\w.-]+(?:/[\w./-]+)?$")
_INPUT = re.compile(r"^[A-Za-z_][\w-]*$")


def parse_script_input(text: str) -> tuple[str, tuple[str, ...]]:
    """``owner/repo[/path]:input[,input...]`` -> (action in lower case, inputs in lower case)."""
    action, sep, names = text.strip().partition(":")
    if not sep or not _ACTION.match(action):
        raise ValueError(f"expected owner/repo:input[,input...] (no @version), got {text!r}")
    inputs = tuple(name.strip().lower() for name in names.split(",") if name.strip())
    if not inputs or not all(_INPUT.match(name) for name in inputs):
        raise ValueError(f"expected input names after ':' in {text!r}")
    return action.lower(), inputs


def merge_script_inputs(specs: list[str]) -> dict[str, tuple[str, ...]]:
    """Several ``--script-input`` values; the same action twice adds up its inputs."""
    merged: dict[str, tuple[str, ...]] = {}
    for spec in specs:
        action, inputs = parse_script_input(spec)
        merged[action] = tuple(dict.fromkeys(merged.get(action, ()) + inputs))
    return merged


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


def scripts(step: Step, extra: Mapping[str, tuple[str, ...]] | None = None) -> list[Script]:
    """The step's script texts, in file order: ``run:`` or the action's script inputs.
    ``extra``: the user's own actions and inputs (``--script-input``), added to the table."""
    found = []
    if isinstance(run := get(step.node, "run"), ScalarNode):
        found.append(Script(run, "run"))
    action = action_name(step.uses)
    added = (extra or {}).get(action, ())
    if action == GITHUB_SCRIPT:
        inputs, note, label = ("script", *added), "", ""
    elif action in SCRIPT_INPUTS or added:
        known, note = SCRIPT_INPUTS.get(action, ((), ""))
        inputs, label = (*known, *added), action
    else:
        return found
    for key, value in items(get(step.node, "with")):
        if key.lower() in inputs and isinstance(value, ScalarNode):
            found.append(Script(value, f"with.{key}", label, note))
    return found
