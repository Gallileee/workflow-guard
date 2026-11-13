"""Following untrusted values into local reusable workflows and local actions.

A reusable workflow (``on: workflow_call``) or a composite action can't tell who calls it, so on
its own ``${{ inputs.title }}`` in a script is only *possibly* untrusted (WG004 medium). When
the caller is checked in the same run, the answer is known:

    # .github/workflows/ci.yml                 # .github/workflows/greet.yml
    jobs:                                       on:
      greet:                                      workflow_call:
        uses: ./.github/workflows/greet.yml         inputs:
        with:                                         title: {type: string}
          title: ${{ github.event.pull_request.title }}   jobs: ... run: echo "${{ inputs.title }}"

Here ``inputs.title`` carries the pull request title (high). If every local caller passes clean
values, the inputs are clean too. The same goes for a step that runs a local action
(``uses: ./.github/actions/greet``), whose ``with:`` values can also read ``env`` and step
outputs at that point of the job.

``link_local_calls`` works this out for all checked files and stores it on each called file
(``Workflow.input_taints``), where ``Tracker`` reads it.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from yaml.nodes import MappingNode, Node

from .taint import Scope, Taint, Tracker
from .workflow import ACTION_FILES, Workflow, get, items, scalar


@dataclass(frozen=True)
class Call:
    caller: Workflow
    where: str
    """For messages: ``.github/workflows/ci.yml (job 'call')`` or ``...ci.yml:12``."""
    with_node: Node | None
    step: MappingNode | None = None
    """For a step that runs a local action: the step, whose scope its ``with:`` values see.
    None for a job that calls a reusable workflow (no ``env`` or steps there)."""


def repo_root(path: Path) -> Path | None:
    """The repository a file belongs to: the folder holding its ``.github``
    (``<root>/.github/workflows/ci.yml``, ``<root>/.github/actions/x/action.yml``)."""
    resolved = path.resolve()
    for folder in resolved.parents:
        if folder.name == ".github":
            return folder.parent
    return None


def _key(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def local_calls(workflows: Sequence[Workflow]) -> dict[str, list[Call]]:
    """For each checked file (by resolved path), the jobs and steps of checked files that call it:
    ``jobs.<id>.uses: ./<file>.yml`` for workflows, step ``uses: ./<folder>`` for actions."""
    targets = {_key(Path(wf.path)) for wf in workflows}
    calls: dict[str, list[Call]] = {}

    def add(target: Path, call: Call) -> None:
        if (key := _key(target)) in targets:
            calls.setdefault(key, []).append(call)

    for wf in workflows:
        if (root := repo_root(Path(wf.path))) is None:
            continue
        for job_id, job in wf.jobs():
            uses = scalar(get(job, "uses")) or ""
            if uses.startswith("./"):
                add(root / uses[2:], Call(wf, f"{wf.path} (job '{job_id}')", get(job, "with")))
        for step in wf.steps():
            uses_node = get(step.node, "uses")
            uses = scalar(uses_node) or ""
            if not uses.startswith("./") or uses.endswith((".yml", ".yaml")):
                continue
            where = f"{wf.path}:{uses_node.start_mark.line + 1}" if uses_node is not None else wf.path
            for name in ACTION_FILES:
                add(root / uses[2:] / name, Call(wf, where, get(step.node, "with"), step.node))
    return calls


def link_local_calls(workflows: Sequence[Workflow]) -> None:
    """Set ``input_taints`` on every checked reusable workflow or action that a checked file
    calls.

    A caller may itself be called, passing its own inputs on, so callers are linked first. A
    loop of calls (which GitHub rejects) is cut where it closes."""
    calls = local_calls(workflows)
    by_key = {_key(Path(wf.path)): wf for wf in workflows}
    done: set[str] = set()
    linking: set[str] = set()

    def link(key: str) -> None:
        if key in done or key in linking or key not in calls:
            return  # no caller among the checked files: input_taints stays None
        linking.add(key)
        taints: dict[str, Taint] = {}
        for call in calls[key]:
            link(_key(Path(call.caller.path)))
            tracker = Tracker(call.caller)
            scope = _scope_of(tracker, call.step)
            for name, value in items(call.with_node):
                text = scalar(value)
                if text is None or (taint := tracker.taint_of_value(text, scope)) is None:
                    continue
                taint = taint.through(f"with.{name} in {call.where}")
                current = taints.get(name.lower())
                if current is None or taint.severity > current.severity:
                    taints[name.lower()] = taint
        by_key[key].input_taints = taints
        linking.discard(key)
        done.add(key)

    for key in calls:
        link(key)


def _scope_of(tracker: Tracker, step: MappingNode | None) -> Scope:
    """What is tainted while ``step`` runs (its own ``env:`` included); empty for a job call."""
    if step is not None:
        for tracked in tracker.steps():
            if tracked.step.node is step:
                return tracked.scope
    return Scope()
