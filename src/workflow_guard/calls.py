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
(``Workflow.input_taints``), where ``Tracker`` reads it. The way back, outputs of the called
file as seen by the caller, is worked out per call by ``Tracker`` itself.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from yaml.nodes import MappingNode, Node

from .project import Project, call_site, file_key
from .taint import Scope, Taint, Tracker
from .workflow import Workflow, get, scalar


@dataclass(frozen=True)
class Call:
    caller: Workflow
    where: str
    """For messages: ``.github/workflows/ci.yml (job 'call')`` or ``...ci.yml:12``."""
    with_node: Node | None
    step: MappingNode | None = None
    """For a step that runs a local action: the step, whose scope its ``with:`` values see.
    None for a job that calls a reusable workflow (no ``env`` or steps there)."""


def local_calls(workflows: Sequence[Workflow], project: Project | None = None) -> dict[str, list[Call]]:
    """For each checked file (by ``file_key``), the jobs and steps of checked files that call it:
    ``jobs.<id>.uses: ./<file>.yml`` for workflows, step ``uses: ./<folder>`` for actions."""
    project = project or Project(workflows)
    calls: dict[str, list[Call]] = {}
    for wf in workflows:
        for job_id, job in wf.jobs():
            if (callee := project.reusable_workflow(wf, scalar(get(job, "uses")))) is not None:
                call = Call(wf, f"{wf.path} (job '{job_id}')", get(job, "with"))
                calls.setdefault(file_key(callee.path), []).append(call)
        for step in wf.steps():
            uses = get(step.node, "uses")
            if (callee := project.local_action(wf, scalar(uses))) is not None:
                call = Call(wf, call_site(wf, uses), get(step.node, "with"), step.node)
                calls.setdefault(file_key(callee.path), []).append(call)
    return calls


def link_local_calls(workflows: Sequence[Workflow]) -> None:
    """Give every checked file the ``Project`` (so trackers can follow outputs of local calls),
    and set ``input_taints`` on every checked reusable workflow or action that a checked file
    calls.

    A caller may itself be called, passing its own inputs on, so callers are linked first. A
    loop of calls (which GitHub rejects) is cut where it closes."""
    project = Project(workflows)
    for wf in workflows:
        wf.project = project
    calls = local_calls(workflows, project)
    done: set[str] = set()
    linking: set[str] = set()

    def link(key: str) -> None:
        if key in done or key in linking or key not in calls:
            return  # no caller among the checked files: input_taints stays None
        linking.add(key)
        taints: dict[str, Taint] = {}
        for call in calls[key]:
            link(file_key(call.caller.path))
            tracker = Tracker(call.caller)
            scope = _scope_of(tracker, call.step)
            for name, taint in tracker.with_taints(call.with_node, scope, call.where).items():
                current = taints.get(name)
                if current is None or taint.severity > current.severity:
                    taints[name] = taint
        project.files[key].input_taints = taints
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
