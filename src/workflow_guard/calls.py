"""Following untrusted values into local reusable workflows (``jobs.<id>.uses: ./...``).

A reusable workflow can't tell who calls it, so on its own ``${{ inputs.title }}`` in a script
is only *possibly* untrusted (WG004 medium). When the caller is checked in the same run, the
answer is known:

    # .github/workflows/ci.yml                 # .github/workflows/greet.yml
    jobs:                                       on:
      greet:                                      workflow_call:
        uses: ./.github/workflows/greet.yml         inputs:
        with:                                         title: {type: string}
          title: ${{ github.event.pull_request.title }}   jobs: ... run: echo "${{ inputs.title }}"

Here ``inputs.title`` carries the pull request title (high). If every local caller passes clean
values, the inputs are clean too. ``link_local_calls`` works this out for all checked files and
stores it on each called workflow (``Workflow.input_taints``), where ``Tracker`` reads it.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from yaml.nodes import Node

from .taint import Taint, Tracker
from .workflow import Workflow, get, items, scalar


@dataclass(frozen=True)
class Call:
    caller: Workflow
    job_id: str
    with_node: Node | None


def repo_root(path: Path) -> Path | None:
    """The repository a workflow file belongs to: ``<root>/.github/workflows/<file>``."""
    folder = path.resolve().parent
    if folder.name == "workflows" and folder.parent.name == ".github":
        return folder.parent.parent
    return None


def _key(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def local_calls(workflows: Sequence[Workflow]) -> dict[str, list[Call]]:
    """For each checked workflow (by resolved path), the jobs of checked workflows that call it."""
    targets = {_key(Path(wf.path)) for wf in workflows if not wf.is_action}
    calls: dict[str, list[Call]] = {}
    for wf in workflows:
        if wf.is_action or (root := repo_root(Path(wf.path))) is None:
            continue
        for job_id, job in wf.jobs():
            uses = scalar(get(job, "uses")) or ""
            if not uses.startswith("./"):
                continue
            target = _key(root / uses[2:])
            if target in targets:
                calls.setdefault(target, []).append(Call(wf, job_id, get(job, "with")))
    return calls


def link_local_calls(workflows: Sequence[Workflow]) -> None:
    """Set ``input_taints`` on every checked reusable workflow that a checked workflow calls.

    A caller may itself be a reusable workflow passing its own inputs on, so callers are
    linked first. A loop of calls (which GitHub rejects) is cut where it closes."""
    calls = local_calls(workflows)
    by_key = {_key(Path(wf.path)): wf for wf in workflows if not wf.is_action}
    done: set[str] = set()
    linking: set[str] = set()

    def link(key: str) -> None:
        if key in done or key in linking or key not in calls:
            return  # no caller among the checked files: input_taints stays None
        linking.add(key)
        taints: dict[str, Taint] = {}
        for call in calls.get(key, []):
            link(_key(Path(call.caller.path)))
            tracker = Tracker(call.caller)
            for name, value in items(call.with_node):
                text = scalar(value)
                if text is None or (taint := tracker.taint_of_value(text)) is None:
                    continue
                taint = taint.through(f"with.{name} in {call.caller.path} (job '{call.job_id}')")
                current = taints.get(name.lower())
                if current is None or taint.severity > current.severity:
                    taints[name.lower()] = taint
        by_key[key].input_taints = taints
        linking.discard(key)
        done.add(key)

    for key in calls:
        link(key)
