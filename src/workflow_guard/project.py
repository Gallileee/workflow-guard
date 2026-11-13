"""The set of files checked together, and which local file a ``uses: ./...`` points to.

A job's ``uses: ./.github/workflows/x.yml`` runs a reusable workflow; a step's ``uses: ./dir``
runs the action in ``dir/action.yml`` (or ``action.yaml``). Paths are relative to the
repository root, the folder that holds ``.github``.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from yaml.nodes import Node

from .workflow import ACTION_FILES, Workflow


def repo_root(path: Path) -> Path | None:
    """The repository a file belongs to: the folder holding its ``.github``
    (``<root>/.github/workflows/ci.yml``, ``<root>/.github/actions/x/action.yml``)."""
    for folder in path.resolve().parents:
        if folder.name == ".github":
            return folder.parent
    return None


def file_key(path: str | Path) -> str:
    """A file's identity: its resolved path, case-folded where the file system ignores case."""
    return os.path.normcase(str(Path(path).resolve()))


def call_site(wf: Workflow, uses: Node | None) -> str:
    """``file:line`` of a step's ``uses:``, for messages."""
    return f"{wf.path}:{uses.start_mark.line + 1}" if uses is not None else wf.path


class Project:
    def __init__(self, workflows: Sequence[Workflow]) -> None:
        self.files = {file_key(wf.path): wf for wf in workflows}

    def reusable_workflow(self, caller: Workflow, uses: str | None) -> Workflow | None:
        """The checked workflow a job's ``uses: ./...yml`` runs, if any."""
        if not uses or not uses.startswith("./") or (root := repo_root(Path(caller.path))) is None:
            return None
        callee = self.files.get(file_key(root / uses[2:]))
        return callee if callee is not None and not callee.is_action else None

    def local_action(self, caller: Workflow, uses: str | None) -> Workflow | None:
        """The checked action a step's ``uses: ./dir`` runs, if any."""
        if not uses or not uses.startswith("./") or uses.endswith((".yml", ".yaml")):
            return None
        if (root := repo_root(Path(caller.path))) is None:
            return None
        for name in ACTION_FILES:
            callee = self.files.get(file_key(root / uses[2:] / name))
            if callee is not None and callee.is_action:
                return callee
        return None
