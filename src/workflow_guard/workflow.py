"""Loading a workflow or action file as YAML *nodes*, so every value keeps its line and column.

Two kinds of file are understood: workflows (``.github/workflows/*.yml``, with ``jobs:``) and
action metadata (``action.yml``, with ``runs:``). For a composite action the steps under
``runs.steps`` are checked like a job's steps; a Docker action's ``runs.image`` like a ``uses:``.

Working on nodes instead of ``yaml.safe_load`` output has a second benefit: YAML 1.1 reads the
key ``on`` as the boolean ``True``. Node keys stay the plain string ``"on"``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


class WorkflowError(Exception):
    """The file isn't readable YAML, or isn't shaped like a workflow or an action at all."""


WORKFLOW = "workflow"
ACTION = "action"
ACTION_JOB = "(action)"
"""The job id given to the steps of a composite action, which has no jobs."""


def get(node: Node | None, key: str) -> Node | None:
    """The value for ``key`` in a mapping node, or None (also when ``node`` isn't a mapping)."""
    if not isinstance(node, MappingNode):
        return None
    for k, v in node.value:
        if isinstance(k, ScalarNode) and k.value == key:
            return v
    return None


def key_node(node: Node | None, key: str) -> Node | None:
    """The key node itself, for reporting the line of ``permissions:`` rather than its value."""
    if not isinstance(node, MappingNode):
        return None
    for k, _ in node.value:
        if isinstance(k, ScalarNode) and k.value == key:
            return k
    return None


def scalar(node: Node | None) -> str | None:
    return node.value if isinstance(node, ScalarNode) else None


def items(node: Node | None) -> Iterator[tuple[str, Node]]:
    """Key/value pairs of a mapping node with string keys."""
    if isinstance(node, MappingNode):
        for k, v in node.value:
            if isinstance(k, ScalarNode):
                yield k.value, v


@dataclass(frozen=True)
class Step:
    job_id: str
    node: MappingNode

    @property
    def uses(self) -> str | None:
        return scalar(get(self.node, "uses"))

    def with_value(self, key: str) -> str | None:
        return scalar(get(get(self.node, "with"), key))


@dataclass
class Workflow:
    path: str
    root: MappingNode
    lines: list[str]
    kind: str = WORKFLOW
    """``WORKFLOW`` or ``ACTION``."""

    @classmethod
    def load(cls, path: Path, display_path: str | None = None) -> Workflow:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            raise WorkflowError(f"cannot read: {e}") from e
        return cls.parse(text, display_path or str(path))

    @classmethod
    def parse(cls, text: str, path: str = "<string>") -> Workflow:
        try:
            root = yaml.compose(text, Loader=yaml.SafeLoader)
        except yaml.YAMLError as e:
            raise WorkflowError(f"not valid YAML: {e}") from e
        if not isinstance(root, MappingNode):
            raise WorkflowError("not a workflow or action (the top level must be a mapping)")
        if get(root, "jobs") is not None:
            kind = WORKFLOW
        elif isinstance(get(root, "runs"), MappingNode):
            kind = ACTION
        else:
            raise WorkflowError("not a workflow or action (no 'jobs' or 'runs')")
        return cls(path, root, text.splitlines(), kind)

    @property
    def is_action(self) -> bool:
        return self.kind == ACTION

    # --- structure -------------------------------------------------------------------------

    def triggers(self) -> set[str]:
        """Event names under ``on:``, whether written as a string, a list or a mapping."""
        on = get(self.root, "on")
        if isinstance(on, ScalarNode):
            return {on.value}
        if isinstance(on, SequenceNode):
            return {n.value for n in on.value if isinstance(n, ScalarNode)}
        return {name for name, _ in items(on)}

    def jobs(self) -> Iterator[tuple[str, MappingNode]]:
        for job_id, job in items(get(self.root, "jobs")):
            if isinstance(job, MappingNode):
                yield job_id, job

    def steps(self) -> Iterator[Step]:
        """Steps of every job, or of a composite action (``runs.steps``)."""
        if self.is_action:
            yield from self._step_list(ACTION_JOB, get(get(self.root, "runs"), "steps"))
            return
        for job_id, job in self.jobs():
            yield from self._step_list(job_id, get(job, "steps"))

    @staticmethod
    def _step_list(job_id: str, seq: Node | None) -> Iterator[Step]:
        if isinstance(seq, SequenceNode):
            for step in seq.value:
                if isinstance(step, MappingNode):
                    yield Step(job_id, step)

    def uses_nodes(self) -> Iterator[Node]:
        """Every ``uses:`` value: reusable workflow calls (``jobs.<id>.uses``) and steps, plus
        a Docker action's ``runs.image`` when it names a registry image (``docker://...``)."""
        for _job_id, job in self.jobs():
            if (uses := get(job, "uses")) is not None:
                yield uses
        for step in self.steps():
            if (uses := get(step.node, "uses")) is not None:
                yield uses
        if self.is_action:
            image = get(get(self.root, "runs"), "image")
            if (scalar(image) or "").startswith("docker://"):
                yield image

    # --- suppression -----------------------------------------------------------------------

    def is_ignored(self, line: int, rule_id: str) -> bool:
        """True if line ``line`` (1-based) carries ``# workflow-guard: ignore[RULE,...]``."""
        if not 1 <= line <= len(self.lines):
            return False
        text = self.lines[line - 1]
        marker = "workflow-guard: ignore["
        start = text.find(marker)
        if start == -1 or "#" not in text[:start]:
            return False
        end = text.find("]", start)
        ids = text[start + len(marker) : end if end != -1 else None]
        return rule_id in {part.strip() for part in ids.split(",")}
