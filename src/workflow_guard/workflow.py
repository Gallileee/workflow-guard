"""Loading a workflow file as YAML *nodes*, so every value keeps its line and column.

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
    """The file isn't readable YAML, or isn't shaped like a workflow at all."""


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
            raise WorkflowError("not a workflow (the top level must be a mapping)")
        if get(root, "jobs") is None:
            raise WorkflowError("not a workflow (no 'jobs')")
        return cls(path, root, text.splitlines())

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
        for job_id, job in self.jobs():
            seq = get(job, "steps")
            if isinstance(seq, SequenceNode):
                for step in seq.value:
                    if isinstance(step, MappingNode):
                        yield Step(job_id, step)

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
