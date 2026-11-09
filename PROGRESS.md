# Progress log

## 2026-11-09 (interactive): Milestone 5, composite and Docker actions

Why: next step 3, picked by the owner after the v0.4.0 action went into lendloop (#23) and
fitness-workout-log (#37), both merged. Composite actions run shell steps exactly like workflows,
with the same mistakes, and this repository's own `action.yml` was only checked by a test.

Acceptance criteria:
- A file with `runs:` is read as an action; one with neither `jobs:` nor `runs:` is an error.
- Composite steps get WG001, WG004, WG006; a Docker action's `docker://` image gets WG001.
- `${{ inputs.* }}` inside `run:` of an action is WG004 (medium), but not in a workflow.
- Without arguments, `action.yml` at the root and `.github/actions/**/action.yml` are checked too,
  so CI's dogfooding step now covers this repository's own action. `--fix` works on actions.
- The pre-commit hook runs on those files as well.

Done:
- `Workflow.kind` (`workflow` / `action`), `is_action`. `steps()` reads `runs.steps` for actions
  (job id `(action)`); `uses_nodes()` adds `runs.image` when it starts with `docker://`. The rules
  needed no other change: WG002/3/5 find no jobs or triggers in an action, so they stay quiet.
- WG004: `inputs.<name>` in a composite action's `run:`/github-script is medium; outsider
  contexts stay high. Rule summary and help updated.
- CLI: `default_paths()`. Pre-commit `files` pattern extended.
- Tests: `test_actions.py` (17, incl. discovery, --fix and the hook pattern). 110 in total.
  Version 0.5.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 110 passed. `ruff check`, `ruff format --check`: clean.
- `workflow-guard` in this repository: 0 findings in 2 files (ci.yml and its own action.yml).
- A copy of `action.yml` with `${{ inputs.paths }}` pasted into `run:` and setup-python on `@v7`:
  WG004 (medium) on the `run:` line and WG001 on the `uses:` line; the same input in `env:` is
  not reported.
- lendloop, fitness-workout-log and GaTe-parking: same results as before (no local actions there).

## 2026-11-09 (scheduled run): Milestone 4, GitHub Action, pre-commit hook and annotations

Why: next step 2. Until now another repository had to `pip install git+...` and write the
upload steps itself; now it is one `uses:` line or three lines of `.pre-commit-config.yaml`.
Next step 1 was checked first: the code-scanning API shows the `main` analysis from 2026-11-08
(6 rules, 0 results) and 0 alerts, as expected.

Acceptance criteria:
- `uses: Gallileee/workflow-guard@<ref>` checks `.github/workflows` and fails the step on findings,
  with every CLI option available as an input.
- Findings appear as annotations without code scanning (works in private repositories).
- The action doesn't change the caller's Python and can't be tricked by its inputs.
- A pre-commit hook that only runs on workflow files.
- CI runs the action itself, on Linux and Windows.

Done:
- `annotations.py` + `--format github`: one `::error`/`::warning`/`::notice` workflow command per
  finding (by severity), with `file`, `line`, `col` and `title` (`WG004 template-injection`).
  Percent-encoding as the runner expects (`%`, CR, LF; in properties also `:` and `,`), so a
  newline in a file name or value can't start a second command such as `::add-mask::`.
  Unreadable files become `::error` annotations on the file.
- `action.yml` (composite): `actions/setup-python` pinned to a SHA with
  `update-environment: false`, a venv in `$RUNNER_TEMP` with the action's own checkout installed,
  inputs passed via `env:` only, `set -f` so `*` in `paths` isn't expanded, and `--` before the
  paths. Inputs: paths, format (default `github`), output, fail-on, min-severity, ignore,
  python-version.
- `.pre-commit-hooks.yaml`: `language: python`, `files: ^\.github/workflows/[^/]+\.ya?ml$`.
- CI: an `action` job (ubuntu-latest, windows-latest) with `uses: ./`: the repository passes, the
  unsafe fixture (`tests/fixtures/unsafe-workflow.yml`) fails with WG004 in the JSON, and
  `ignore: WG004` + `fail-on: high` passes.
- Tests: `test_annotations.py` (8), `test_distribution.py` (7: action inputs documented and used,
  no `${{` in `run:`, actions pinned, `--` present, hook entry and file pattern). 93 in total.
  Version 0.4.0.

Verified locally (Python 3.14 venv, Git Bash):
- `pytest -q -W error`: 93 passed. `ruff check`, `ruff format --check`: clean.
- The action's two bash steps, run with fake runner variables (`RUNNER_OS=Windows`,
  `RUNNER_TEMP`, `GITHUB_OUTPUT`, `GITHUB_ACTION_PATH`) and `py -3.14` standing in for
  setup-python: install OK; default paths exit 0; the fixture exit 1 with 4 annotations; two paths
  on separate lines with `ignore`/`fail-on` exit 0; `paths: --fix` is treated as a missing file
  (exit 2), and `paths: tests/fixtures/*.yml` isn't globbed (exit 2).
- `workflow-guard` on its own changed workflow: 0 findings.

Not verified locally: the `action` job on real runners (Linux and Windows) and setup-python's
`python-path` output; see the PR's checks.

Pre-commit, checked with `pre-commit try-repo <this repo> workflow-guard --all-files`
(pre-commit 4 in a scratch venv): lendloop passed; a scratch repository with the unsafe fixture
as `.github/workflows/bad.yml` and a `.github/dependabot.yml` failed with the 4 findings, and only
1 file was checked, so the `files` pattern works.

## 2026-11-08 (scheduled run): Milestone 3, SARIF output for GitHub code scanning

Why: next step 2. Step 1 (running `--fix` on the three repositories) was done earlier the same
day (lendloop #18, fitness-workout-log #32, GaTe-parking #34). SARIF is what turns the checker from
"a CLI you remember to run" into alerts on the Security tab and annotations on pull requests.

Acceptance criteria:
- `--format sarif` produces SARIF 2.1.0 that validates against the OASIS schema.
- Every rule has the texts code scanning requires; every result has rule, level, location and a
  fingerprint that survives lines moving.
- Files that can't be parsed show up in the report.
- `--output FILE` writes UTF-8 (PowerShell's `>` writes UTF-16).
- This repository's CI uploads its own results.

Done:
- `sarif.py`: `to_sarif(findings, errors)`. Severity -> `level` per result (high=error,
  medium=warning, low=note); no `security-severity`, since GitHub reads it per rule and WG001/WG005
  vary per finding. `partialFingerprints["workflowGuard/v1"]` = SHA-256 of rule, path, message and
  occurrence number (no line). Relative paths get `uriBaseId: %SRCROOT%` and are percent-encoded;
  absolute ones become `file:` URIs (built by hand, `PurePath.as_uri()` is deprecated in 3.14).
  Unreadable files become `toolExecutionNotifications` and `executionSuccessful: false`.
- `Rule.help`: a "why and how to fix" text per rule, used as the SARIF `help`.
- CLI: `--format sarif`, `--output FILE` (all formats; exit 2 if it can't be written). Output
  formatting moved into `_report`.
- CI: a `code-scanning` job (push and same-repository PRs only; fork PRs get a read-only token)
  that uploads with `github/codeql-action/upload-sarif`, pinned to the v4.39.3 SHA.
- `fix.py`: an `HTTPError` is now closed after reading it (found with `pytest -W error`:
  `ResourceWarning: Implicitly cleaning up <HTTPError ...>`).
- Tests: `test_sarif.py` (17). 78 in total. Version 0.3.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 78 passed. `ruff check`, `ruff format --check`: clean.
- SARIF for GaTe-parking (30 findings), for a run with a broken file, and for this repository
  validated against the OASIS `sarif-schema-2.1.0.json` with `jsonschema` (Draft 4): 0 errors.
  `jsonschema` was installed in the venv only for that check; it isn't a dependency.
- `workflow-guard` on its own (changed) workflow: 0 findings.

Not verified locally: the upload itself. It only runs on GitHub; check the PR's `code-scanning`
job and the Security tab after merge.

## 2026-11-08: Milestone 2, `--fix` pins actions to commit SHAs

Why: next step 1, picked by the owner. WG001 was the most common finding in every repository,
and fixing it by hand means looking up 40-character SHAs one by one.

Done:
- `fix.py`:
  - `GitHubResolver`: `GET /repos/{repo}/commits/{ref}` with `Accept: application/vnd.github.sha`
    (the bare SHA for branches and tags, annotated tags included), urllib only, an optional
    token from `GITHUB_TOKEN`/`GH_TOKEN`, a per-run cache, and clear errors: not found
    (404/422), refused or rate-limited (401/403/429, with GitHub's message), server errors,
    no connection, and anything that isn't a SHA.
  - `pin_actions`: edits the text at the YAML node's character offsets, so the rest of the file
    stays byte for byte (quotes, comments, `\r\n`). Adds `  # v4`, or `# v4; ` in front of an
    existing comment. Skips ignored lines, local/Docker/version-less uses, and the comment when
    two uses share one line (flow style).
  - Owner and repo must match GitHub's name characters before they go into a URL; the ref is
    percent-encoded (`feature/x` -> `feature%2Fx`).
- `Workflow.uses_nodes()`: shared by WG001 and `--fix`, so both see the same places.
- CLI: `--fix` reads and writes with `newline=""`, prints what it pinned or couldn't, then
  checks the fixed text. `--ignore WG001` turns it off.
- Tests: `test_fix.py` (17), with a real `http.server` on localhost standing in for the API.
  61 in total.

Verified locally:
- `pytest -q`: 61 passed; ruff clean.
- Mutation check: without the `\r` handling, the Windows line-ending test fails.
- Real run against api.github.com on *copies* of the workflows of lendloop, fitness-workout-log
  and GaTe-parking (token from `gh auth token`): 26 actions pinned, 0 failures. A diff against
  the originals changes exactly one line per `uses:`, nothing else. The SHA for
  `actions/checkout@v7` matched a separate `gh api` lookup. The repositories themselves weren't
  changed.

Found on the way: anonymous requests to api.github.com from this machine got `504` HTML error
pages while authenticated `gh api` calls worked, hence the explicit "GitHub API error 5xx, try
again later" message and the token support.

## 2026-11-08: Milestone 1, the checker (MVP)

Why this project: the portfolio had Java (lendloop) and JavaScript (fitness-workout-log) but no
Python of its own, and no developer tool. Every repository uses GitHub Actions, and the common
mistakes there are well documented, so the rules have clear right answers and real test data.

Done:
- `workflow.py`: workflows loaded as PyYAML nodes (line/column for every value; `on` stays a
  string), helpers for jobs, steps and triggers, and `# workflow-guard: ignore[...]` comments.
- `rules.py`: WG001 unpinned actions (severity by owner; Docker tags; reusable workflows),
  WG002 missing permissions, WG003 write-all, WG004 template injection in `run:` and
  github-script (reports the expression's own line inside `run: |`), WG005 pull_request_target
  (high with a PR-head checkout), WG006 persisted checkout credentials.
- `cli.py`: files and directories, text or JSON, `--ignore`, `--min-severity`, `--fail-on`,
  `--list-rules`, exit codes 0/1/2.
- CI on Python 3.10/3.12/3.14 that also runs the tool on its own workflow (pinned to SHAs).
- Tests: 44 (pytest).

Verified locally (Python 3.14 venv):
- `pytest -q`: 44 passed. `ruff check` and `ruff format --check`: clean.
- Mutation check: without the "+1 line for block scalars" fix, a WG004 line test fails.
- Ran it on three local repositories. It found:
  - lendloop: only low findings (pinning, persisted credentials).
  - fitness-workout-log: no `permissions:` in either workflow (medium).
  - GaTe-parking: missing permissions in two workflows and third-party Docker actions on tags.

Found while building: YAML can't hold `run: echo "x: y"` as a plain scalar (the `: ` starts a
mapping), so one test needed quoting. PyYAML's error is the same one GitHub would show.

Environment note: the scoop-installed Python 3.12 can't create a venv on this machine (missing
`venvlauncher.exe`); `py -3.14 -m venv .venv` works.

## Next steps (in order)

1. Tag `v0.5.0` after the merge; Dependabot then offers the update in lendloop and
   fitness-workout-log (their `# v0.4.0` pins).
2. Parse `${{ }}` expressions properly (bracket syntax) instead of regex matching.
3. `--fix`: match the file's comment style (one space before `# v7` where Prettier wants it).
4. A GitHub Release with notes, and later the Marketplace listing.
