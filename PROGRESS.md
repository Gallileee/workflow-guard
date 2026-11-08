# Progress log

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

1. Use `--fix` on lendloop, fitness-workout-log and GaTe-parking (one PR each), and add the
   missing `permissions:` in GaTe-parking.
2. SARIF output, so findings show up in GitHub code scanning on pull requests.
3. Publish it as a GitHub Action / pre-commit hook.
4. Parse `${{ }}` expressions properly (bracket syntax) instead of regex matching.
