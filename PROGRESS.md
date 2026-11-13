# Progress log

## 2026-11-13 (interactive): Milestone 14, outputs back to the caller

Why: next step 2, picked by the owner ("Outputs to callers"). Milestones 12 and 13 followed
untrusted text *into* local reusable workflows and actions. The way back was still blind: an
action that reads the PR title and returns it as an output, or a reusable workflow that hands
an input back through `on.workflow_call.outputs`, made the caller's `${{ steps.x.outputs.y }}`
or `${{ needs.call.outputs.y }}` look clean.

Acceptance criteria:
- After a step with an `id` running a local action: `steps.<id>.outputs.<name>` carries the
  taint of the action's `outputs.<name>.value` (step outputs, env, inputs inside the action).
- After a job calling a local reusable workflow: `needs.<job>.outputs.<name>` carries the taint
  of `on.workflow_call.outputs.<name>.value`, with `jobs.<id>.outputs.*` understood there.
- Each call uses its own `with:` values (context-sensitive), not the merge of all callers.
- Loops of calls terminate; the message names the callee's output; WG007 sees outputs too.
- No change in findings on the five local repositories.

Done:
- `project.py` (new): `Project` (the files checked together) resolves `uses: ./...` for jobs
  and steps; `repo_root`, `file_key` and `call_site` moved here from `calls.py`.
- `taint.py`: `Tracker(wf, inputs, stack)` with per-call inputs and a stack of files being
  walked; `outputs()`, `with_taints()`, `_called_outputs`, `_apply_action_outputs`; the
  action walk is cached; `jobs.<id>.outputs.*` resolves like `needs`.
- `calls.py`: uses `Project`; `link_local_calls` also sets `Workflow.project`, so every
  tracker (rules included) can follow local calls.
- Tests: `test_call_outputs.py` (12). 292 in total. Version 0.14.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 292 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks: using the merged inputs instead of each call's own fails 2 tests; dropping
  the loop guard fails 1 (recursion); not resolving `jobs.*` in workflow_call outputs fails 1.
- Demo: `label.yml` (pull_request_target) runs `./.github/actions/pr-meta`, which puts the PR
  title in an output; `echo "${{ steps.meta.outputs.title }}"` is high, the message going
  through `outputs.title of .github/actions/pr-meta/action.yml`.
- JSON output for workflow-guard, lendloop, fitness-workout-log, transit-raptor and
  GaTe-parking is byte-identical to v0.13.0's.

## 2026-11-13 (interactive): Milestone 13, local action inputs

Why: next step 2, picked by the owner ("Composite action inputs") after v0.12.0 was published.
Milestone 12 linked reusable workflows to their callers, but a composite action's inputs were
still always medium, even when the only caller in the repository passes clean values, and a
caller passing a comment body only made it medium instead of high.

Acceptance criteria:
- A step with `uses: ./<folder>` (also `uses: ./` for a root `action.yml`) is a caller of that
  folder's `action.yml`/`action.yaml` when both files are checked.
- Its `with:` values are read with what is tainted at that step: env at every level (the
  step's own too) and earlier step outputs. Worst caller wins; clean callers mean no finding.
- Chains: composite action -> local action, reusable workflow -> local action.
- No change in findings on the five local repositories.

Done:
- `calls.py`: `local_calls` adds step calls (`Call.step`, `where` = file:line), `repo_root`
  finds the folder holding `.github` from any depth, `_scope_of` gets the step's scope from
  the caller's `Tracker`.
- `taint.py`: inputs of actions go through the same `_caller_input` as reusable workflows;
  `direct_taint` lost its `in_action` flag; `taint_of_value` takes a scope.
- `workflow.py`: `ACTION_FILES` moved here from `cli.py`.
- Tests: `test_local_actions.py` (13). 280 in total. Version 0.13.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 280 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks: evaluating `with:` without the step's scope fails 2 tests; not resolving
  step calls at all fails 9.
- Demo (`reply.yml` on `issue_comment` passing the comment body through step `env:` into
  `.github/actions/comment`): high with the detour named; the action alone gives medium.
- This repository's own `ci.yml` (`uses: ./` three times) is now linked to `action.yml` and
  found clean. JSON output for workflow-guard, lendloop, fitness-workout-log, transit-raptor
  and GaTe-parking is byte-identical to v0.12.0's.

## 2026-11-13 (scheduled run): Milestone 12, local reusable workflows

Why: the open item from the previous runs ("checking inside called local reusable workflows").
A reusable workflow (`on: workflow_call`) pasting `${{ inputs.title }}` into `run:` wasn't
reported at all, although a `pull_request_target` workflow can call it with the PR title. That
is the composite-action problem from milestone 5 one level up, and unlike an action, the caller
is usually in the same repository, so the real answer can be worked out.

Acceptance criteria:
- `inputs.*` of a reusable workflow in `run:`/github-script: medium when no checked file calls
  it (not for `type: boolean`/`number`); `workflow_dispatch`-only inputs stay trusted.
- With local callers among the checked files: the taint of what they pass in `with:` (direct
  values, `needs.*.outputs`, their own inputs through a chain), the worst caller winning; clean
  callers mean no finding. The message names the caller's file and job.
- Detours inside the called workflow (env:, $GITHUB_ENV, outputs) and WG007 work unchanged.
- No new findings on the five local repositories (none uses `workflow_call`).

Done:
- `calls.py` (new): `repo_root`, `local_calls`, `link_local_calls` (callers first, loops cut).
- `workflow.py`: `Workflow.input_taints`, `is_reusable`, `input_type`.
- `taint.py`: `Tracker._reusable_input`, `Tracker.taint_of_value` (a `with:` value of a job).
- `cli.py`: loads every file before checking any, then links the calls.
- Tests: `test_calls.py` (17). 267 in total. Version 0.12.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 267 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks: not linking callers before their callees fails the chain test; giving
  uncalled workflows an empty map (instead of None) fails the medium pass-on test.
- Demo in a scratch folder (`triage.yml` on `pull_request_target` calling `label.yml` with the
  PR title): the folder gives WG004 high on label.yml's `echo` line naming triage.yml's job;
  label.yml alone gives medium; its boolean `dry-run` input isn't reported.
- workflow-guard, lendloop, fitness-workout-log, transit-raptor, GaTe-parking: same findings as
  before (0 at medium+ except GaTe-parking's known WG001/WG002).

Not done: tag v0.12.0 and its GitHub Release (release notes need the owner's approval; draft in
`prVSCode/workflow-guard-v0.12.0-release-notes-DRAFT.md`).

## 2026-11-09 (interactive): Milestone 11, WG008 secrets exposure

Why: next step 3, picked by the owner after the releases were published. Secrets are what an
attacker wants from a workflow, and three mistakes hand them out without any injection: pasting
`${{ secrets.X }}` into a script, `toJSON(secrets)`, and `secrets: inherit` to a workflow in
another repository.

Acceptance criteria:
- `${{ secrets.X }}` (any spelling the expression reader knows, computed names too) inside `run:`
  or a github-script: medium, on the expression's line.
- `toJSON(secrets)` anywhere in the file: high, reported once (not also as the script case).
- `secrets: inherit` on `jobs.<id>.uses` that isn't `./...`: medium.
- Secrets in `env:` or an action's `with:`, and listed `secrets:` for reusable workflows: fine.

Done:
- `rules.py`: WG008 `secrets-exposure` (`secrets_exposure`), with helpers `_scalars` (every scalar
  value in the file) and `_expression_offset`.
- Tests: `test_wg008.py` (18), rule count in `test_cli.py`. 250 in total. Version 0.11.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 250 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks: treating `./` reusable workflows like remote ones, reporting `toJSON(secrets)`
  twice, or not recognising it at all each fail tests (1, 1, 3).
- Real data: GaTe-parking's release.yml passes `secrets.GITHUB_TOKEN` through `env:` and an
  action's `with: password:`; neither is reported. workflow-guard, lendloop,
  fitness-workout-log: 0 findings.

## 2026-11-09 (interactive): Milestone 10, multi-line writes and github-script

Why: next step 2, picked by the owner. The tracker from milestones 8 and 9 only understood
`echo "name=value" >> "$GITHUB_..."` on one line. GitHub's own docs show multi-line values
(`name<<EOF`) written from a `{ ... } >> "$GITHUB_OUTPUT"` group, which is exactly how issue and
PR bodies (always multi-line) get passed on, and github-script steps set outputs with
`core.setOutput`. Both were invisible to WG004 and WG007.

Acceptance criteria:
- Groups (several lines or one), `cat <<EOF >> $GITHUB_*` heredocs and `name<<DELIM` blocks
  (also with `>>` on every line) are read as the values the runner sees.
- `core.setOutput` / `exportVariable` / `addPath` in github-script feed outputs, env and WG007,
  with `context.payload.*` = `github.event.*` and `process.env.X` = the env variable.
- WG007 reports the line inside the block or script that carries the untrusted text.
- All earlier tests pass unchanged; no new findings on the real repositories.

Done:
- `writes.py` (new, no YAML or taint inside): `shell_writes` -> `Write` (line, file, shell text,
  written text), `assignments` (one-line and multi-line values per file; an unclosed block runs
  to the end), `github_script_calls`, `payload` (drops echo/printf and quotes).
- `taint.py`: `_apply_shell_writes` and `_apply_script_calls` replace the two line regexes;
  `_taint_of_js` for github-script values; `FileWrite.key` says which script a line is in.
- `rules.py`: WG007 points into `with.script` for github-script findings.
- Tests: `test_writes.py` (19). 232 in total. Version 0.10.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 232 passed. `ruff check`, `ruff format --check`: clean. The 213 earlier
  tests passed on the new reader before any new test was added.
- Mutation checks: without groups 2 tests fail, without `name<<DELIM` blocks 7, without
  `context.payload` 2.
- Real data: GaTe-parking's pr-title.yml (PR title in `env:`, `valid=true/false` and `id=$id`
  outputs, a `cat > help.md <<'EOF'` to an ordinary file) and release.yml (`VERSION` from the tag
  into `$GITHUB_ENV`): the tracker sees `PR_TITLE` as tainted, everything written as clean, and
  reports nothing. workflow-guard, lendloop, fitness-workout-log: 0 findings.

## 2026-11-09 (interactive): Milestone 9, WG007 untrusted text in $GITHUB_ENV / $GITHUB_PATH

Why: next step 2, picked by the owner. `echo "T=$TITLE" >> "$GITHUB_ENV"` has no `${{ }}` in the
script, so WG004 is silent, yet a title with a line break sets any variable for the later steps
(`BASH_ENV`, `LD_PRELOAD`, `NODE_OPTIONS`), which runs the sender's code. GitHub's own hardening
guide warns about exactly this. The tracker from milestone 8 already knows which shell variables
are tainted, so the rule is small.

Acceptance criteria:
- A `run:` line that appends tainted text to `$GITHUB_ENV` or `$GITHUB_PATH` is reported on that
  line, whether the text comes from an expression, `env:` or an earlier `$GITHUB_ENV` write, and
  also without a literal `NAME=` (`echo "$LINE" >> $GITHUB_ENV`).
- Runner variables (`$GITHUB_SHA`), `$GITHUB_OUTPUT`, plain files and numbers aren't reported.
- Composite action inputs: medium. Inline ignores and SARIF work like for the other rules.

Done:
- `taint.py`: `FileWrite` and `TrackedStep.writes`, filled by `_file_writes` (any line with
  `>> $GITHUB_ENV|PATH`; the text before `>>` is checked).
- `rules.py`: WG007 `untrusted-github-env` with summary and help; `_origin` shared with WG004.
- Tests: `test_wg007.py` (15), the rule count in `test_cli.py`. 213 in total. Version 0.9.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 213 passed. `ruff check`, `ruff format --check`: clean.
- Mutation check: without `PATH` in the write pattern, the `$GITHUB_PATH` test fails.
- No new findings on workflow-guard, lendloop, fitness-workout-log, GaTe-parking.

## 2026-11-09 (interactive): Milestone 8, following untrusted values through detours (WG004)

Why: next step 2, picked by the owner. Since v0.6.0 WG004 reads expressions properly, but only
direct uses: a PR title moved into `env:` and then pasted as `${{ env.TITLE }}`, or passed on as
a step output, slipped through. That detour is common in real workflows, often because someone
followed the "use env:" advice halfway.

Acceptance criteria:
- `${{ env.X }}` in `run:` is reported when X holds untrusted text, whether X was set in `env:`
  at workflow, job or step level or written to `$GITHUB_ENV` by an earlier step.
- `${{ steps.<id>.outputs.<name>}}` and `${{ needs.<job>.outputs.<name> }}` are reported when the
  output was written from untrusted text, also through a shell variable (`title=$TITLE`).
- `"$TITLE"` in a script, clean overrides, step env in later steps, outputs of steps without an
  `id`, and loops in `needs:` don't produce findings (or hangs).
- The message names the chain; no new findings on the real repositories.

Done:
- `taint.py`: `Taint` (kind, source, severity, the hops), `direct_taint` (the former WG004
  patterns, moved here), `Scope` (tainted env by exact name, outputs by lower-case id/name) and
  `Tracker`, which walks the steps of each job in order and caches each job's result for
  `needs:`; a job being walked counts as having no outputs, which stops `needs:` loops.
- `rules.py`: WG004 asks the tracker for each expression in `run:`/github-script. Direct uses keep
  their old messages; detours get `'<path>' carries <origin> (via a -> b) ...` and, for env, the
  advice to use `"$NAME"`.
- Tests: `test_taint.py` (21). 198 in total. Version 0.8.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 198 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks on `taint.py`: without the env lookup 7 tests fail, without clean overrides 1,
  without `needs:` outputs 2.
- workflow-guard, lendloop, fitness-workout-log: 0 findings. GaTe-parking (local clone, on a team
  member's branch): the same single low WG001 as before; its PR-title check reads the title
  through `env:` correctly and isn't reported.

## 2026-11-09 (interactive): Milestone 7, `--fix` matches the comment style

Why: next step 2, picked by the owner. In GaTe-parking (a team repository that runs
`prettier --check .`), every `--fix` needed a `prettier --write .github/` afterwards, because
`--fix` always wrote two spaces before `# v7` and Prettier wants one.

Acceptance criteria:
- A file whose comments use one space gets one space; two gets two.
- A file with no end-of-line comments in a Prettier repository gets one space.
- `--comment-spaces N` overrides everything; 1 to 8, anything else is a usage error.
- On GaTe-parking's real workflows, unpinning and re-pinning gives the original bytes back, and
  Prettier's own check passes.

Done:
- `fix.py`: `comment_gap(text, fallback)` (most common whitespace before an end-of-line `#`, tie
  to two spaces), `repository_root`, `uses_prettier` (config files, or `prettier` in
  package.json at the top level / dependencies / devDependencies; `eslint-config-prettier`
  alone doesn't count), `fallback_gap(path)`. `pin_actions` takes `gap` and `fallback`.
- CLI: `--comment-spaces N`; `--fix` passes the file's repository fallback.
- Tests: 27 new in `test_fix.py` (gap detection, Prettier detection, repository root with a
  worktree `.git` file, the order of the four sources, the option's validation). One existing
  expectation changed on purpose: a file whose only comment uses three spaces now gets three.
  177 in total. Version 0.7.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 177 passed. `ruff check`, `ruff format --check`: clean.
- GaTe-parking `origin/main` workflows (5 files, Prettier style), copied to a scratch folder
  with its real package.json and a `.git` marker, re-pinned against the real API:
  - all 20 pins removed: `--fix` restored them byte for byte (via the Prettier fallback);
  - only the 8 checkout pins removed: byte for byte again, and `npx prettier@3.6.2 --check`
    passes. Without package.json, `no-ai-attribution.yml` (no other comment) got two spaces,
    as designed.
  - Before this change the same round trip gave 20 differing lines and a failing Prettier check.

## 2026-11-09 (interactive): Milestone 6, a real expression reader

Why: next step 2, picked by the owner. WG004 and WG005 used regular expressions on the raw
text, which GitHub's expression syntax easily slips past (`github.event['pull_request']['title']`,
upper case, `toJSON(github.event)`), and which flagged text that only looks like a context
(`'github.head_ref'` as a string literal).

Acceptance criteria:
- Bracket syntax, any letter case and array indexes resolve to the same path as dot syntax.
- String literals are not contexts; `}}` inside a string doesn't end an expression.
- `toJSON()` of an object that contains an untrusted field is reported.
- WG005 sees the same spellings in `ref:`, plus `refs/pull/...` refs.
- No change on the real repositories (lendloop, fitness-workout-log, GaTe-parking).

Done:
- `expressions.py`: `find_expressions` (string-aware search for `${{ }}`), `tokenize` (names,
  strings with `''` escapes, numbers, operators, punctuation; `ExpressionError` for anything
  else), `context_paths` (lower-cased paths, `*` for array elements, the innermost function
  each path is an argument of), `matches` / `is_ancestor` for comparing with patterns.
- `rules.py`: the untrusted contexts are now a list of path patterns instead of one regex.
  WG004 reports per expression (first hit); an expression GitHub would reject is skipped,
  later ones are still checked. WG005 uses the same reader, and `refs/pull/` counts as PR code.
- Tests: `test_expressions.py` (40: lexer, paths, 8 former bypasses, 7 former false positives,
  WG005 spellings). 150 in total. Version 0.6.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 150 passed. `ruff check`, `ruff format --check`: clean.
- Mutation check: without lower-casing path names, 3 tests fail.
- `workflow-guard` here 0 findings; lendloop, fitness-workout-log and GaTe-parking report the
  same as before.

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

1. Tag `v0.14.0` and publish its release once the owner approves the drafted notes
   (`prVSCode/workflow-guard-v0.14.0-release-notes-DRAFT.md`); then bump the pins in lendloop,
   fitness-workout-log and transit-raptor.
2. Per-call inputs for findings too: a finding inside an action is reported with the worst
   caller; it could list every caller that passes untrusted text.
3. A CHANGELOG.md in the repository with the same content as the releases.
4. The Marketplace listing (needs the owner: it's a public listing under their account).
