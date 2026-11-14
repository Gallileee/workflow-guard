# Changelog

Every release of workflow-guard, newest first. Each section is the text of its
[GitHub Release](https://github.com/Gallileee/workflow-guard/releases), with headings one
level deeper; `scripts/release_check.py` checks that the two agree.

## v0.19.0 — Your own actions that run a script

### `--script-input` and the `script-inputs` input

v0.18.0 taught WG004 and WG008 the script inputs of 14 public actions. In-house actions that
run an input as a script weren't known. Now you can name them:

```bash
workflow-guard --script-input my-org/deploy:commands --script-input my-org/notify:message,on_failure
```

or, in the GitHub Action:

```yaml
- uses: Gallileee/workflow-guard@<sha>  # v0.19.0
  with:
    script-inputs: |
      my-org/deploy:commands
      my-org/notify:message,on_failure
```

Those inputs are then checked exactly like `run:`. The message names your action:

```
.github/workflows/deploy.yml:14:21: WG004 [high] 'github.event.pull_request.title' can be set by
outsiders and is pasted into a script; pass it through 'env:' and use the variable instead
(my-org/deploy runs its 'commands' input as a script)
```

- Names match without case; an action in a subfolder (`my-org/actions/deploy:run`) works too.
- Naming a listed action adds to its inputs and keeps its advice (`appleboy/ssh-action:script_after`).
- A malformed value (no `:`, an `@version`, a local `./` path) is an error before anything is
  checked.

Other rules' output is unchanged.

## v0.18.0 — WG004 checks actions that run a script (2026-11-13)

### Script inputs of actions

WG004 (untrusted `${{ }}` pasted into code) and WG008 (secrets pasted into code) looked only at
`run:` and `actions/github-script`. Many workflows run their commands through an action
instead: over SSH, in a container, with retries. Their script inputs are now checked too:

| Action | Inputs |
|--------|--------|
| `appleboy/ssh-action` | `script` |
| `garygrossgarten/github-action-ssh`, `google-github-actions/ssh-compute` | `command` |
| `addnab/docker-run-action` | `run` |
| `uraimo/run-on-arch-action` | `run`, `install`, `setup` |
| `nick-fields/retry`, `nick-invision/retry` | `command`, `on_retry_command`, `new_command_on_retry` |
| `Wandalen/wretry.action` | `command` |
| `azure/cli`, `azure/powershell` | `inlineScript` |
| `cypress-io/github-action` | `build`, `start`, `command`, `install-command` |
| `mathiasvr/command-output` | `run` |
| `jannekem/run-python-script-action` | `script` |

The message names the action and, where the step's `env:` doesn't reach the script, how to pass a
variable there:

```
.github/workflows/deploy.yml:16:19: WG004 [high] 'github.event.pull_request.title' can be set by
outsiders and is pasted into a script; pass it through 'env:' and use the variable instead
(appleboy/ssh-action runs its 'script' input as a script; on the server, pass it with the
action's 'envs:' input)
```

Detours (`env:`, step and job outputs, local callers) are followed into these inputs as into
`run:`. Other inputs of the same actions (`host:`, `key:`) are data and stay unreported.

Other rules' output is unchanged.

## v0.17.0 — WG009 sees git checkouts in scripts (2026-11-13)

### Checking out with git or gh in a script

WG009 now also reports a `workflow_run` workflow that brings the triggering run's commit into
the working tree from a `run:` script (high), not only with `actions/checkout`:

- `git checkout`, `git switch`, `git fetch`, `git pull`, `git reset` or `git worktree add` with
  `github.event.workflow_run.head_sha`, `head_branch` and the like, also as `git -C dir ...` and
  across `\` line continuations;
- the same through an `env:` variable of the workflow, job or step (`git checkout "$HEAD_SHA"`,
  `${{ env.HEAD_SHA }}`); a step's `env:` overrides the job's, as on GitHub;
- `gh pr checkout` of the triggering run's pull request.

```
.github/workflows/preview.yml:14:9: WG009 [high] checks out the triggering run's code with git
or gh in a script, under 'workflow_run', which runs with secrets and a write token; the
triggering run can be a pull request from a fork, and its code then runs here
```

### `branches:` is not a protection

A `branches: [main]` filter under `on.workflow_run` matches the head branch of the triggering
run. For a fork's pull request that is the fork's own branch, which it can call `main`. WG009
findings now say so when such a filter (or `branches-ignore:`) is present, instead of leaving
the impression that the filter made the workflow safe.

Other rules' output is unchanged.

## v0.16.0 — WG009: workflow_run (2026-11-13)

### New rule: WG009 workflow-run

A `workflow_run` workflow runs with your repository's secrets and a write token, but the run that triggered it may have built a pull request from a fork. WG009 reports when such a workflow uses that run's code or files:

- **high:** `actions/checkout` of the triggering commit (`github.event.workflow_run.head_sha`, `head_branch`, `head_repository`, …). The fork's code then runs with your secrets.
- **high:** the triggering run's artifacts unpacked into the workspace, followed by a `run:` step or a local action in the same job. The artifact can replace your scripts and config before they run.
- **medium:** any other download of those artifacts. Treat them as data.

These count as artifact downloads:
- `actions/download-artifact` with `run-id:`
- `dawidd6/action-download-artifact`
- `gh run download`
- `downloadArtifact` in a github-script

If every workflow listed under `on.workflow_run.workflows` is in the checked files and none of them runs on `pull_request`, nothing is reported. Those runs only build your own commits. Findings name the workflow that makes the run untrusted.

**Fix:** download to `${{ runner.temp }}`, never check out the triggering commit, and don't run, source or paste the files.

Other rules' output is unchanged. `--list-rules` now lists 9 rules.

## v0.15.0 — Every tainted caller in the message (2026-11-13)

Since v0.12.0, a WG004/WG007 finding inside a local reusable workflow or action showed only the
**worst** caller. With several callers passing untrusted text, you fixed one, re-ran, and found
the next. Now every one of them is named:

```
.github/workflows/label.yml:12:14: WG004 [high] 'inputs.title' carries 'github.event.issue.title',
which outsiders can set (via with.title in .github/workflows/issues.yml (job 'label')) and is
pasted into a script; pass it through 'env:' and use the variable instead; other callers pass
untrusted text too: with.title in .github/workflows/triage.yml (job 'label')
('github.event.pull_request.title')
```

- The worst caller still leads as the detour; the others follow, highest severity first, then
  in file order, without duplicates.
- Callers that pass clean values aren't listed, and with a single tainted caller the message is
  unchanged.
- Works for reusable workflows and local actions, through `env:` detours and chains.

Code scanning: SARIF fingerprints include the message, so a finding that gains a caller list
appears as a new alert (the old one closes).

```yaml
- uses: Gallileee/workflow-guard@3823d2fc5436ec3cdcea03625e50d54c4aab4a96  # v0.15.0
```

298 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.14.0...v0.15.0

## v0.14.0 — Outputs come back: follow local actions and reusable workflows to the caller (2026-11-13)

v0.12.0 and v0.13.0 followed untrusted text **into** local reusable workflows and actions.
v0.14.0 follows it **back out**:

- After a step with an `id` that runs a local action (`uses: ./.github/actions/<name>`),
  `${{ steps.<id>.outputs.<name> }}` carries whatever the action's `outputs.<name>.value`
  carries: a PR title the action read itself, or an input handed straight back.
- After a job that calls a local reusable workflow, `${{ needs.<job>.outputs.<name> }}`
  carries whatever its `on.workflow_call.outputs.<name>.value` carries.
- Each call is worked out with its own `with:` values, so a clean call doesn't inherit the
  title another call passed to the same action.
- WG007 (`$GITHUB_ENV` / `$GITHUB_PATH`) sees these outputs too.

```
.github/workflows/label.yml:9:14: WG004 [high] 'steps.meta.outputs.title' carries
'github.event.pull_request.title', which outsiders can set (via env.TITLE (step 'meta') ->
steps.meta.outputs.title -> outputs.title of .github/actions/pr-meta/action.yml ->
steps.meta.outputs.title) and is pasted into a script; ...
```

Outputs of remote actions and reusable workflows (`uses: owner/repo...`) are still trusted;
only files in the checked repository are read.

```yaml
- uses: Gallileee/workflow-guard@a16822661831a0cfef65ffb805000dd9a592e66e  # v0.14.0
```

292 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.13.0...v0.14.0

## v0.13.0 — Local actions: follow what the calling step passes in (2026-11-13)

v0.12.0 linked reusable workflows to their callers. v0.13.0 does the same for **local actions**:

- A step with `uses: ./.github/actions/<name>` (or `uses: ./` for an `action.yml` at the
  repository root) is linked to that action when both files are checked, which the default
  does (`.github/workflows/`, a root `action.yml` and `.github/actions/`).
- The step's `with:` values are read with what is tainted at that step: `env:` at every level,
  the step's own included, and earlier step outputs.
- The action's `${{ inputs.* }}` in `run:` then carries what its callers really pass: **high**
  for a comment body or PR title, **no finding** when every local caller passes clean values.
  Before, it was always medium.
- Chains work too: a composite action running another local action, and a reusable workflow
  running a local action.

```
.github/actions/comment/action.yml:9:12: WG004 [high] 'inputs.body' carries
'github.event.comment.body', which outsiders can set (via env.BODY (step 1 of job 'reply')
-> with.body in .github/workflows/reply.yml:7) and is pasted into a script; ...
```

An action with no caller among the checked files keeps the medium finding.

```yaml
- uses: Gallileee/workflow-guard@2078311d18e4c3befd7ab37333fabefef7a0f257  # v0.13.0
```

280 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.12.0...v0.13.0

## v0.12.0 — Reusable workflows: follow what the caller passes in (2026-11-13)

WG004 (and WG007) now look at **reusable workflows** (`on: workflow_call`):

- `${{ inputs.title }}` pasted into `run:` or a github-script of a reusable workflow is reported
  (medium), like a composite action's inputs: any caller may pass untrusted text. Inputs with
  `type: boolean` or `type: number` can't carry text and are skipped.
- When the **caller is in the same repository** (`jobs.<id>.uses: ./.github/workflows/x.yml`),
  workflow-guard reads what it really passes in `with:`. A `pull_request_target` workflow
  passing `${{ github.event.pull_request.title }}` makes it **high**, and the message names the
  caller's file and job; callers passing only clean values mean no finding. `needs.*.outputs`
  and chains of reusable workflows are followed.

```
.github/workflows/label.yml:12:14: WG004 [high] 'inputs.title' carries
'github.event.pull_request.title', which outsiders can set (via with.title in
.github/workflows/triage.yml (job 'label')) and is pasted into a script; ...
```

Callers are linked only when both files are checked in the same run, which is the default
(`.github/workflows/`).

```yaml
- uses: Gallileee/workflow-guard@6020472cbd3268b94220325921ce6497f4d7c9f5  # v0.12.0
```

267 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.11.0...v0.12.0

## v0.11.0 — WG008: secrets exposure (2026-11-09)

New rule **WG008 `secrets-exposure`** for three ways a workflow hands out secrets without any
injection:

- **`${{ secrets.X }}` pasted into `run:` or a github-script** (medium). The secret becomes part
  of the script text: quotes or `$` in it break the script, and `set -x`, an error message or a
  process listing can show it. GitHub's log masking only catches exact matches. Pass it through
  `env:` and use `"$X"`.
- **`toJSON(secrets)`** anywhere (high): every secret of the repository in one value.
- **`secrets: inherit`** on a reusable workflow from another repository (medium): all secrets go
  to code that lives elsewhere. List the ones it needs instead.

Passing a secret through `env:` or to an action's `with:` stays fine.

```yaml
- uses: Gallileee/workflow-guard@ad49d2071c05f5f58a571b08aa1b9f82f8fef412  # v0.11.0
```

250 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.10.0...v0.11.0

## v0.10.0 — Multi-line writes and github-script outputs (2026-11-09)

The tracker behind WG004 and WG007 now reads the ways workflows actually pass values on:

- `{ ... } >> "$GITHUB_OUTPUT"` groups (over several lines or on one), `cat <<EOF >> "$GITHUB_ENV"`
  heredocs, and multi-line `name<<DELIMITER` values, which is how issue and PR bodies get passed on.
- `actions/github-script`: `core.setOutput`, `core.exportVariable` and `core.addPath`, with
  `context.payload.*` read as `github.event.*` and `process.env.NAME` as the env variable.
- WG007 points to the exact line inside a block or a github-script.

```yaml
- uses: Gallileee/workflow-guard@53e5b2efc68a768264f3b5002410ff85885ae794  # v0.10.0
```

232 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.9.0...v0.10.0

## v0.9.0 — WG007: untrusted text in $GITHUB_ENV / $GITHUB_PATH (2026-11-09)

New rule **WG007 `untrusted-github-env`**: untrusted text appended to `$GITHUB_ENV` or
`$GITHUB_PATH`, e.g. `echo "TITLE=$TITLE" >> "$GITHUB_ENV"` with a pull request title in `TITLE`.
There is no `${{ }}` in the script, so WG004 can't see it, but a title with a line break sets any
variable for the later steps (`BASH_ENV`, `LD_PRELOAD`, `NODE_OPTIONS`) and runs the sender's code;
`$GITHUB_PATH` can put their directory first in `PATH`. High; medium for a composite action's inputs.

```yaml
- uses: Gallileee/workflow-guard@f50a28bcfe5ed2247792adcd169a5801f56ddebf  # v0.9.0
```

213 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.8.0...v0.9.0

## v0.8.0 — WG004 follows untrusted values on a detour (2026-11-09)

WG004 (template injection) used to see only direct uses. It now walks each job's steps in order
and follows untrusted values through `env:` (workflow, job and step level), `$GITHUB_ENV`,
`$GITHUB_OUTPUT` and job outputs read via `needs`, so this is reported too:

```yaml
env:
  TITLE: ${{ github.event.pull_request.title }}
steps:
  - id: meta
    run: echo "title=$TITLE" >> "$GITHUB_OUTPUT"
  - run: echo "${{ steps.meta.outputs.title }}"   # reported, with the detour in the message
```

A clean value at a lower level removes the taint; `"$TITLE"` in a script stays fine.

```yaml
- uses: Gallileee/workflow-guard@349a8dcf3a23584b79290a3b82336ea2c12d6982  # v0.8.0
```

198 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.7.0...v0.8.0

## v0.7.0 — `--fix` keeps the file's comment style (2026-11-09)

`--fix` wrote two spaces before the added `# v4` comment, so repositories formatted with
Prettier (one space) failed their format check after every fix. The gap now comes from
`--comment-spaces N`, else the file's own end-of-line comments, else one space if the repository
uses Prettier (config file or `package.json`), else two.

```yaml
- uses: Gallileee/workflow-guard@82d701cf876d01e369f69ffda271de76046c9718  # v0.7.0
```

177 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.6.0...v0.7.0

## v0.6.0 — A real expression reader (2026-11-09)

`${{ }}` expressions are parsed by a small lexer instead of matched with regular expressions.

- Now caught: `github.event['pull_request']['title']`, `github['head_ref']`, any letter case
  (`GITHUB.EVENT.ISSUE.BODY`), and `toJSON(github.event)`, which prints every field.
- No longer reported: a quoted string that only looks like a context (`'github.head_ref'`).
- WG005 reads `ref:` the same way and treats `refs/pull/...` as the pull request's code.

```yaml
- uses: Gallileee/workflow-guard@1492aecf7fccd88bc2c96db454f1e87b13626fa6  # v0.6.0
```

150 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.5.0...v0.6.0

## v0.5.0 — Composite and Docker actions (2026-11-09)

workflow-guard now checks `action.yml` files as well as workflows: the steps of composite actions
get WG001, WG004 and WG006, a Docker action's `docker://` image gets WG001, and
`${{ inputs.* }}` pasted into `run:` of a composite action is reported (medium). Without
arguments it checks `.github/workflows/`, `action.yml` at the root and `.github/actions/**/action.yml`.

```yaml
- uses: Gallileee/workflow-guard@56d4f43be878a99f49fdeed79506163cb5272bf9  # v0.5.0
```

110 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/compare/v0.4.0...v0.5.0

## v0.4.0 — Use it as a GitHub Action or pre-commit hook (2026-11-09)

The first tagged release. workflow-guard is a small, readable checker for security mistakes in
GitHub Actions workflows (rules WG001–WG006: unpinned actions, missing or `write-all`
permissions, template injection, `pull_request_target`, persisted checkout credentials), with
`--fix` to pin actions to commit SHAs and `--format sarif` for code scanning (built in 0.1–0.3).

New in this release:

- **GitHub Action**: `uses: Gallileee/workflow-guard@<sha>` checks `.github/workflows` and shows
  findings as annotations on the pull request, with no extra permissions. Inputs: `paths`,
  `format`, `output`, `fail-on`, `min-severity`, `ignore`, `python-version`.
- **pre-commit hook**: `id: workflow-guard`.
- `--format github`: annotations, escaped so a line break can't start another workflow command.

```yaml
- uses: Gallileee/workflow-guard@c9201e515f48fb008d9114c307eb6578e99148e9  # v0.4.0
```

93 tests. **Full changelog**: https://github.com/Gallileee/workflow-guard/commits/v0.4.0
