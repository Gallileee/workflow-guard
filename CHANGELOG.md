# Changelog

Every release of workflow-guard, newest first. Each section is the text of its
[GitHub Release](https://github.com/Gallileee/workflow-guard/releases), with headings one
level deeper; `scripts/release_check.py` checks that the two agree.

## v0.37.0 — WG010: gh wrappers and functions in `$(...)`

### What a function prints is followed

Bash permission checks often wrap `gh` in a retry helper or a small function:

```bash
gh_retry() {
  local n=0
  while true; do
    if gh "$@"; then return 0; fi
    n=$((n+1)); [ "$n" -ge 3 ] && return 1
    sleep $((n * 2))
  done
}
P=$(gh_retry api "repos/$GITHUB_REPOSITORY/collaborators/$COMMENTER/permission" --jq .permission)
case "$P" in admin|maintain|write) ;; *) exit 1 ;; esac
```

The bash evaluator didn't follow the call inside the function. Now `P=$(f ...)`, where `f` is a
function, runs `f` the way bash does, in a subshell: `set -e` isn't inherited, its variables
stay there, and what it writes to `$GITHUB_OUTPUT` comes back. What it prints becomes the value:

- `echo` (`-n` too) and `printf '%s'`; a login stays a login, none of the names written down;
- a permission call about the commenter prints `none` or `read` on a line; a failed one prints
  its error body (a 404's) or nothing, and a retried failure's body counts once, so retry loops
  settle;
- `gh "$@"` is the call the caller wrote, read with the caller's variables (a wrapper's own
  `local` can't change it), through any number of wrappers;
- output sent elsewhere (`>&2`, `> file`, `{ ...; } >&2`) prints nothing, `grep -q` and `sleep`
  print nothing, and anything else (`2>&1`, another command) prints something unknown.

`exit` inside `$(...)` isn't followed (the value is unknown, as before).

### Fixed: an assignment's status is its command substitution's

`if P=$(cmd); then exit 1; fi` was read as always taking the `then`: an assignment always
succeeded. Its status is now the command's (unknown unless followed; `$((...))` succeeds).

On the public workflows, 30 of the 40 bash permission scripts are now decided (29 before).
No finding changed.

## v0.36.0 — WG010: arrays in bash checks (2026-11-21)

### Arrays, `< <(...)` and `(( ))` are followed

Bash permission checks often keep the allowed roles in an array:

```bash
allowed=(admin maintain write)
perm=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$GITHUB_ACTOR/permission" --jq .permission)
for role in "${allowed[@]}"; do [ "$perm" = "$role" ] && exit 0; done
exit 1
```

The bash evaluator gave up on them. Now it follows:

- `a=(x y z)`, also over several lines and after `declare -a`/`local -a`, and `a+=(w)`;
- `"${a[@]}"` (each element, also one with spaces, in a `for`), `${a[*]}` (joined by spaces),
  `${a[N]}`, `${#a[@]}`, and `$a` (the first element);
- `mapfile`/`readarray` (an array whose elements are unknown);
- `<(cmd)` and `>(cmd)`, so `while read ...; done < <(gh api ...)` reads unknown lines;
- `(( expr ))`: its status is unknown, and an assignment in it (`n++`, `n += 2`) makes its
  variables unknown;
- `x+=text`, which used to leave `x` unchanged.

Associative arrays (`declare -A`, `([key]=value)`) still make the script unknown.

On the public workflows, 29 of the 40 bash permission scripts are now decided (24 before).
No finding changed.

## v0.35.0 — WG010: functions and callbacks in github-script (2026-11-21)

### Arrow functions, functions, `for...of`, Map and Set are followed

Most github-script checks that were still judged from their text used functions:

```js
const allowed = new Set(['admin', 'maintain', 'write'])
async function canRun(user) {
  const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ ...context.repo, username: user })
  return allowed.has(data.permission)
}
if (!(await canRun(context.actor))) core.setFailed('write access needed')
```

Now the JavaScript evaluator follows them:

- `function f(a, b = 1) {}`, `async function`, arrow functions with an expression or a block
  body, and immediately called ones `(() => {...})()`. A function runs where it's called; its
  parameters and declarations are its own, and changes to the caller's names stay. Function
  statements are hoisted.
- `.some`, `.every`, `.find`, `.findIndex`, `.filter`, `.map` and `.forEach` call their callback
  for each element of a known list. On an unknown list the callback may run once or not at all,
  and the result is unknown.
- `for (const x of list)` with `break` and `continue`: once per element of a known list, round
  after round on an unknown one until nothing new turns up.
- `new Map()`, `new Set([...])` with `has`, `get`, `set` and `add`. A cache keyed by the
  commenter's login stays sound: two strangers' logins may be the same.
- `\u0041`, `\x41` and `\u{41}` escapes in strings.

On the public workflows, 27 of 31 github-script permission checks are now decided (19 before).
One cached check (`new Map()` in front of the API) was briefly misread as only reporting and
is now a check again; no finding changed.

## v0.34.0 — WG005 and WG009: why a guard doesn't hold (2026-11-21)

### The message names the weak guard

v0.33.0 made WG005 and WG009 skip steps that a fork can't reach. When there is a guard that
doesn't hold, the message now says why, as WG010 does:

```
wf.yml:21:9: WG005 [high] checks out the pull request's code under 'pull_request_target', which
runs with secrets and a write token (the job's 'if:' checks a label, which stays on the pull
request when the fork pushes new commits); a fork's PR can then run its own code
```

- `author_association != 'NONE'` and other deny-lists: who they still let in.
- A label (`github.event.pull_request.labels`, `github.event.label`): it stays on the pull
  request when the fork pushes new commits.
- `github.event.workflow_run.conclusion == 'success'` alone: it says how the triggering run
  ended, not whose code it ran.
- A check of the head repository or author that is still true for a fork
  (`head.repo.full_name != github.repository`, `workflow_run.event == 'pull_request'`).
- `always()` (or `!cancelled()`...) that runs the job, or a job it needs, past a guard job.

The step's, the job's and the needed jobs' `if:` are looked at, nearest first. On the public
`pull_request_target`/`workflow_run` workflows, 76 of the 145 findings get a note; the number
of findings doesn't change.

## v0.33.0 — WG005 and WG009: guards against forks (2026-11-21)

### An `if:` that keeps forks out guards the checkout

WG005 (`pull_request_target`) and WG009 (`workflow_run`) didn't read `if:`. A checkout of the
pull request's code was high even in a job that only runs for the repository's own branches:

```yaml
jobs:
  preview:
    if: github.event.pull_request.head.repo.full_name == github.repository
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

Now the step's, the job's and the needed jobs' `if:` are evaluated for a fork (the same
evaluator as WG010's, with the fork as the stranger). A guard is anything that is false for a
fork's pull request or run:

- the head repository: `head.repo.full_name == github.repository`, `!head.repo.fork`,
  `head.repo.owner.login == github.repository_owner`, and for `workflow_run`
  `head_repository.full_name == github.repository`;
- the author: `contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'),
  github.event.pull_request.author_association)`, `github.actor == 'renovate[bot]'`;
- the trigger: `github.event_name == 'push'` in a workflow with more triggers, and
  `github.event.workflow_run.event == 'push'` (a fork's run is a `pull_request` run).

A deny-list (`author_association != 'NONE'`), a label check (the label stays when the fork
pushes again) or `workflow_run.conclusion == 'success'` is no guard. A job that needs a guard job
is guarded unless its own `if:` runs it anyway (`always()`, `!cancelled()`). The low reminder
for `pull_request_target` goes when every job keeps forks out.

On 141 public `pull_request_target` and `workflow_run` workflows: 182 findings -> 145, with
nothing new but one reminder (in a workflow whose only checkout is now guarded).

### `github.repository_owner` for comments

For WG010 too, `github.repository_owner` and `github.repository` are the repository's own
names: `github.actor == github.repository_owner` keeps a commenter who isn't the owner out.

## v0.32.0 — WG010: github-script checks run on paper (2026-11-21)

### `actions/github-script` is followed, not guessed

A github-script that asked the permission API counted as a check whenever `core.setFailed`,
`throw` or `process.exit(1)` appeared anywhere in it. That holds for a script that fails only when
the API call itself fails:

```js
try {
  const { data } = await github.rest.repos.getCollaboratorPermissionLevel({
    ...context.repo, username: context.actor })
  core.setOutput('level', data.permission)
} catch (e) {
  core.setFailed(e.message)
}
```

Now such a script runs on paper (a small JavaScript evaluator, `jscript.py`) for a commenter who
can't write. The API about them answers `none` or `read`, or throws a 404 (into `catch` if there
is one), and any other call may throw. The evaluator follows `const`/`let` with `{ data: {
permission } }` patterns, `if`/`else`, `return`, `throw`, `try`/`catch`/`finally`,
`core.setFailed`, `core.setOutput`, `process.exit`, `.includes()` and the usual operators. If
every path fails, the step is a check. Otherwise it only reports, and its outputs are what it
really writes, `level=none` or `level=read` here, so `if: steps.perm.outputs.level != 'none'`
is reported:

```
wf.yml:14:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the step at line 9 asks for the commenter's permission but doesn't fail on a no, and
this step's 'if:' is still true when it answers 'level=read'); ...
```

- `return x` is the `result` output: JSON by default (`return false` is the text `false`, which
  is true in an `if:`, so `if: ${{ !steps.x.outputs.result }}` is never true), or the plain text
  with `result-encoding: string`.
- A github-script that checks `author_association` or the login without the API, and fails for
  everyone who can't write, is a check too.
- Arrow functions, functions, loops and `switch` aren't followed: such a script is judged from
  its text, as before.

### Outputs of a step that doesn't run

A step whose `if:` keeps strangers out writes no outputs for them. So a job output that carries
one is empty (`ready: ${{ steps.ready.outputs.ready }}` after `if: steps.perm.outputs.ok ==
'true'`), and a dependent job's `if: needs.gate.outputs.ready == 'yes'` is false for a stranger.

On the public workflows, 19 of the 31 github-script permission checks are now run on paper:
17 as the text said, two only report (one returns early when the comment isn't its command,
one sets `authorized=false`, which the job after it checks through a step that doesn't run).
No finding changed.

## v0.31.0 — WG010: loops in bash checks (2026-11-21)

### `for`, `while` and `until` are followed

A permission script with a loop was judged from its text:

```bash
ok=no
for role in admin maintain write; do
  [ "$PERM" = "$role" ] && { ok=yes; break; }
done
[ "$ok" = yes ] || exit 1
```

Now the bash evaluator follows loops. `for x in a b c` runs its body once per word. Over words
it can't count (`$LIST`, `$(...)`, a glob, a value with spaces), and for `while`/`until`, the
body runs round after round from every state the last round left, until no new state turns up
(at most 8 rounds; a counter that never settles makes the script unknown). `break`,
`continue`, and `done < file` are followed too.

### Commands that set variables

Before, `read X` or `export X=...` left `X` as it was, so a later test of `X` could be decided
wrongly. Now `read` makes its variables unknown, `export`/`declare`/`readonly NAME=value`
assign, `unset` empties, `printf -v` makes unknown, and `IFS=, read -r a b` runs `read` (the
prefix only lasts for the command). `eval`, `source`, `shift`, `let` and `getopts` make the
script unknown.

### The permission step's own token

A step that asks for the commenter's permission needs a token for the API
(`GH_TOKEN: ${{ secrets.BOT_PAT }}`); it was reported as a job that uses secrets once it only
reported its answer. The check itself is no longer counted, only the steps it guards.

On the public workflows, 24 of 40 permission scripts are now decided (21 before); 2 findings
went away (a permission step that holds its own token), none was added.

## v0.30.0 — WG010: scripts that report to $GITHUB_OUTPUT (2026-11-21)

### A script that writes its check to `$GITHUB_OUTPUT` is read like an action that reports

Some workflows check the commenter in a script and pass the result on:

```yaml
- id: trust
  run: |
    case "${{ github.event.comment.author_association }}" in
      OWNER|MEMBER|COLLABORATOR) echo "trusted=true" >> "$GITHUB_OUTPUT" ;;
      *) echo "trusted=false" >> "$GITHUB_OUTPUT" ;;
    esac
- if: steps.trust.outputs.trusted != 'true'
  run: exit 1
- if: steps.trust.outputs.trusted == 'true'
  env:
    GH_TOKEN: ${{ secrets.DISPATCH_TOKEN }}
  run: gh workflow run ...
```

WG010 didn't know what such a script writes, so the job was reported. Now the bash evaluator
follows `echo "name=value" >> "$GITHUB_OUTPUT"` (also `printf`, and `echo` in a
`{ ...; } >> "$GITHUB_OUTPUT"` group) on every path where the script succeeds. A script that
looks at who commented and writes something is a step that only reports, and an `if:` on its
outputs is evaluated with what it writes for a stranger (`trusted=false` here). The message names
those outputs:

```
wf.yml:14:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the step at line 9 looks at who commented but doesn't fail on a no, and this step's
'if:' is still true when it answers 'trusted=false'); ...
```

- Any other way of writing to `$GITHUB_OUTPUT` (`tee`, a copy in a variable, a multiline value)
  makes the outputs unknown, so the step is no check.
- A script that asks the permission API but writes an output the evaluator can't work out
  (`ok=$(...)`) keeps the earlier answers (empty, `false`, `none`, `read`).

### `a || b` as a value

With `a` unknown and `b` truthy, `a || b` is truthy, but its value may be `a`. It was taken as
`true` everywhere, so `EVENT: ${{ steps.replay.outputs.event || github.event_name }}` became the
text `true`. Now that is unknown wherever the value matters (a comparison, a function argument,
`env:`, a job output); only as a condition it stays true.

On the public workflows, one more finding went away (a script like the one above); no other
finding changed.

## v0.29.0 — WG010: a check that may be skipped (2026-11-21)

### A permission check with its own `if:` covers only steps with the same condition

A step that fails unless the commenter may write covered every step after it, even when its own
`if:` could skip it:

```yaml
- uses: xt0rted/slash-command-action@v2
  if: contains(github.event.comment.body, '/test')
  with:
    command: test
- uses: actions/checkout@v4
  with:
    ref: refs/pull/${{ github.event.issue.number }}/head
```

A comment without `/test` skips the check, and the checkout still runs. Now such a check covers
only the later steps whose `if:` has the same condition (every part of it, joined by `&&`), and
the rest are reported:

```
wf.yml:13:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the step at line 9 fails unless the commenter may write, but its 'if:' may skip it,
and this step doesn't have the same condition); ...
```

- A check whose `if:` is true for every stranger (`github.event_name == 'issue_comment'`) still
  covers everything after it, and so does a later check that always runs.
- A job that needs the job with a check that may be skipped is covered only if its own `if:`
  has the check's condition, read through the needed job's outputs: `proceed: ${{
  steps.command.outputs.proceed }}` turns the check's `steps.command.outputs.proceed == 'true'`
  into `needs.authorize.outputs.proceed == 'true'`.
- A bash script check (v0.26.0) with an `if:` no longer has to always run; it follows the same
  rule.
- The `exit 1` step after an action that only reports (v0.25.0) is unchanged: its `if:` is about
  that answer, so it runs whenever it should.

## v0.28.0 — WG010: functions in bash checks (2026-11-20)

### Scripts with functions are run on paper too

A permission check is often written as a function:

```bash
check() {
  local perm
  perm=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$1/permission" --jq .permission)
  [[ "$perm" == admin || "$perm" == write ]]
}
check "$GITHUB_ACTOR" || { echo "::error::write access needed"; exit 1; }
```

The bash evaluator gave up on any function, so such a script was judged from its text. Now
functions (`name() { ...; }`, `function name { ...; }`) run where they're called: `$1`... come
from the call, `local` variables are put back afterwards, and `return` ends the function with
its status (the last command's without one). `{ ...; }` groups run in place, and redirections
after a compound command (`} >> "$GITHUB_OUTPUT"`) are skipped.

`set -e` follows bash: inside a function or group that is called in a condition, negated, or
before the last command of a `&&`/`||` list, a failing command doesn't end the script, so
`check || exit 1` depends on what `check` returns.

On the public workflows from v0.25.0, 21 of the 40 permission scripts are now decided (18
before). One more turns out to only report: it also lets the issue's author through on purpose.
No finding changed.

## v0.27.0 — WG010: permission API scripts run on paper (2026-11-20)

### A script that exits only when the API call fails is no check

A `run:` script that asked the permission API counted as a check whenever it had an `exit 1`
somewhere. But this one only exits when the call itself fails, and a no goes to an output:

```yaml
- run: |
    P=$(gh api "repos/$GITHUB_REPOSITORY/collaborators/$GITHUB_ACTOR/permission" --jq .permission || exit 1)
    echo "permission=$P" >> "$GITHUB_OUTPUT"
```

Now such a script is run on paper (`shell.py`): a stranger gets `none` or `read`, or the call
fails (a non-collaborator can get a 404), which ends the script under `bash -e` or takes the
`else` of `if P=$(...)`. `|| echo none` turns the failure into `none` (maybe after gh's error
text); without `--jq` the answer is JSON. `gh api ... | grep -q PATTERN` is followed too (`-E`,
`-i`, `-w`, `-x`, `-F`, basic regex `admin\|write`). The step fails on a no only if every path
exits; otherwise it only reports, and the steps that don't read its answer are reported:

```
wf.yml:12:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the step at line 9 asks for the commenter's permission but doesn't fail on a no, and
this step's 'if:' doesn't check its answer); ...
```

- Only when the user asked about is the commenter (`${{ github.actor }}`,
  `${{ github.event.comment.user.login }}`, `$GITHUB_ACTOR`, a step `env:` set from them).
- Scripts it can't follow (functions, loops, another user, another jq filter), PowerShell and
  github-scripts are still judged from their text, as before.
- On 40 permission API scripts in public workflows the evaluator decided 18: 17 as before, and
  one that only reports `trusted=false` (its dependent job reads that, so nothing new there).

## v0.26.0 — WG010: checks written in bash (2026-11-20)

### A `run:` script that exits for strangers is a check

Some workflows check who commented in a script instead of an `if:`:

```yaml
- run: |
    case "$ASSOC" in
      OWNER|MEMBER|COLLABORATOR) ;;
      *) echo "not allowed"; exit 1 ;;
    esac
  env:
    ASSOC: ${{ github.event.comment.author_association }}
```

WG010 now runs such a script on paper (a small bash evaluator, `shell.py`), once for each
association that can't write: `if`/`elif`/`else`, `case`, `&&`/`||`/`!`, `[ ]`, `test`,
`[[ ]]` (with `=~`), assignments, `exit` and `set -e`. If every path exits non-zero, the step
covers the steps after it, like a permission step that fails on a no. A test it can't decide
goes both ways, and loops, functions, subshells and heredocs make the script unknown.

A script that lets some through is named:

```
wf.yml:21:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the script at line 60 in job 'check', which it needs, looks at who commented but
still lets CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR, FIRST_TIMER, MANNEQUIN and NONE in: ...); ...
```

- Only bash/sh steps (not `shell: pwsh`, not a Windows runner without `shell: bash`), and only
  when the step always runs for a stranger (no `if:`, or one that is true for them).
- Only the `env:` variables the script uses are looked at.
- `gh api "repos/.../collaborators/${{ github.event.comment.user.login }}/permission"` is now
  recognised as asking for the permission (the space inside `${{ }}` hid it).

## v0.25.0 — WG010 on public workflows: fewer false positives (2026-11-20)

### Checked against 148 public `issue_comment` workflows

WG010 ran on 148 public workflows found with GitHub code search
(`getCollaboratorPermissionLevel`, `check-user-permission`, `slash-command-action`,
`author_association` with `refs/pull`). It reported 100 findings. The changes below remove 77
of them; each kind was traced to a check WG010 didn't understand. 23 remain.

- **The event is known.** In a run started by a comment, `github.event_name` is
  `issue_comment`. Workflows with more triggers write
  `github.event_name == 'workflow_dispatch' || (github.event_name == 'issue_comment' && ...)`;
  that `if:` is now evaluated, and a job whose `if:` is never true for a comment
  (`github.event_name == 'push'`) isn't reported.
- **Exit on a reported no.** An action that only reports, followed by a step that fails
  whenever its `if:` lets it run, is a check for the steps after that step:

  ```yaml
  - uses: actions-cool/check-user-permission@v2
    id: perm
    with:
      require: write
  - if: steps.perm.outputs.require-result != 'true'
    run: exit 1
  ```

- **What an action answers.** `actions-cool/check-user-permission` always sets
  `user-permission`, and `require-result` when `require:` is given (its `src/main.js`), so
  only `false` (or `none`/`read`) is tried for those outputs, not an empty answer.
  `require-result == 'false'` then `exit 1` counts, and so does `!= 'false'`.
- **Every needed job at once.** `(needs.check.result == 'success' || needs.manual.result ==
  'success') && !cancelled()` is false when `check` fails for a stranger and `manual` only runs
  on `workflow_dispatch`; until now only one needed job's result was known at a time.
- **A failing check that also writes its answer.** A dependent job's `if:` on
  `needs.<job>.outputs` is evaluated for a permission step that fails on a no too, not only for
  one that reports.
- **Not a checkout.** A script that only saves a pull request's ref
  (`echo "REF=refs/pull/1/merge" >> $GITHUB_ENV`, `>> $GITHUB_OUTPUT`) isn't a checkout; a git
  command (`fetch`, `checkout`, `switch`, `pull`, `reset`, `worktree add`) or `gh pr checkout`
  on the same line as the ref is.

## v0.24.0 — WG010: a check that `always()` runs past (2026-11-20)

### A failed check stops only what doesn't run after a failure

A step that fails on a no, or a needed job that fails or is skipped for a stranger, used to
count as a check for everything after it. But GitHub only puts `success() &&` in front of an
`if:` that has no status function of its own. With `always()`, `failure()` or `!cancelled()`
the step or job runs anyway, after the check has said no:

```yaml
jobs:
  gate:
    steps:
      - uses: xt0rted/slash-command-action@v2
        with:
          command: test
  test:
    needs: gate
    if: ${{ !cancelled() }}
    steps:
      - run: gh pr checkout ${{ github.event.issue.number }} && npm test
```

Now that is reported, and the message names the function:

```
wf.yml:17:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (job 'gate', which it needs, fails for commenters who can't write, but this job's
'if:' uses cancelled(), so it runs anyway); ...
```

- The `if:` is evaluated with `success()` false, `failure()` true after a failure, `cancelled()`
  unknown, `always()` true and `needs.<job>.result` set to `failure` or `skipped`, so
  `always() && needs.gate.result == 'success'` and `${{ !failure() }}` after a failed check
  still count.
- The same within a job: a step with `if: always()` after a step that fails on a no is open
  again (a checkout is high, secrets are medium).
- A chain breaks where a job in the middle runs anyway: `test` needs `middle`, which has
  `if: always()` and needs a `gate` that keeps strangers out.

## v0.23.0 — WG010: a permission check that comes too late or lets a no through (2026-11-19)

### A permission step only covers the steps after it

A step that fails unless the commenter may write (`xt0rted/slash-command-action`,
`core.setFailed` in a github-script, `exit 1`...) used to count for the whole job. But the
steps before it have already run by the time it fails:

```yaml
- run: gh pr checkout ${{ github.event.issue.number }}
- uses: xt0rted/slash-command-action@v2
  with:
    command: deploy
```

Now it covers only the steps after it. A checkout or a secret before it is reported:

```
wf.yml:22:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the step at line 23 fails unless the commenter may write, but this step runs before
it); ...
```

In a job named in `needs:` the order doesn't matter: when that job fails, the jobs that need it
don't run.

### An `if:` on the answer has to keep a no out

A step that only reports the answer covered every step whose `if:` read it, whatever it did
with it. Now the `if:` is evaluated for each answer someone who can't write may get: nothing
(an output that wasn't set, or a misspelt name), `false`, `none` or `read`.

- Still a check: `steps.perm.outputs.require-result == 'true'`,
  `contains(fromJSON('["admin","write"]'), steps.perm.outputs.result)`, and
  `steps.perm.outcome == 'success'` for a step that would fail but has `continue-on-error`.
- Not a check any more: `steps.perm.outputs.require-result` alone (the text `false` is true in
  an `if:`), `!= 'false'` (an empty answer gets through: it fails open),
  `steps.perm.outcome == 'success'` for a step that never fails, and an answer check joined
  with `||` to the comment's text or `always()`.
- The same goes for a job's `if:` on `needs.<job>.outputs.<name>`: the output's own expression
  is worked out first, so `${{ steps.perm.outputs.require-result == 'true' }}` gives `false`.

```
wf.yml:13:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the step at line 9 asks for the commenter's permission but doesn't fail on a no, and
this step's 'if:' is still true when it answers nothing, 'none' or 'read'); ...
```

## v0.22.0 — WG010: weak checks of the commenter (2026-11-17)

### An `if:` that looks at who commented isn't always a check

Until now any mention of `github.event.comment.author_association` or `github.actor` in a
job's `if:` counted as a check of who commented. But a deny-list keeps almost no one out:

```yaml
if: github.event.comment.author_association != 'NONE'
```

lets in everyone with a merged pull request (`CONTRIBUTOR`) or an open one
(`FIRST_TIME_CONTRIBUTOR`), none of whom can write to the repository. Now the `if:` is
evaluated for every commenter who can't write, and only a condition that keeps all of them out
counts:

```
wf.yml:9:9: WG010 [high] checks out the pull request's code in a job that anyone who can
comment can start (...), without checking who commented (its 'if:' looks at who commented but
still lets CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR, FIRST_TIMER and MANNEQUIN in: author_association
values of people who can't write to the repository); ...
```

- Still a check: `== 'OWNER' || == 'MEMBER'`, `contains(fromJSON('["OWNER","MEMBER"]'), ...)`,
  `github.actor == 'me'`, `contains(fromJSON(vars.MAINTAINERS), github.actor)`.
- Not a check any more: `!= 'NONE'`, `github.actor != 'renovate[bot]'`,
  `contains('alice,bob', github.actor)` (a new account can be called `ice`),
  `startsWith(github.actor, 'team-')`, and an allow-list joined with `||` to the comment's text.
- The same goes for a step's `if:` and for a check in a job named in `needs:`.

### A permission step only counts if it stops the job

A step that asks GitHub for the commenter's permission used to count as a check whatever it did
with the answer. But some only report it:

```yaml
- uses: actions-cool/check-user-permission@v2
  id: perm
  with:
    require: write          # sets outputs.require-result; doesn't fail without error-if-missing
- uses: actions/checkout@v4
  with:
    ref: refs/pull/${{ github.event.issue.number }}/head
```

Now a permission step is a check for the whole job only if it fails on a no
(`error-if-missing: true`, `core.setFailed` or `throw` in a github-script, `exit 1` or a
`| grep -q` in a script, and no `continue-on-error: true`). One that only reports the answer
covers the steps whose `if:` reads `steps.<id>...`, and the jobs whose `if:` reads it through
`needs.<job>.outputs`. The message says which step asked:

```
wf.yml:15:9: WG010 [high] checks out the pull request's code (...) without checking who
commented (the step at line 11 asks for the commenter's permission but doesn't fail on a no,
and this step's 'if:' doesn't check its answer); ...
```

A weak `if:` in a job named in `needs:` is now named too: "(the 'if:' of job 'gate', which it
needs, looks at who commented but still lets CONTRIBUTOR, ... in ...)".

## v0.21.0 — A settings file (2026-11-14)

### `.github/workflow-guard.yml`

The same options used to be repeated in three places: the workflow that runs the action, the
pre-commit configuration and the command line. Now they can live in one file:

```yaml
ignore: [WG006]
min-severity: low
fail-on: medium
script-inputs:
  - my-org/deploy:commands
```

- The command line and the pre-commit hook find it in the current folder or the nearest one
  above it, up to the repository root; the action reads it from the checked-out repository.
- Options given directly win (`--fail-on high` over `fail-on:`); `ignore` and `script-inputs`
  from both are combined.
- `--config FILE` / `--no-config`, and the action's new `config` input (`none` for no file).
- An unknown key, rule id or level is an error (exit 2) instead of a silently ignored setting:

```
workflow-guard: .github/workflow-guard.yml: unknown setting(s): fail_on; known: ignore,
min-severity, fail-on, script-inputs
```

### Action inputs

`fail-on` and `min-severity` now default to empty, which means "the settings file's level, else
`low`", so a level in the settings file isn't overridden by the input's default. Without a
settings file nothing changes.

Other rules' output is unchanged.

## v0.20.0 — WG010: comment commands (2026-11-14)

### New rule: WG010 comment-command

`issue_comment` runs with your repository's secrets and a write token, and anyone who can
comment starts it; on a public repository that is anyone with an account. A `/test` or
`/deploy` command therefore has to check who wrote the comment. WG010 reports jobs that don't:

- **high:** the job checks out the pull request: `ref: refs/pull/${{ github.event.issue.number }}/head`
  (or `/merge`), a ref taken from a step or job output, `gh pr checkout`, or
  `git fetch origin pull/N/head` in a script. The stranger's code then runs with your secrets.
- **medium:** the job uses secrets other than `GITHUB_TOKEN`.

These count as a check:
- `github.event.comment.author_association`, `github.actor`, `github.triggering_actor` or the
  commenter's login in the job's `if:` (in a step's `if:`, for that step);
- a step that checks the commenter's permission: `getCollaboratorPermissionLevel` in a
  github-script, `gh api .../collaborators/<user>/permission`, or an action such as
  `actions-cool/check-user-permission`, `xt0rted/slash-command-action` or
  `peter-evans/slash-command-dispatch`;
- such a check in a job this job `needs:`.

Matching the comment's text is not a check, and the message says so:

```
.github/workflows/pr-test.yml:12:9: WG010 [high] checks out the pull request's code in a job that
anyone who can comment can start ('issue_comment' runs with secrets and a write token), without
checking who commented (its 'if:' only looks at the comment's text, which anyone can write);
check github.event.comment.author_association (OWNER, MEMBER, COLLABORATOR) in the job's 'if:',
or the commenter's permission in a first step
```

**Fix:**

```yaml
if: >-
  github.event.issue.pull_request &&
  contains(fromJSON('["OWNER", "MEMBER", "COLLABORATOR"]'), github.event.comment.author_association) &&
  startsWith(github.event.comment.body, '/test')
```

Other rules' output is unchanged. `--list-rules` now lists 10 rules.

## v0.19.0 — Your own actions that run a script (2026-11-14)

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
