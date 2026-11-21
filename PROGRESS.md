# Progress log

## 2026-11-21 (interactive, user picked "Šipky v JS"): functions and callbacks in jscript

Why: next step 2. Of the github-script permission checks in the corpora, 12 fell back to the
text guess: arrow functions (5), `async function` (5), `function` (3), an escape (1).

Acceptance criteria:
- Parser: `function`/`async function` statements (hoisted) and expressions, arrows (`x =>`,
  `(a, b = 1) =>`, `async`), expression or block bodies, `for (const x of ...)`, `break` and
  `continue` (no labels); parameter patterns and rest stay unsupported.
- Calls: `_invoke` binds parameters (defaults), runs the body, keeps the caller's own names
  but not the function's locals (`_locals`, `_back`); depth 8. IIFEs. Throws go to the caller.
- Callbacks on known lists per element (`_callback`, `_combine`); on unknown ones zero or one
  call and an unknown result.
- `for...of`: per element of a known list; rounds until no new state on an unknown one (8).
- Found on the way: a check that caches in `new Map()` read as reporting (and added a WG010
  finding): `_Collection` for Map/Set with `has`/`get`/`set`/`add`; a key that may equal
  another (two strangers) makes `has`/`get` unknown and `set` turn the map unknown.

Done:
- `jscript.py`: parser `function`, `params`, `arrow`, `for_of`; `_Fn`, `_invoke`, `_locals`,
  `_back`, `_callback`, `_combine`, `_for_of`, `_Collection`, `_construct`, `_collection_call`;
  `\u`/`\x` escapes; `break` at the top is unsupported.
- Tests: 45 more in `test_jscript.py` (4 old "doesn't follow" examples replaced by ones that
  still aren't followed); 1193 in total.
- README (How it works, limitations), CHANGELOG v0.35.0, version 0.35.0, v0.34.0 heading dated.

What the corpora showed: 27 of 31 github-script permission checks decided (was 19): 15 fail on
a no, 12 only report; 2 still fall back (array patterns in a lock file). Findings 20, 17 and
the fork corpus unchanged.

Verified locally:
- `pytest -q -W error`: 1193 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.35.0, 0 errors (warning: v0.35.0 not tagged yet).
- All three corpora: same finding counts as main, no errors. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 21 mutants; 20 killed (5 after adding tests), one equivalent (a duplicate
  entry after `Map.set` on a known key: the values are replaced before it, so lookups agree).

## 2026-11-21 (interactive, user picked "Zprávy WG005/9"): why a fork guard doesn't hold

Why: next step 3. v0.33.0 skips steps a fork can't reach, but a guard that doesn't hold was
reported without a word about it; WG010 names its weak checks.

Acceptance criteria:
- `_fork_if_note`: for an `if:` that may still be true for a fork: an `author_association`
  deny-list (who it lets in, `_who`), a label, only `workflow_run.conclusion`, or a head
  repository/author/event check still true for a fork; nothing for an `if:` that doesn't look.
- `_fork_note`: the step's, then the job's `if:`, an `always()` past a needed guard job, then the
  needed jobs' `if:` (nearest first), and a needed job that runs past its own guard job.
- Notes go into every WG005 high and WG009 message; the findings themselves don't change.

Done:
- `rules.py`: `_FORK_PATHS`, `_LABELS`, `_CONCLUSION`, `_fork_if_note`, `_fork_note`; WG005
  and WG009 messages.
- Tests: 11 more in `test_fork_guards.py`; 1148 in total.
- README (How it works), CHANGELOG v0.34.0, version 0.34.0, v0.33.0 heading dated.

What the corpora showed: 76 of the 145 WG005/WG009 findings in the fork corpus get a note:
37 only the triggering run's conclusion, 18 a label, 19 a head/event check still true for a
fork, 2 an `author_association` deny-list (8 of the 76 from a needed job's `if:`). Finding
counts (475, 170, and the fork corpus) unchanged from main.

Verified locally:
- `pytest -q -W error`: 1148 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.34.0, 0 errors (warning: v0.34.0 not tagged yet).
- All three corpora: same finding counts as main, no errors. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 12 mutants; 11 killed (one after adding a test that also led to the
  "runs past job" note for a needed job), one equivalent in context (the `if not passing`
  check in `_fork_if_note`: a needed job that keeps forks out is reached only after an
  `always()` note or when the step is guarded anyway; kept so the function stands alone).

## 2026-11-21 (interactive, user picked "Stavové funkce WG005/9"): fork guards in WG005/WG009

Why: next step 3 (picked over step 2). WG005 and WG009 didn't read `if:` at all: a checkout of
a pull request's code guarded by `head.repo.full_name == github.repository` was still high.

Acceptance criteria:
- `conditions.py`: profiles for the stranger (`COMMENT`, `FORK_PR`, `FORK_RUN`) in
  `_stranger_lookup`; `lets_in`, `may_pass` and `_for_strangers` take the profile. A fork's
  head repository/owner/author are a stranger, `fork` is true, `github.repository`,
  `repository_owner`, the base repository are the owners' (`OWNERS_LIST`), PR
  `author_association` per association, `workflow_run.event` is `pull_request`,
  `github.event_name` the trigger. Labels stay unknown.
- `rules.py`: `_keeps_forks_out`, `_job_keeps_forks_out` (own `if:`, or needed jobs that keep
  forks out unless `_runs_anyway(..., profile)`), `_fork_guarded`; WG005 skips guarded
  checkouts and drops the reminder when every job is guarded; WG009 skips guarded steps.
- No change for WG010 except `github.repository_owner`/`github.repository` being the owners'
  for comments too (found by a mutant: `github.actor == github.repository_owner` is a check).

Done:
- `conditions.py`, `rules.py` as above; `_runs_anyway` has a `profile`.
- Tests: `test_fork_guards.py` (45); 1137 in total.
- README (WG005/WG009 rows, How it works), CHANGELOG v0.33.0, version 0.33.0, v0.32.0 heading
  dated.

What the corpora showed: a new corpus of 141 public `pull_request_target`/`workflow_run`
workflows (code search: `head.repo.full_name`, `pull_request.head.sha`, `head_repository`,
`workflow_run.head_sha`, `author_association` with a checkout; in the session scratchpad, not
committed). WG005/WG009 findings 182 -> 145 (WG005 high 73 -> 68, low 32 -> 31, WG009 high 57 ->
37, medium 20 -> 9); one reminder added where the only checkout is now guarded. Sampled
removals: `workflow_run.event == 'push'`, `head_repository.full_name == github.repository`,
`author_association` allow-lists, a step guard on `head.repo.full_name`. Comment corpora: 20
and 17, as before.

Verified locally:
- `pytest -q -W error`: 1137 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.33.0, 0 errors (warning: v0.33.0 not tagged yet).
- All three corpora run with all rules without errors. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 17 mutants (profile entries, event name, common values, guards in WG005
  and WG009, needed jobs, running anyway with the fork's profile), all killed (two after adding
  tests; one of them made `_COMMON` apply to comments too).

## 2026-11-21 (interactive, user picked "github-script kontroly"): github-script on paper

Why: next step 2. `actions/github-script` permission checks were judged from their text
(`core.setFailed`/`throw`/`process.exit(1)` anywhere); 31 such steps in the corpora.

Acceptance criteria:
- `jscript.run`: tokens (strings, templates, regex literals as unknown, comments, line breaks
  for `return`), a parser for statements (`const`/`let`/`var` with object patterns, `if`,
  `return`, `throw`, `try`/`catch`/`finally`, blocks, expressions) and expressions (precedence
  as JS, calls, members, `?.`, arrays, objects with spread, `new`); paths with `_Env` (names,
  outputs, failed, asked); ends: normal, return, throw, exit.
- `context` for a stranger; `getCollaboratorPermissionLevel` about them: `none`/`read` or a
  throw; other calls: unknown and may throw (matters inside `try`).
- `core.setFailed` (fails at the end), `core.setOutput` (JSON for non-text), `return` -> `result`
  (JSON, or `result-encoding: string`), `process.exit` as a statement only.
- Unsupported: arrow functions, functions, loops, `switch`, classes, array patterns, `++`,
  unknown `setOutput` names: the text guess stays.
- Rules: `_asks` uses it for github-script with the API; `_js_stops` for scripts that look at
  the commenter without the API; `_script_answers` gives github-script outputs.
- Found on the way: a step that never runs for a stranger writes no outputs, so a job output
  carrying one is empty (`_silent_ids` in `_needed_answer_gate`). Without it one corpus
  workflow got 4 false findings once its `authorized=false` step was seen to only report.

Done:
- `jscript.py` (new), `rules.py` (`_is_github_script`, `_js_results`/`_js_run` cached,
  `_js_looks`, `_js_stops`, github-script branch in `_script_answers`, `_silent_ids`).
- Tests: `test_jscript.py` (85) and 10 more in `test_wg010.py` (3 old expectations changed: the
  github-script answers are now 'result=false', and `!= 'false'` on a real `false` output
  holds); 1092 in total.
- README (How it works, modules, limitations), CHANGELOG v0.32.0, version 0.32.0, v0.31.0
  heading dated.

What the corpora showed: 19 of 31 github-script permission checks decided (17 agree with the
text guess; 2 only report: an early `return` when the comment isn't the command, and an
`authorized=false` output). 12 fall back (helper scripts loaded with `require`, arrow
functions, loops, another user's permission). Findings 20 and 17, as on main.

Verified locally:
- `pytest -q -W error`: 1092 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.32.0, 0 errors (warning: v0.32.0 not tagged yet).
- Both corpora: all rules without errors, same findings as main. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 28 mutants; 27 killed (11 after adding tests); one showed dead code (the
  404 path was added twice), removed.

## 2026-11-21 (interactive, user picked "Cykly v shell.py"): loops in the bash evaluator

Why: next step 2. Loops were the largest group of permission scripts that fell back to the
text guess (5 of 19).

Acceptance criteria:
- `for x in WORDS` with known words (no `$`, glob or spaces): once per word, in order.
  Otherwise (and `for x;`, `while`, `until`): rounds from every state the last one left until no
  new state (`_key`) turns up, at most 8, else unknown. A `for` over unknown words may end
  before any round; `while`/`until` end where the condition says so (`-e` off in it).
- `break`/`continue` (no count above 1, only inside a loop); `return` leaves loops too; redirect
  `done < file`, and `done >> "$GITHUB_OUTPUT"` writes like a group.
- Found on the way (soundness): `read`, `export`/`declare`/`readonly`, `unset`, `printf -v`
  and `NAME=value cmd` prefixes now change variables; `eval`, `source`, `.`, `shift`, `let`,
  `getopts`, `mapfile`, `readarray`, `select`, `coproc` are unsupported.
- A permission step's own secrets aren't counted (corpus: a check holding `CI_BOT_PAT` became a
  new "uses secrets" finding once the evaluator saw it only reports).

Done:
- `shell.py`: `_For`, `_While`, parser `for_`/`while_`/`do_done`, `_round`, `_for`, `_while`,
  `_rounds` (fixed point), `_BREAK`/`_CONTINUE`/`_LOOPS`, `_jumped`, `_key`, `_sets`,
  `_UNFOLLOWED`, `<` in `redirections`.
- `rules.py`: `comment_commands` skips permission steps like stops.
- Tests: 44 more (`test_shell.py`, one in `test_wg010.py`; 4 old ones that used loops as the
  unsupported example now use `eval`, `source`, `((...))`); 997 in total.
- README (How it works, limitations), CHANGELOG v0.31.0, version 0.31.0, v0.30.0 heading dated.

What the corpora showed: permission scripts decided 24 of 40 (was 21): 15 fail on a no as the
guess said, 9 only report (4 of them the guess counted as checks: they `exit 1` only on an API
error or for another reason). Findings 22 -> 20 and 17 -> 17: the permission step's own token
(ceph, uf-mil) and one found and then fixed during this change (QwenLM's authorize job). 16
still fall back: arrays and `< <(...)` (5), a `(` in a function body, a heredoc, a `gh_retry`
wrapper around the API call, and calls about someone other than the commenter.

Verified locally:
- `pytest -q -W error`: 997 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.31.0, 0 errors (warning: v0.31.0 not tagged yet).
- Both corpora: all rules without errors. workflow-guard, LendLoop, fitness-workout-log,
  transit-raptor: same output as main.
- Mutation checks: 24 mutants; 23 killed (7 after rewriting or adding tests), one equivalent
  (the status a `_seq_status` gives a path after `break`/`continue` is never read; commented).

## 2026-11-21 (interactive, user picked "$GITHUB_OUTPUT v shell.py"): scripts that report

Why: next step 2. A script that checks the commenter and writes `trusted=false` to
`$GITHUB_OUTPUT` wasn't understood: the job was reported (a false positive seen in the corpus).

Acceptance criteria:
- `shell.script_outputs`: the outputs on every path where the script succeeds (end of script,
  `exit 0`, an unknown exit code), from `echo name=value`, `printf 'name=%s\n' x`,
  `printf '%s\n' name=x`, `printf 'name=v\n'`, and `echo` in a `{ ...; } >> $GITHUB_OUTPUT`
  group; any other mention of `GITHUB_OUTPUT` (tokens or substitutions) -> unknown.
- A bash script that looks at the commenter and writes something is an answer step
  (`_is_answer`, `_askers`); `_no_answers` gives every combination of the scripts' outputs (at
  most 64), labelled `_SCRIPT` when only scripts answer; messages name `'name=value'`.
- API scripts with an output the evaluator can't work out keep `NO_ANSWERS`.
- Found on the way: `a || b` with `a` unknown evaluated to `True` as a value. `evaluate` got
  `as_value` (comparisons, function arguments, `text_value`, `stranger_text`).

Done:
- `shell.py`: `_Simple.output`, `_Group.output`, `_Parser.target`/`output_targets`,
  `_write`, `_PASSED`, `script_outputs`, file descriptors (`2>&1`) no longer become arguments.
- `conditions.py`: `evaluate(..., as_value=)`.
- `rules.py`: `_script_answers`/`_script_maps` (cached), `_is_answer`, `_answers`/`_askers`
  include them, `_no_answers` combinations, `_passing` returns lookups, `_answer_words`,
  "looks at who commented" in messages.
- Tests: 45 more (`test_shell.py`, `test_wg010.py`, `test_conditions.py`); 953 in total.
- README (WG010 row, How it works, modules), CHANGELOG v0.30.0, version 0.30.0, v0.29.0
  heading dated (2026-11-21, its release day).

What the corpora showed: 18 steps report through `$GITHUB_OUTPUT`. Findings 22 and 18 -> 22
and 17 (the `trusted=false` script). Two scripts gave `allowed=true` for a stranger: one was the
`||` bug (`EVENT_NAME: ${{ steps.replay.outputs.event_name || github.event_name }}`, now
unknown), the other is a rate limiter that lets comments through on purpose.

Verified locally:
- `pytest -q -W error`: 953 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.30.0, 0 errors (warning: v0.30.0 not tagged yet).
- Both corpora run with all rules without errors. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 29 mutants (shell writes, value mode, answer steps), all killed (2 after
  adding tests).

## 2026-11-20 (interactive, user picked "if: kroku kontroly"): a check that may be skipped

Why: next step 2. A permission step that fails on a no covered every later step even when its
own `if:` could skip it (only bash script checks had to always run). A known false negative.

Acceptance criteria:
- A stop whose `if:` may be false for a stranger covers only later steps whose `if:` contains
  every top-level `&&` part of it (parsed, so `${{ }}` and spacing don't matter).
- A stop whose `if:` is true for every stranger (or none) covers everything after it; a later
  sure stop covers what follows it. Deny steps (`exit 1` on a reported no) stay sure.
- A needed job only "fails" for a stranger through a sure stop; a dependent job is covered by a
  conditional one if its `if:` has the stop's condition with `steps.<id>.outputs.<x>` read as
  the job output carrying exactly that value.
- Messages: "its 'if:' may skip it, and this step / a step that uses secrets doesn't have the
  same condition".

Done:
- `rules.py`: `_Stop` (index, step, sure), `_stops`, `_stop_step` (first sure stop),
  `_condition`, `_conjuncts`, `_parts`, `_covers`, `_covers_through` (in `_needed_results`);
  `comment_commands` decides coverage per step; `_why_open(skipped=)`. Shell script stops no
  longer need `_always_runs`: they follow the same rule.
- Tests: 19 more in `test_wg010.py`; 908 in total.
- README (WG010 row, How it works, limitations), CHANGELOG v0.29.0, version 0.29.0, v0.28.0
  heading dated.

What the corpora showed: the first version added one finding (a `sonar` job needing an
`authorize` job whose check has `if: steps.command.outputs.proceed == 'true'`, while the
`sonar` job has `if: needs.authorize.outputs.proceed == 'true'`): a false positive, fixed by
reading the condition through the job outputs. After that the findings are as on main (22, 18);
one message changed for a check that writes `trusted=false` to `$GITHUB_OUTPUT` from a `case` on
the association and then exits in a step with `if: trusted != 'true'`: still reported (it was
before, as "only looks at the comment's text"), because the evaluator doesn't follow what a
script writes to `$GITHUB_OUTPUT` yet.

Verified locally:
- `pytest -q -W error`: 908 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.29.0, 0 errors (warning: v0.29.0 not tagged yet).
- Both corpora: 22 and 18 findings, all rules without errors. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 13 mutants, all killed; a first run showed an equivalent branch in
  `_covers_through` (an untranslated `steps.*` part), which was removed.

## 2026-11-20 (interactive, user picked "Funkce v shell.py"): functions in the bash evaluator

Why: next step 2. Functions were the most common reason a permission script fell back to the
text guess (8 of 22 in the corpora).

Acceptance criteria:
- `name() { ...; }` and `function name [()] { ...; }` are parsed; a call runs the body with
  `$1`... from its arguments, then puts `$1`... and `local` variables back; `return [N]` ends
  the function (status N, or unknown without N); without it the last command's status counts.
- `{ ...; }` groups; redirections after `}`, `fi`, `esac`, `]]`.
- `set -e` doesn't act inside a function or group called in a condition, negated, or before the
  last command of a `&&`/`||` list (this also fixes `if`/`case` bodies in those places).
- Top-level `$1`... are empty (GitHub passes no arguments).
- Unsupported: `return`/`local` outside a function, recursion past 8 calls, a `( )` body.

Done:
- `shell.py`: `_Group`, `_Define`, `_Function`; parser `group`, `define`, `redirections`;
  `_call` (positional, locals, depth), `return`/`local` in `_simple`; `_RETURNED` marker skipped
  by `_run_seq`, `_seq_status` and `_and_or`; `_pipe(last=)` runs non-last and negated
  pipelines with `-e` off.
- Tests: 32 more in `test_shell.py` (3 old ones that expected functions to be unsupported now use
  loops); 889 in total.
- README (How it works, limitations), CHANGELOG v0.28.0, version 0.28.0, v0.27.0 heading dated.

What the corpora showed: 21 of 40 permission scripts decided (was 18); one more only reports
(qd-today-style: the issue's author may run it too, and `exit 0` skips). 19 still fall back:
`while`/`for` (5), arrays and `< <(...)` (3), a heredoc, and calls about someone other than the
commenter. WG010 findings unchanged (22 and 18).

Verified locally:
- `pytest -q -W error`: 889 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.28.0, 0 errors (warning: v0.28.0 not tagged yet).
- Both corpora: same WG010 output as main, all rules without errors. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 16 mutants on functions/groups/`-e` contexts, all killed (5 after adding
  tests).

## 2026-11-20 (interactive, user picked "API skripty na papíře"): permission API scripts on paper

Why: next step 2. A `run:` script with the permission API counted as failing on a no when it
had `exit 1` anywhere (`_STOPS`), even if it only exits when the call fails.

Acceptance criteria:
- `P=$(gh api .../collaborators/<commenter>/permission ...)` is `none`/`read`, or a failed
  call (assignment status, `-e`, the `else` of `if P=$(...)`); `|| echo X` / `|| true`
  fallbacks (the fallback or gh's error text first); no jq -> JSON (equal to no word); other jq
  filters -> not followed. `gh api ... | [jq -r .permission |] grep -q PATTERN` too.
- Only for the commenter as the user; otherwise, and for anything not followed, the text guess
  stays (no new findings from scripts it can't read).
- A script that exits only on an API error reports (and is then reported if nothing reads it).

Done:
- `shell.py`: `_prepare` keeps each substitution's text (`_Sub`), `_api_answers`, `_grep`
  (`-qEiwxFs`, basic regex), `_api_pipe`, API assignments branch per answer, `api_fails`,
  `_analyse` with a `ContextVar` noting whether an API call was followed.
- `rules.py`: `_asks` asks `_api_verdict` (cached) for bash `run:` scripts first; `_shell_run`
  shared with `_shell_passing`; `_DEFAULT_ENV` (`GITHUB_ACTOR`, `GITHUB_TRIGGERING_ACTOR`,
  `GITHUB_EVENT_NAME`).
- Tests: 33 in `test_shell.py`, 8 in `test_wg010.py`; 857 in total.
- README (How it works, modules, limitations), CHANGELOG v0.27.0, version 0.27.0, v0.26.0
  heading dated.

What the corpora showed: 40 permission API scripts. The evaluator decided 18 (12 fail on a no,
6 only report); 17 agree with the text guess, and the one that differs (a script that writes
`trusted=false`) didn't change any finding because its dependent job checks that output. 22
fall back to the guess: functions (8), `while` (4), `{ }` groups (2), a heredoc, and calls about
the pull request's author rather than the commenter. Findings: 22 and 18, as on main.

Verified locally:
- `pytest -q -W error`: 857 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.27.0, 0 errors (warning: v0.27.0 not tagged yet).
- Both corpora: same WG010 output as main, all rules without errors. workflow-guard, LendLoop,
  fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 16 mutants; 14 killed (5 after adding tests), one removed with the code it
  tested (a failed call's output is empty anyway), one equivalent kept on purpose (`_value`
  turns a substitution into UNKNOWN, which every comparison treats the same).

## 2026-11-20 (interactive, user picked "Shell kontrola asociace"): WG010 checks written in bash

Why: next step 2 of the previous entry. A check of `author_association` in a `run:` script
(`case ... in OWNER|MEMBER|COLLABORATOR) ;; *) exit 1`) wasn't recognised.

Acceptance criteria:
- A bash script that exits non-zero on every path for every association that can't write,
  in a step that always runs (no `continue-on-error`), stops the job like a failing permission
  step. Unknown tests go both ways; unsupported syntax means no check.
- `set -e` as bash applies it (not in conditions, negations, or before the last of `&&`/`||`).
- A script with an exit that still lets some through is named in the message.
- Not for pwsh/python steps or a Windows runner's default shell; only env vars the script uses.
- No change on the four own repositories; check both public corpora.

Done:
- `shell.py` (new): `_prepare` (continuations, comments, `$(...)`/backticks unknown), shlex
  tokens, parser (`if`, `case`, `[[ ]]`, pipelines, and-or lists, redirections), path-following
  evaluator with per-path variables, `_Test` for `[ ]`/`test`/`[[ ]]`, 64-path cap.
- `conditions.py`: `stranger_text` (an `env:` value for a stranger).
- `rules.py`: `_shell`, `_shell_inputs`, `_shell_check`, cached `_shell_passing`, `_always_runs`;
  `_stop_step` uses them; `_why_open` names a weak script; `_who`; `_PERMISSION_API` allows
  `${{ }}` in the URL.
- Tests: `test_shell.py` (60) and 28 more in `test_wg010.py`/`test_conditions.py`; 816 in total.
- README (WG010 row, How it works, modules, limitations), CHANGELOG v0.26.0, version 0.26.0,
  v0.25.0 heading dated.

What the corpora showed: real bash checks mostly test the permission API's answer
(`P=$(gh api .../permission)`), which the `exit 1` heuristic already counted; checks of the
association were few and mostly let more people in on purpose (the pull request's author, or
contributors with five merged pull requests): those stay reported, now with the reason. A
second corpus (56 files: `AUTHOR_ASSOCIATION "exit 1"`, `author_association case esac`)
didn't change (18 findings). The first corpus went 23 -> 22 (the `${{ }}` in a permission URL).

Verified locally:
- `pytest -q -W error`: 816 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.26.0, 0 errors (warning: v0.26.0 not tagged yet).
- Corpora: 148 files 22 WG010 findings, 56 files 18; all rules run on both without errors.
  workflow-guard, LendLoop, fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 27 mutants on `shell.py`, the wiring and `stranger_text`, all killed (11
  after adding tests; one showed a redundant branch in `_value`, removed).

## 2026-11-20 (interactive, "pokračuj podle plánu"): WG010 on public workflows

Why: next step 2 (step 1, tagging v0.24.0, was done the same day at the owner's request). Look
for false positives on real `issue_comment` workflows instead of guessing.

How: GitHub code search (`gh api search/code`, `path:.github/workflows language:YAML`) for
`getCollaboratorPermissionLevel issue_comment`, `check-user-permission issue_comment`,
`slash-command-action issue_comment`, `author_association issue_comment refs/pull` and
`collaborators permission issue_comment gh pr checkout`, 30 results each: 148 distinct files,
downloaded into the session scratchpad (not committed: other people's code, and the remaining
findings may be real problems in their repositories, so no repository names here). Run with
only WG010.

Acceptance criteria:
- Every kind of finding sampled; each false-positive pattern fixed with tests, the rest left.
- No change on workflow-guard, LendLoop, fitness-workout-log, transit-raptor.
- v0.24.0 heading dated; v0.25.0 section and version.

Findings 100 -> 23, by fix (in the order applied):
- 100 -> 51: `github.event_name` is `issue_comment` (`conditions._stranger_lookup`), and an
  `if:` that is never true for a comment covers the step/job (`_commenter_gate` no longer needs
  a commenter path to say yes). Pattern: `event_name == 'workflow_dispatch' || (...)`.
- 51 -> 46: `_denies`: a step that fails whenever it runs (`_ALWAYS_FAILS`) after a reporting
  step, with an `if:` that `must_pass` (new in `conditions.py`) for every no answer, is a stop.
- 46 -> 31: `_needed_results`/`_failure_after`: every needed job's stranger result at once
  (`needs.a.result == 'success' || needs.b.result == 'success'`), which also covers the
  generated gh-aw `.lock.yml` conclusion jobs.
- 31 -> 29: `_pr_script`: a git command or `gh pr checkout` on the line with the ref; saving
  a ref to `$GITHUB_ENV`/`$GITHUB_OUTPUT` isn't a checkout.
- 29 -> 25: `_askers`: job outputs from a permission step that fails on a no are evaluated
  too (a step with `exit 1` for API errors that writes `should_review=false` for a no).
- 25 -> 23: `_ACTION_ANSWERS`/`_possible_answers`: actions-cool/check-user-permission's
  `user-permission` (never empty) and `require-result` (never empty with `require:`), checked
  against its `action.yml` and `src/main.js`. `_passing` names only answers an output can give.

The 23 left, not all checked by hand: about 6 are checks WG010 can't see (a permission check in
a script of the repository, a shell `case "$AUTHOR_ASSOCIATION"` with `exit 1`, a check passed
through workflow `env:`); the sampled others look real (a slash-command action with
`continue-on-error: true` and nothing reading its outcome, a reporting step nothing waits for).

Done:
- `conditions.py`: `EVENT_NAME`, `_for_strangers`, `must_pass`.
- `rules.py`: `_ACTION_ANSWERS`, `_possible_answers`, `_said`, `_ALWAYS_FAILS`, `_denies`,
  `_askers`, `_needed_results`, `_failure_after` (replaces `_alone`), `_PR_REF_TEXT`,
  `_pr_script` (replaces `_PR_SCRIPT`); `_runs_anyway(node, results, wf)`.
- Tests: 31 new, 7 old expectations changed (`require-result` answers only `'false'`). 728 in
  total.
- README (WG010 row, How it works, limitations), CHANGELOG v0.25.0, version 0.25.0.

Verified locally:
- `pytest -q -W error`: 728 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.25.0, 0 errors (warning: v0.25.0 not tagged yet).
- Corpus: 100 -> 23 WG010 findings; all rules together run on all 148 files without errors.
  workflow-guard, LendLoop, fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 15 mutants (event name unknown, must_pass as may_pass in conditions and in
  `_denies`, no line join, any ref as checkout, old commenter-gate rule, continue-on-error
  ignored, no deny steps, setFailed not a failure, one needed result only, `_answers` for
  outputs, `require` ignored, no action answers, `_said` always true, only failed needs), all
  killed (one after adding a test).

## 2026-11-20 (scheduled run): WG010 checks that `always()` runs past

Why: next step 3 (step 1, tagging v0.23.0, was done on 2026-11-19; step 2 needs a survey of
public workflows). A step that fails on a no, or a needed job that fails or is skipped for a
stranger, counted as a check for everything after it. GitHub only adds `success() &&` to an
`if:` without a status function, so `always()`, `failure()` or `${{ !cancelled() }}` ran the
step or job anyway.

Acceptance criteria:
- A dependent job whose `if:` has a status function counts a needed job's check only if the
  `if:` is false for a stranger with `success()` false, `failure()` true after a failure,
  `cancelled()` unknown, `always()` true and `needs.<job>.result` set (`failure`/`skipped`;
  a skipped job's outputs empty). Without a status function nothing changes.
- The same for a step after a step that fails on a no (high for a checkout, medium for secrets).
- Chains: a job in the middle that runs anyway passes nothing on.
- Messages name the job or step check and the functions ("uses always(), so it runs anyway").
- v0.23.0 heading gets its date; v0.24.0 section and version.

Done:
- `conditions.py`: `STATUS_FUNCTIONS`, `status_functions(text)`; `evaluate` asks the lookup
  for `success()`, `failure()`, `cancelled()`.
- `rules.py`: `_runs_anyway`, `_output_paths`, `_function_words`, `_stranger_result`
  ("skipped"/"failure"/None), `_alone`; `_job_checks_commenter` uses them for every needed
  job; `comment_commands` opens steps after the stop that run anyway; `_why_open(anyway=)` and
  a note for a needed job that the job runs past.
- Tests: 45 new (`test_wg010.py`, `test_conditions.py`), 697 in total.
- README (WG010 row, How it works, limitations), CHANGELOG v0.24.0, version 0.24.0.

Verified locally:
- `pytest -q -W error`: 697 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.24.0, 0 errors (warning: v0.24.0 not tagged yet).
- CLI on a demo workflow (`test` needs a `gate` with `xt0rted/slash-command-action` and has
  `${{ !cancelled() }}`; `report` has `if: always()` with a secret after its own check): main
  0 findings, exit 0; this branch WG010 high (line 17) and medium (line 18), exit 1.
  workflow-guard, LendLoop, fitness-workout-log, transit-raptor: same output as main.
- Mutation checks: 13 mutants (success() unknown, failure() unknown/always false, cancelled()
  false, needs.result unset, skipped outputs not empty, needed-job check ignoring status
  functions, steps after the stop never open, late secret note always, `_alone` ignoring
  ancestors, "is skipped" wording, status functions not looked up, duplicates), all killed
  (two after adding tests).

## 2026-11-19 (scheduled run): WG010 permission checks that come too late or let a no through

Why: next step 2 (step 1, tagging v0.22.0, was done on 2026-11-17). A permission step that fails
on a no covered the whole job, even a `gh pr checkout` that runs before it. And any `if:` that
mentioned a reporting step's answer covered its step: `steps.perm.outputs.require-result`
alone (the text `false` is truthy), `!= 'false'` (fails open on an empty or misspelt output) and
`steps.perm.outcome == 'success'` on a step that never fails all counted.

Acceptance criteria:
- A failing permission step covers only the steps after it in its job; a checkout before it is
  high, secrets before it are medium, and the message names the late step. Job-level `env:`
  secrets don't count when nothing before the check uses secrets. In a needed job, order
  doesn't matter.
- An `if:` reading `steps.<id>` of a reporting step counts only if it is false for every
  answer in `NO_ANSWERS` (empty, `false`, `none`, `read`) and every association that can't
  write; `outcome` is `success`, or `failure` for a failing step with `continue-on-error`.
- The same for a job `if:` on `needs.<job>.outputs.<name>`, after working out the output's own
  expression (text around it kept; an unknown part makes it unknown).
- Messages name the answers that still pass ("is still true when it answers nothing, 'none' or
  'read'", or "anything").
- v0.22.0 heading gets its date; v0.23.0 section and version.

Done:
- `conditions.py`: `NO_ANSWERS`, `may_pass(condition, lookup)`, `text_value(expression, lookup)`.
- `rules.py`: `_asks` (fails on a no before continue-on-error), `_stop_step`, `_no_answers`,
  `_passing`, `_answer_words`, `_answer_gate`, `_output_text`, `_needed_answer_gate`;
  `_answer_outputs` returns the raw values; `_why_open(..., stop=)`; `comment_commands` only
  looks at the steps before the first failing permission step.
- Tests: 2 old cases changed (`outcome == 'success'` on a github-script that never fails, and a
  bare `steps.checkperm.outputs.require-result`, are no check any more), 43 new
  (`test_wg010.py`, `test_conditions.py`). 652 in total.
- README (WG010 row, How it works, limitations), CHANGELOG v0.23.0, version 0.23.0.

Verified locally:
- `pytest -q -W error`: 652 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.23.0, 0 errors (warning: v0.23.0 not tagged yet).
- CLI on a demo workflow (a `test` job gated by `!= 'false'`, a `deploy` job with
  `gh pr checkout` before `xt0rted/slash-command-action`): main 0 findings, exit 0; this branch
  two WG010 high (lines 13 and 22), exit 1. workflow-guard, LendLoop, fitness-workout-log,
  transit-raptor, GaTe-parking, market-pulse, tracker, DriverBro: same output as main (none has
  an `issue_comment` workflow, so this only shows nothing else moved).
- Mutation checks: 15 mutants (outcome always success, an answer dropped from NO_ANSWERS twice,
  order ignored, nothing before the stop, needed-job gate always true, job-level secrets with a
  stop, stop in needed job ignored, conclusion failure, bad `if:` passing nothing, unknown
  output parts, text around an output dropped, `may_pass` only on certain truth, stop note
  dropped, "anything" wording), all killed (three after adding tests).

## 2026-11-17 (scheduled run): WG010 permission steps that only report

Why: next step 2 (step 1, tagging v0.22.0, needs the owner). A permission step counted as a
check whatever it did with the answer. `actions-cool/check-user-permission` only sets
`require-result` unless `error-if-missing: true` (its README), `sushichop/action-repository-permission`
exits 0 with `relax: true`, and a github-script that `return`s the answer never fails. A weak
check in a `needs:` job didn't count, but the message didn't say so.

Acceptance criteria:
- A permission step covers the whole job only if it fails on a no: known actions (with their
  switch input), `core.setFailed`/`throw`/`process.exit(1)` in a github-script, `exit 1` or a
  bare `| grep -q` in a script; `continue-on-error: true` turns that off.
- A step that only reports covers the steps whose `if:` reads `steps.<id>` (ids without case),
  and the jobs whose `if:` reads a job output carrying it (`needs.<job>.outputs.<name>`).
  Secrets only in covered steps aren't reported.
- Messages name the permission step (and its job, when it's a needed one) and a weak `if:` in a
  needed job.
- v0.22.0 isn't tagged yet, so the notes go into its CHANGELOG section (a v0.23.0 section would
  fail release_check: a version that is neither in the code nor tagged).

Done:
- `rules.py`: `_PERMISSION_ACTIONS` dict with switch inputs, `_STOPS`, `_permission_check`
  (`_FAILS`/`_REPORTS`), `_answers`, `_waits_for_answer`, `_answer_outputs`, `_needed_jobs`,
  `_weak_note`; `_why_open(wf, job_id, what, ...)`; `_scalars(skip=)` for secrets.
- Tests: 20 more in `test_wg010.py` (2 old cases changed: actions-cool without
  `error-if-missing` and `gh api ... --jq .permission` alone are no check any more). 609 in total.
- README (WG010 row, How it works, limitations), CHANGELOG v0.22.0 section.

Verified locally:
- `pytest -q -W error`: 609 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.22.0, 0 errors (warning: v0.22.0 not tagged yet).
- CLI on a `/test` workflow with `actions-cool/check-user-permission` (id, no
  `error-if-missing`) before a PR checkout: one WG010 high naming line 11, exit 1; with
  `error-if-missing: true`: 0 findings, exit 0. workflow-guard, lendloop, fitness-workout-log,
  transit-raptor, GaTe-parking: same output as main.
- Mutation checks: 15 mutants (switch inputs flipped, continue-on-error ignored, grep/exit not
  stops, grep in an `if` or before `||` counted, step `if:` on the answer ignored or any `if:`
  accepted, job outputs ignored, needs answer ignored, answers counted as failing, covered
  secrets counted, needed weak note dropped, ids case-sensitive), all killed (two after adding
  tests: the needed-job note assertion hadn't been applied, and a mixed-case id).

## 2026-11-15 (scheduled run): WG010 weak checks

Why: next step 2 (step 1, the v0.21.0 release, was already published). Any mention of the
commenter in an `if:` counted as a check, so `author_association != 'NONE'` (CONTRIBUTOR and
FIRST_TIME_CONTRIBUTOR still get in) silenced WG010. Projects gate `issue_comment` jobs on
OWNER/MEMBER/COLLABORATOR (e.g. google/adk-python), and Wiz's "Pwn Request Reckoning" warns that
author_association is easy to get wrong.

Acceptance criteria:
- A job or step `if:` counts as a check only if it is certainly false for every
  author_association that can't write (CONTRIBUTOR, FIRST_TIME_CONTRIBUTOR, FIRST_TIMER,
  MANNEQUIN, NONE) and for a commenter login that equals no login written in the workflow.
- Allow-lists still pass: `==`, `contains(fromJSON('[...]'), ...)`, `contains('A,B', assoc)`,
  `vars.*` / `secrets.*` lists. Deny-lists, substring login checks, `startsWith(github.actor..)`,
  `|| <comment text>` and `|| always()` don't.
- The message names who still gets in (the associations, or "every account it doesn't name");
  this replaces the "only looks at the comment's text" note when both apply.
- An `if:` that isn't a valid expression is no check (as before). A weak check in a `needs:` job
  doesn't count.
- Release notes in CHANGELOG.md; v0.21.0's heading gets its date.

Done:
- `src/workflow_guard/conditions.py`: recursive-descent parser on the existing tokenizer,
  three-valued evaluator (UNKNOWN, STRANGER, OWNERS_LIST), GitHub's loose equality and
  case-insensitive strings, contains/startsWith/endsWith/fromJSON/always; `lets_in()`.
- `rules.py`: `_commenter_gate()` replaces the mention test in the job, step and `needs:` checks;
  `_why_open()` replaces `_body_only()`.
- Tests: `test_conditions.py` (61), 8 more in `test_wg010.py`. 589 in total.
- README (WG010 row, How it works, layout, limitations), CHANGELOG v0.22.0, version 0.22.0.

Verified locally:
- `pytest -q -W error`: 589 passed. `ruff check`, `ruff format --check`: clean.
- `release_check.py`: version 0.22.0, 0 errors (warning: v0.22.0 not tagged yet).
- CLI on a workflow with `author_association != 'NONE'` and `gh pr checkout`: one WG010 high
  naming the four associations, exit 1. lendloop, fitness-workout-log, transit-raptor,
  GaTe-parking: unchanged (no issue_comment workflows).
- Mutation checks: 12 mutants (case-sensitive strings, unknown `&&` taking the right side, a
  stranger equal to nothing known, owners' lists not excluding strangers, substring login check
  counted as safe, only certain-true counted as letting in, `!` dropped, owners' values truthy,
  no short-circuit, no number coercion, `always()` unknown), all killed (one after adding a
  test for `!vars.LOCKED`).

## 2026-11-14 (interactive): a settings file

Why: picked by the owner ("Config file"). `ignore`, the levels and `script-inputs` had to be
repeated in the workflow, the pre-commit configuration and the shell.

Acceptance criteria:
- `.github/workflow-guard.yml` or `.yaml` with `ignore`, `min-severity`, `fail-on`,
  `script-inputs` (lists or comma/space-separated strings); found from the current folder up
  to the repository root (the folder with `.git`); `--config FILE`, `--no-config`.
- Command-line options win; `ignore` and `script-inputs` add up; defaults stay `low`.
- Errors (exit 2, message with the file name): unknown keys, unknown rule ids, bad levels, bad
  script inputs, wrong types, invalid YAML, an unreadable `--config`. `--list-rules` doesn't
  read the file. The file isn't checked as a workflow.
- Action: new `config` input (`none` = `--no-config`); `fail-on`/`min-severity` default to ""
  and are passed only when set. CI runs the action with a settings file.
- Release notes in CHANGELOG.md in this pull request; v0.20.0's heading gets its date.

Done:
- `src/workflow_guard/config.py` (`find_config`, `parse_config`, `load_config`); `cli.py`
  (`_settings`, `_apply`, options without defaults); `action.yml`; fixture
  `tests/fixtures/workflow-guard-config.yml` and a CI step.
- Tests: `test_config.py` (26), 1 more in `test_distribution.py`. 520 in total.
- README (Settings file, inputs table, usage), CHANGELOG v0.21.0, version 0.21.0.

Verified locally:
- `pytest -q -W error`: 520 passed. `ruff check`, `ruff format --check`: clean.
- `unsafe-workflow.yml` with `--config tests/fixtures/workflow-guard-config.yml`: exit 0;
  without: exit 1.
- Mutation checks: 15 mutants (search past the repository root, no `.yaml`, unknown keys or
  rule ids accepted, no upper-casing, strings not split, script inputs unchecked, empty file,
  ignore/script-inputs not combined, config level winning over the option, config fail-on
  unused, `--no-config`/`--config` ignored, the action not passing `config`), all killed (one
  after fixing a test that passed either way).

## 2026-11-14 (interactive): WG010 comment commands

Why: picked by the owner ("WG010 issue_comment"). `issue_comment` runs with secrets and a write
token for any commenter; a `/test` job that checks out `refs/pull/N/head` and only matches
`startsWith(github.event.comment.body, '/test')` runs a stranger's code with those secrets.
None of WG001-WG009 looked at who triggered a comment command.

Acceptance criteria:
- Only `issue_comment` (a fork's `pull_request_review_comment` runs without secrets).
- High, at the step: `actions/checkout` whose `ref:`/`repository:` names the PR (`refs/pull/`,
  `github.event.issue.number`, `github.event.issue.pull_request`, `github.event.pull_request`,
  `github.head_ref`, or a step/job output), or a script with `gh pr checkout`,
  `pull/<n>/head|merge`, `refs/pull/`.
- Medium, at the job: no PR checkout but `secrets.*` other than `GITHUB_TOKEN`.
- A check: the commenter (`author_association`, login, `github.actor`, `github.triggering_actor`)
  in the job's `if:` (with or without `${{ }}`) or the step's; a permission step (6 known
  actions, `getCollaboratorPermissionLevel`, `collaborators/<user>/permission`); either in a job
  reached through `needs:` (loops end).
- A body-only `if:` is named in the message as no check.
- Release notes in CHANGELOG.md in this pull request; v0.19.0's heading gets its date.

Done:
- `rules.py`: `comment_commands` (WG010) with `_job_checks_commenter`, `_checks_out_pr`,
  `_checks_permission`, `_uses_secrets`, `_body_only`.
- Tests: `test_wg010.py` (33). 493 in total. `--list-rules` lists 10 rules.
- README (WG010 row, limitations), CHANGELOG v0.20.0, version 0.20.0.

Verified locally:
- `pytest -q -W error`: 493 passed. `ruff check`, `ruff format --check`: clean.
- Demo: a `/test` workflow with a body-only `if:` and a `refs/pull/N/head` checkout gives the
  high finding with the body note; adding the `author_association` allow-list gives 0.
- Mutation checks: 21 mutants (each commenter path, permission actions and API pattern, PR
  ref patterns, job/step/needs checks, GITHUB_TOKEN exception, secrets only without a
  checkout, `${{ }}` in `if:`, step body note, script patterns, the trigger), all killed (one
  after adding a `refs/pull/${{ env.PR }}` case).

## 2026-11-14 (interactive): your own actions that run a script

Why: picked by the owner ("Custom script inputs"). v0.18.0's list of script-running actions is
fixed; an in-house `my-org/deploy` with `commands: ./release.sh "${{ github.event.pull_request.title }}"`
stayed unreported.

Acceptance criteria:
- `--script-input owner/repo[/path]:input[,input]`, repeatable; the same action twice adds up;
  names without case. Malformed values (no `:`, no inputs, `@version`, `./local`, `docker://`,
  odd characters) fail argument parsing (exit 2) with a clear message.
- The action's `script-inputs` input (spaces or new lines) passes one `--script-input` per value,
  through `env:` (no `${{ }}` in the script) and after `set -f`.
- WG004 and WG008 check the named inputs like `run:`; the message names the action; a listed
  action keeps its own inputs and advice; github-script keeps its message.
- CI runs the action on a fixture both ways (clean without, failing with `script-inputs`).
- Release notes in CHANGELOG.md in this pull request; v0.18.0's heading gets its date.

Done:
- `scripts.py`: `parse_script_input`, `merge_script_inputs`, `scripts(step, extra)`;
  `Workflow.script_inputs`; `cli.py`: `--script-input`; `action.yml`: `script-inputs`;
  `tests/fixtures/custom-script-input.yml` and two steps in the CI action job.
- Tests: 21 more in `test_script_inputs.py`, 1 in `test_distribution.py`. 460 in total.
- README (option, action input, "Your own actions", limitations), CHANGELOG v0.19.0, version
  0.19.0.

Verified locally:
- `pytest -q -W error`: 460 passed. `ruff check`, `ruff format --check`: clean.
- The fixture: 0 findings without the option; WG004 naming `my-org/deploy` with
  `--script-input other-org/tool:run --script-input my-org/deploy:commands`.
- Mutation checks: 13 mutants (extra inputs ignored, for github-script or a listed action,
  merging, lower-casing, both validations, a leading dot allowed, rules not passing the
  inputs, the CLI not setting or validating them, the action not passing them), all killed.

## 2026-11-13 (interactive): WG004 for actions that run a script

Why: picked by the owner ("WG004 for more actions"). WG004 and WG008 only looked at `run:` and
github-script; `appleboy/ssh-action`'s `script: echo "${{ github.event.pull_request.title }}"`
runs the same injected command on a production server and went unreported.

Acceptance criteria:
- A table of 14 actions and their script inputs (`scripts.py`); action and input names match
  without case, any ref; local (`./`) and `docker://` steps never match.
- WG004 and WG008 check those inputs exactly like `run:` (same tracker, detours, line offsets,
  inline ignores); the message ends with the action and input, plus how to get a variable to
  the script where `env:` doesn't reach it (SSH, containers).
- github-script keeps its old messages; other inputs (`host:`, `key:`) aren't checked.
- Release notes in CHANGELOG.md in this pull request; v0.17.0's heading gets its date.

Done:
- `src/workflow_guard/scripts.py` (`SCRIPT_INPUTS`, `scripts(step)`, `Script.hint()`), used by
  WG004 and WG008. Rule summary/help updated.
- Tests: `test_script_inputs.py` (41). 438 in total.
- README (WG004 row, "Actions that run a script", limitations), CHANGELOG v0.18.0, version
  0.18.0.

Verified locally:
- `pytest -q -W error`: 438 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks: 9 mutants (case-sensitive inputs or actions, empty note separator, a hint
  for github-script, docker:// as an action, no run:, hints dropped from WG004/WG008), all
  killed (the docker:// one after adding a digest case).

## 2026-11-13 (interactive): WG009 follow-ups

Why: picked by the owner ("WG009 follow-ups"). WG009 (v0.16.0) only saw `actions/checkout`; the
same attack written as `git fetch origin $SHA && git checkout FETCH_HEAD` in a script went
unreported. And its limitations said `branches:` filters "aren't read", as if they could make a
workflow safe; they can't (a fork picks its branch name).

Acceptance criteria:
- High: a `run:` line with `git checkout|switch|fetch|pull|reset|worktree add` (also
  `git -C dir ...`) and a reference to the triggering run's head, directly or through an `env:`
  variable of the workflow, job or step (`$X`, `${X}`, `${{ env.X }}`; step overrides job
  overrides workflow); `gh pr checkout` with any reference to the triggering run. `\`
  continuations are joined; other lines don't count.
- No finding for `git checkout main`, `gh pr checkout 12`, `gh pr view <run PR>`, or a head SHA
  only echoed.
- A `branches:`/`branches-ignore:` filter under `on.workflow_run` is named in WG009 messages as
  no protection; trusted triggering workflows are still not reported.
- Release notes written in CHANGELOG.md in this pull request (the new release process).

Done:
- `rules.py`: `_script_checks_out_run`, `_env_naming`, `_names`, `_branch_filter_note`.
- Tests: 31 more in `test_wg009.py`. 397 in total.
- README (WG009 row, limitations), CHANGELOG.md `v0.17.0`, version 0.17.0.

Verified locally:
- `pytest -q -W error`: 397 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks: 13 mutants (no continuation joining, whole script as one line, no
  `${{ env.X }}`, no `$X`, wrong env override order, gh pr checkout without a run reference, no
  git command required, no `-C`, no `worktree add`, no `branches-ignore`, no branch note), all
  killed.

## 2026-11-13 (interactive): CHANGELOG.md

Why: picked by the owner ("CHANGELOG.md"). The release notes of 13 versions lived only on
GitHub, and each was written in a separate draft file after the merge. Now the notes are written
in the pull request that bumps the version, reviewed with the code, and the release is published
from them.

Acceptance criteria:
- CHANGELOG.md has one section per release, newest first: `## <release title> (<date>)`, then
  the release notes with headings one level deeper and without a first heading that repeats the
  title. Generated from the 13 published releases; `notes` gives back each release's text.
- `scripts/release_notes.py`: `notes vX` / `title vX` for `gh release create`, `sync` to copy
  edited releases back. Standard library only.
- Release check errors: no CHANGELOG.md; no section for the version in the code (so a bump PR
  must bring its notes) or for a tag; a section for a version that is neither; not newest
  first; a duplicate section; with `--releases`, a title or text that differs from the GitHub
  Release. Warning: a date that differs. A missing date is fine (written before the release).
- On this repository: 0 errors.

Done:
- `scripts/release_notes.py`, `CHANGELOG.md` (13 sections), `check_changelog()` in
  `scripts/release_check.py`; releases are now read with `gh api .../releases` (title, text and
  date in one call).
- Tests: `test_release_notes.py` (11), 12 more in `test_release_check.py`. 366 in total.
- README: the Releasing steps now start from CHANGELOG.md. No version bump: the package is
  unchanged.

Verified locally:
- `pytest -q -W error`: 366 passed. `ruff check`, `ruff format --check`: clean.
- `python scripts/release_check.py --releases`: version 0.16.0, 13 tags, 0 errors.
- `release_notes.py notes` gives each release's exact text for v0.4.0-v0.11.0 and v0.16.0;
  for v0.12.0-v0.15.0 the same minus the first heading that repeated the title.
- Mutation checks: 11 mutants (ordering by text, skipped tag/section checks, comparing raw
  bodies, case-sensitive title match, headings inside code blocks, sync dropping unreleased
  sections, notes not shifting headings back), all killed.

## 2026-11-13 (interactive): WG009 workflow_run

Why: picked by the owner ("WG009 workflow_run"). A `workflow_run` workflow runs with the base
repository's secrets and write token after a run that may have built a fork's pull request.
Checking out that run's commit, or unpacking its artifacts where later steps run commands, gives
the fork author's files those secrets. Nothing in WG001-WG008 sees it: no `${{ }}` reaches a
script, and WG005 only looks at `pull_request_target`.

Acceptance criteria:
- High: `actions/checkout` with `ref:`/`repository:` naming the triggering run's head
  (`head_sha`, `head_branch`, `head_commit`, `head_repository`, `pull_requests`).
- High: another run's artifacts unpacked into the workspace (`actions/download-artifact` with
  `run-id:` and no `path:` or `path: .`/`${{ github.workspace }}`, `dawidd6/action-download-
  artifact` with its default `./`, `gh run download` without `-D`) followed by a `run:` step or a
  local action in the same job. Medium otherwise, and for `downloadArtifact` in a github-script.
- A download of the run's own artifacts (no `run-id:`) isn't reported.
- No findings when every workflow listed under `on.workflow_run.workflows` is a checked file of
  the same repository (matched by `name:`, else by its path) and none runs on `pull_request` or
  `workflow_run`. An unknown name counts as untrusted. Messages name the untrusted workflow.
- The other rules' output is unchanged on the portfolio repositories.

Done:
- `rules.py`: `workflow_run` (WG009) with `_fork_runs`, `_artifact_download`.
- Tests: `test_wg009.py` (30). 343 in total. `--list-rules` now lists 9 rules.
- README: the WG009 row and its limitations. Version 0.16.0.

## 2026-11-13 (interactive): a Release check in CI

Why: picked by the owner ("Release check in CI") after four releases in one day (v0.12.0 to
v0.15.0). Each release is five manual steps (bump two files, merge, tag, push the tag, publish
notes); nothing caught a skipped one.

Acceptance criteria:
- Errors: pyproject.toml and `__version__` disagree; the version is older than the newest
  `v*` tag (numerically: 0.9.5 < 0.10.0); a pushed tag or published release doesn't match the
  code; an older tag has no GitHub Release.
- Warnings only (normal between steps): the version isn't tagged yet; the newest tag has no
  release yet.
- Runs on pull requests, pushes to main, `v*` tag pushes and published releases; passes
  workflow-guard's own checks; standard library only.
- On the current repository: 0 errors (version 0.15.0, 12 tags, all with releases).

Done:
- `scripts/release_check.py`: `check()` (pure), `git_tags`, `published_releases` (gh CLI),
  `report` (`::error::`/`::warning::` annotations in Actions), `main` (exit 0/1/2).
- `.github/workflows/release-check.yml`: full-history checkout, `GH_TOKEN: github.token`.
- Tests: `test_release_check.py` (15, one on a real temporary git repository). 313 in total.
- README: a Releasing section. No version bump: nothing in the package changed.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 313 passed. `ruff check`, `ruff format --check`: clean.
- `python scripts/release_check.py --releases` on this repository: 0 errors.
- workflow-guard on its own workflows (now 3 files): 0 findings.
- Mutation checks: comparing versions as text fails 1 test (added for exactly that), sorting
  tags as text 3, skipping the tag/ref match 1.

## 2026-11-13 (interactive): Milestone 15, every tainted caller in the message

Why: next step 2, picked by the owner ("List all callers"). Since milestone 12 a finding inside
a reusable workflow or action showed only the worst caller. With several callers passing a
title, fixing that one and re-running revealed the next one, one at a time.

Acceptance criteria:
- WG004 and WG007 findings on an input name every *other* local caller that passes untrusted
  text, after the existing message: `; other callers pass untrusted text too: <hop> ('<source>'); ...`.
- The worst caller still leads (the detour); others follow highest severity first, then in
  file order; no duplicates; callers passing clean values aren't listed.
- Works for reusable workflows (job callers) and actions (step callers), through env detours in
  the callee and through chains (a middle workflow's own callers are carried along).
- One tainted caller: message unchanged. No change on the five local repositories.

Done:
- `taint.py`: `Taint.callers`, `merge_callers` (worst first, others listed, nested lists kept).
- `calls.py`: `link_local_calls` collects every tainted value per input and merges them.
- `rules.py`: `_other_callers` suffix for WG004 (`_injection_message`) and WG007.
- Tests: `test_all_callers.py` (6). 298 in total. Version 0.15.0.

Verified locally (Python 3.14 venv):
- `pytest -q -W error`: 298 passed. `ruff check`, `ruff format --check`: clean.
- Mutation checks: no de-duplication fails 1 test, no severity ordering 2, dropping a middle
  caller's own list 1.
- Demo (scratch folder: triage.yml with the PR title, issues.yml with the issue title, push.yml
  with a constant, all calling label.yml): one high finding led by issues.yml, triage.yml listed,
  push.yml not.
- JSON output for workflow-guard, lendloop, fitness-workout-log, transit-raptor and
  GaTe-parking is byte-identical to v0.14.0's.

Note: the SARIF fingerprint includes the message, so a finding that gains a caller list gets a
new fingerprint in code scanning (the old alert closes, a new one opens).

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

1. Tag `v0.35.0` on the merge commit and publish its release from CHANGELOG.md (needs the owner).
2. `jscript.py`: `require()`d helper scripts of the checked repository (read the file and run
   its exported function), and array patterns (`const [a, b] = ...`, `([k, v]) =>`).
3. `shell.py`: simple arrays (`roles=(admin write)`, `${roles[@]}`) and `< <(...)` as an unknown
   input (5 of the 16 bash fallbacks).
4. WG005: a label gate with a step that removes the label (`labeled` + `actions-ecosystem/
   action-remove-labels` before the checkout) as a recognised pattern, with a note on the
   remaining race.
5. The Marketplace listing (needs the owner: it's a public listing under their account).
