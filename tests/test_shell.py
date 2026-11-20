"""shell.py: does a bash script exit for a commenter who can't write?"""

import pytest

from workflow_guard.conditions import STRANGER, UNTRUSTED_ASSOCIATIONS
from workflow_guard.shell import always_fails


def fails(script: str, **variables: object) -> bool:
    """For every association that can't write (A), with a stranger's login (L)."""
    results = {always_fails(script, {"A": a, "L": STRANGER, **variables}) for a in UNTRUSTED_ASSOCIATIONS}
    assert len(results) == 1, "the same for every association"
    return results.pop()


@pytest.mark.parametrize(
    "script",
    [
        'case "$A" in\n  OWNER|MEMBER|COLLABORATOR) ;;\n  *) echo "no"; exit 1 ;;\nesac\n',
        "case $A in (OWNER) echo ok ;; (*) exit 2 ;; esac",
        'if [ "$A" != "OWNER" ] && [ "$A" != "MEMBER" ]; then\n  echo no\n  exit 1\nfi\necho ok',
        'if [[ "$A" == "OWNER" || "$A" == "MEMBER" ]]; then\n  echo ok\nelse\n  exit 1\nfi',
        'if [ "$A" = OWNER ]; then echo ok; elif [ "$A" = MEMBER ]; then echo ok; else exit 1; fi',
        '[[ "$A" =~ ^(OWNER|MEMBER|COLLABORATOR)$ ]] || exit 1',
        "[[ $A == OWN* ]] || exit 1",
        'test "$A" = OWNER || exit 1',
        '[ "$A" = OWNER -o "$A" = MEMBER ] || exit 1',
        '! [ "$A" != OWNER ] || exit 1',
        # `bash -e`: a failing test on its own line ends the script.
        '[[ "$A" == "OWNER" ]]\necho go',
        # A flag set in a case and checked later.
        'OK=false\ncase "$A" in OWNER|MEMBER) OK=true ;; esac\nif [ "$OK" != "true" ]; then exit 1; fi',
        # The login: a stranger is none of the names written down.
        'if [ "$L" != "octocat" ]; then exit 1; fi',
        '[ -z "$A" ] && exit 0\n[ "$A" = OWNER ] || exit 1',
        # Comments, redirections, continuations, ${VAR}.
        '# who?\ncase ${A} in OWNER) ;; *) echo "no #1" >> "$GITHUB_STEP_SUMMARY" 2>&1; exit 1;; esac # end',
        'if [ "$A" != OWNER ] \\\n  && [ "$A" != MEMBER ]; then exit 1; fi',
        # What a command prints is unknown, but it doesn't decide anything here.
        'NOW=$(date)\nCOUNT=`ls | wc -l`\n[ "$A" = OWNER ] || exit 1',
        # The event is known.
        'if [ "$E" = "workflow_dispatch" ]; then exit 0; fi\n[ "$A" = OWNER ] || exit 1',
    ],
)
def test_scripts_that_exit_for_everyone_who_cant_write(script):
    assert fails(script, E="issue_comment") is True


@pytest.mark.parametrize(
    "script",
    [
        # Deny-lists let the others through.
        'if [ "$L" = "bot" ]; then exit 1; fi',
        '[ "$A" != OWNER ] && echo "not the owner"\necho go',  # && isn't the last command
        # `set +e` turns off the exit on a failing test.
        'set +e\n[ "$A" = OWNER ]\necho go',
        'set +o errexit\n[ "$A" = OWNER ]\necho go',
        # Something unknown decides.
        'case "$A" in OWNER) exit 0;; esac\nif [ "$(gh api x)" -ge 5 ]; then exit 0; fi\nexit 1',
        '[ "$A" = OWNER ] || [ "$X" = yes ] || exit 1',
        '[ "$A" = OWNER ] || exit $CODE',
        '[ "$A" = OWNER ] || exit',
        # An exit in a pipeline ends only that part.
        '[ "$A" = OWNER ] || echo no | exit 1',
        # A compound command's status is not followed.
        'if [ "$A" = OWNER ]; then true; fi && exit 1',
        # Never exits.
        'echo "$A"',
        # Not followed: loops, functions, subshells, background jobs, heredocs, bad syntax.
        "for x in a; do exit 1; done",
        "while true; do exit 1; done",
        "check() { exit 1; }\ncheck",
        "( exit 1 )",
        "exit 1 &",
        "cat <<EOF\nx\nEOF\nexit 1",
        'echo "unclosed',
        'if [ "$A" = OWNER ]; then exit 1',
        "echo $(unclosed",
        # extglob isn't followed: unknown.
        "[[ $A == @(OWNER) ]] || exit 1",
    ],
)
def test_scripts_that_may_let_someone_through(script):
    assert fails(script) is False


def test_associations_are_told_apart():
    script = 'case "$A" in NONE|FIRST_TIMER) exit 1;; esac'
    assert always_fails(script, {"A": "NONE"}) is True
    assert always_fails(script, {"A": "CONTRIBUTOR"}) is False


def test_exit_codes():
    assert always_fails("exit 0", {}) is False
    assert always_fails("exit 256", {}) is False
    assert always_fails("exit 3", {}) is True
    assert always_fails("false", {}) is True  # bash -e
    assert always_fails("false || true", {}) is False
    assert always_fails(":", {}) is False


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ('[ -n "$L" ] || exit 1\nexit 1', True),
        ('[ -z "$L" ] && exit 0\nexit 1', True),
        ('[ "$L" = "$L" ] && exit 0\nexit 1', False),  # the same unknown name: can't tell
        ('[ "$L" ] || exit 0\nexit 1', True),
        ('[ "x$A" = "xOWNER" ] || exit 1', True),
        ('[ "$A" -eq 1 ] || exit 1', False),
        ('[[ "$A" == "OWN"* ]] || exit 1', True),
        ('[[ "$A" =~ [ ]] || exit 1', False),  # a bad regex
    ],
)
def test_tests(script, expected):
    assert fails(script) is expected


def test_too_many_paths_is_unknown():
    lines = [f'if [ "$X{i}" = y ]; then V{i}=1; else V{i}=2; fi' for i in range(8)]
    assert always_fails("\n".join([*lines, "exit 1"]), {}) is False


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        # A case pattern that may match (an unknown word) is followed both ways.
        ('case "$X" in yes) exit 0;; esac\nexit 1', False),
        # Case patterns are globs.
        ('case "$A" in *CONTRIB*|FIRST*|NONE|MANNEQUIN) exit 1;; esac', True),
        # `set -e` doesn't act inside an if condition, nor on a negated command.
        ('if [ "$A" = OWNER ]; then exit 1; fi', False),
        ('if [ "$A" = OWNER ]; [ "$A" = MEMBER ]; then exit 1; fi', False),
        ('! [ "$A" != OWNER ]\necho go', False),
        # bash -e without pipefail: a pipeline's status is its last part's.
        ('[ "$A" = OWNER ] || exit 1 | true\necho go', False),
        # -o, -a and -n decide.
        ('[ "$A" = OWNER -o "$A" != OWNER ] && exit 1\nexit 0', True),
        ('[ "$A" != OWNER -a "$A" = OWNER ] || exit 1\nexit 0', True),
        ('[ -n "$A" ] && exit 1\nexit 0', True),
        # [[ == ]] with a glob on the right.
        ('[[ "$A" == *[A-Z]* ]] && exit 1\nexit 0', True),
    ],
)
def test_more_shell(script, expected):
    assert fails(script) is expected
