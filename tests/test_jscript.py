"""jscript.py: does an actions/github-script step fail for a commenter who can't write?"""

import pytest

from workflow_guard.conditions import STRANGER, UNKNOWN, UNTRUSTED_ASSOCIATIONS
from workflow_guard.expressions import find_expressions
from workflow_guard.jscript import paste, run

API = (
    "const { data } = await github.rest.repos.getCollaboratorPermissionLevel({\n"
    "  owner: context.repo.owner,\n"
    "  repo: context.repo.repo,\n"
    "  username: context.actor,\n"
    "});\n"
)


def result(script: str, encoding: str = "json", **values: object):
    results = {
        repr(run(script, {int(k[1:]): v for k, v in values.items()}, a, encoding))
        for a in UNTRUSTED_ASSOCIATIONS
    }
    assert len(results) == 1 or "author_association" in script
    return run(script, {int(k[1:]): v for k, v in values.items()}, "NONE", encoding)


@pytest.mark.parametrize(
    "script",
    [
        API + "if (!['admin', 'write'].includes(data.permission)) { core.setFailed('no') }",
        API + "if (data.permission !== 'admin' && data.permission !== 'write') throw new Error(`no`);",
        API + "if (data.role_name === 'read') core.setFailed('read only')\n"
        "else if (data.permission === 'none') throw 1",
        API + "if (!data.user.permissions.push) { core.setFailed('x'); return }",
        API
        + "const ok = ['ADMIN', 'WRITE'].includes(data.permission.toUpperCase())\nif (!ok) process.exit(1)",
        # The answer under another name.
        "const r = await github.rest.repos.getCollaboratorPermissionLevel({...context.repo,"
        " username: context.payload.comment.user.login});\n"
        "const { data: { permission: level } } = r\n"
        "if (level != 'admin') core.setFailed(`${level}`)",
        # The 404 a non-collaborator gets is caught, and then the no is acted on.
        "let allowed = false\ntry {\n" + API + "  allowed = data.user.permissions.triage\n} catch (e) {\n"
        "  core.warning(e.message)\n}\nif (!allowed) core.setFailed('no')",
        "let ok\ntry {\n" + API + "  ok = data.permission === 'admin'\n} catch {\n  ok = false\n} finally {\n"
        "  core.info('done')\n}\nif (!ok) { throw new Error('nope') }",
        "const user = context.payload.sender.login\nconst extra = ['octocat']\n"
        "let can = false\ntry {\n" + API + "  can = data.user.permissions.triage\n} catch (e) {}\n"
        "if (can || extra.includes(user)) { core.info('ok') } else { core.setFailed('no') }",
    ],
)
def test_scripts_that_fail_on_a_no(script):
    r = result(script)
    assert r is not None
    assert (r.fails, r.asked) == (True, True)


@pytest.mark.parametrize(
    ("script", "outputs"),
    [
        (API + "return ['admin', 'write'].includes(data.permission)", [{"result": "false"}]),
        (
            API + "core.setOutput('allowed', data.permission === 'admin' ? 'yes' : 'no')",
            [{"allowed": "no", "result": ""}],
        ),
        (
            API + "core.setOutput('level', data.permission)",
            [{"level": "none", "result": ""}, {"level": "read", "result": ""}],
        ),
        (API + "return data.permission", [{"result": '"none"'}, {"result": '"read"'}]),
        (API + "return { ok: false, who: 'x' }", [{"result": '{"ok":false,"who":"x"}'}]),
        # An early return when the comment isn't the command: a path that succeeds.
        (
            "if (!context.payload.comment.body.startsWith('/go')) return;\n"
            + API
            + "if (data.permission !== 'admin')"
            " throw new Error('no')",
            [{"result": ""}],
        ),  # fmt: skip
        # A caught 404 that only reports.
        (
            "try {\n"
            + API
            + "  core.setOutput('ok', String(data.permission === 'write'))\n} catch (error) {\n"
            "  core.setOutput('ok', 'false')\n}",
            [{"ok": "false", "result": ""}],
        ),  # fmt: skip
    ],
)
def test_scripts_that_report(script, outputs):
    r = result(script)
    assert r is not None
    assert (r.fails, r.asked) == (False, True)
    assert r.outputs == outputs


def test_result_encoding_string():
    r = result(API + "return data.permission === 'admin'", encoding="string")
    assert r.outputs == [{"result": "false"}]
    r = result(API + "return data.permission", encoding="string")
    assert r.outputs == [{"result": "none"}, {"result": "read"}]


@pytest.mark.parametrize(
    ("script", "fails"),
    [
        (
            "const a = context.payload.comment.author_association\n"
            "if (a !== 'OWNER' && a !== 'MEMBER') core.setFailed('x')",
            True,
        ),
        ("if (context.payload.comment.author_association === 'NONE') core.setFailed('x')", False),
        ("if (context.actor !== 'octocat') { throw new Error('only octocat') }", True),
        ("if (context.actor === 'spam-bot') { throw new Error('no bots') }", False),
        ("if (context.eventName === 'issue_comment') core.setFailed('comments are off')", True),
        # A template with the login alone is the login; with text around it, unknown text.
        ("const who = `${context.actor}`\nif (who !== 'a') core.setFailed('x')", True),
        ("const who = `@${context.actor}`\nif (who !== '@a') core.setFailed('x')", False),
        (
            "const ok = ['OWNER', 'MEMBER'].includes(context.payload.comment.author_association)\n"
            "if (!ok) core.setFailed('x')",
            True,
        ),
        ("const user = context.actor.toLowerCase()\nif (user !== 'octocat') core.setFailed('x')", True),
        ("const o = context.payload.comment ?? {}\nif (o.author_association !== 'OWNER') throw 'x'", True),
        ("const login = context.payload.comment?.user?.login\nif (login !== 'a') throw 'x'", True),
    ],
)
def test_checks_without_the_api(script, fails):
    r = run(script, {}, "CONTRIBUTOR")
    assert r is not None and r.fails is fails and r.asked is False


def test_another_users_permission_is_not_followed():
    script = (
        API.replace("context.actor", "'octocat'") + "if (data.permission !== 'admin') core.setFailed('x')"
    )
    r = result(script)
    assert r is not None and r.asked is False and r.fails is False


@pytest.mark.parametrize(
    "script",
    [
        API + "if (!['admin'].some(p => p === data.permission)) core.setFailed('x')",
        "function check() { return false }\nif (!check()) core.setFailed('x')",
        "for (const p of ['a']) { core.setFailed(p) }",
        "while (true) { break }",
        "switch (context.actor) { default: core.setFailed('x') }",
        "class A {}",
        "const [a, b] = [1, 2]",
        "core.setOutput(context.actor, 'x')",
        "const x = cond ? process.exit(1) : 0",
        "let s = 'unclosed",
        "const t = `${unclosed`",
        "/* unclosed",
        "x = /unclosed",
        "x++",
        "const s = '\\u0041'",
    ],
)
def test_scripts_it_doesnt_follow(script):
    assert run(script, {}, "NONE") is None


def pasted(script: str) -> str:
    return paste(script, [(e.start, e.end) for e in find_expressions(script)])


def test_pasted_expressions():
    script = pasted(
        "const a = '${{ github.event.comment.author_association }}'\n"
        "if (a !== 'OWNER') core.setFailed(`${{ github.actor }}`)"
    )
    assert run(script, {0: "NONE", 1: STRANGER}, "NONE").fails is True
    assert run(script, {0: UNKNOWN, 1: STRANGER}, "NONE").fails is False
    bare = pasted("const n = ${{ github.event.issue.number }}\nif (n) core.setFailed('x')")
    assert run(bare, {0: "7"}, "NONE").fails is True
    mixed = pasted("const t = 'by ${{ github.actor }}'\nif (t !== 'by x') core.setFailed('x')")
    assert run(mixed, {0: STRANGER}, "NONE").fails is False
    template = pasted("const t = `${{ github.actor }}`\nif (t !== 'x') core.setFailed('x')")
    assert run(template, {0: STRANGER}, "NONE").fails is True


@pytest.mark.parametrize(
    ("script", "fails"),
    [
        # Values and operators.
        ("if (1 + 1 !== 2) core.setFailed('x')", False),
        ("if ('a' + 1 === 'a1') core.setFailed('x')", True),
        ("if (null == undefined) core.setFailed('x')", True),
        ("if (null === undefined) core.setFailed('x')", False),
        ("if ([1, 2].length === 2 && 'ab'.length === 2) core.setFailed('x')", True),
        ("if (['a', 'b'].indexOf('b') === 1) core.setFailed('x')", True),
        (
            "if ('abc'.startsWith('a') && 'abc'.endsWith('c') && ' a '.trim() === 'a') core.setFailed('x')",
            True,
        ),
        ("if (JSON.stringify({a: [1, true, null]}) === '{\"a\":[1,true,null]}') core.setFailed('x')", True),
        ("if (Boolean('') || String(false) !== 'false') core.setFailed('x')", False),
        ("let x = 1\nx = 2\nif (x === 2) core.setFailed('x')", True),
        ("let x = 1\nx += 1\nif (x === 1) core.setFailed('x')", False),
        ("const o = {a: 1}\no.a = 2\nif (o.a === 1) core.setFailed('x')", False),
        ("if (typeof x === 'string') core.setFailed('x')", False),
        ("if (void 0 === undefined && -(1) === -1 && !0) core.setFailed('x')", True),
        ("const a = null\nconst b = a.c\ncore.setFailed('x')", True),  # throws
        ("const a = null\nconst b = a?.c\nif (b === undefined) core.setFailed('x')", True),
        ("if (null ?? 'd') core.setFailed('x')", True),
        ("if ([...context.labels].length) core.setFailed('x')", False),
        ("const {a, b: {c}} = {a: 1, b: {c: 2}}\nif (a + c === 3) core.setFailed('x')", True),
        ("// a comment\n/* another */ if (1) core.setFailed('x');;", True),
        ("if (/x/.test('x')) core.setFailed('x')", False),  # a regex: unknown
        ("if (0x10 === 16 && 1_000 === 1000 && .5 === 0.5) core.setFailed('x')", True),
        ("const a = 1, b = 2\nif (a < b) core.setFailed('x')", False),  # < isn't followed
        ("if ('a' in {a: 1} || ('x', 0)) core.setFailed('x')", False),
        ("new Error('x')\ncore.setFailed('x')", True),
        ("if (`a${1}b` === 'a1b') core.setFailed('x')", True),
        ("return\ncore.setFailed('x')", False),
        ("process.exit(0)", False),
        ("await process.exit(2)", True),
        ("process.exit(code)", False),
    ],
)
def test_expressions(script, fails):
    r = run(script, {}, "NONE")
    assert r is not None and r.fails is fails


@pytest.mark.parametrize(
    ("script", "fails"),
    [
        # The 404 (or any other call's error) goes to catch, which may let the script pass.
        (
            "let ok = false\ntry {\n"
            + API
            + "  ok = data.permission === 'admin'\n} catch (e) {\n  ok = true\n}\n"
            "if (!ok) core.setFailed('x')",
            False,
        ),  # fmt: skip
        (
            "let ok = false\ntry {\n  await github.rest.issues.get({})\n} catch (e) {\n  ok = true\n}\n"
            "if (!ok) core.setFailed('x')",
            False,
        ),  # fmt: skip
        (
            "let ok = false\ntry {\n  const b = null.c\n} catch (e) {\n  ok = true\n}\n"
            "if (!ok) core.setFailed('x')",
            False,
        ),
        # finally runs either way.
        ("let x\ntry {\n  x = 1\n} finally {\n  core.setFailed('x')\n}", True),
        # A login is never empty.
        ("if (context.actor) core.setFailed('x')", True),
        # A list with an unknown element may hold anything.
        ("if (![context.payload.comment.body].includes('/go')) core.setFailed('x')", False),
        # || and ? : on an unknown value go both ways.
        ("const v = context.payload.comment.body || 'none'\nif (v === 'none') core.setFailed('x')", False),
        ("const v = context.payload.comment.body ? 'a' : 'b'\nif (v === 'a') core.setFailed('x')", False),
        # After ...context.repo the other keys are unknown.
        ("const o = {...context.repo, a: 1}\nif (o.b === undefined && o.a === 1) core.setFailed('x')", False),
    ],
)
def test_paths(script, fails):
    r = run(script, {}, "NONE")
    assert r is not None and r.fails is fails


def test_set_output_writes_json_for_anything_but_text():
    r = result(API + "core.setOutput('ok', data.permission === 'admin')\ncore.setOutput('n', null)")
    assert r.outputs == [{"ok": "false", "n": "", "result": ""}]
