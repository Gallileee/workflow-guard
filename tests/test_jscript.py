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
        "while (true) { break }",
        "for (let i = 0; i < 3; i++) {}",
        "for (const k in {a: 1}) {}",
        "[a, b] = [1, 2]",
        "const { [k]: v } = {}",
        "function f() { return f() }\nf()",
        "function f() { process.exit(1) }\nf()",
        "break",
        "outer: for (const x of [1]) { break outer }",
        "switch (context.actor) { default: core.setFailed('x') }",
        "class A {}",
        "function f(a = core.setFailed('x')) {}\nf()",
        "const { b = github.rest.repos.get() } = {}",
        "const { 'a' } = {}",
        "const { ...[a] } = {}",
        "core.setOutput(context.actor, 'x')",
        "const x = cond ? process.exit(1) : 0",
        "let s = 'unclosed",
        "const t = `${unclosed`",
        "/* unclosed",
        "x = /unclosed",
        "x++",
        "const s = '\\u{zz}'",
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


# --- functions, callbacks, loops ------------------------------------------------------------------


@pytest.mark.parametrize(
    "script",
    [
        API + "if (!['admin', 'write'].some(p => p === data.permission)) core.setFailed('x')",
        API + "if (!['admin', 'write'].some((p) => { return p === data.permission })) throw new Error('x')",
        API + "if (['none', 'read'].find(p => p === data.permission)) core.setFailed('x')",
        API + "if (!['admin'].every(p => p === data.permission)) core.setFailed('x')",
        API + "if (['admin'].filter(p => p === data.permission).length === 0) core.setFailed('x')",
        API + "if (!['ADMIN'].map(p => p.toLowerCase()).includes(data.permission)) core.setFailed('x')",
        API + "if (['admin', 'write'].findIndex(p => p === data.permission) === -1) core.setFailed('x')",
        # A function declared after it's called (hoisted), async, with a default.
        "if (!(await allowed(context.actor))) core.setFailed('no')\n"
        "async function allowed(user, levels = ['admin', 'write']) {\n"
        "  const { data } = await github.rest.repos.getCollaboratorPermissionLevel(\n"
        "    {...context.repo, username: user})\n"
        "  return levels.includes(data.permission)\n}",
        # An arrow in a const, an IIFE.
        "const check = async (user) => {\n"
        "  try {\n"
        "    const r = await github.rest.repos.getCollaboratorPermissionLevel(\n"
        "      {...context.repo, username: user})\n"
        "    return r.data.permission === 'admin'\n"
        "  } catch (e) { return false }\n}\n"
        "if (!(await check(context.actor))) core.setFailed('no')",
        "(() => { core.setFailed('always') })()",
        # A loop over the allowed levels.
        API + "let ok = false\nfor (const level of ['admin', 'write']) {\n"
        "  if (data.permission === level) { ok = true; break }\n}\n"
        "if (!ok) core.setFailed('x')",
        # A Map cache in front of the API.
        "const cache = new Map()\nasync function can(user) {\n"
        "  if (cache.has(user)) return cache.get(user)\n"
        "  const { data } = await github.rest.repos.getCollaboratorPermissionLevel(\n"
        "    {...context.repo, username: user})\n"
        "  const ok = ['admin', 'write'].includes(data.permission)\n  cache.set(user, ok)\n  return ok\n}\n"
        "if (!(await can(context.actor))) core.setFailed('x')\n"
        "if (!(await can(context.payload.comment.user.login))) core.setFailed('y')",
        API + "if (!new Set(['admin', 'write']).has(data.permission)) core.setFailed('x')",
    ],
)
def test_functions_and_callbacks_that_fail_on_a_no(script):
    r = result(script)
    assert r is not None and r.fails is True


@pytest.mark.parametrize(
    ("script", "fails"),
    [
        # A function's parameters and declarations are its own.
        (
            "const ok = false\nfunction f(ok) { const x = 1; return ok }\nf(true)\n"
            "if (!ok) core.setFailed('x')",
            True,
        ),
        ("let n = 'a'\nfunction f() { n = 'b' }\nf()\nif (n === 'b') core.setFailed('x')", True),
        ("let n = 'a'\nfunction f() { let n = 'b' }\nf()\nif (n === 'b') core.setFailed('x')", False),
        ("const f = x => x\nif (f('a') === 'a') core.setFailed('x')", True),
        ("function f(a = 'd') { return a }\nif (f() === 'd' && f('e') === 'e') core.setFailed('x')", True),
        # A throw inside a function goes to the caller's catch.
        (
            "function f() { throw new Error('x') }\nlet ok = false\ntry { f() } catch (e) { ok = true }\n"
            "if (ok) core.setFailed('x')",
            True,
        ),  # fmt: skip
        # Callbacks on an unknown list: an unknown result.
        ("if (context.payload.issue.labels.some(l => l.name === 'ok')) core.setFailed('x')", False),
        ("if (!context.payload.issue.labels.some(l => l.name === 'ok')) core.setFailed('x')", False),
        # ... and a side effect may happen or not.
        ("context.payload.issue.labels.forEach(l => core.setFailed('x'))", False),
        ("[1, 2].forEach(n => core.setFailed('x'))", True),
        ("[].forEach(n => core.setFailed('x'))", False),
        # A callback that isn't a function.
        ("if ([1].some(cb)) core.setFailed('x')", False),
        # for...of over an unknown list runs any number of times.
        (
            "let n = 0\nfor (const x of context.payload.issue.labels) { n = 1 }\n"
            "if (n === 1) core.setFailed('x')",
            False,
        ),
        ("for (const x of context.payload.issue.labels) { core.setFailed('x') }", False),
        ("for (const x of [1, 2]) { continue\ncore.setFailed('x') }", False),
        ("for (const x of ['a', 'b']) { if (x === 'b') core.setFailed('x') }", True),
        # Maps and Sets.
        ("const m = new Map([['a', 1]])\nif (m.get('a') === 1 && !m.has('b')) core.setFailed('x')", True),
        ("const s = new Set()\ns.add('a')\nif (s.has('a')) core.setFailed('x')", True),
        (
            "const m = new Map()\nm.set('a', 1)\nm.set('a', 2)\nif (m.get('a') === 2) core.setFailed('x')",
            True,
        ),
        ("const m = new Map()\nif (m.get('a') === undefined) core.setFailed('x')", True),
        # A stranger's login as a key may be another stranger's.
        (
            "const m = new Map([[context.actor, 1]])\n"
            "if (m.has(context.payload.sender.login)) core.setFailed('x')",
            False,
        ),
        # Escapes.
        ("if ('\\u0041\\x42\\u{43}' === 'ABC') core.setFailed('x')", True),
    ],
)
def test_functions_callbacks_loops(script, fails):
    r = run(script, {}, "NONE")
    assert r is not None and r.fails is fails


@pytest.mark.parametrize(
    ("script", "fails"),
    [
        # A function's own new names don't reach the caller.
        ("function f() { const leaked = true }\nf()\nif (leaked) core.setFailed('x')", False),
        # A callback on an unknown list may run (and change things) or not.
        (
            "let ok = false\ncontext.payload.issue.labels.forEach(l => { ok = true })\n"
            "if (!ok) core.setFailed('x')",
            False,
        ),
        # An element with an unknown test makes .some and .filter unknown.
        ("if (!['a', context.payload.comment.body].some(x => x === 'go')) core.setFailed('x')", False),
        (
            "if ([context.payload.comment.body].filter(x => x === 'go').length === 0) core.setFailed('x')",
            False,
        ),
        # break ends a loop over a known list.
        ("for (const x of ['a', 'b']) {\n  if (x === 'a') break\n  core.setFailed('x')\n}", False),
    ],
)
def test_more_functions_and_loops(script, fails):
    r = run(script, {}, "NONE")
    assert r is not None and r.fails is fails


PERMISSION = "github.rest.repos.getCollaboratorPermissionLevel({ ...context.repo, username: context.actor })"
THREW = "let threw = false\ntry { %s } catch { threw = true }\nif (!threw) core.setFailed('x')"


@pytest.mark.parametrize(
    "script",
    [
        # Two calls at once, the answers taken apart by position.
        "const [perm, issue] = await Promise.all([\n  " + PERMISSION + ",\n"
        "  github.rest.issues.get({ ...context.repo, issue_number: 1 }),\n])\n"
        "if (!['admin', 'write'].includes(perm.data.permission)) core.setFailed('no')",
        # An array pattern in a callback's parameters, over Object.entries.
        "const levels = { admin: true, maintain: true, write: true, read: false }\n"
        "const { data } = await " + PERMISSION + "\n"
        "const ok = Object.entries(levels).some(([level, yes]) => yes && level === data.permission)\n"
        "if (!ok) core.setFailed('no')",
        # for...of over a Map's entries.
        "const { data } = await " + PERMISSION + "\nlet ok = false\n"
        "for (const [level, yes] of new Map([['admin', true], ['write', true]])) {\n"
        "  if (yes && data.permission === level) ok = true\n}\nif (!ok) core.setFailed('no')",
        # A default in a nested object pattern.
        "const { data: { permission = 'none' } = {} } = await " + PERMISSION + "\n"
        "if (permission !== 'admin') core.setFailed(permission)",
        # A function that takes its options apart.
        "async function level({ username, fallback = 'none' }) {\n"
        "  const { data } = await github.rest.repos.getCollaboratorPermissionLevel(\n"
        "    { ...context.repo, username },\n  )\n"
        "  return data.permission ?? fallback\n}\n"
        "if ((await level({ username: context.actor })) !== 'admin') core.setFailed('no')",
    ],
)
def test_patterns_in_checks_that_fail_on_a_no(script):
    r = result(script)
    assert r is not None
    assert (r.fails, r.asked) == (True, True)


@pytest.mark.parametrize(
    ("script", "fails"),
    [
        # Positions, holes, defaults and the rest.
        ("const [a, , b = 3, ...r] = [1, 2]\nif (a === 1 && b === 3 && !r.length) core.setFailed('x')", True),
        ("const [, second] = ['a', 'b']\nif (second === 'b') core.setFailed('x')", True),
        ("const [x, ...r] = [1, 2, 3]\nif (r.length === 2 && r[1] === 3) core.setFailed('x')", True),
        ("const [[x], { y }] = [[1], { y: 2 }]\nif (x === 1 && y === 2) core.setFailed('x')", True),
        ("const [c] = 'ab'\nif (c === 'a') core.setFailed('x')", True),
        ("const [a = 5] = [null]\nif (a === null) core.setFailed('x')", True),
        # Taken from something unknown: unknown, whatever the default.
        ("const [a] = context.payload.comment.body.split(' ')\nif (a === '/go') core.setFailed('x')", False),
        ("const { a = 5 } = context.payload.issue\nif (a === 5) core.setFailed('x')", False),
        ("const [a = 5] = context.payload.issue.labels\nif (a === 5) core.setFailed('x')", False),
        # Object patterns: defaults, quoted keys and the rest.
        ("const { a = 5 } = {}\nif (a === 5) core.setFailed('x')", True),
        ("const { 'a-b': c } = { 'a-b': 1 }\nif (c === 1) core.setFailed('x')", True),
        (
            "const { a, ...others } = { a: 1, b: 2 }\n"
            "if (Object.keys(others).length === 1 && others.b === 2) core.setFailed('x')",
            True,
        ),
        # JavaScript throws for these.
        ("try { const [a] = null } catch { core.setFailed('x') }", True),
        ("try { const {} = null } catch { core.setFailed('x') }", True),
        ("try { const [a] = { a: 1 } } catch { core.setFailed('x') }", True),
        ("try { for (const x of null) {} } catch { core.setFailed('x') }", True),
        ("try { for (const [a] of [1]) {} } catch { core.setFailed('x') }", True),
        ("function f({ a }) { return a }\ntry { f() } catch { core.setFailed('x') }", True),
        ("try { Object.keys(null) } catch { core.setFailed('x') }", True),
        # ... and only there: a path that doesn't throw doesn't fail.
        (THREW % "for (const [a] of [1]) {}", False),
        (THREW % "const [a] = null", False),
        (THREW % "Object.keys(null)", False),
        # Parameters: patterns, defaults and the rest.
        ("function count(...xs) { return xs.length }\nif (count(1, 2) === 2) core.setFailed('x')", True),
        ("const f = (a, ...r) => r[0]\nif (f(1, 2) === 2) core.setFailed('x')", True),
        ("const f = ([a, b] = [1, 2]) => b\nif (f() === 2) core.setFailed('x')", True),
        # A rest parameter is the function's own name.
        ("let r = 1\nfunction f(...r) { r = 2 }\nf()\nif (r === 1) core.setFailed('x')", True),
        ("const f = ({ a } = {}) => a\nif (f() === undefined) core.setFailed('x')", True),
        # Sets and Maps are iterable; callbacks get the list as their third argument.
        ("for (const x of new Set(['a'])) { if (x === 'a') core.setFailed('x') }", True),
        ("for (const [k, v] of new Map([['a', 1]])) { if (k === 'a' && v === 1) core.setFailed('x') }", True),
        ("if (![1, 2].every((x, i, all) => all.length === 2)) core.setFailed('x')", False),
        # Object.values and a for...of pattern on objects.
        ("for (const { n } of [{ n: 1 }]) { if (n === 1) core.setFailed('x') }", True),
        ("if (Object.values({ a: 1 })[0] === 1) core.setFailed('x')", True),
        ("const [[k, v]] = Object.entries({ a: 1 })\nif (k === 'a' && v === 1) core.setFailed('x')", True),
        ("if (Object.keys(context.repo).length === 2) core.setFailed('x')", False),
        # A for...of pattern's names stay in the function.
        ("function f() { for (const [x] of [[1]]) {} }\nf()\nif (x === 1) core.setFailed('x')", False),
    ],
)
def test_array_and_object_patterns(script, fails):
    r = run(script, {}, "NONE")
    assert r is not None and r.fails is fails


def test_a_call_in_promise_all_may_throw():
    # Without the 404 path the step would fail on every path.
    script = (
        "let threw = false\ntry {\n  const [p] = await Promise.all([" + PERMISSION + "])\n"
        "  core.info(p.data.permission)\n} catch {\n  threw = true\n}\nif (!threw) core.setFailed('x')"
    )
    r = result(script)
    assert r is not None and r.asked is True and r.fails is False
