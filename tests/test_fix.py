import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from workflow_guard.cli import run
from workflow_guard.fix import (
    GitHubResolver,
    ResolveError,
    comment_gap,
    pin_actions,
    repository_root,
    uses_prettier,
)

A = "a" * 40
B = "b" * 40
HEAD = "on: push\njobs:\n  a:\n    runs-on: x\n    steps:"


class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def resolve(self, repo, ref):
        self.calls.append((repo, ref))
        answer = self.answers.get((repo, ref))
        if answer is None:
            raise ResolveError(f"{repo}@{ref} not found")
        return answer


RESOLVER = {
    ("actions/checkout", "v4"): A,
    ("github/codeql-action", "v3"): B,
    ("some-org/shared", "main"): B,
}


def pin(text, answers=RESOLVER):
    resolver = FakeResolver(answers)
    return pin_actions(text, resolver), resolver


def test_a_tag_becomes_its_sha_with_the_version_in_a_comment():
    text = HEAD + "\n      - uses: actions/checkout@v4\n      - run: make\n"
    result, _ = pin(text)
    assert result.text == text.replace("actions/checkout@v4", f"actions/checkout@{A}  # v4")
    assert [(p.line, p.old) for p in result.pinned] == [(6, "actions/checkout@v4")]


def test_windows_line_endings_quotes_and_existing_comments_are_kept():
    text = (
        "on: push\r\n"
        "jobs:\r\n"
        "  a:\r\n"
        "    runs-on: x\r\n"
        "    steps:\r\n"
        '      - uses: "actions/checkout@v4"\r\n'
        "      - uses: 'github/codeql-action/init@v3'   # scan the code\r\n"
    )
    result, _ = pin(text)
    assert result.text == (
        "on: push\r\n"
        "jobs:\r\n"
        "  a:\r\n"
        "    runs-on: x\r\n"
        "    steps:\r\n"
        # Three spaces: the file's only other comment uses three (see test_comment_gap below).
        f'      - uses: "actions/checkout@{A}"   # v4\r\n'
        f"      - uses: 'github/codeql-action/init@{B}'   # v3; scan the code\r\n"
    )


def test_reusable_workflows_and_a_file_without_final_newline():
    text = "on: push\njobs:\n  call:\n    uses: some-org/shared/.github/workflows/build.yml@main"
    result, resolver = pin(text)
    assert result.text.endswith(f"uses: some-org/shared/.github/workflows/build.yml@{B}  # main")
    assert resolver.calls == [("some-org/shared", "main")]


def test_things_that_need_no_lookup_are_left_alone():
    text = HEAD + (
        f"\n      - uses: actions/checkout@{A}"
        "\n      - uses: ./.github/actions/local"
        "\n      - uses: docker://alpine:3.20"
        "\n      - uses: actions/checkout"
        "\n      - uses: actions/checkout@v4  # workflow-guard: ignore[WG001]\n"
    )
    result, resolver = pin(text)
    assert result.text == text and result.pinned == [] and resolver.calls == []


def test_two_uses_on_one_line_get_no_comment():
    text = HEAD + " [{uses: actions/checkout@v4}, {uses: actions/checkout@v4}]\n"
    result, _ = pin(text)
    assert result.text == text.replace("@v4", f"@{A}")


@pytest.mark.parametrize(
    ("text", "gap"),
    [
        ("a: b\n", "  "),  # no comments: two spaces
        ("# a full-line comment\n  # indented\na: b\n", "  "),  # not end-of-line comments
        ("a: b # x\nc: d # y\ne: f  # z\n", " "),  # Prettier style wins 2:1
        ("a: b  # x\nc: d # y\n", "  "),  # a tie goes to two spaces
        ("a: b # x\r\nc: d # y\r\n", " "),  # Windows line endings
        ("a: b # x\nc: d #\n", " "),  # an empty comment counts
        ('run: echo "#1" and a#b\n', "  "),  # no whitespace before "#", or no space after it
        ("a: b\t# x\n", "\t"),
    ],
)
def test_comment_gap(text, gap):
    assert comment_gap(text) == gap


PRETTIER_STYLE = HEAD + (
    f"\n      - uses: actions/setup-node@{B} # v4"
    "\n      - uses: actions/checkout@v4"
    "\n      - uses: github/codeql-action/init@v3 # scan\n"
)


def test_fix_follows_the_files_comment_style():
    result, _ = pin(PRETTIER_STYLE)
    assert f"      - uses: actions/checkout@{A} # v4\n" in result.text
    # An existing comment is extended in place, keeping its own gap.
    assert f"      - uses: github/codeql-action/init@{B} # v3; scan\n" in result.text


def test_an_explicit_gap_overrides_the_file():
    result = pin_actions(PRETTIER_STYLE, FakeResolver(RESOLVER), gap="  ")
    assert f"      - uses: actions/checkout@{A}  # v4\n" in result.text


def test_a_failed_lookup_is_reported_and_leaves_that_line_alone():
    text = HEAD + "\n      - uses: some-org/x@v9\n      - uses: actions/checkout@v4\n"
    result, _ = pin(text)
    assert "some-org/x@v9" in result.text and f"actions/checkout@{A}" in result.text
    assert result.failed == [(6, "some-org/x@v9", "some-org/x@v9 not found")]


# --- GitHubResolver against a local HTTP server ---------------------------------------------------


class FakeGitHub(BaseHTTPRequestHandler):
    requests: list = []

    def do_GET(self):
        FakeGitHub.requests.append((self.path, dict(self.headers)))
        routes = {
            "/repos/o/r/commits/v1": (200, A),
            "/repos/o/r/commits/feature%2Fx": (200, B),
            "/repos/o/r/commits/missing": (422, json.dumps({"message": "No commit found"})),
            "/repos/o/gone/commits/v1": (404, json.dumps({"message": "Not Found"})),
            "/repos/o/r/commits/limited": (403, json.dumps({"message": "API rate limit exceeded"})),
            "/repos/o/r/commits/broken": (502, "<html>unicorn</html>"),
            "/repos/o/r/commits/odd": (200, "<html>not a sha</html>"),
        }
        status, body = routes.get(self.path, (500, ""))
        self.send_response(status)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def api():
    FakeGitHub.requests = []
    server = HTTPServer(("127.0.0.1", 0), FakeGitHub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


def test_resolver_asks_for_the_bare_sha_and_caches(api):
    resolver = GitHubResolver(token="t0ken", api_url=api)
    assert resolver.resolve("o/r", "v1") == A
    assert resolver.resolve("o/r", "v1") == A
    assert resolver.resolve("o/r", "feature/x") == B  # a slash in a branch name is escaped
    paths = [path for path, _ in FakeGitHub.requests]
    assert paths == ["/repos/o/r/commits/v1", "/repos/o/r/commits/feature%2Fx"]
    headers = FakeGitHub.requests[0][1]
    assert headers["Accept"] == "application/vnd.github.sha"
    assert headers["Authorization"] == "Bearer t0ken"


def test_resolver_sends_no_authorization_without_a_token(api):
    GitHubResolver(api_url=api).resolve("o/r", "v1")
    assert "Authorization" not in FakeGitHub.requests[0][1]


@pytest.mark.parametrize(
    ("repo", "ref", "message"),
    [
        ("o/r", "missing", "o/r@missing not found"),
        ("o/gone", "v1", "o/gone@v1 not found"),
        ("o/r", "limited", "refused the request (403 API rate limit exceeded); set GITHUB_TOKEN"),
        ("o/r", "broken", "GitHub API error 502"),
        ("o/r", "odd", "unexpected answer"),
    ],
)
def test_resolver_errors(api, repo, ref, message):
    with pytest.raises(ResolveError) as e:
        GitHubResolver(api_url=api).resolve(repo, ref)
    assert message in str(e.value)


def test_resolver_cannot_connect():
    with pytest.raises(ResolveError, match="cannot reach the GitHub API"):
        GitHubResolver(api_url="http://127.0.0.1:9", timeout=2).resolve("o/r", "v1")


# --- CLI --------------------------------------------------------------------------------------------

WORKFLOW = """on: push
permissions: {}
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - uses: some-org/x@v9
"""


def test_cli_fix_rewrites_the_file_and_reports_what_is_left(tmp_path):
    wf = tmp_path / "ci.yml"
    wf.write_bytes(WORKFLOW.encode())
    out, err = io.StringIO(), io.StringIO()
    code = run(["--fix", str(wf)], out, err, resolver=FakeResolver(RESOLVER))

    assert f"actions/checkout@{A}  # v4" in wf.read_text(encoding="utf-8")
    assert f"ci.yml:7: pinned actions/checkout@v4 -> actions/checkout@{A}" in err.getvalue()
    assert "ci.yml:10: could not pin some-org/x@v9: some-org/x@v9 not found" in err.getvalue()
    # Only the action that couldn't be pinned is still reported.
    assert [line.split()[1] for line in out.getvalue().splitlines()] == ["WG001"]
    assert "some-org/x@v9" in out.getvalue()
    assert code == 1


def test_cli_fix_is_skipped_when_wg001_is_ignored(tmp_path):
    wf = tmp_path / "ci.yml"
    wf.write_bytes(WORKFLOW.encode())
    resolver = FakeResolver(RESOLVER)
    code = run(["--fix", "--ignore", "WG001", str(wf)], io.StringIO(), io.StringIO(), resolver=resolver)
    assert resolver.calls == [] and wf.read_bytes() == WORKFLOW.encode() and code == 0


def test_without_fix_files_are_never_written(tmp_path):
    wf = tmp_path / "ci.yml"
    wf.write_bytes(WORKFLOW.encode())
    resolver = FakeResolver(RESOLVER)
    run([str(wf)], io.StringIO(), io.StringIO(), resolver=resolver)
    assert resolver.calls == [] and wf.read_bytes() == WORKFLOW.encode()


def test_cli_comment_spaces(tmp_path):
    wf = tmp_path / "ci.yml"
    wf.write_bytes(WORKFLOW.encode())
    run(
        ["--fix", "--comment-spaces", "1", str(wf)],
        io.StringIO(),
        io.StringIO(),
        resolver=FakeResolver(RESOLVER),
    )
    assert f"actions/checkout@{A} # v4\n" in wf.read_text(encoding="utf-8")


@pytest.mark.parametrize("bad", ["0", "9", "two"])
def test_cli_comment_spaces_must_be_1_to_8(bad, capsys):
    with pytest.raises(SystemExit) as exit_info:
        run(["--fix", "--comment-spaces", bad], io.StringIO(), io.StringIO(), resolver=FakeResolver({}))
    assert exit_info.value.code == 2
    assert "expected a number from 1 to 8" in capsys.readouterr().err


# --- the repository's formatter as a fallback ------------------------------------------------------


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        ({}, False),
        ({".prettierrc": "{}"}, True),
        ({"prettier.config.mjs": "export default {}"}, True),
        ({"package.json": '{"devDependencies": {"prettier": "^3"}}'}, True),
        ({"package.json": '{"prettier": {"semi": false}}'}, True),
        ({"package.json": '{"devDependencies": {"eslint-config-prettier": "^10"}}'}, False),
        ({"package.json": "not json"}, False),
        ({"package.json": "[1, 2]"}, False),
    ],
)
def test_uses_prettier(tmp_path, files, expected):
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    assert uses_prettier(tmp_path) is expected


def test_repository_root_is_the_nearest_folder_with_git(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "sub" / ".git").parent.mkdir()
    (tmp_path / "sub" / ".git").write_text("gitdir: elsewhere")  # a worktree has a .git file
    deep = tmp_path / "sub" / ".github" / "workflows"
    deep.mkdir(parents=True)
    assert repository_root(deep / "ci.yml") == (tmp_path / "sub").resolve()
    assert repository_root(tmp_path / "ci.yml") == tmp_path.resolve()


def prettier_repo(tmp_path, workflow_text):
    (tmp_path / ".git").mkdir()
    (tmp_path / "package.json").write_text('{"devDependencies": {"prettier": "^3"}}')
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(workflow_text, encoding="utf-8")
    return wf


def fix_file(wf, *extra):
    run(["--fix", *extra, str(wf)], io.StringIO(), io.StringIO(), resolver=FakeResolver(RESOLVER))
    return wf.read_text(encoding="utf-8")


def test_prettier_repository_without_comments_gets_one_space(tmp_path):
    wf = prettier_repo(tmp_path, HEAD + "\n      - uses: actions/checkout@v4\n")
    assert f"actions/checkout@{A} # v4\n" in fix_file(wf)


def test_the_files_own_comments_beat_the_repository(tmp_path):
    wf = prettier_repo(tmp_path, HEAD + "\n      - run: make  # build\n      - uses: actions/checkout@v4\n")
    assert f"actions/checkout@{A}  # v4\n" in fix_file(wf)


def test_comment_spaces_beats_everything(tmp_path):
    wf = prettier_repo(tmp_path, HEAD + "\n      - uses: actions/checkout@v4\n")
    assert f"actions/checkout@{A}  # v4\n" in fix_file(wf, "--comment-spaces", "2")


def test_no_repository_means_two_spaces(tmp_path):
    wf = tmp_path / "ci.yml"
    wf.write_text(HEAD + "\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"devDependencies": {"prettier": "^3"}}')  # no .git
    assert f"actions/checkout@{A}  # v4\n" in fix_file(wf)
