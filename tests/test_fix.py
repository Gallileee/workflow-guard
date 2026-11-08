import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from workflow_guard.cli import run
from workflow_guard.fix import GitHubResolver, ResolveError, pin_actions

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
        f'      - uses: "actions/checkout@{A}"  # v4\r\n'
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
