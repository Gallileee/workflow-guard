import io
import json
from pathlib import Path

import pytest

from workflow_guard.cli import run

UNSAFE = """\
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.head_ref }}"
"""

SAFE = """\
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""


def call(*args, cwd: Path | None = None, monkeypatch=None):
    if cwd is not None:
        monkeypatch.chdir(cwd)
    out, err = io.StringIO(), io.StringIO()
    code = run(list(args), out, err)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def repo(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(UNSAFE, encoding="utf-8")
    (wf / "ok.yaml").write_text(SAFE, encoding="utf-8")
    (wf / "notes.txt").write_text("not a workflow", encoding="utf-8")
    return tmp_path


def test_default_directory_text_output_and_exit_code(repo, monkeypatch):
    code, out, err = call(cwd=repo, monkeypatch=monkeypatch)
    lines = out.splitlines()
    assert code == 1
    assert lines[0] == (
        ".github/workflows/ci.yml:2:1: WG002 [medium] no 'permissions:' at the top or in job(s)"
        " test; the GITHUB_TOKEN gets the repository default, which may allow writes."
        " Add e.g. 'permissions: contents: read'"
    )
    assert [line.split(": ")[1].split(" ")[0] for line in lines] == ["WG002", "WG001", "WG006", "WG004"]
    assert "4 finding(s) in 2 file(s)" in err


def test_json_output(repo, monkeypatch):
    code, out, _ = call("--format", "json", cwd=repo, monkeypatch=monkeypatch)
    data = json.loads(out)
    assert code == 1
    assert data["files"] == 2
    assert {f["rule"] for f in data["findings"]} == {"WG001", "WG002", "WG004", "WG006"}
    assert data["findings"][-1] == {
        "path": ".github/workflows/ci.yml",
        "line": 7,
        "column": 14,
        "rule": "WG004",
        "severity": "high",
        "message": data["findings"][-1]["message"],
    }


def test_fail_on_and_min_severity(repo, monkeypatch):
    code, out, _ = call("--min-severity", "high", cwd=repo, monkeypatch=monkeypatch)
    assert code == 1 and [line.split()[1] for line in out.splitlines()] == ["WG004"]

    code, _, _ = call("--ignore", "WG004", "--fail-on", "high", cwd=repo, monkeypatch=monkeypatch)
    assert code == 0  # medium and low findings are shown but don't fail


def test_a_clean_file_exits_zero(repo):
    code, out, err = call(str(repo / ".github" / "workflows" / "ok.yaml"))
    assert (code, out) == (0, "")
    assert "0 finding(s) in 1 file(s)" in err


def test_a_broken_file_is_reported_and_exits_two_but_others_are_still_checked(repo):
    bad = repo / ".github" / "workflows" / "bad.yml"
    bad.write_text("jobs: [\n", encoding="utf-8")
    code, out, err = call(str(repo / ".github" / "workflows"))
    assert code == 2
    assert "bad.yml: error: not valid YAML" in err
    assert "WG004" in out


def test_no_workflows_found(tmp_path, monkeypatch):
    code, _, err = call(cwd=tmp_path, monkeypatch=monkeypatch)
    assert code == 2 and "no workflow files found" in err


def test_unknown_rule_or_severity_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as e:
        run(["--ignore", "WG999"])
    assert e.value.code == 2 and "unknown rule(s): WG999" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        run(["--fail-on", "critical"])


def test_list_rules():
    code, out, _ = call("--list-rules")
    assert code == 0 and len(out.splitlines()) == 9 and out.startswith("WG001")


def test_a_missing_path_is_an_error(tmp_path):
    code, _, err = call(str(tmp_path / "nope.yml"))
    assert code == 2 and "nope.yml: no such file or directory" in err
