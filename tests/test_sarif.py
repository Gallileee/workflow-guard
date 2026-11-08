import io
import json

import pytest

from workflow_guard.cli import run
from workflow_guard.model import Finding, Severity
from workflow_guard.rules import RULES
from workflow_guard.sarif import FINGERPRINT_KEY, artifact_location, to_sarif

UNSAFE = """\
on: pull_request
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: someone/deploy@main
      - run: echo "${{ github.head_ref }}"
"""


def finding(line=3, rule="WG001", severity=Severity.LOW, message="m", path=".github/workflows/ci.yml"):
    return Finding(path, line, 7, rule, severity, message)


def only_run(log):
    assert log["version"] == "2.1.0" and len(log["runs"]) == 1
    return log["runs"][0]


def test_every_rule_is_described_with_the_texts_code_scanning_requires():
    rules = only_run(to_sarif([]))["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == [r.id for r in RULES]
    for r in rules:
        # GitHub rejects empty strings for these.
        for key in ("shortDescription", "fullDescription", "help"):
            assert r[key]["text"].strip()
        assert "security" in r["properties"]["tags"]
    assert all(rule.help for rule in RULES)


def test_a_result_has_level_location_rule_index_and_fingerprint():
    result = only_run(to_sarif([finding(rule="WG004", severity=Severity.HIGH, message="bad")]))["results"][0]
    assert result["ruleId"] == "WG004"
    assert result["ruleIndex"] == [r.id for r in RULES].index("WG004")
    assert result["level"] == "error"
    assert result["message"] == {"text": "bad"}
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": ".github/workflows/ci.yml", "uriBaseId": "%SRCROOT%"},
        "region": {"startLine": 3, "startColumn": 7},
    }
    assert len(result["partialFingerprints"][FINGERPRINT_KEY]) == 32


@pytest.mark.parametrize(
    ("severity", "level"), [(Severity.LOW, "note"), (Severity.MEDIUM, "warning"), (Severity.HIGH, "error")]
)
def test_severity_maps_to_sarif_level(severity, level):
    assert only_run(to_sarif([finding(severity=severity)]))["results"][0]["level"] == level


def test_fingerprints_ignore_the_line_but_tell_equal_findings_apart():
    def fps(findings):
        return [r["partialFingerprints"][FINGERPRINT_KEY] for r in only_run(to_sarif(findings))["results"]]

    # Lines above moved: same alert.
    assert fps([finding(line=3)]) == fps([finding(line=10)])
    # Anything else differs: another alert.
    assert fps([finding()]) != fps([finding(message="other")])
    assert fps([finding()]) != fps([finding(path="other.yml")])
    assert fps([finding()]) != fps([finding(rule="WG006")])
    # Two identical problems in one file are two alerts.
    a, b = fps([finding(line=3), finding(line=9)])
    assert a != b


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (".github/workflows/ci.yml", {"uri": ".github/workflows/ci.yml", "uriBaseId": "%SRCROOT%"}),
        ("./ci.yml", {"uri": "ci.yml", "uriBaseId": "%SRCROOT%"}),
        ("my flows\\ci #1.yml", {"uri": "my%20flows/ci%20%231.yml", "uriBaseId": "%SRCROOT%"}),
        ("/home/u/ci.yml", {"uri": "file:///home/u/ci.yml"}),
        ("C:\\repo\\ci.yml", {"uri": "file:///C:/repo/ci.yml"}),
    ],
)
def test_artifact_location(path, expected):
    assert artifact_location(path) == expected


def test_unreadable_files_become_notifications():
    run_ = only_run(to_sarif([], [("bad.yml", "not valid YAML")]))
    invocation = run_["invocations"][0]
    assert invocation["executionSuccessful"] is False
    note = invocation["toolExecutionNotifications"][0]
    assert note["level"] == "error" and note["message"]["text"] == "not valid YAML"
    assert note["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bad.yml"
    assert only_run(to_sarif([]))["invocations"][0]["executionSuccessful"] is True


@pytest.fixture
def repo(tmp_path, monkeypatch):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(UNSAFE, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def call(*args):
    out, err = io.StringIO(), io.StringIO()
    code = run(list(args), out, err)
    return code, out.getvalue(), err.getvalue()


def test_cli_sarif_to_stdout(repo):
    code, out, err = call("--format", "sarif")
    results = only_run(json.loads(out))["results"]
    assert code == 1 and err == ""
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["WG004"]["level"] == "error"
    # WG001 varies per finding: actions/* is low, a third-party action high.
    assert sorted(r["level"] for r in results if r["ruleId"] == "WG001") == ["error", "note"]
    uri = by_rule["WG004"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == ".github/workflows/ci.yml"


def test_cli_output_file_is_utf8_and_stdout_stays_empty(repo):
    code, out, err = call("--format", "sarif", "--output", "results.sarif", "--min-severity", "high")
    assert out == ""
    data = json.loads((repo / "results.sarif").read_bytes().decode("utf-8"))
    assert {r["level"] for r in only_run(data)["results"]} == {"error"}
    assert code == 1 and "finding(s) in 1 file(s)" in err


def test_cli_text_output_file(repo):
    code, out, _ = call("--output", "report.txt", "--ignore", "WG001,WG002,WG004,WG006")
    assert (code, out) == (0, "")
    assert (repo / "report.txt").read_text(encoding="utf-8") == "\n"


def test_cli_broken_file_still_writes_sarif(repo):
    (repo / ".github" / "workflows" / "bad.yml").write_text("jobs: [\n", encoding="utf-8")
    code, out, _ = call("--format", "sarif")
    run_ = only_run(json.loads(out))
    assert code == 2
    assert run_["invocations"][0]["executionSuccessful"] is False
    assert run_["results"]  # ci.yml was still checked


def test_cli_unwritable_output_is_an_error(repo):
    code, _, err = call("--format", "sarif", "--output", str(repo / "no" / "such" / "dir" / "x.sarif"))
    assert code == 2 and "cannot write" in err
