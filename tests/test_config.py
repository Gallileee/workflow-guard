""".github/workflow-guard.yml: settings shared by the CLI, the pre-commit hook and the action."""

import io
from pathlib import Path

import pytest

from workflow_guard.cli import run
from workflow_guard.config import Config, ConfigError, find_config, load_config, parse_config
from workflow_guard.model import Severity

SHA = "a" * 40
# WG004 high (PR title in run:), WG006 low (checkout keeps the token).
WORKFLOW = f"""\
on: pull_request
permissions: {{}}
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/checkout@{SHA}
      - run: echo "${{{{ github.event.pull_request.title }}}}"
      - uses: my-org/deploy@{SHA}
        with:
          commands: echo "${{{{ github.event.pull_request.body }}}}"
"""


# --- parsing --------------------------------------------------------------------------------------


def test_a_full_config():
    config = parse_config(
        "ignore: [wg006, WG002]\nmin-severity: medium\nfail-on: HIGH\n"
        "script-inputs:\n  - my-org/deploy:commands\n"
    )
    assert config.ignore == frozenset({"WG006", "WG002"})
    assert (config.min_severity, config.fail_on) == (Severity.MEDIUM, Severity.HIGH)
    assert config.script_inputs == ("my-org/deploy:commands",)


def test_strings_instead_of_lists():
    config = parse_config("ignore: WG006, WG002\nscript-inputs: a/b:x c/d:y\n")
    assert config.ignore == frozenset({"WG006", "WG002"})
    assert config.script_inputs == ("a/b:x", "c/d:y")


@pytest.mark.parametrize("text", ["", "# nothing yet\n"])
def test_an_empty_file_changes_nothing(text):
    assert parse_config(text) == Config()


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("ignore: [WG099]\n", "'ignore': unknown rule(s): WG099"),
        (
            "fail_on: high\n",
            "unknown setting(s): fail_on; known: ignore, min-severity, fail-on, script-inputs",
        ),
        ("min-severity: critical\n", "'min-severity':"),
        ("fail-on: 3\n", "'fail-on':"),
        ("script-inputs: [my-org/deploy]\n", "'script-inputs': expected owner/repo:input"),
        ("ignore: {WG001: true}\n", "'ignore' must be a list of strings"),
        ("ignore: [1, 2]\n", "'ignore' must be a list of strings"),
        ("- WG001\n", "expected a mapping of settings"),
        ("ignore: [WG001\n", "not valid YAML"),
    ],
)
def test_mistakes_are_errors(text, message):
    with pytest.raises(ConfigError, match=None) as e:
        parse_config(text)
    assert message in str(e.value)


def test_an_unreadable_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.yml")


# --- finding the file -----------------------------------------------------------------------------


def make_repo(root: Path, config: str | None = None, name: str = "workflow-guard.yml") -> Path:
    (root / ".git").mkdir(parents=True)
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(WORKFLOW, encoding="utf-8")
    if config is not None:
        (root / ".github" / name).write_text(config, encoding="utf-8")
    return root


def test_found_in_this_folder_and_below_the_root(tmp_path):
    repo = make_repo(tmp_path / "repo", "ignore: [WG006]\n")
    assert find_config(repo) == repo / ".github" / "workflow-guard.yml"
    (repo / "src" / "deep").mkdir(parents=True)
    assert find_config(repo / "src" / "deep") == repo / ".github" / "workflow-guard.yml"


def test_the_yaml_spelling(tmp_path):
    repo = make_repo(tmp_path / "repo", "ignore: [WG006]\n", name="workflow-guard.yaml")
    assert find_config(repo) == repo / ".github" / "workflow-guard.yaml"


def test_the_search_stops_at_the_repository_root(tmp_path):
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "workflow-guard.yml").write_text("ignore: [WG006]\n", encoding="utf-8")
    repo = make_repo(tmp_path / "repo")
    assert find_config(repo) is None


# --- the command line ----------------------------------------------------------------------------


def call(repo: Path, monkeypatch, *args: str):
    monkeypatch.chdir(repo)
    out, err = io.StringIO(), io.StringIO()
    code = run(["--format", "json", *args], out, err)
    return code, out.getvalue(), err.getvalue()


def rules(out: str) -> list[str]:
    return sorted({line.split('"')[3] for line in out.splitlines() if '"rule":' in line})


def test_without_a_config(tmp_path, monkeypatch):
    code, out, _ = call(make_repo(tmp_path / "r"), monkeypatch)
    assert (code, rules(out)) == (1, ["WG004", "WG006"])


def test_the_config_is_applied(tmp_path, monkeypatch):
    repo = make_repo(
        tmp_path / "r", "ignore: [WG006]\nscript-inputs: [my-org/deploy:commands]\nfail-on: high\n"
    )
    code, out, _ = call(repo, monkeypatch)
    assert code == 1 and rules(out) == ["WG004"]
    assert out.count('"rule": "WG004"') == 2  # run: and the custom action's commands


def test_command_line_options_win(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", "min-severity: high\nfail-on: high\n")
    _, out, _ = call(repo, monkeypatch)
    assert rules(out) == ["WG004"]
    code, out, _ = call(repo, monkeypatch, "--min-severity", "low", "--fail-on", "low", "--ignore", "WG004")
    assert (code, rules(out)) == (1, ["WG006"])


def test_ignore_and_script_inputs_add_up(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", "ignore: [WG006]\n")
    code, out, _ = call(repo, monkeypatch, "--ignore", "WG004")
    assert (code, rules(out)) == (0, [])
    # The config names the action in WORKFLOW, the command line another one: both count.
    repo2 = make_repo(tmp_path / "r2", "script-inputs: [my-org/deploy:commands]\n")
    _, out, _ = call(repo2, monkeypatch, "--script-input", "other/x:y", "--ignore", "WG006")
    assert out.count('"rule": "WG004"') == 2


def test_fail_on_from_the_config_sets_the_exit_code(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", "ignore: [WG004]\nfail-on: medium\n")
    code, out, _ = call(repo, monkeypatch)
    assert (code, rules(out)) == (0, ["WG006"])


def test_no_config_and_an_explicit_config(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", "ignore: [WG004, WG006]\n")
    assert call(repo, monkeypatch)[0] == 0
    code, out, _ = call(repo, monkeypatch, "--no-config")
    assert (code, rules(out)) == (1, ["WG004", "WG006"])
    other = tmp_path / "other.yml"
    other.write_text("ignore: [WG004]\n", encoding="utf-8")
    code, out, _ = call(repo, monkeypatch, "--config", str(other))
    assert rules(out) == ["WG006"]


def test_a_broken_config_stops_the_run(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", "ignore: [WG099]\n")
    code, out, err = call(repo, monkeypatch)
    assert (code, out) == (2, "")
    assert err.startswith("workflow-guard: .github/workflow-guard.yml: 'ignore': unknown rule(s): WG099")
    code, _, err = call(repo, monkeypatch, "--config", str(tmp_path / "nope.yml"))
    assert code == 2 and "nope.yml: cannot read" in err


def test_list_rules_ignores_the_config(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", "ignore: [WG099]\n")
    monkeypatch.chdir(repo)
    out = io.StringIO()
    assert run(["--list-rules"], out, io.StringIO()) == 0


def test_the_config_file_is_not_checked_as_a_workflow(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "r", "ignore: [WG006]\n")
    monkeypatch.chdir(repo)
    err = io.StringIO()
    run([], io.StringIO(), err)
    assert "in 1 file(s)" in err.getvalue()
