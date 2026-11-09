"""Checks on the files other repositories use: action.yml and .pre-commit-hooks.yaml."""

import re
from pathlib import Path

import yaml

from workflow_guard.fix import SHA

ROOT = Path(__file__).parent.parent
ACTION = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
HOOKS = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
# tomllib needs Python 3.11; CI also runs 3.10, and one line is all that is needed here.
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

STEPS = ACTION["runs"]["steps"]


def test_action_is_a_composite_action_with_documented_inputs():
    assert ACTION["runs"]["using"] == "composite"
    assert ACTION["inputs"], "no inputs"
    for name, spec in ACTION["inputs"].items():
        assert spec.get("description"), f"input {name} has no description"
        assert "default" in spec, f"input {name} has no default"


def test_action_run_scripts_never_contain_expressions():
    # The same rule the tool enforces (WG004), applied to its own action: values reach the
    # scripts through env: only.
    for step in STEPS:
        if "run" in step:
            assert "${{" not in step["run"], step["run"]
            assert step.get("shell") == "bash", "composite run steps need an explicit shell"


def test_every_input_is_used():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    for name in ACTION["inputs"]:
        assert f"inputs.{name} }}}}" in text, f"input {name} is never used"


def test_actions_used_by_the_action_are_pinned_to_full_shas():
    for step in STEPS:
        if "uses" in step:
            ref = step["uses"].split("@", 1)[1]
            assert SHA.match(ref), step["uses"]


def test_action_passes_options_before_a_double_dash():
    script = STEPS[-1]["run"]
    assert '-m workflow_guard "${args[@]}" -- "${paths[@]}"' in script


def test_pre_commit_hook_runs_the_installed_script():
    (hook,) = HOOKS
    assert hook["id"] == "workflow-guard"
    assert hook["language"] == "python"
    assert f'\n{hook["entry"]} = "workflow_guard.cli:main"' in PYPROJECT


def test_pre_commit_hook_only_matches_workflow_files():
    files = re.compile(HOOKS[0]["files"])
    assert files.search(".github/workflows/ci.yml")
    assert files.search(".github/workflows/release.yaml")
    assert not files.search(".github/dependabot.yml")
    assert not files.search(".github/workflows/sub/x.yml")  # GitHub doesn't read subdirectories
    assert not files.search("docs/.github/workflows/ci.yml")
    assert not files.search(".github/workflows/notes.txt")
