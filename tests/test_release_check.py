"""scripts/release_check.py: the release steps that are easy to forget."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("release_check", ROOT / "scripts" / "release_check.py")
rc = importlib.util.module_from_spec(_spec)
sys.modules["release_check"] = rc  # dataclasses look the module up while the class is built
_spec.loader.exec_module(rc)

TAGS = ["v0.4.0", "v0.10.0", "v0.9.0", "latest", "v1.0", "v0.11.0"]


def levels(problems):
    return [(p.level, p.text.split(" ")[0]) for p in problems]


def test_versions_compare_as_numbers():
    assert rc.parse_version("v0.10.0") > rc.parse_version("0.9.9")
    assert rc.version_tags(TAGS) == ["v0.4.0", "v0.9.0", "v0.10.0", "v0.11.0"]
    with pytest.raises(ValueError):
        rc.parse_version("1.0")


def test_a_finished_release_is_clean():
    assert rc.check("0.11.0", "0.11.0", TAGS, set(rc.version_tags(TAGS)), "refs/heads/main") == []


def test_pyproject_and_init_must_agree():
    (p,) = rc.check("0.11.0", "0.10.0", TAGS)
    assert p.level == rc.ERROR
    assert "__init__.py says 0.10.0" in p.text


def test_a_bump_without_a_tag_is_a_warning():
    (p,) = rc.check("0.12.0", "0.12.0", TAGS, ref="refs/pull/7/merge")
    assert p.level == rc.WARNING
    assert "v0.12.0 isn't tagged yet" in p.text


def test_a_version_older_than_the_newest_tag_is_an_error():
    (p,) = rc.check("0.10.0", "0.10.0", TAGS)
    assert p.level == rc.ERROR
    assert "older than the newest tag v0.11.0" in p.text


def test_older_means_numerically_older():
    # As text "0.9.5" sorts after "0.10.0"; as a version it comes before.
    (p,) = rc.check("0.9.5", "0.9.5", ["v0.9.0", "v0.10.0"])
    assert p.level == rc.ERROR
    assert "older than the newest tag v0.10.0" in p.text


def test_a_pushed_tag_must_match_the_code():
    problems = rc.check("0.11.0", "0.11.0", [*TAGS, "v0.12.0"], ref="refs/tags/v0.12.0")
    assert ("error", "tag") in levels(problems)
    assert any("tag v0.12.0 doesn't match the version in the code (0.11.0)" in p.text for p in problems)
    assert rc.check("0.11.0", "0.11.0", TAGS, ref="refs/tags/v0.11.0") == []


def test_releases_old_tags_error_newest_tag_warns():
    problems = rc.check("0.11.0", "0.11.0", TAGS, {"v0.4.0", "v0.10.0"})
    assert [(p.level, p.text) for p in problems] == [
        (rc.ERROR, "tag v0.9.0 has no GitHub Release"),
        (rc.WARNING, "tag v0.11.0 has no GitHub Release yet: publish one with its notes"),
    ]


def test_releases_are_skipped_when_not_asked_for():
    assert rc.check("0.11.0", "0.11.0", TAGS, None) == []


def test_no_tags_at_all_is_a_warning():
    (p,) = rc.check("0.1.0", "0.1.0", [])
    assert p.level == rc.WARNING
    assert "no v* tags found" in p.text


def test_a_broken_version_is_an_error():
    (p,) = rc.check("0.x", "0.x", TAGS)
    assert p.level == rc.ERROR


def test_report_uses_workflow_commands_in_actions():
    problems = [rc.Problem(rc.WARNING, "w"), rc.Problem(rc.ERROR, "e")]
    assert rc.report(problems, annotate=True) == "::warning::w\n::error::e"
    assert rc.report(problems, annotate=False) == "warning: w\nerror: e"


def test_this_repository_agrees_with_itself():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    init = (ROOT / "src" / "workflow_guard" / "__init__.py").read_text(encoding="utf-8")
    assert rc.read_version(pyproject, rc._PYPROJECT_VERSION, "pyproject.toml") == rc.read_version(
        init, rc._INIT_VERSION, "__init__.py"
    )


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def test_main_reads_a_real_repository(tmp_path, monkeypatch, capsys):
    (tmp_path / "src" / "workflow_guard").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n', encoding="utf-8")
    (tmp_path / "src" / "workflow_guard" / "__init__.py").write_text(
        '__version__ = "0.2.0"\n', encoding="utf-8"
    )
    _git(tmp_path, "init", "-q")
    _git(
        tmp_path,
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "x",
    )
    _git(tmp_path, "tag", "v0.1.0")
    _git(tmp_path, "tag", "v0.3.0")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.delenv("GITHUB_REF", raising=False)
    assert rc.main([], root=tmp_path) == 1
    out = capsys.readouterr()
    assert (
        out.out.strip()
        == "::error::version 0.2.0 is older than the newest tag v0.3.0; was a version bump lost?"
    )
    assert "2 tag(s), 1 error(s)" in out.err


def test_main_reports_an_unreadable_repository(tmp_path, capsys):
    assert rc.main([], root=tmp_path) == 2
    assert "cannot read the release state" in capsys.readouterr().err
