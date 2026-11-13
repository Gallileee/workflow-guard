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
    (tmp_path / "CHANGELOG.md").write_text(
        "# Changelog\n\n## v0.3.0\n\nc\n\n## v0.2.0\n\nb\n\n## v0.1.0\n\na\n", encoding="utf-8"
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


# --- CHANGELOG.md --------------------------------------------------------------------------------

rn = sys.modules["release_notes"]
CL_TAGS = ["v0.9.0", "v0.10.0"]


def section(tag, text="notes", title=None, date=""):
    return rn.Section(tag, title or f"{tag} — T", date, text, line=3)


def released(tag, body="notes", name=None, date="2026-11-09"):
    return rn.Release(tag, name or f"{tag} — T", body, date)


def changelog(*tags):
    return [section(t) for t in tags]


def test_a_complete_changelog_is_clean():
    releases = {t: released(t) for t in CL_TAGS}
    assert rc.check_changelog(changelog("v0.10.0", "v0.9.0"), "0.10.0", CL_TAGS, releases) == []


def test_a_missing_changelog_is_an_error():
    (p,) = rc.check_changelog(None, "0.10.0", CL_TAGS)
    assert p.level == rc.ERROR and "CHANGELOG.md is missing" in p.text


def test_the_bumped_version_needs_its_section_in_the_pull_request():
    (p,) = rc.check_changelog(changelog("v0.10.0", "v0.9.0"), "0.11.0", CL_TAGS)
    assert p.level == rc.ERROR
    assert "no section for v0.11.0: write its release notes there" in p.text
    assert rc.check_changelog(changelog("v0.11.0", "v0.10.0", "v0.9.0"), "0.11.0", CL_TAGS) == []


def test_every_tag_needs_a_section():
    (p,) = rc.check_changelog(changelog("v0.10.0"), "0.10.0", CL_TAGS)
    assert p.text == "CHANGELOG.md has no section for tag v0.9.0"


def test_a_section_for_an_unknown_version_is_an_error():
    (p,) = rc.check_changelog(changelog("v0.12.0", "v0.10.0", "v0.9.0"), "0.10.0", CL_TAGS)
    assert "section v0.12.0 is neither tagged nor the version in the code (0.10.0)" in p.text


def test_sections_must_be_newest_first_by_number():
    (p,) = rc.check_changelog(changelog("v0.9.0", "v0.10.0"), "0.10.0", CL_TAGS)
    assert "aren't newest first" in p.text
    # as text "v0.9.0" > "v0.10.0"; as versions it isn't
    assert rc.check_changelog(changelog("v0.10.0", "v0.9.0"), "0.10.0", CL_TAGS) == []


def test_a_second_section_for_a_tag_is_an_error():
    problems = rc.check_changelog(changelog("v0.10.0", "v0.10.0", "v0.9.0"), "0.10.0", CL_TAGS)
    assert [p.text for p in problems] == ["CHANGELOG.md:3: a second section for v0.10.0"]


def test_text_and_title_must_match_the_release():
    releases = {
        "v0.10.0": released("v0.10.0", body="edited on GitHub"),
        "v0.9.0": released("v0.9.0", name="Other"),
    }
    problems = rc.check_changelog(changelog("v0.10.0", "v0.9.0"), "0.10.0", CL_TAGS, releases)
    assert [p.level for p in problems] == [rc.ERROR, rc.ERROR]
    assert "the text of v0.10.0 differs from its GitHub Release" in problems[0].text
    assert "title 'v0.9.0 — T' differs from the release's 'Other'" in problems[1].text


def test_the_release_body_may_repeat_the_title_and_use_shallower_headings():
    body = "## v0.10.0 — T\n\n## Upgrade\n\nnotes"
    releases = {"v0.10.0": released("v0.10.0", body=body)}
    sections = [section("v0.10.0", "### Upgrade\n\nnotes"), section("v0.9.0")]
    assert rc.check_changelog(sections, "0.10.0", CL_TAGS, releases) == []


def test_a_wrong_date_is_a_warning_and_a_missing_one_is_fine():
    releases = {"v0.10.0": released("v0.10.0", date="2026-11-13")}
    sections = [section("v0.10.0", date="2026-11-12"), section("v0.9.0")]
    (p,) = rc.check_changelog(sections, "0.10.0", CL_TAGS, releases)
    assert p.level == rc.WARNING and "released on 2026-11-13, not 2026-11-12" in p.text
    assert rc.check_changelog(changelog("v0.10.0", "v0.9.0"), "0.10.0", CL_TAGS, releases) == []


def test_unreleased_sections_are_not_compared():
    assert rc.check_changelog(changelog("v0.10.0", "v0.9.0"), "0.10.0", CL_TAGS, {}) == []


def test_this_repositorys_changelog_covers_its_version():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = rc.read_version(pyproject, rc._PYPROJECT_VERSION, "pyproject.toml")
    assert f"v{version}" in {s.tag for s in rc.read_changelog(ROOT)}
