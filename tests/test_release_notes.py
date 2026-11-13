"""scripts/release_notes.py: CHANGELOG.md sections <-> GitHub Release notes."""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
_spec = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts" / "release_notes.py")
rn = importlib.util.module_from_spec(_spec)
sys.modules["release_notes"] = rn  # dataclasses look the module up while the class is built
_spec.loader.exec_module(rn)

BODY = """## v0.9.0 — WG007: untrusted text

Now with **more**.

## Upgrade

```yaml
# not a heading
- uses: Gallileee/workflow-guard@abc  # v0.9.0
```

### Details
- a
"""
RELEASE = rn.Release("v0.9.0", "v0.9.0 — WG007: untrusted text", BODY, "2026-11-09")


def test_a_section_is_the_body_with_deeper_headings_and_no_repeated_title():
    text = rn.section_text(RELEASE)
    assert text.startswith("Now with **more**.")
    assert "### Upgrade" in text and "#### Details" in text
    assert "\n# not a heading\n" in text  # code blocks are left alone
    assert "v0.9.0 — WG007" not in text


def test_the_repeated_title_is_matched_without_case():
    release = rn.Release("v1.0.0", "v1.0.0 — Big", "## v1.0.0 — big\n\nText", "")
    assert rn.section_text(release) == "Text"


def test_a_different_first_heading_stays():
    release = rn.Release("v1.0.0", "v1.0.0 — Big", "## New rule\n\nText", "")
    assert rn.section_text(release) == "### New rule\n\nText"


def test_notes_give_back_the_body_minus_the_title():
    section = rn.from_release(RELEASE)
    assert rn.notes(section) == BODY.split("\n", 2)[2]


def test_render_and_parse_round_trip():
    sections = [
        rn.Section("v0.10.0", "v0.10.0 — Next", "", "### A\n\ntext"),
        rn.from_release(RELEASE),
    ]
    text = rn.render(sections)
    assert "## v0.9.0 — WG007: untrusted text (2026-11-09)\n" in text
    assert "## v0.10.0 — Next\n" in text  # no date until it's released
    parsed = rn.parse(text)
    assert [(s.tag, s.title, s.date, s.text) for s in parsed] == [
        (s.tag, s.title, s.date, s.text) for s in sections
    ]
    assert [s.line for s in parsed] == [7, 13]


def test_a_section_heading_inside_a_code_block_is_not_a_section():
    text = "# Changelog\n\n## v1.0.0 — A\n\n```\n## v0.1.0 — not a section\n```\n"
    assert [s.tag for s in rn.parse(text)] == ["v1.0.0"]


def test_sync_rewrites_released_sections_and_keeps_unreleased_ones():
    current = [
        rn.Section("v0.10.0", "v0.10.0 — Next", "", "unreleased text"),
        rn.Section("v0.9.0", "v0.9.0 — Old title", "", "stale"),
    ]
    other = rn.Release("v0.8.0", "v0.8.0 — Older", "body", "2026-11-01")
    synced = rn.sync(current, {"v0.9.0": RELEASE, "v0.8.0": other})
    assert [(s.tag, s.title) for s in synced] == [
        ("v0.10.0", "v0.10.0 — Next"),
        ("v0.9.0", "v0.9.0 — WG007: untrusted text"),
        ("v0.8.0", "v0.8.0 — Older"),
    ]
    assert synced[0].text == "unreleased text"
    assert synced[1].text == rn.section_text(RELEASE)


def test_versions_sort_as_numbers():
    tags = ["v0.9.0", "v0.10.0", "v0.4.0"]
    assert sorted(tags, key=rn.version_key) == ["v0.4.0", "v0.9.0", "v0.10.0"]


def test_tidy_ignores_line_endings_and_trailing_spaces():
    assert rn.tidy("a  \r\nb\r\n\r\n") == "a\nb"


def test_main_prints_notes_and_title(tmp_path, capsys):
    (tmp_path / "CHANGELOG.md").write_text(rn.render([rn.from_release(RELEASE)]), encoding="utf-8")
    assert rn.main(["notes", "v0.9.0"], root=tmp_path) == 0
    assert capsys.readouterr().out == rn.notes(rn.from_release(RELEASE))
    assert rn.main(["title", "v0.9.0"], root=tmp_path) == 0
    assert capsys.readouterr().out.strip() == "v0.9.0 — WG007: untrusted text"
    with pytest.raises(SystemExit, match="no section for v1.0.0"):
        rn.main(["notes", "v1.0.0"], root=tmp_path)


def test_this_repositorys_changelog_parses():
    sections = rn.parse((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    assert sections and all(s.title.startswith(s.tag) for s in sections)
