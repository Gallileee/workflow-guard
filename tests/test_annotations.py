import io
from pathlib import Path

from workflow_guard.annotations import annotation, escape_data, escape_property, to_annotations
from workflow_guard.cli import run
from workflow_guard.model import Finding, Severity

FIXTURE = Path(__file__).parent / "fixtures" / "unsafe-workflow.yml"


def finding(severity=Severity.HIGH, message="bad", path=".github/workflows/ci.yml"):
    return Finding(path, 9, 14, "WG004", severity, message)


def test_one_command_per_finding_with_location_and_title():
    assert annotation(finding()) == (
        "::error file=.github/workflows/ci.yml,line=9,col=14,title=WG004 template-injection::[high] bad"
    )


def test_severity_picks_the_annotation_level():
    levels = [annotation(finding(s)).split(" ")[0] for s in Severity]
    assert levels == ["::notice", "::warning", "::error"]


def test_escaping_data():
    assert escape_data("100% done\r\nnext") == "100%25 done%0D%0Anext"


def test_escaping_properties_also_escapes_separators():
    assert escape_property("a,b:c%\n") == "a%2Cb%3Ac%25%0A"


def test_a_newline_in_a_message_cannot_start_a_second_command():
    # A file name or YAML value with a newline must stay inside its own annotation; otherwise
    # "::add-mask::" (or any other command) would be run by the runner.
    text = annotation(finding(message="x\n::add-mask::secret", path="evil\n::stop-commands::t.yml"))
    # The runner only reads "::" commands at the start of a line, so one line = one command.
    assert "\n" not in text
    assert "file=evil%0A%3A%3Astop-commands%3A%3At.yml," in text
    assert text.endswith("::[high] x%0A::add-mask::secret")


def test_files_that_could_not_be_checked_are_errors():
    text = to_annotations([], [("broken.yml", "line 3: bad indentation")])
    assert text == (
        "::error file=broken.yml,title=workflow-guard::"
        "workflow-guard could not check this file: line 3: bad indentation"
    )


def test_cli_github_format_on_the_fixture():
    out, err = io.StringIO(), io.StringIO()
    code = run(["--format", "github", FIXTURE.as_posix()], out, err)
    lines = out.getvalue().splitlines()
    assert code == 1
    assert [line.split("title=")[1].split(" ")[0] for line in lines] == ["WG002", "WG001", "WG006", "WG004"]
    assert all(line.startswith(("::error ", "::warning ", "::notice ")) for line in lines)
    # The summary goes to stderr, so stdout holds nothing but workflow commands.
    assert "4 finding(s) in 1 file(s)" in err.getvalue()


def test_cli_github_format_without_findings_prints_nothing(tmp_path):
    wf = tmp_path / "ok.yml"
    wf.write_text("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: hi\n")
    out, err = io.StringIO(), io.StringIO()
    assert run(["--format", "github", str(wf)], out, err) == 0
    assert out.getvalue() == ""
