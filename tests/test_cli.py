"""Tests du parcours et de l'interface en ligne de commande."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from terraformizer.cli import main
from terraformizer.detectors.base import Detector, slugify
from terraformizer.models import Finding
from terraformizer.scanner import MAX_FILE_SIZE, scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_outputs(tmp_path: Path) -> None:
    out = tmp_path / "generated"
    assert main([str(FIXTURES), "-o", str(out)]) == 0
    assert {
        "aws.tf",
        "google.tf",
        "azurerm.tf",
        "versions.tf",
        "variables.tf",
        "import.sh",
        "report.json",
        "REPORT.md",
    } <= {p.name for p in out.iterdir()}
    assert (out / "import.sh").stat().st_mode & 0o777 == 0o755
    report = json.loads((out / "report.json").read_text())
    assert report
    assert all(not Path(row["source_file"]).is_absolute() for row in report)
    assert not any(row["tf_type"] == "ERROR" for row in report)


def test_cli_exit_codes_and_dry_run(tmp_path: Path) -> None:
    out = tmp_path / "dry"
    assert main([str(FIXTURES), "-o", str(out), "--dry-run"]) == 0
    assert not out.exists()
    assert main([str(FIXTURES), "--dry-run", "--fail-on-findings"]) == 2
    assert main([str(tmp_path / "missing")]) == 1
    assert main([str(tmp_path), "--only", "unknown"]) == 1
    assert main([str(tmp_path), "--dry-run", "--fail-on-findings"]) == 0


def test_cli_filter_report_and_fmt(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with patch("terraformizer.cli.shutil.which", return_value="/bin/terraform"):
        with patch("terraformizer.cli.subprocess.run") as run:
            assert (
                main(
                    [
                        str(FIXTURES),
                        "-o",
                        str(out),
                        "--only",
                        "bash_aws",
                        "--report",
                        "json",
                        "--fmt",
                    ]
                )
                == 0
            )
            run.assert_called_once_with(
                ["/bin/terraform", "fmt", "-recursive", str(out)],
                check=True,
            )
    assert not (out / "REPORT.md").exists()
    assert not (out / "google.tf").exists()
    assert main([str(FIXTURES), "-o", str(out), "--dry-run", "--min-confidence", "1"]) == 0
    with pytest.raises(SystemExit):
        main([str(FIXTURES), "--min-confidence", "nan"])


def test_scanner_ignores_size_links_and_terraform(tmp_path: Path) -> None:
    command = "aws s3 mb s3://demo-bucket"
    (tmp_path / "deploy.sh").write_text(command)
    for directory in (".git", ".terraform", "node_modules", ".venv"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "deploy.sh").write_text(command)
    for filename in ("main.tf", "vars.tfvars", "state.tfstate.sh", "main.hcl"):
        (tmp_path / filename).write_text(command)
    (tmp_path / "large.sh").write_text(command + " " * MAX_FILE_SIZE)
    (tmp_path / "link.sh").symlink_to(tmp_path / "deploy.sh")
    findings = scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].source_file == Path("deploy.sh")


def test_detector_exception_is_reported_and_scan_continues(tmp_path: Path) -> None:
    class BrokenDetector(Detector):
        name = "broken"
        extensions = (".sh",)

        def detect(self, path: Path, content: str) -> list[Finding]:
            raise RuntimeError("échec simulé")

    (tmp_path / "deploy.sh").write_text("anything")
    with patch("terraformizer.scanner.get_detectors", return_value=[BrokenDetector()]):
        findings = scan(tmp_path)
    assert findings[0].tf_type == "ERROR"
    assert findings[0].confidence == 0
    assert "échec simulé" in findings[0].notes[0]


def test_slugify_and_file_scan(tmp_path: Path) -> None:
    assert slugify("Web-01") == "web_01"
    assert slugify("123") == "resource_123"
    assert slugify("!!!") == "resource"
    assert slugify("", fallback="123") == "resource_123"
    source = tmp_path / "one.sh"
    source.write_text("aws s3 mb s3://one-bucket")
    assert scan(source)[0].source_file == Path("one.sh")


def test_output_is_not_rescanned(tmp_path: Path) -> None:
    (tmp_path / "deploy.sh").write_text("aws s3 mb s3://one-bucket")
    out = tmp_path / "nested" / "output"
    out.mkdir(parents=True)
    (out / "copy.sh").write_text("aws s3 mb s3://other-bucket")
    assert main([str(tmp_path), "-o", str(out)]) == 0
    assert len(json.loads((out / "report.json").read_text())) == 1


def test_cli_refuses_symlink_output_file(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    protected = tmp_path / "protected"
    protected.write_text("ne pas modifier")
    (out / "aws.tf").symlink_to(protected)
    assert main([str(FIXTURES), "-o", str(out)]) == 1
    assert protected.read_text() == "ne pas modifier"


def test_fmt_missing_and_markdown_report(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    out = tmp_path / "out"
    with patch("terraformizer.cli.shutil.which", return_value=None):
        assert main([str(FIXTURES), "-o", str(out), "--fmt", "--report", "md"]) == 0
    assert "absent du PATH" in capsys.readouterr().out
    assert (out / "REPORT.md").exists()
    assert not (out / "report.json").exists()


def test_fail_on_findings_applies_before_confidence_filter(tmp_path: Path) -> None:
    source = tmp_path / "template.yaml"
    source.write_text("Resources:\n  Unknown:\n    Type: AWS::Unknown::Resource\n")
    assert main([str(source), "--dry-run", "--min-confidence", "1", "--fail-on-findings"]) == 2


def test_fail_on_filtered_applies_after_confidence_filter(tmp_path: Path) -> None:
    source = tmp_path / "template.yaml"
    source.write_text("Resources:\n  Unknown:\n    Type: AWS::Unknown::Resource\n")
    assert main([str(source), "--dry-run", "--min-confidence", "1", "--fail-on-filtered"]) == 0
    assert main([str(source), "--dry-run", "--fail-on-filtered"]) == 2
