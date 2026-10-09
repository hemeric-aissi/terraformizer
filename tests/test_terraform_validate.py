"""Validation syntaxique et sémantique des fichiers Terraform générés."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from terraformizer.generators.hcl import generate_files
from terraformizer.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"
TODO_DIAGNOSTIC_ALLOWLIST: dict[str, tuple[tuple[str, str], ...]] = {
    "aws": (
        ("Invalid function argument", 'no file exists at "bootstrap.sh"'),
        ("Reference to undeclared resource", "aws_RESOURCE.missingsubnet"),
    ),
    "google": (),
    "azurerm": (("Missing required argument", "network_interface_ids"),),
}
FORBIDDEN_SUMMARIES = (
    "Invalid",
    "Unsupported block type",
    "Unsupported argument",
    "Missing required argument",
)


@pytest.mark.skipif(shutil.which("terraform") is None, reason="terraform absent du PATH")
def test_generated_terraform_formats_and_validates_by_provider(tmp_path: Path) -> None:
    """Refuse les erreurs de syntaxe et tolère seulement les TODO connus."""
    findings = scan(FIXTURES)
    providers = sorted({finding.provider for finding in findings})
    assert providers

    for provider in providers:
        provider_dir = tmp_path / provider
        provider_dir.mkdir()
        generated = generate_files(finding for finding in findings if finding.provider == provider)
        for name, content in generated.items():
            if name.endswith(".tf"):
                (provider_dir / name).write_text(content, encoding="utf-8")

        formatted = subprocess.run(
            ["terraform", "fmt", "-check", "-diff"],
            cwd=provider_dir,
            capture_output=True,
            text=True,
        )
        assert formatted.returncode == 0, formatted.stdout + formatted.stderr

        initialized = subprocess.run(
            ["terraform", "init", "-backend=false", "-input=false"],
            cwd=provider_dir,
            capture_output=True,
            text=True,
        )
        assert initialized.returncode == 0, initialized.stdout + initialized.stderr

        validated = subprocess.run(
            ["terraform", "validate", "-no-color", "-json"],
            cwd=provider_dir,
            capture_output=True,
            text=True,
        )
        report = json.loads(validated.stdout)
        diagnostics = report.get("diagnostics", [])
        errors = [item for item in diagnostics if item.get("severity") == "error"]
        allowed = TODO_DIAGNOSTIC_ALLOWLIST.get(provider, ())
        for diagnostic in diagnostics:
            summary = diagnostic.get("summary", "")
            detail = diagnostic.get("detail", "")
            is_allowed = any(
                summary_fragment in summary and detail_fragment in detail
                for summary_fragment, detail_fragment in allowed
            )
            if diagnostic.get("severity") == "error":
                assert is_allowed, f"{provider}: erreur Terraform inattendue : {summary}\n{detail}"
            assert not any(term in summary for term in FORBIDDEN_SUMMARIES) or is_allowed, (
                f"{provider}: erreur HCL ou schéma Terraform : {summary}\n{detail}"
            )
        assert validated.returncode == (1 if errors else 0), validated.stdout + validated.stderr
