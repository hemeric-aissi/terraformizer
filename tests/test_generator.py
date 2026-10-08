"""Vérifications du rendu HCL et des scripts d'import."""

from __future__ import annotations

import subprocess
from pathlib import Path

from terraformizer.generators.hcl import generate_files, render_resource
from terraformizer.models import Finding


def resource(**kwargs: object) -> Finding:
    values = dict(
        provider="aws", tf_type="aws_instance", name="web", attributes={},
        source_file=Path("deploy.sh"), line=2, original="aws ec2 run-instances",
    )
    values.update(kwargs)
    return Finding(**values)


def test_nested_blocks_lists_raw_tags_and_alignment() -> None:
    finding = resource(attributes={
        "name": "web",
        "enabled": True,
        "count": 2,
        "ids": ["sg-one", "sg-two"],
        "zone": {"__raw__": "var.zone"},
        "boot_disk": {"initialize_params": {"image": "debian-cloud/debian-12"}},
        "allow": [{"protocol": "tcp", "ports": ["22"]}, {"protocol": "icmp"}],
        "tags": {"Name": "web", "Env": "prod"},
    })
    text = render_resource(finding)
    assert 'boot_disk {\n    initialize_params {' in text
    assert text.count("allow {") == 2
    assert 'ids     = ["sg-one", "sg-two"]' in text
    assert "zone    = var.zone" in text
    assert "enabled = true" in text
    assert 'tags    = {\n    "Name" = "web"' in text
    assert "# Source : deploy.sh:2 (confiance 100%)" in text


def test_deduplication_does_not_mutate_and_generates_variables() -> None:
    findings = [
        resource(import_id="i-123", attributes={"ami": {"__raw__": "var.ami"}}),
        resource(),
        resource(name="web_2"),
        resource(tf_type="UNMAPPED"),
        resource(tf_type="ERROR"),
    ]
    files = generate_files(findings)
    assert 'resource "aws_instance" "web"' in files["aws.tf"]
    assert 'resource "aws_instance" "web_2"' in files["aws.tf"]
    assert 'resource "aws_instance" "web_2_2"' in files["aws.tf"]
    assert "UNMAPPED" not in files["aws.tf"]
    assert "ERROR" not in files["aws.tf"]
    assert findings[1].name == "web"
    assert findings[1].notes == []
    assert "vérifier les références" in files["aws.tf"]
    assert 'variable "ami"' in files["variables.tf"]
    assert 'source  = "hashicorp/aws"' in files["versions.tf"]
    assert "terraform import 'aws_instance.web' 'i-123'" in files["import.sh"]
    assert "# terraform import 'aws_instance.web_2' '<ID_A_RENSEIGNER>'" in files["import.sh"]


def test_strings_and_comments_cannot_inject_hcl() -> None:
    text = render_resource(resource(
        original='command\nresource "bad" "bad" {}',
        notes=["vérifier\nune note"],
        attributes={"ami": '${file("secret")}', "tags": {"%{if true}": "x"}},
    ))
    assert '$${file(\\"secret\\")}' in text
    assert '"%%{if true}"' in text
    assert '\nresource "bad"' not in text
    assert "# TODO : vérifier une note" in text


def test_multiline_string_delimiter_collision() -> None:
    text = render_resource(resource(attributes={"user_data": "EOT\nhello\n"}))
    assert "<<-EOT_" in text
    assert "\n  EOT_\n" in text
    text = render_resource(resource(attributes={"user_data": "hello\nworld"}))
    assert "chomp(<<-EOT\nhello\nworld\n  EOT\n  )" in text


def test_import_identifier_is_shell_quoted(tmp_path: Path) -> None:
    identifier = "bucket'$(touch UNEXPECTED)\nother"
    text = generate_files([resource(import_id=identifier)])["import.sh"]
    script = tmp_path / "import.sh"
    script.write_text(text)
    subprocess.run(["bash", "-n", str(script)], check=True)
    # Le faux terraform affiche uniquement les arguments, sans aucune exécution d'import.
    script.write_text("terraform() { printf '%s\\n' \"$@\"; }\n" + text)
    result = subprocess.run(["bash", str(script)], cwd=tmp_path, capture_output=True,
                            text=True, check=True)
    assert identifier in result.stdout
    assert not (tmp_path / "UNEXPECTED").exists()


def test_all_providers_and_empty_generation() -> None:
    files = generate_files([
        resource(),
        resource(provider="google", tf_type="google_compute_instance"),
        resource(provider="azurerm", tf_type="azurerm_resource_group"),
    ])
    assert {"aws.tf", "google.tf", "azurerm.tf"} <= files.keys()
    assert "features {}" in files["azurerm.tf"]
    assert 'data "azurerm_client_config" "current"' in files["azurerm.tf"]
    assert "var.google_project" in files["google.tf"]
    assert "required_providers" not in generate_files([])["versions.tf"]
