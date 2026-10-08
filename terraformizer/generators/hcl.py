"""Rendu HCL et commandes d'import, sans exécution."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from terraformizer.models import Finding

PROVIDERS = {
    "aws": 'provider "aws" {\n  region = var.aws_region\n}\n',
    "google": (
        'provider "google" {\n  project = var.google_project\n'
        '  region  = var.google_region\n}\n'
    ),
    "azurerm": (
        'provider "azurerm" {\n  features {}\n}\n\n'
        'data "azurerm_client_config" "current" {}\n'
    ),
}
PROVIDER_VERSIONS = {"aws": "~> 5.0", "google": "~> 5.0", "azurerm": "~> 3.0"}


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Rend les adresses uniques sans modifier les findings d'origine."""
    used: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        name = finding.name
        index = 2
        while f"{finding.tf_type}.{name}" in used:
            name = f"{finding.name}_{index}"
            index += 1
        used.add(f"{finding.tf_type}.{name}")
        notes = list(finding.notes)
        if name != finding.name:
            notes.append(
                f"Adresse dupliquée {finding.address} renommée en {finding.tf_type}.{name} : "
                "vérifier les références et éviter d'importer deux fois la même ressource."
            )
        result.append(replace(finding, name=name, notes=notes))
    return result


def _quote(value: str) -> str:
    """Cite une chaîne sans activer les interpolations HCL."""
    return json.dumps(value.replace("${", "$${").replace("%{", "%%{"), ensure_ascii=False)


def _value(value: Any, indent: int = 0) -> str:
    """Sérialise un littéral ou une expression brute contrôlée."""
    if isinstance(value, dict) and "__raw__" in value:
        return str(value["__raw__"])
    if isinstance(value, str):
        if "\n" not in value:
            return _quote(value)
        delimiter = "EOT"
        while delimiter in {line.strip() for line in value.splitlines()}:
            delimiter += "_"
        escaped = value.replace("${", "$${").replace("%{", "%%{")
        if escaped.endswith("\n"):
            return f"<<-{delimiter}\n{escaped}{' ' * indent}{delimiter}"
        return (
            f"chomp(<<-{delimiter}\n{escaped}\n"
            f"{' ' * indent}{delimiter}\n{' ' * indent})"
        )
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("Une valeur HCL numérique doit être finie")
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_value(item, indent) for item in value) + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        entries = [
            f"{' ' * (indent + 2)}{_quote(str(key))} = {_value(item, indent + 2)}"
            for key, item in value.items()
        ]
        return "{\n" + "\n".join(entries) + f"\n{' ' * indent}}}"
    raise TypeError(f"Valeur HCL non prise en charge : {type(value).__name__}")


def _attributes(attributes: dict[str, Any], indent: int) -> list[str]:
    """Rend les attributs alignés et les blocs imbriqués."""
    simple = [
        key for key, value in attributes.items()
        if key == "tags" or not (
            isinstance(value, dict) and "__raw__" not in value
            or isinstance(value, list) and value
            and all(isinstance(item, dict) and "__raw__" not in item for item in value)
        )
    ]
    width = max(map(len, simple), default=0)
    lines: list[str] = []
    prefix = " " * indent
    for key, value in attributes.items():
        if key in simple:
            lines.append(f"{prefix}{key:<{width}} = {_value(value, indent)}")
            continue
        blocks = value if isinstance(value, list) else [value]
        for block in blocks:
            lines.append(f"{prefix}{key} {{")
            lines.extend(_attributes(block, indent + 2))
            lines.append(f"{prefix}}}")
    return lines


def _comment(value: str) -> str:
    """Maintient chaque commentaire sur une seule ligne."""
    return " ".join(str(value).splitlines())


def render_resource(finding: Finding) -> str:
    """Produit une ressource et les avertissements de conversion."""
    lines = [
        f"# Source : {_comment(str(finding.source_file))}:{finding.line} "
        f"(confiance {finding.confidence:.0%})",
        f"# Origine : {_comment(finding.original)[:120]}",
    ]
    lines.extend(f"# TODO : {_comment(note)}" for note in finding.notes)
    lines.append(f'resource "{finding.tf_type}" "{finding.name}" {{')
    lines.extend(_attributes(finding.attributes, 2))
    lines.append("}")
    return "\n".join(lines) + "\n"


def _raw_variables(value: Any) -> set[str]:
    """Collecte les variables mentionnées dans les expressions brutes."""
    if isinstance(value, dict):
        if "__raw__" in value:
            return set(re.findall(r"\bvar\.([a-zA-Z_][a-zA-Z0-9_]*)", str(value["__raw__"])))
        return set().union(*(_raw_variables(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_raw_variables(item) for item in value))
    return set()


def generate_files(findings: Iterable[Finding]) -> dict[str, str]:
    """Génère les providers, ressources, variables et imports nécessaires."""
    resources = deduplicate(
        finding for finding in findings
        if finding.tf_type not in ("UNMAPPED", "ERROR") and finding.provider in PROVIDERS
    )
    providers = sorted({finding.provider for finding in resources})
    files: dict[str, str] = {}
    for provider in providers:
        rendered = [render_resource(f) for f in resources if f.provider == provider]
        files[f"{provider}.tf"] = PROVIDERS[provider] + "\n" + "\n".join(rendered)
    versions = ['terraform {', '  required_version = ">= 1.5"']
    if providers:
        versions.append("  required_providers {")
        for provider in providers:
            versions.extend([
                f"    {provider} = {{",
                f'      source  = "hashicorp/{provider}"',
                f'      version = "{PROVIDER_VERSIONS[provider]}"',
                "    }",
            ])
        versions.append("  }")
    versions.append("}")
    files["versions.tf"] = "\n".join(versions) + "\n"
    variables: dict[str, str] = {}
    if "aws" in providers:
        variables["aws_region"] = '  type    = string\n  default = "us-east-1"'
    if "google" in providers:
        variables["google_project"] = "  type = string"
        variables["google_region"] = '  type    = string\n  default = "europe-west1"'
    for resource in resources:
        for name in sorted(_raw_variables(resource.attributes)):
            variables.setdefault(name, '  description = "TODO : valeur issue du code source"')
    files["variables.tf"] = "\n\n".join(
        f'variable "{name}" {{\n{body}\n}}' for name, body in sorted(variables.items())
    ) + "\n"
    imports = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    for resource in resources:
        # Le quoting protège les identifiants issus de sources non fiables.
        address = _shell_quote(resource.address)
        if resource.import_id:
            identifier = _shell_quote(resource.import_id)
            imports.append(f"terraform import {address} {identifier}")
        else:
            imports.append(f"# terraform import {address} '<ID_A_RENSEIGNER>'")
    files["import.sh"] = "\n".join(imports) + "\n"
    return files


def _shell_quote(value: str) -> str:
    """Cite un argument Bash, y compris les apostrophes et retours à la ligne."""
    return "'" + value.replace("'", "'\"'\"'") + "'"
