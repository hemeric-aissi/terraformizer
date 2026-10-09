"""Rapports lisibles et exportables des détections."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from terraformizer.models import Finding


def print_summary(findings: list[Finding]) -> None:
    """Affiche un tableau de synthèse dans le terminal."""
    table = Table(title="Ressources détectées")
    for column in ("Provider", "Type", "Nom", "Fichier", "Ligne", "Confiance", "Notes"):
        table.add_column(column)
    for finding in findings:
        color = (
            "green"
            if finding.confidence >= 0.8
            else "yellow"
            if finding.confidence >= 0.5
            else "red"
        )
        table.add_row(
            Text(finding.provider),
            Text(finding.tf_type),
            Text(finding.name),
            Text(str(finding.source_file)),
            str(finding.line),
            Text(f"{finding.confidence:.0%}", style=color),
            Text("; ".join(finding.notes)),
        )
    Console().print(table)


def write_json(findings: list[Finding], dest: Path) -> None:
    """Écrit les findings au format JSON UTF-8."""
    rows = []
    for finding in findings:
        row = asdict(finding)
        row["source_file"] = finding.source_file.as_posix()
        row["address"] = finding.address
        rows.append(row)
    dest.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _cell(value: object) -> str:
    """Protège les séparateurs et retours à la ligne d'une cellule."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def write_markdown(findings: list[Finding], dest: Path) -> None:
    """Écrit un tableau Markdown des détections."""
    lines = [
        "# Rapport terraformizer",
        "",
        "| Provider | Type | Nom | Fichier | Ligne | Confiance | Notes |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for finding in findings:
        cells = [
            finding.provider,
            finding.tf_type,
            finding.name,
            finding.source_file,
            finding.line,
            f"{finding.confidence:.0%}",
            "; ".join(finding.notes),
        ]
        lines.append("| " + " | ".join(_cell(cell) for cell in cells) + " |")
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
