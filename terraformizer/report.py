"""Présenter les détections locales dans le terminal, en JSON ou en Markdown.

Entrées : objets Finding et destinations locales pour les exports.
Sorties : tableau de synthèse ou rapports UTF-8, sans analyse supplémentaire.
Sécurité : aucune exécution de contenu ni aucun accès cloud ; les valeurs
proviennent d'une analyse statique et peuvent contenir des données sensibles.
La CLI vérifie les liens symboliques avant d'appeler les fonctions d'écriture.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from terraformizer.models import Finding


def print_summary(findings: list[Finding]) -> None:
    """Afficher les ressources et leur confiance sans interpréter leur balisage.

    Args:
        findings: Détections à afficher dans leur ordre courant.

    Une liste vide produit un tableau sans lignes ; les couleurs expriment un
    niveau heuristique, pas une garantie de validité du Terraform.
    """
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
    """Exporter les détections et leur adresse en JSON UTF-8.

    Args:
        findings: Détections sérialisables ; une liste vide produit [].
        dest: Fichier à remplacer, dont le dossier parent doit déjà exister.

    Le chemin source est converti en notation POSIX ; les erreurs d'écriture
    et de sérialisation remontent à l'appelant. Aucun contrôle des liens ni
    masquage des données sources n'est effectué ici.
    """
    rows = []
    for finding in findings:
        row = asdict(finding)
        row["source_file"] = finding.source_file.as_posix()
        row["address"] = finding.address
        rows.append(row)
    dest.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _cell(value: object) -> str:
    """Échapper les séparateurs et retours à la ligne d'une cellule Markdown.

    Args:
        value: Valeur convertie en texte, y compris None.

    Returns:
        Texte avec barres et antislashs échappés, sauts de ligne remplacés par
        <br> ; ce traitement n'est pas une désinfection HTML générale.
    """
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "<br>")


def write_markdown(findings: list[Finding], dest: Path) -> None:
    """Exporter un tableau Markdown des ressources et de leurs limites.

    Args:
        findings: Détections dans l'ordre du rapport ; la liste peut être vide.
        dest: Fichier à remplacer, dont le dossier parent doit déjà exister.

    Une liste vide conserve les en-têtes ; les erreurs d'écriture remontent
    à l'appelant, qui doit contrôler les liens symboliques si nécessaire.
    """
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
