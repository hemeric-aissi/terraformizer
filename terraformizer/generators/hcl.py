"""Transformer des findings en contenus de fichiers HCL et de script d'import.

Les sorties sont des chaînes à écrire par l'appelant : ce module n'accède pas
au cloud, n'exécute ni Terraform ni le shell et ne lit pas les fichiers sources.
Les littéraux non fiables sont échappés ; les marqueurs __raw__ sont réservés
aux expressions construites par les détecteurs lors de leur analyse statique.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import replace
from typing import Any

from terraformizer.models import Finding

# Fournisseur -> préambule HCL ; seules ces clés sont admises au rendu.
# Les paramètres restent des références Terraform, jamais des requêtes cloud.
PROVIDERS = {
    "aws": 'provider "aws" {\n  region = var.aws_region\n}\n',
    "google": (
        'provider "google" {\n  project = var.google_project\n  region  = var.google_region\n}\n'
    ),
    "azurerm": (
        # La data source sera résolue par Terraform, pas pendant la génération ;
        # elle permet notamment de référencer le tenant sans inventer sa valeur.
        'provider "azurerm" {\n  features {}\n}\n\ndata "azurerm_client_config" "current" {}\n'
    ),
}
# Fournisseur -> contrainte du schéma ciblé par les mappings des détecteurs.
PROVIDER_VERSIONS = {"aws": "~> 5.0", "google": "~> 5.0", "azurerm": "~> 3.0"}


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Rendre les adresses uniques sans altérer les résultats de détection.

    Args:
        findings: Résultats dans l'ordre de détection, éventuellement un itérateur.

    Returns:
        Copies des findings, avec noms et notes ajustés en cas de collision.

    Les suffixes déjà occupés sont sautés ; deux types différents peuvent garder
    le même nom. Les références internes ne sont pas réécrites : une note exige
    leur vérification lorsque le nom change.
    """
    used: set[str] = set()
    result: list[Finding] = []
    for finding in findings:
        name = finding.name
        index = 2
        while f"{finding.tf_type}.{name}" in used:
            name = f"{finding.name}_{index}"
            index += 1
        used.add(f"{finding.tf_type}.{name}")
        # Copier les notes avant d'y ajouter un TODO évite de polluer le rapport
        # source. replace est une copie superficielle : les attributs, non modifiés
        # ici, restent partagés, mais le finding original conserve son nom.
        notes = list(finding.notes)
        if name != finding.name:
            notes.append(
                f"Adresse dupliquée {finding.address} renommée en {finding.tf_type}.{name} : "
                "vérifier les références et éviter d'importer deux fois la même ressource."
            )
        result.append(replace(finding, name=name, notes=notes))
    return result


def _quote(value: str) -> str:
    """Citer un littéral Unicode sans activer d'interpolation ni directive HCL.

    JSON protège les quotes et contrôles ; ${ et %{ nécessitent en plus
    l'échappement propre aux templates Terraform, même dans une chaîne citée.
    """
    return json.dumps(value.replace("${", "$${").replace("%{", "%%{"), ensure_ascii=False)


def _value(value: Any, indent: int = 0) -> str:
    """Sérialiser une valeur en préservant le contenu des chaînes multilignes.

    Args:
        value: Littéral, collection ou expression __raw__ contrôlée.
        indent: Indentation du contexte pour fermer maps et heredocs.

    Returns:
        Expression HCL, éventuellement répartie sur plusieurs lignes.

    Les heredocs évitent d'échapper chaque retour à la ligne ; leur délimiteur
    est choisi sans collision et chomp retire le retour ajouté quand la source
    n'en avait pas. Les nombres non finis et types inconnus sont refusés.
    """
    if isinstance(value, dict) and "__raw__" in value:
        # Cette échappatoire suppose un marqueur créé par un détecteur, jamais
        # une clé arbitraire provenant directement d'un document non fiable.
        return str(value["__raw__"])
    if isinstance(value, str):
        if "\n" not in value:
            return _quote(value)
        delimiter = "EOT"
        # Une ligne du contenu égale au délimiteur fermerait le heredoc trop tôt.
        # strip tient compte des espaces tolérés par la forme indentée <<-.
        while delimiter in {line.strip() for line in value.splitlines()}:
            delimiter += "_"
        escaped = value.replace("${", "$${").replace("%{", "%%{")
        if escaped.endswith("\n"):
            return f"<<-{delimiter}\n{escaped}{' ' * indent}{delimiter}"
        # HCL impose une newline avant la fermeture ; chomp empêche cette
        # contrainte de syntaxe d'ajouter une newline absente du littéral source.
        return f"chomp(<<-{delimiter}\n{escaped}\n{' ' * indent}{delimiter}\n{' ' * indent})"
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
    """Distinguer les attributs affectés des blocs attendus par les providers.

    Args:
        attributes: Attributs selon la convention commune des détecteurs.
        indent: Nombre d'espaces devant chaque ligne du niveau courant.

    Returns:
        Lignes HCL avec blocs imbriqués et alignement des attributs simples.

    Un dict ordinaire représente un bloc, une liste non vide de dicts des blocs
    répétés. tags reste une map affectée avec « = ». Les expressions __raw__,
    listes vides ou mixtes sont des valeurs simples, pas des blocs répétés.
    """
    simple = [
        key
        for key, value in attributes.items()
        if key == "tags"
        or not (
            isinstance(value, dict)
            and "__raw__" not in value
            or isinstance(value, list)
            and value
            and all(isinstance(item, dict) and "__raw__" not in item for item in value)
        )
    ]
    width = max(map(len, simple), default=0)
    lines: list[str] = []
    prefix = " " * indent
    for key, value in attributes.items():
        if key in simple:
            if key == "tags" and isinstance(value, dict) and "__raw__" not in value:
                # L'ouverture d'une map tags suit le format Terraform sans
                # l'alignement réservé aux autres affectations de ce niveau.
                lines.append(f"{prefix}{key} = {_value(value, indent)}")
                continue
            lines.append(f"{prefix}{key:<{width}} = {_value(value, indent)}")
            continue
        blocks = value if isinstance(value, list) else [value]
        for block in blocks:
            lines.append(f"{prefix}{key} {{")
            lines.extend(_attributes(block, indent + 2))
            lines.append(f"{prefix}}}")
    return lines


def _comment(value: str) -> str:
    """Empêcher qu'un retour à la ligne source sorte du commentaire généré.

    Les lignes vides ou multiples sont aplaties, sans interpréter leur contenu ;
    une source non fiable ne peut ainsi ajouter une ligne de code HCL.
    """
    return " ".join(str(value).splitlines())


def render_resource(finding: Finding) -> str:
    """Rendre une ressource avec la provenance et les TODO de conversion.

    Args:
        finding: Résultat dont type et nom ont été normalisés par le détecteur.

    Returns:
        Bloc resource terminé par un retour à la ligne.

    Les textes source et notes sont réduits à une ligne pour rester des
    commentaires ; l'extrait d'origine est tronqué pour limiter le bruit.
    """
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
    """Collecter les variables des expressions contrôlées, pas des littéraux.

    La recherche descend dans les maps et listes, y compris vides. Elle reste
    lexicale, sans parser HCL : seules les formes var.identifiant sont reconnues
    et les références répétées ne créent qu'une déclaration.
    """
    if isinstance(value, dict):
        if "__raw__" in value:
            # \b impose une frontière de mot avant « var » (pas « myvar »).
            # var\. exige le namespace et son point littéral.
            # Le groupe commence par une lettre ASCII ou _, puis accepte aussi
            # les chiffres ; il capture le nom, sans index ni attribut suivant.
            # On n'applique pas cette regex aux chaînes littérales, où « var.x »
            # peut être du texte et ne nécessite aucune déclaration Terraform.
            return set(re.findall(r"\bvar\.([a-zA-Z_][a-zA-Z0-9_]*)", str(value["__raw__"])))
        return set().union(*(_raw_variables(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_raw_variables(item) for item in value))
    return set()


def generate_files(findings: Iterable[Finding]) -> dict[str, str]:
    """Préparer les fichiers sans écrire sur disque ni lancer d'import.

    Args:
        findings: Résultats de détection, consommés une seule fois.

    Returns:
        Dictionnaire nom de fichier -> contenu HCL ou script Bash.

    ERROR, UNMAPPED et fournisseurs inconnus ne produisent pas de ressource.
    Même sans ressource, les fichiers communs sont rendus. Un import sans ID
    reste commenté ; les variables dynamiques deviennent des TODO sans valeur
    inventée et les adresses dupliquées nécessitent une vérification manuelle.
    """
    resources = deduplicate(
        finding
        for finding in findings
        if finding.tf_type not in ("UNMAPPED", "ERROR") and finding.provider in PROVIDERS
    )
    providers = sorted({finding.provider for finding in resources})
    files: dict[str, str] = {}
    for provider in providers:
        rendered = [render_resource(f) for f in resources if f.provider == provider]
        files[f"{provider}.tf"] = PROVIDERS[provider] + "\n" + "\n".join(rendered)
    versions = ["terraform {", '  required_version = ">= 1.5"']
    if providers:
        versions.append("  required_providers {")
        for provider in providers:
            versions.extend(
                [
                    f"    {provider} = {{",
                    f'      source  = "hashicorp/{provider}"',
                    f'      version = "{PROVIDER_VERSIONS[provider]}"',
                    "    }",
                ]
            )
        versions.append("  }")
    versions.append("}")
    files["versions.tf"] = "\n".join(versions) + "\n"
    variables: dict[str, str] = {}
    if "aws" in providers:
        # Ne pas inventer une région AWS : l'utilisateur doit choisir celle des
        # ressources existantes avant un import ou un plan.
        variables["aws_region"] = (
            '  type        = string\n  description = "Région AWS des ressources importées"'
        )
    if "google" in providers:
        variables["google_project"] = "  type = string"
        variables["google_region"] = '  type    = string\n  default = "europe-west1"'
    for resource in resources:
        for name in sorted(_raw_variables(resource.attributes)):
            # Une référence source ne doit pas écraser la définition d'une
            # variable déjà nécessaire au provider.
            variables.setdefault(name, '  description = "TODO : valeur issue du code source"')
    files["variables.tf"] = (
        "\n\n".join(f'variable "{name}" {{\n{body}\n}}' for name, body in sorted(variables.items()))
        + "\n"
    )
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
    """Protéger un argument d'import contre toute interprétation par Bash.

    Les quotes simples inhibent $, backticks, séparateurs et retours à la ligne.
    Une apostrophe ferme la quote, s'écrit entre doubles quotes puis rouvre la
    quote simple ; même la chaîne vide reste ainsi un argument unique.
    """
    return "'" + value.replace("'", "'\"'\"'") + "'"
