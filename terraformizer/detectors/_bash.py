"""Lecture statique de commandes shell, sans jamais les exécuter."""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from terraformizer.detectors.base import Detector, slugify
from terraformizer.models import Finding


@dataclass
class Command:
    """Commande reconnue et emplacement dans le texte d'origine."""

    words: list[str]
    line: int
    original: str
    notes: list[str]


class BashDetector(Detector):
    """Extensions communes aux scripts et aux fichiers d'automatisation."""

    extensions = (".sh", ".bash", ".zsh", ".yml", ".yaml", ".mk")
    filenames = ("Makefile", "Jenkinsfile", "Dockerfile")


def commands(content: str, executable: str) -> list[Command]:
    """Joint les continuations et reconnaît les frontières de commandes shell."""
    logical: list[tuple[str, list[tuple[int, int]], str]] = []
    text, original = "", ""
    positions: list[tuple[int, int]] = []
    for number, line in enumerate(content.splitlines(keepends=True), 1):
        positions.append((len(text), number))
        original += line
        clean = line.rstrip("\r\n")
        continued = clean.endswith("\\") and not clean.endswith("\\\\")
        text += clean[:-1] + " " if continued else clean
        if not continued:
            logical.append((text, positions, original.rstrip("\r\n")))
            text, original = "", ""
            positions = []
    if text:
        logical.append((text, positions, original.rstrip("\r\n")))

    boundary = re.compile(
        rf"(?:^\s*(?:(?:-\s+|@\s*|RUN\s+|exec\s+))?"
        rf"(?:run:\s*(?:[\"']\s*)?)?"
        rf"|&&\s*|\|\|\s*|;\s*|\$\(\s*|`\s*"
        rf"|\bsh\s*(?:\(\s*|(?:-c\s+)?)[\"']\s*)"
        rf"{re.escape(executable)}(?=\s|$)"
    )
    result: list[Command] = []
    for text, positions, original in logical:
        for match in boundary.finditer(text):
            if not _valid_boundary(text, match.start(), match.group()):
                continue
            position = match.end() - len(executable)
            prefix = match.group()[: -len(executable)].rstrip()
            wrapper = prefix[-1:] if prefix.endswith(("'", '"', "`")) else ""
            tail = _command_tail(text[position:], wrapper)
            line = next(number for offset, number in reversed(positions) if offset <= position)
            notes: list[str] = []
            try:
                words = shlex.split(tail, comments=True)
            except ValueError:
                words = tail.split()
                notes.append("Guillemets shell incomplets : analyse de secours.")
            if words:
                result.append(Command(words, line, original, notes))
    return result


def _valid_boundary(text: str, position: int, boundary: str) -> bool:
    """Écarte les commentaires et séparateurs cités, sauf substitutions shell."""
    quote = ""
    escaped = False
    for index, char in enumerate(text[:position]):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or text[index - 1].isspace()):
            return False
    return not quote or (quote == '"' and boundary.startswith(("$(", "`")))


def _command_tail(text: str, wrapper: str = "") -> str:
    """Retire les commandes suivantes, en respectant les chaînes et substitutions."""
    quote = ""
    depth = 0
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote != "'":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = ""
            continue
        if wrapper and char == wrapper and not depth:
            return text[:index].rstrip()
        if char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            if not depth:
                return text[:index].rstrip()
            depth -= 1
        elif not depth and (
            char in ";|&" or (char == "#" and (index == 0 or text[index - 1].isspace()))
        ):
            return text[:index].rstrip()
    # Les apostrophes fermant « sh 'commande' » ne font pas partie de la commande.
    if quote and text.endswith(quote) and text.count(quote) % 2:
        return text[:-1].rstrip()
    return text.rstrip()


def flags(
    words: list[str], aliases: dict[str, str] | None = None
) -> tuple[dict[str, Any], list[str]]:
    """Lit --flag valeur, --flag=valeur, les booléens et les listes d'identifiants."""
    aliases = aliases or {}
    values: dict[str, Any] = {}
    positional: list[str] = []
    boolean_flags = {
        "quiet",
        "no-cli-pager",
        "only-show-errors",
        "no-address",
        "can-ip-forward",
        "publicly-accessible",
        "multi-az",
        "storage-encrypted",
        "multi-region",
        "generate-ssh-keys",
        "enable-managed-identity",
        "enable-rbac-authorization",
        "enable-purge-protection",
        "enable-autopilot",
        "uniform-bucket-level-access",
        "disabled",
        "https-only",
        "allow-blob-public-access",
        "manage-master-user-password",
    }
    index = 0
    while index < len(words):
        word = words[index]
        if not word.startswith("-") or word == "-":
            positional.append(word)
            index += 1
            continue
        key, separator, value = word.lstrip("-").partition("=")
        key = aliases.get(key, key)
        if separator:
            values[key] = value
        elif key in boolean_flags and (
            index + 1 == len(words) or words[index + 1].lower() not in ("true", "false")
        ):
            values[key] = True
        elif index + 1 < len(words) and not words[index + 1].startswith("-"):
            index += 1
            value = words[index]
            if key in (
                "security-group-ids",
                "vpc-security-group-ids",
                "attribute-definitions",
                "key-schema",
                "address-prefixes",
                "nics",
                "subnet-prefixes",
            ):
                items = [value]
                while index + 1 < len(words) and not words[index + 1].startswith("-"):
                    index += 1
                    items.append(words[index])
                values[key] = items
            else:
                values[key] = value
        else:
            values[key] = True
        index += 1
    return values, positional


_parse_flags = flags


def scalar(value: Any) -> Any:
    """Convertit les booléens et les entiers explicites du CLI."""
    if isinstance(value, str):
        if value.lower() in ("true", "false"):
            return value.lower() == "true"
        if re.fullmatch(r"\d+", value):
            return int(value)
    return value


def typed_value(attribute: str, value: Any) -> Any:
    """Convertit uniquement les attributs Terraform explicitement typés."""
    numeric = {
        "max_session_duration",
        "allocated_storage",
        "timeout",
        "memory_size",
        "retention_in_days",
        "read_capacity",
        "write_capacity",
        "delay_seconds",
        "max_message_size",
        "message_retention_seconds",
        "receive_wait_time_seconds",
        "visibility_timeout_seconds",
        "mtu",
        "priority",
        "initial_node_count",
        "disk_size_gb",
        "node_count",
    }
    boolean = {
        "publicly_accessible",
        "multi_az",
        "storage_encrypted",
        "multi_region",
        "manage_master_user_password",
        "scan_on_push",
        "fifo_queue",
        "fifo_topic",
        "content_based_deduplication",
        "endpoint_public_access",
        "endpoint_private_access",
        "can_ip_forward",
        "uniform_bucket_level_access",
        "disabled",
        "enable_autopilot",
        "https_traffic_only_enabled",
        "allow_nested_items_to_be_public",
        "enable_rbac_authorization",
        "purge_protection_enabled",
    }
    if attribute in numeric and isinstance(value, str) and re.fullmatch(r"\d+", value):
        return int(value)
    if attribute in boolean:
        return scalar(value)
    return value


def items(value: Any) -> list[str]:
    """Normalise les listes séparées par des virgules ou des espaces."""
    if isinstance(value, list):
        return [part for entry in value for part in re.split(r"[,\s]+", entry) if part]
    return [part for part in re.split(r"[,\s]+", str(value)) if part]


def shorthand(value: Any) -> dict[str, str]:
    """Lit la notation AWS clé=valeur, sans évaluer les valeurs."""
    return dict(re.findall(r"([\w-]+)=([^,]+(?:,(?![\w-]+=)[^,]+)*)", str(value)))


def file_expression(value: Any) -> Any:
    """Convertit file:// en expression HCL ; ne lit jamais le fichier référencé."""
    if isinstance(value, str) and value.startswith("file://"):
        return {"__raw__": f"file({hcl_string(value[7:])})"}
    return value


def hcl_string(value: str) -> str:
    """Cite une chaîne JSON et neutralise les délimiteurs d'interpolation HCL."""
    return json.dumps(value.replace("${", "$${").replace("%{", "%%{"))


def finding(
    *,
    path: Path,
    command: Command,
    provider: str,
    tf_type: str,
    name: Any,
    attributes: dict[str, Any],
    values: dict[str, Any],
    known: set[str],
    ignored: set[str],
    required: tuple[str, ...] = (),
    import_id: str | None = None,
    notes: list[str] | None = None,
) -> Finding:
    """Construit un résultat et signale les informations impossibles à convertir."""
    warnings = list(command.notes) + (notes or [])
    for key in values:
        if key not in known | ignored:
            warnings.append(f"Flag non mappé : --{key}")
    for key in required:
        if key not in attributes or attributes[key] in (None, "", []):
            warnings.append(f"Attribut requis absent : {key}")
    if any(re.search(r"\$|`", str(value)) for key, value in values.items() if key not in ignored):
        warnings.append("Valeur shell dynamique : résolution manuelle nécessaire.")
        import_id = None
    if import_id and re.search(r"\$|`", import_id):
        import_id = None
    return Finding(
        provider=provider,
        tf_type=tf_type,
        name=slugify(str(name or tf_type), tf_type),
        attributes=attributes,
        source_file=path,
        line=command.line,
        original=command.original,
        import_id=import_id,
        confidence=max(0.3, 1.0 - 0.1 * len(warnings)),
        notes=warnings,
    )
