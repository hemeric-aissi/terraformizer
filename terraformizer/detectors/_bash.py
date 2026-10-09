"""Extraire des commandes et attributs depuis du texte shell non fiable.

Les détecteurs reçoivent des sources et produisent des commandes localisées puis
des findings assortis d'avertissements. Cette analyse statique est volontairement
partielle : aucun script ni substitution n'est exécuté, aucun accès cloud n'a
lieu et les fichiers mentionnés dans les arguments ne sont pas ouverts.
"""

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
    """Conserver les mots analysés et leur provenance pour rendre l'audit possible.

    ``line`` désigne la ligne de l'exécutable, tandis que ``original`` conserve
    toute la ligne logique, continuations comprises. ``notes`` garde notamment
    la trace d'une tokenisation de secours sur des guillemets incomplets.
    """

    words: list[str]
    line: int
    original: str
    notes: list[str]


class BashDetector(Detector):
    """Inclure les scripts et les fichiers pouvant embarquer des commandes shell.

    Les extensions YAML et les noms Makefile/Jenkinsfile/Dockerfile permettent
    l'analyse de wrappers d'automatisation, sans exécuter ces formats.
    """

    extensions = (".sh", ".bash", ".zsh", ".yml", ".yaml", ".mk")
    filenames = ("Makefile", "Jenkinsfile", "Dockerfile")


def commands(content: str, executable: str) -> list[Command]:
    """Reconnaître des commandes sans confondre les séparateurs cités avec du shell.

    Args:
        content: Source complète, avec ses retours à la ligne d'origine.
        executable: Nom littéral du CLI recherché, protégé dans la regex.

    Returns:
        Commandes reconnues avec ligne d'origine et avertissements de lecture.

    Les continuations sont réunies avant la recherche. Un dernier fragment sans
    newline reste analysable ; les guillemets incomplets déclenchent une lecture
    de secours, pas une exécution. Ce n'est pas une grammaire shell exhaustive.
    """
    logical: list[tuple[str, list[tuple[int, int]], str]] = []
    text, original = "", ""
    positions: list[tuple[int, int]] = []
    for number, line in enumerate(content.splitlines(keepends=True), 1):
        # Chaque couple (offset logique, ligne physique) est enregistré avant
        # concaténation : retirer « \ + newline » ne doit pas déplacer le diagnostic.
        positions.append((len(text), number))
        original += line
        clean = line.rstrip("\r\n")
        continued = clean.endswith("\\") and not clean.endswith("\\\\")
        # L'espace remplace la continuation reconnue pour garder les mots distincts.
        # Un double antislash final n'est pas traité comme une continuation.
        text += clean[:-1] + " " if continued else clean
        if not continued:
            logical.append((text, positions, original.rstrip("\r\n")))
            text, original = "", ""
            positions = []
    # Une continuation à EOF ne doit pas faire disparaître la commande incomplète.
    if text:
        logical.append((text, positions, original.rstrip("\r\n")))

    # Alternatives de frontière, avant le nom littéral de l'exécutable :
    # - début de ligne + wrapper optionnel : liste YAML « - », recette Make « @ »,
    #   instruction Docker « RUN » ou remplacement du processus « exec » ;
    # - clé CI « run: », éventuellement suivie d'un guillemet ;
    # - enchaînements &&, || et ;, puis substitutions $(...) ou backticks ;
    # - wrapper sh '...', sh -c '...' ou sh('...') des fichiers d'automatisation.
    # Le lookahead final impose un espace ou EOF : « aws » ne doit pas reconnaître
    # « aws-helper ». La regex propose des candidats, _valid_boundary les filtre.
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
            # Le dernier offset qui précède l'exécutable désigne sa ligne physique,
            # même si celui-ci apparaît après plusieurs continuations.
            line = next(number for offset, number in reversed(positions) if offset <= position)
            notes: list[str] = []
            try:
                words = shlex.split(tail, comments=True)
            except ValueError:
                # Garder une piste exploitable sur une source incomplète, en abaissant
                # ensuite la confiance plutôt que d'arrêter tout le scan.
                words = tail.split()
                notes.append("Guillemets shell incomplets : analyse de secours.")
            if words:
                result.append(Command(words, line, original, notes))
    return result


def _valid_boundary(text: str, position: int, boundary: str) -> bool:
    """Vérifier le contexte lexical précédant une frontière candidate.

    Args:
        text: Ligne logique complète.
        position: Début de la frontière proposée par la regex.
        boundary: Texte reconnu, utilisé pour identifier une substitution.

    Returns:
        Vrai hors guillemets/commentaires, ou pour une substitution entre doubles quotes.

    Les apostrophes inhibent les échappements ; les doubles guillemets autorisent
    encore $(...) et les backticks. Un # ne débute un commentaire qu'au début ou
    après un espace. Cette vérification locale n'évalue aucune substitution.
    """
    quote = ""
    escaped = False
    for index, char in enumerate(text[:position]):
        if escaped:
            # Un caractère protégé ne peut ni ouvrir ni fermer une chaîne.
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
    # « echo "x; aws ..." » est du texte, contrairement à « echo "$(aws ...)" ».
    return not quote or (quote == '"' and boundary.startswith(("$(", "`")))


def _command_tail(text: str, wrapper: str = "") -> str:
    """Isoler une commande pour ne pas absorber les arguments de la suivante.

    Args:
        text: Fragment commençant par l'exécutable reconnu.
        wrapper: Quote fermante d'un wrapper sh ou backtick, sinon chaîne vide.

    Returns:
        Fragment à tokeniser, privé des séparateurs externes et du wrapper.

    Les guillemets et échappements protègent les séparateurs. Les parenthèses
    imbriquées sont conservées ; une parenthèse fermante sans ouverture locale
    termine notamment une substitution qui enveloppe la commande.
    """
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
            # La quote de sh '...' appartient au wrapper, pas aux arguments du CLI.
            return text[:index].rstrip()
        if char in "'\"`":
            quote = char
        elif char == "(":
            # Les séparateurs d'une sous-expression parenthésée restent dans le
            # fragment ; seuls ceux à profondeur zéro coupent la commande.
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
    """Lire les options sans faire consommer un argument par un booléen connu.

    Args:
        words: Mots déjà tokenisés, hors préfixe service/commande.
        aliases: Correspondance des formes courtes vers les clés canoniques.

    Returns:
        Couple (options par clé canonique, arguments positionnels).

    Une valeur après « = » reste littérale, même vide. Les booléens connus
    acceptent true/false explicites ; les listes reconnues consomment jusqu'au
    prochain flag. Un flag sans valeur devient True, et une répétition écrase
    la valeur précédente. Aucune expansion shell n'est tentée.
    """
    aliases = aliases or {}
    values: dict[str, Any] = {}
    positional: list[str] = []
    # Cette liste évite que « --quiet nom » avale un nom positionnel. Les formes
    # explicitement suivies de true/false empruntent la branche à valeur.
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
                # Seuls ces flags sont multi-valeurs : généraliser cette règle
                # ferait disparaître les arguments positionnels des autres CLI.
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
    """Convertir les booléens et entiers explicites, sans évaluer d'expression.

    Les signes et décimales restent des chaînes ; les autres types sont rendus
    tels quels. Cette conversion ne convient donc pas aux identifiants textuels.
    """
    if isinstance(value, str):
        if value.lower() in ("true", "false"):
            return value.lower() == "true"
        if re.fullmatch(r"\d+", value):
            return int(value)
    return value


def typed_value(attribute: str, value: Any) -> Any:
    """Limiter la coercition aux attributs dont le type Terraform est connu.

    Args:
        attribute: Nom de l'attribut cible, pas du flag source.
        value: Littéral issu de la commande.

    Returns:
        Valeur convertie si le type est connu, sinon valeur inchangée.

    Les noms numériques restent des chaînes. Les expressions shell dynamiques
    ou nombres signés ne sont pas interprétés comme des entiers.
    """
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
    """Unifier les listes CLI séparées par des virgules ou des espaces.

    Les éléments vides sont éliminés, y compris dans une liste déjà tokenisée ;
    les chaînes conservées ne font l'objet d'aucune expansion shell.
    """
    if isinstance(value, list):
        return [part for entry in value for part in re.split(r"[,\s]+", entry) if part]
    return [part for part in re.split(r"[,\s]+", str(value)) if part]


def shorthand(value: Any) -> dict[str, str]:
    """Lire la notation AWS sans couper les virgules internes à une valeur.

    Une virgule ne termine la valeur que si elle précède une nouvelle clé=.
    Les clés répétées gardent leur dernière valeur ; les fragments sans clé ou
    avec valeur vide ne sont pas reconnus. Les quotes ne sont pas interprétées.
    """
    # ([\w-]+) capture la clé, suivie d'un « = » littéral.
    # [^,]+ exige une première portion de valeur non vide.
    # (?:,(?![\w-]+=)[^,]+)* conserve les portions après une virgule tant
    # qu'elles n'annoncent pas une nouvelle clé= ; ainsi Value=a,b reste entier.
    return dict(re.findall(r"([\w-]+)=([^,]+(?:,(?![\w-]+=)[^,]+)*)", str(value)))


def file_expression(value: Any) -> Any:
    """Reporter file:// sous forme HCL sans ouvrir le fichier référencé.

    Seul le préfixe exact est reconnu ; les autres valeurs sont inchangées.
    Le chemin est cité comme un littéral pour ne pas injecter d'expression HCL.
    """
    if isinstance(value, str) and value.startswith("file://"):
        return {"__raw__": f"file({hcl_string(value[7:])})"}
    return value


def hcl_string(value: str) -> str:
    """Citer une chaîne sans laisser la source injecter un template HCL.

    JSON protège quotes et caractères de contrôle ; ${ et %{ sont échappés
    séparément car une chaîne JSON valide peut encore activer un template HCL.
    """
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
    """Construire un finding en rendant explicites les incertitudes de conversion.

    Args:
        path: Chemin source pour la traçabilité, sans lecture supplémentaire.
        command: Commande et notes de tokenisation.
        provider: Fournisseur Terraform cible.
        tf_type: Type de ressource Terraform cible.
        name: Nom proposé, normalisé en identifiant Terraform.
        attributes: Attributs HCL déjà convertis.
        values: Options CLI originales utilisées pour repérer les incertitudes.
        known: Flags pris en charge par le détecteur.
        ignored: Flags sans effet pertinent sur la ressource.
        required: Attributs dont l'absence exige une correction manuelle.
        import_id: Identifiant connu, jamais déduit d'une valeur dynamique.
        notes: Avertissements spécifiques au fournisseur.

    Returns:
        Finding localisé avec confiance et avertissements agrégés.

    Les attributs requis vides et flags inconnus diminuent la confiance sans
    empêcher le rendu. Une valeur shell dynamique non ignorée supprime l'import,
    même si un autre argument semblait fournir un identifiant statique.
    """
    warnings = list(command.notes) + (notes or [])
    for key in values:
        if key not in known | ignored:
            warnings.append(f"Flag non mappé : --{key}")
    for key in required:
        if key not in attributes or attributes[key] in (None, "", []):
            warnings.append(f"Attribut requis absent : {key}")
    if any(re.search(r"\$|`", str(value)) for key, value in values.items() if key not in ignored):
        # Sans exécuter le shell, ni variable ni substitution ne donnent un ID
        # fiable. Un import erroné est plus dangereux qu'un TODO manuel.
        warnings.append("Valeur shell dynamique : résolution manuelle nécessaire.")
        import_id = None
    if import_id and re.search(r"\$|`", import_id):
        import_id = None
    # Chaque avertissement retire 0,1 à la confiance (1 au départ), avec un
    # plancher de 0,3 pour garder la détection visible malgré ses limites.
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
