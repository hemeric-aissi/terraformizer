"""Parcourir les sources locales pour produire des détections ordonnées.

Entrées : fichier ou projet, détecteurs sélectionnés et motifs d'exclusion.
Sorties : ressources candidates et diagnostics, sans écriture de fichiers.
Sécurité : analyse statique, sans accès cloud ni exécution des sources ;
les liens rencontrés dans le parcours et les fichiers trop volumineux sont ignorés.
Les résultats reflètent les reconnaissances partielles des détecteurs, pas
un inventaire exhaustif des ressources ni une validation des programmes sources.
"""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterable
from pathlib import Path

from terraformizer.detectors import get_detectors
from terraformizer.detectors.base import slugify
from terraformizer.models import Finding

DEFAULT_IGNORES: tuple[str, ...] = (
    ".git",
    ".terraform",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    "*.tfstate*",
)
MAX_FILE_SIZE = 2 * 1024 * 1024


def scan(
    root: Path | str,
    only: Iterable[str] | None = None,
    ignores: Iterable[str] = DEFAULT_IGNORES,
) -> list[Finding]:
    """Analyser les sources admissibles dans un ordre déterministe.

    Args:
        root: Fichier ou dossier local ; le chemin initial est résolu, y compris
            s'il est lui-même un lien symbolique.
        only: Noms des détecteurs retenus, ou tous si la valeur est None.
        ignores: Motifs appliqués aux composants et aux chemins relatifs ;
            la CLI y ajoute son dossier de sortie quand il est sous la racine.

    Returns:
        Détections non dédupliquées, avec chemins relatifs et diagnostics ERROR
        de confiance nulle lorsqu'un détecteur échoue.

    Raises:
        ValueError: Racine inexistante ou nom de détecteur inconnu.

    Les liens rencontrés après résolution, fichiers Terraform, fichiers de plus
    de MAX_FILE_SIZE et fichiers illisibles sont ignorés ; une analyse vide
    renvoie une liste vide, sans accès cloud ni exécution du contenu.
    """
    root = Path(root).resolve()
    if not root.exists():
        raise ValueError(f"Chemin introuvable : {root}")
    detectors = get_detectors(only)
    patterns = tuple(ignores)
    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []

    def ignored(path: Path) -> bool:
        """Tester les exclusions sans consulter le contenu du fichier.

        Args:
            path: Chemin situé sous la base de l'analyse.

        Returns:
            Vrai si un motif correspond à un composant ou au chemin relatif.
        """
        relative = path.relative_to(base)
        return any(
            fnmatch.fnmatch(part, pattern) or fnmatch.fnmatch(relative.as_posix(), pattern)
            for pattern in patterns
            for part in relative.parts
        )

    def inspect(path: Path) -> None:
        """Lire un fichier admissible et accumuler ses détections.

        Args:
            path: Chemin local sous la base ; liens et fichiers exclus sont ignorés.

        Les erreurs de lecture sont ignorées et celles des détecteurs deviennent
        des diagnostics, afin de poursuivre le parcours sans exécuter la source.
        """
        if path.is_symlink() or ignored(path) or path.suffix.lower() in (".tf", ".tfvars", ".hcl"):
            return
        applicable = [detector for detector in detectors if detector.handles(path)]
        if not applicable:
            return
        try:
            if path.stat().st_size > MAX_FILE_SIZE or not path.is_file():
                return
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        relative = path.relative_to(base)
        for detector in applicable:
            try:
                detected = detector.detect(relative, content)
                for finding in detected:
                    finding.source_file = relative
                findings.extend(detected)
            except Exception as exc:
                # Isoler l'échec d'un détecteur permet de poursuivre les autres analyses.
                findings.append(
                    Finding(
                        provider="unknown",
                        tf_type="ERROR",
                        name=slugify(f"{detector.name}_{relative}"),
                        attributes={},
                        source_file=relative,
                        line=1,
                        original="",
                        confidence=0.0,
                        notes=[f"Erreur du détecteur {detector.name} : {exc}"],
                    )
                )

    if root.is_file():
        inspect(root)
    else:
        for directory, dirs, files in os.walk(root, followlinks=False):
            parent = Path(directory)
            # Élaguer les dossiers exclus ou liés empêche leur traversée.
            # Le tri des dossiers et fichiers stabilise les détections et les snapshots.
            dirs[:] = sorted(
                name
                for name in dirs
                if not (parent / name).is_symlink() and not ignored(parent / name)
            )
            for name in sorted(files):
                inspect(parent / name)
    return findings
