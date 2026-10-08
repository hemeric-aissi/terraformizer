"""Contrat des détecteurs et noms Terraform."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path

from terraformizer.models import Finding


def slugify(value: str, fallback: str = "resource") -> str:
    """Normalise un nom en identifiant Terraform."""
    slug = re.sub(r"[^a-z0-9_]", "_", str(value).lower()).strip("_")
    prefix = re.sub(r"[^a-z0-9_]", "_", fallback.lower()).strip("_") or "resource"
    if prefix[0].isdigit():
        prefix = f"resource_{prefix}"
    if not slug:
        return prefix
    return f"{prefix}_{slug}" if slug[0].isdigit() else slug


class Detector(ABC):
    """Analyse statique de fichiers, sans exécuter leur contenu."""

    name: str
    extensions: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()

    def handles(self, path: Path) -> bool:
        """Indique si le fichier est pris en charge."""
        return path.suffix.lower() in self.extensions or path.name in self.filenames

    @abstractmethod
    def detect(self, path: Path, content: str) -> list[Finding]:
        """Retourne les ressources reconnues dans un fichier."""
