"""Modèle commun des ressources détectées."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """Une ressource et les limites de sa conversion."""

    provider: str
    tf_type: str
    name: str
    attributes: dict[str, Any]
    source_file: Path
    line: int
    original: str
    import_id: str | None = None
    confidence: float = 1.0
    notes: list[str] = field(default_factory=list)

    @property
    def address(self) -> str:
        """Adresse Terraform de la ressource."""
        return f"{self.tf_type}.{self.name}"
