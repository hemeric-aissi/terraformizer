"""Définir le modèle partagé des ressources issues de l'analyse statique.

Entrées : attributs convertis, provenance et limites fournies par les détecteurs.
Sorties : objets Finding mutables et adresses Terraform calculées.
Sécurité : aucun accès cloud, lecture de fichier ou exécution ; le modèle
ne valide ni l'existence des ressources ni l'innocuité des valeurs reçues.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """Décrire une ressource candidate et les limites de sa conversion.

    Args:
        provider: Fournisseur ciblé, ou unknown pour certains diagnostics.
        tf_type: Type Terraform, ou marqueur ERROR ou UNMAPPED non générable.
        name: Nom Terraform proposé, susceptible d'être dédupliqué.
        attributes: Valeurs et blocs convertis ; les expressions HCL produites
            par les détecteurs peuvent utiliser la représentation __raw__.
        source_file: Provenance, normalement relative à la base du scan.
        line: Ligne source, numérotée à partir de un.
        original: Texte source conservé à des fins de traçabilité.
        import_id: Identifiant d'import connu, ou None s'il reste à renseigner.
        confidence: Score heuristique attendu entre 0 et 1, non validé ici ;
            zéro signale notamment une erreur ou une conversion non reconnue,
            et un ne garantit ni validité ni application sûre.
        notes: Limites et avertissements, avec une liste indépendante par défaut.

    Les champs restent mutables et ne sont pas validés à la construction ;
    aucune ressource distante n'est consultée pour confirmer ces informations.
    """

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
        """Calculer l'adresse Terraform sans normalisation ni validation.

        Returns:
            Concaténation du type et du nom, même pour ERROR ou UNMAPPED.
        """
        return f"{self.tf_type}.{self.name}"
