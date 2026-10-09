"""Définir le contrat d'analyse statique et la normalisation des noms.

Entrées : chemins indicatifs, contenus textuels et noms à normaliser.
Sorties : choix de prise en charge, objets Finding et identifiants Terraform.
Sécurité : aucun accès cloud ni exécution des sources ; les détecteurs
analysent le contenu fourni plutôt que de lancer les commandes qu'il décrit.
Leurs reconnaissances restent partielles et ne garantissent ni une interprétation
complète du langage source ni une conversion Terraform exhaustive.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path

from terraformizer.models import Finding


def slugify(value: str, fallback: str = "resource") -> str:
    """Normaliser un nom en identifiant Terraform non vide.

    Args:
        value: Valeur convertie en texte puis en minuscules ASCII admissibles.
        fallback: Nom de repli et préfixe utilisé si le nom commence par un chiffre.

    Returns:
        Identifiant composé de lettres minuscules, chiffres et underscores ;
        un repli vide ou inutilisable devient resource et un chiffre initial
        entraîne l'ajout d'un préfixe valide.
    """
    slug = re.sub(r"[^a-z0-9_]", "_", str(value).lower()).strip("_")
    prefix = re.sub(r"[^a-z0-9_]", "_", fallback.lower()).strip("_") or "resource"
    if prefix[0].isdigit():
        prefix = f"resource_{prefix}"
    if not slug:
        return prefix
    return f"{prefix}_{slug}" if slug[0].isdigit() else slug


class Detector(ABC):
    """Définir un détecteur qui interprète des textes sans les exécuter.

    Les sous-classes déclarent name pour leur sélection, extensions pour les
    suffixes en minuscules et filenames pour les noms exacts reconnus.
    Le contrat n'implique ni lecture du chemin fourni ni accès cloud.
    """

    name: str
    extensions: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()

    def handles(self, path: Path) -> bool:
        """Décider la prise en charge à partir du nom, sans lire le fichier.

        Args:
            path: Chemin indicatif, qui peut ne pas exister.

        Returns:
            Vrai pour un suffixe reconnu sans distinction de casse ou un nom
            exact reconnu ; faux si les deux collections sont vides.
        """
        return path.suffix.lower() in self.extensions or path.name in self.filenames

    @abstractmethod
    def detect(self, path: Path, content: str) -> list[Finding]:
        """Analyser statiquement le contenu fourni sans exécution ni accès cloud.

        Args:
            path: Chemin de provenance à reporter dans les détections.
            content: Texte source à interpréter, jamais à exécuter.

        Returns:
            Ressources reconnues et leurs limites ; une liste vide est possible.

        Les exceptions d'une implémentation sont transformées en diagnostics
        ERROR par le scanner ; un appel direct ne bénéficie pas de ce traitement.
        """
