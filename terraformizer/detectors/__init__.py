"""Répertorier et sélectionner les détecteurs d'analyse statique disponibles.

Entrée : noms optionnels des détecteurs ; sortie : instances dans l'ordre
du registre, sans lecture des sources à la sélection.
Sécurité : aucun accès cloud ni exécution de contenu ; les instances
interprètent les textes seulement lorsqu'elles sont sollicitées.
"""

from __future__ import annotations

from collections.abc import Iterable

from terraformizer.detectors.base import Detector
from terraformizer.detectors.bash_aws import BashAWSDetector
from terraformizer.detectors.bash_az import BashAzDetector
from terraformizer.detectors.bash_gcloud import BashGcloudDetector
from terraformizer.detectors.cloudformation import CloudFormationDetector
from terraformizer.detectors.python_boto3 import PythonBoto3Detector

ALL_DETECTORS: tuple[Detector, ...] = (
    BashAWSDetector(),
    BashGcloudDetector(),
    BashAzDetector(),
    PythonBoto3Detector(),
    CloudFormationDetector(),
)


def get_detectors(only: Iterable[str] | None = None) -> list[Detector]:
    """Sélectionner les détecteurs dans l'ordre stable du registre.

    Args:
        only: Noms exacts demandés ; None sélectionne tous les détecteurs.

    Returns:
        Nouvelle liste des instances partagées, sans doublons ; un itérable
        vide ne sélectionne aucun détecteur.

    Raises:
        ValueError: Au moins un nom demandé n'existe pas dans le registre.
    """
    if only is None:
        return list(ALL_DETECTORS)
    selected = set(only)
    unknown = selected - {detector.name for detector in ALL_DETECTORS}
    if unknown:
        raise ValueError(f"Détecteurs inconnus : {', '.join(sorted(unknown))}")
    return [detector for detector in ALL_DETECTORS if detector.name in selected]
