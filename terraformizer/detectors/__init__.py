"""Registre des détecteurs disponibles."""

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
    """Sélectionne les détecteurs, en rejetant les noms inconnus."""
    if only is None:
        return list(ALL_DETECTORS)
    selected = set(only)
    unknown = selected - {detector.name for detector in ALL_DETECTORS}
    if unknown:
        raise ValueError(f"Détecteurs inconnus : {', '.join(sorted(unknown))}")
    return [detector for detector in ALL_DETECTORS if detector.name in selected]
