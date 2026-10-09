"""Définir l'option pytest de mise à jour des snapshots et sa fixture.

Entrées : arguments pytest ; sortie : indicateur booléen partagé par les tests.
Sécurité : aucun accès cloud, aucune exécution de source ni analyse à cet endroit ;
les autres tests vérifient l'analyse statique et certains subprocess contrôlés.
"""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Ajouter l'option explicite de mise à jour des snapshots.

    Args:
        parser: Parseur pytest recevant une option désactivée par défaut.
    """
    parser.addoption(
        "--update-snapshots",
        action="store_true",
        default=False,
        help="Régénérer les snapshots attendus",
    )


@pytest.fixture
def update_snapshots(request: pytest.FixtureRequest) -> bool:
    """Lire l'autorisation explicite de réécrire les snapshots.

    Args:
        request: Contexte pytest portant les options de la session.

    Returns:
        Vrai uniquement lorsque --update-snapshots a été demandé.
    """
    return request.config.getoption("--update-snapshots")
