"""Options pytest partagées."""

from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    """Ajoute l'option de mise à jour des snapshots."""
    parser.addoption(
        "--update-snapshots",
        action="store_true",
        default=False,
        help="Régénérer les snapshots attendus",
    )


@pytest.fixture
def update_snapshots(request: pytest.FixtureRequest) -> bool:
    """Indique si les snapshots doivent être réécrits."""
    return request.config.getoption("--update-snapshots")
