"""Exposer la version du paquet d'analyse statique et de conversion Terraform.

Entrée : import du paquet ; sortie : métadonnée __version__.
Sécurité : cet import n'analyse aucun fichier, n'exécute aucune source et
n'effectue aucun accès cloud ; les conversions restent des propositions.
"""

from __future__ import annotations

__version__ = "0.1.0"
