"""Regrouper les générateurs de propositions Terraform et de scripts d'import.

Entrées des générateurs : détections issues de l'analyse statique.
Sorties : textes HCL et scripts à relire avant toute utilisation.
Sécurité : cet espace de noms ne lit aucun fichier, n'accède pas au cloud et
n'exécute ni les sources analysées ni les scripts proposés.
"""

from __future__ import annotations
