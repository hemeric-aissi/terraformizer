"""Tests de non-régression des fichiers générés."""

from __future__ import annotations

import difflib
from pathlib import Path

from terraformizer.generators.hcl import deduplicate, generate_files
from terraformizer.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOTS = Path(__file__).parent / "snapshots"


def test_generated_files_match_snapshots(update_snapshots: bool) -> None:
    """Compare chaque fichier généré à son snapshot enregistré."""
    generated = generate_files(deduplicate(scan(FIXTURES)))
    SNAPSHOTS.mkdir(exist_ok=True)

    for name, actual in generated.items():
        snapshot = SNAPSHOTS / name
        if update_snapshots:
            snapshot.write_text(actual, encoding="utf-8")
            continue
        expected = snapshot.read_text(encoding="utf-8") if snapshot.exists() else ""
        assert actual == expected, "\n".join(
            difflib.unified_diff(
                expected.splitlines(),
                actual.splitlines(),
                fromfile=str(snapshot),
                tofile=f"generated/{name}",
                lineterm="",
            )
        )
