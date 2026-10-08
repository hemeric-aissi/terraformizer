"""Parcours déterministe des sources d'un projet."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterable
from pathlib import Path

from terraformizer.detectors import get_detectors
from terraformizer.detectors.base import slugify
from terraformizer.models import Finding

DEFAULT_IGNORES: tuple[str, ...] = (
    ".git", ".terraform", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", "*.tfstate*",
)
MAX_FILE_SIZE = 2 * 1024 * 1024


def scan(
    root: Path | str,
    only: Iterable[str] | None = None,
    ignores: Iterable[str] = DEFAULT_IGNORES,
) -> list[Finding]:
    """Analyse les fichiers sans suivre les liens ni exécuter les sources."""
    root = Path(root).resolve()
    if not root.exists():
        raise ValueError(f"Chemin introuvable : {root}")
    detectors = get_detectors(only)
    patterns = tuple(ignores)
    base = root if root.is_dir() else root.parent
    findings: list[Finding] = []

    def ignored(path: Path) -> bool:
        relative = path.relative_to(base)
        return any(
            fnmatch.fnmatch(part, pattern)
            or fnmatch.fnmatch(relative.as_posix(), pattern)
            for pattern in patterns
            for part in relative.parts
        )

    def inspect(path: Path) -> None:
        if path.is_symlink() or ignored(path) or path.suffix.lower() in (".tf", ".tfvars", ".hcl"):
            return
        applicable = [detector for detector in detectors if detector.handles(path)]
        if not applicable:
            return
        try:
            if path.stat().st_size > MAX_FILE_SIZE or not path.is_file():
                return
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        relative = path.relative_to(base)
        for detector in applicable:
            try:
                detected = detector.detect(relative, content)
                for finding in detected:
                    finding.source_file = relative
                findings.extend(detected)
            except Exception as exc:
                findings.append(Finding(
                    provider="unknown",
                    tf_type="ERROR",
                    name=slugify(f"{detector.name}_{relative}"),
                    attributes={},
                    source_file=relative,
                    line=1,
                    original="",
                    confidence=0.0,
                    notes=[f"Erreur du détecteur {detector.name} : {exc}"],
                ))

    if root.is_file():
        inspect(root)
    else:
        for directory, dirs, files in os.walk(root, followlinks=False):
            parent = Path(directory)
            dirs[:] = sorted(
                name for name in dirs
                if not (parent / name).is_symlink() and not ignored(parent / name)
            )
            for name in sorted(files):
                inspect(parent / name)
    return findings
