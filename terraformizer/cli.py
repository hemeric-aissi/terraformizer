"""Interface en ligne de commande de terraformizer."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from terraformizer import __version__
from terraformizer.generators.hcl import deduplicate, generate_files
from terraformizer.report import print_summary, write_json, write_markdown
from terraformizer.scanner import DEFAULT_IGNORES, scan


def _confidence(value: str) -> float:
    """Valide un seuil de confiance compris entre zéro et un."""
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise argparse.ArgumentTypeError("La confiance doit être comprise entre 0 et 1")
    return result


def main(argv: list[str] | None = None) -> int:
    """Analyse un projet et écrit les propositions de migration."""
    parser = argparse.ArgumentParser(
        prog="terraformizer",
        description="Détecte l'infrastructure créée hors Terraform et propose du HCL.",
        add_help=False,
    )
    parser._positionals.title = "Arguments"
    parser.add_argument("-h", "--help", action="help", help="Afficher cette aide puis quitter")
    parser.add_argument("path", type=Path, help="Projet ou fichier à analyser")
    parser.add_argument("-o", "--out", type=Path, default=Path("terraformized"),
                        help="Dossier de sortie (défaut : terraformized)")
    parser.add_argument("--only", nargs="+", metavar="DÉTECTEUR",
                        help="Détecteurs : bash_aws, bash_gcloud, bash_az, python_boto3, cloudformation")
    parser.add_argument("--min-confidence", type=_confidence, default=0.0,
                        help="Seuil de confiance entre 0 et 1")
    parser.add_argument("--report", choices=("json", "md", "both"), default="both",
                        help="Formats de rapport (défaut : both)")
    parser.add_argument("--fmt", action="store_true", help="Exécuter terraform fmt si disponible")
    parser.add_argument("--dry-run", action="store_true", help="Afficher sans écrire de fichiers")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Retourner 2 si des ressources sont détectées")
    parser.add_argument("--version", action="version", version=__version__,
                        help="Afficher la version puis quitter")
    args = parser.parse_args(argv)
    console = Console()
    root = args.path.resolve()
    if not root.exists() or not (root.is_file() or root.is_dir()):
        console.print(f"Erreur : chemin invalide : {root}", markup=False)
        return 1
    out = args.out.resolve()
    ignores = list(DEFAULT_IGNORES)
    if root.is_dir() and out.is_relative_to(root) and out != root:
        ignores.append(out.relative_to(root).as_posix())
    try:
        detected = scan(root, only=args.only, ignores=ignores)
    except (ValueError, OSError) as exc:
        console.print(f"Erreur : {exc}", markup=False)
        return 1
    findings = deduplicate([f for f in detected if f.confidence >= args.min_confidence])
    print_summary(findings)
    if args.dry_run:
        console.print("Simulation : aucun fichier écrit.")
    else:
        try:
            files = generate_files(findings)
            out.mkdir(parents=True, exist_ok=True)
            for name, content in files.items():
                destination = out / name
                if destination.is_symlink():
                    raise OSError(f"Refus d'écrire dans un lien symbolique : {destination}")
                destination.write_text(content, encoding="utf-8")
            (out / "import.sh").chmod(0o755)
            reports = (
                ("report.json", write_json, ("json", "both")),
                ("REPORT.md", write_markdown, ("md", "both")),
            )
            for name, writer, modes in reports:
                if args.report in modes:
                    destination = out / name
                    if destination.is_symlink():
                        raise OSError(f"Refus d'écrire dans un lien symbolique : {destination}")
                    writer(findings, destination)
        except (OSError, ValueError, TypeError) as exc:
            console.print(f"Erreur d'écriture : {exc}", markup=False)
            return 1
        if args.fmt:
            terraform = shutil.which("terraform")
            if terraform:
                try:
                    subprocess.run([terraform, "fmt", "-recursive", str(out)], check=True)
                except (OSError, subprocess.CalledProcessError) as exc:
                    console.print(f"Avertissement : terraform fmt a échoué : {exc}", markup=False)
            else:
                console.print("Avertissement : terraform absent du PATH, formatage ignoré.")
        console.print(f"Fichiers générés dans {out}", markup=False)
    console.print(
        "Étapes suivantes : relire les TODO et les identifiants d'import, puis dans la sortie :\n"
        "  terraform init\n  bash import.sh\n  terraform plan\n"
        "Ne pas appliquer avant de vérifier que le plan ne recrée pas les ressources existantes."
    )
    return 2 if args.fail_on_findings and detected else 0


if __name__ == "__main__":
    sys.exit(main())
