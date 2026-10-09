"""Orchestrer l'analyse locale et la génération depuis la ligne de commande.

Entrées : arguments CLI, sources locales et options de filtrage ou de rapport.
Sorties : synthèse, fichiers proposés et code de retour.
Sécurité : analyse statique sans accès cloud ni exécution des sources ou imports ;
seul --fmt autorise un subprocess de formatage Terraform après l'écriture.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console

from terraformizer import __version__
from terraformizer.detectors import ALL_DETECTORS
from terraformizer.generators.hcl import deduplicate, generate_files
from terraformizer.report import print_summary, write_json, write_markdown
from terraformizer.scanner import DEFAULT_IGNORES, scan


def _confidence(value: str) -> float:
    """Valider un seuil numérique fini compris entre zéro et un inclus.

    Args:
        value: Représentation textuelle du seuil fournie à argparse.

    Returns:
        Seuil converti en nombre flottant.

    Raises:
        ValueError: Texte non convertible en nombre.
        argparse.ArgumentTypeError: Valeur hors intervalle, infinie ou NaN.
    """
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise argparse.ArgumentTypeError("La confiance doit être comprise entre 0 et 1")
    return result


def main(argv: list[str] | None = None) -> int:
    """Analyser un projet et proposer sa migration sans l'appliquer.

    Args:
        argv: Arguments sans le nom du programme ; None utilise sys.argv.

    Returns:
        0 en cas de succès, 1 pour une erreur de chemin, d'analyse ou d'écriture,
        2 si --fail-on-findings voit une détection avant filtrage ou si
        --fail-on-filtered en voit après filtrage ; une erreur de fmt avertit
        seulement et ne change pas ce résultat.

    Raises:
        SystemExit: Aide, version ou arguments rejetés par argparse.

    La sortie située strictement sous la racine est exclue du scan.
    --dry-run n'écrit rien et ne lance pas fmt ; sinon les fichiers de sortie
    qui sont des liens symboliques sont refusés, sans annuler les écritures
    déjà effectuées. Les chemins de racine et de sortie sont résolus :
    ce refus ne constitue pas une protection contre toute course concurrente.
    Aucun import, plan, apply ou script source n'est exécuté et aucun accès
    cloud n'est effectué ; --fmt seul lance un formatage local contrôlé.
    """
    parser = argparse.ArgumentParser(
        prog="terraformizer",
        description="Détecte l'infrastructure créée hors Terraform et propose du HCL.",
        add_help=False,
    )
    parser._positionals.title = "Arguments"
    parser.add_argument("-h", "--help", action="help", help="Afficher cette aide puis quitter")
    parser.add_argument("path", type=Path, help="Projet ou fichier à analyser")
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path("terraformized"),
        help="Dossier de sortie (défaut : terraformized)",
    )
    parser.add_argument(
        "--only",
        nargs="+",
        metavar="DÉTECTEUR",
        help=f"Détecteurs : {', '.join(d.name for d in ALL_DETECTORS)}",
    )
    parser.add_argument(
        "--min-confidence", type=_confidence, default=0.0, help="Seuil de confiance entre 0 et 1"
    )
    parser.add_argument(
        "--report",
        choices=("json", "md", "both"),
        default="both",
        help="Formats de rapport (défaut : both)",
    )
    parser.add_argument("--fmt", action="store_true", help="Exécuter terraform fmt si disponible")
    parser.add_argument("--dry-run", action="store_true", help="Afficher sans écrire de fichiers")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Retourner 2 si des ressources sont détectées",
    )
    parser.add_argument(
        "--fail-on-filtered",
        action="store_true",
        help="Retourner 2 si des ressources dépassent --min-confidence",
    )
    parser.add_argument(
        "--version", action="version", version=__version__, help="Afficher la version puis quitter"
    )
    args = parser.parse_args(argv)
    console = Console()
    root = args.path.resolve()
    if not root.exists() or not (root.is_file() or root.is_dir()):
        console.print(f"Erreur : chemin invalide : {root}", markup=False)
        return 1
    out = args.out.resolve()
    ignores = list(DEFAULT_IGNORES)
    # Exclure la sortie évite de réanalyser les fichiers déjà générés.
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
                # Refuser le lien évite d'écraser sa cible potentiellement hors de la sortie.
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
                    # Les rapports doivent protéger les cibles de liens comme les fichiers HCL.
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
    return 2 if (args.fail_on_findings and detected) or (args.fail_on_filtered and findings) else 0


if __name__ == "__main__":
    sys.exit(main())
