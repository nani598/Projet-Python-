"""Point d'entrée principal : exécute tout le pipeline d'analyse de logs.

Utilisation (depuis la racine du projet, venv activé) :
    python main.py                          # analyse tous les fichiers de data/
    python main.py --threshold 6            # seuil de force brute personnalisé
    python main.py data/server_1.log        # analyse un seul fichier
    python main.py --generate               # régénère les logs de test avant l'analyse
    python main.py --help                   # affiche l'aide
"""

import argparse
import sys
from collections.abc import Iterator
from pathlib import Path

from logengine.analysis import (BLACKLIST, active_ips, compare_with_blacklist, count_by,
                                detect_brute_force, ips_with_errors)
from logengine.audit import export_audit_report
from logengine.generator import generate_log_file
from logengine.ingestion import LogRecord, read_multiple_files
from logengine.pipeline import build_pipeline
from logengine.rules import (apply_security_rules, rule_blacklisted_ip, rule_critical_level,
                             rule_privileged_login_failure, rule_unexpected_port)

DATA_DIR = Path("data")
REPORTS_DIR = Path("reports")


def parse_arguments() -> argparse.Namespace:
    """Lit les options passées en ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Moteur d'ingestion et d'analyse de logs sécurisé.")
    parser.add_argument("files", nargs="*", type=Path,
                        help="fichiers de logs à analyser (par défaut : data/*.log)")
    parser.add_argument("--generate", action="store_true",
                        help="régénère les fichiers de logs de test avant l'analyse")
    parser.add_argument("--threshold", type=int, default=5,
                        help="nombre d'échecs consécutifs pour une attaque (défaut : 5)")
    parser.add_argument("--max-gap", type=int, default=10,
                        help="écart maximal en secondes entre deux échecs (défaut : 10)")
    return parser.parse_args()


def generate_test_data() -> None:
    """Crée les fichiers de logs de test dans data/."""
    for name, size in (("server_1.log", 1000), ("server_2.log", 500)):
        count = generate_log_file(DATA_DIR / name, n_lines=size, seed=len(name) + size)
        print(f"  {name} : {count} lignes générées")


def title(text: str) -> None:
    """Affiche un titre de section."""
    print(f"\n{'=' * 70}\n {text}\n{'=' * 70}")


def run(files: list[Path], threshold: int, max_gap: int) -> None:
    """Exécute les 4 modules les uns après les autres."""

    def fresh_logs() -> Iterator[LogRecord]:
        """Nouveau flux de logs propres (un générateur ne se parcourt qu'une fois)."""
        return build_pipeline(read_multiple_files(files))

    # --- Modules 1 et 2 : ingestion + pipeline ---
    title("MODULES 1 & 2 : ingestion et nettoyage")
    total_lines = sum(1 for _ in read_multiple_files(files))
    total_valid = sum(1 for _ in fresh_logs())
    print(f"Fichiers analysés : {', '.join(f.name for f in files)}")
    print(f"Lignes lues : {total_lines} | logs valides : {total_valid} "
          f"| lignes rejetées : {total_lines - total_valid}")

    # --- Module 3 : agrégation ---
    title("MODULE 3 : agrégation et détection")
    active = active_ips(fresh_logs())
    errors = ips_with_errors(fresh_logs())
    print(f"IP actives : {len(active)} | IP ayant généré des erreurs : {len(errors)}")
    for operation, result in compare_with_blacklist(active, BLACKLIST).items():
        print(f"  {operation:35} -> {len(result)} IP")

    print("\nLogs par niveau :")
    for level, count in sorted(count_by(fresh_logs(), "level").items()):
        print(f"  {level:10} {count:5}")

    suspects = detect_brute_force(fresh_logs(), threshold=threshold, max_gap_seconds=max_gap)
    print(f"\nForce brute ({threshold} échecs d'affilée, {max_gap} s max entre deux) :")
    if not suspects:
        print("  Aucune attaque détectée.")
    for ip, streaks in suspects.items():
        worst = max(nb for _, nb in streaks)
        print(f"  {ip:15} {len(streaks)} attaque(s), jusqu'à {worst} échecs d'affilée")
    new_threats = set(suspects) - BLACKLIST
    print(f"  IP à ajouter à la liste noire : {sorted(new_threats) or 'aucune'}")

    # --- Module 4 : moteur de règles + audit ---
    title("MODULE 4 : moteur de règles et audit")
    alerts = apply_security_rules(
        rule_blacklisted_ip,
        rule_critical_level,
        rule_unexpected_port,
        rule_privileged_login_failure,
        records=fresh_logs(),
        blacklist=BLACKLIST | new_threats,       # la liste noire inclut les nouveaux attaquants
        allowed_ports=frozenset({53, 80, 443}),
        watched_users=("admin", "root"),
    )
    for rule_name, messages in alerts.items():
        print(f"  {rule_name:32} {len(messages):4} alerte(s)")

    report = export_audit_report(globals(), locals(), REPORTS_DIR / "audit.txt")
    print(f"\nRapport d'audit exporté : {report}")


def main() -> int:
    """Fonction principale : renvoie 0 si tout s'est bien passé, 1 sinon."""
    args = parse_arguments()

    if args.generate:
        print("Génération des logs de test...")
        generate_test_data()

    files: list[Path] = args.files or sorted(DATA_DIR.glob("*.log"))
    if not files:
        print("Aucun fichier de logs trouvé. Lancez : python main.py --generate")
        return 1

    missing = [f for f in files if not f.is_file()]
    if missing:
        print(f"Fichier(s) introuvable(s) : {', '.join(map(str, missing))}")
        return 1

    if args.threshold < 1 or args.max_gap < 0:
        print("Le seuil doit être >= 1 et l'écart maximal >= 0.")
        return 1

    try:
        run(files, args.threshold, args.max_gap)
    except KeyboardInterrupt:
        print("\nAnalyse interrompue par l'utilisateur.")
        return 1
    except OSError as error:
        print(f"Erreur de lecture ou d'écriture : {error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())