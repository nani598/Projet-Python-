"""Module 4 (partie 2) : introspection et audit du contexte d'exécution.

    globals() : dictionnaire des variables GLOBALES du module où on l'appelle
                (imports, constantes, fonctions définies dans le fichier...)
    locals()  : dictionnaire des variables LOCALES de la fonction où on l'appelle

Attention : globals() et locals() renvoient les variables de l'endroit où ils
sont APPELÉS. C'est pourquoi l'appelant les passe en argument à audit_scope().
"""

import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Une ligne du rapport : (nom, type, taille en octets, aperçu de la valeur)
AuditEntry = tuple[str, str, int, str]


def audit_scope(scope: dict[str, Any], include_private: bool = False) -> list[AuditEntry]:
    """Inspecte un dictionnaire de variables (obtenu par globals() ou locals())."""
    entries: list[AuditEntry] = []
    for name, value in sorted(scope.items()):
        if name.startswith("_") and not include_private:
            continue                             # on ignore __name__, __file__, etc.
        preview = repr(value)
        if len(preview) > 50:
            preview = preview[:47] + "..."
        entries.append((name, type(value).__name__, sys.getsizeof(value), preview))
    return entries


def format_section(title: str, entries: list[AuditEntry]) -> str:
    """Met en forme une section du rapport sous forme de tableau texte."""
    lines = [f"=== {title} ({len(entries)} variables) ===",
             f"{'NOM':28} {'TYPE':22} {'TAILLE':>8}  APERÇU"]
    for name, type_name, size, preview in entries:
        lines.append(f"{name:28} {type_name:22} {size:>8}  {preview}")
    return "\n".join(lines)


def export_audit_report(global_scope: dict[str, Any], local_scope: dict[str, Any],
                        output: str | Path = Path("reports") / "audit.txt") -> Path:
    """Écrit le rapport d'audit (variables globales + locales) dans un fichier texte."""
    report = "\n\n".join([
        f"RAPPORT D'AUDIT - généré le {datetime.now():%d/%m/%Y à %H:%M:%S}",
        format_section("Variables globales (globals)", audit_scope(global_scope)),
        format_section("Variables locales (locals)", audit_scope(local_scope)),
    ])
    output = Path(output)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report + "\n", encoding="utf-8")
    except OSError as error:                     # disque plein, droits insuffisants...
        print(f"[ERREUR] Impossible d'écrire le rapport d'audit : {error}")
        raise
    return output


# ---------------------------------------------------------------------------
# Démonstration : python -m logengine.audit
# ---------------------------------------------------------------------------

def _demo() -> None:
    """Crée quelques variables locales, puis les audite."""
    from logengine.ingestion import read_log_file

    log_file = Path("data") / "server_1.log"
    lines_generator = read_log_file(log_file)            # générateur : rien n'est chargé
    lines_list = list(read_log_file(log_file))            # liste : TOUT est chargé
    threshold = 5                                         # visible dans locals()

    print(format_section("Variables locales de _demo()", audit_scope(locals())))
    print(f"\n-> Taille du générateur : {sys.getsizeof(lines_generator)} octets")
    total_list = sys.getsizeof(lines_list) + sum(sys.getsizeof(line) for line in lines_list)
    print(f"-> Taille de la liste    : {total_list} octets "
          f"(la liste + ses {len(lines_list)} chaînes)")

    path = export_audit_report(globals(), locals())
    print(f"\nRapport complet exporté dans : {path}")


if __name__ == "__main__":
    _demo()