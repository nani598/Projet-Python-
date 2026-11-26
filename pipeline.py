"""Module 2 : pipeline de transformation en programmation fonctionnelle.

    lignes brutes --map(parse_line)--> dicts ou None
                  --filter(None)----> sans les None (lignes vides / corrompues)
                  --map(normaliser)--> données propres
                  --filter(lambda)--> uniquement les logs valides

map() et filter() sont PARESSEUX : comme les générateurs, ils ne traitent
une ligne que lorsqu'on la demande. Rien n'est stocké en mémoire.
"""

from collections.abc import Iterable, Iterator
from datetime import datetime

from logengine.ingestion import Connection, LogRecord, parse_line

VALID_LEVELS: frozenset[str] = frozenset({"INFO", "WARNING", "ERROR", "CRITICAL"})


# ---------------------------------------------------------------------------
# 1. Normalisation (appliquée avec map)
# ---------------------------------------------------------------------------

def normalize_record(record: LogRecord) -> LogRecord:
    """Nettoie un log : espaces, casse, et ajoute un résumé lisible en f-string.

    On renvoie un NOUVEAU dictionnaire au lieu de modifier l'original.
    """
    level = record["level"].strip().upper()      # " error " -> "ERROR"
    user = record["user"].strip().lower()        # " Alice " -> "alice"
    payload = record["payload"]
    if isinstance(payload, str):
        payload = payload.strip()

    ip, port, protocol = record["connection"]    # déballage du tuple
    # un tuple est immuable : on ne le modifie pas, on en crée un nouveau
    connection: Connection = (ip.strip(), port, protocol.strip().upper())
    timestamp: datetime = record["timestamp"]

    return {
        **record,                                # copie toutes les clés d'origine
        "level": level,
        "user": user,
        "connection": connection,
        "payload": payload,
        # f-string avec mise en forme : heure, et colonnes alignées (:<8)
        "summary": f"[{timestamp:%H:%M:%S}] {level:<8} {user:<8} "
                   f"{connection[0]}:{connection[1]}/{connection[2]}",
    }


# ---------------------------------------------------------------------------
# 2. Le pipeline complet : map + filter + lambda
# ---------------------------------------------------------------------------

def build_pipeline(lines: Iterable[str]) -> Iterator[LogRecord]:
    """Enchaîne toutes les transformations, sans jamais créer de liste."""
    parsed = map(parse_line, lines)              # str -> dict ou None
    non_empty = filter(None, parsed)             # supprime les None
    normalized = map(normalize_record, non_empty)
    valid = filter(                              # prédicat personnalisé avec lambda
        lambda r: r["level"] in VALID_LEVELS and r["user"] != "",
        normalized,
    )
    return valid


# ---------------------------------------------------------------------------
# 3. Routage avec le Structural Pattern Matching (match-case)
# ---------------------------------------------------------------------------

def route_log(entry: LogRecord | Connection | str) -> str:
    """Renvoie la catégorie d'une entrée selon sa FORME.

    match-case compare la structure de l'objet (str, dict, tuple...)
    et peut extraire des valeurs au passage (ici : code, message, ip...).
    """
    match entry:
        # --- Chaîne brute (ligne non parsée) ---
        case str() if not entry.strip():
            return "ligne vide"
        case str():
            return "chaîne brute"

        # --- Dictionnaires : on regarde le niveau ET le contenu du payload ---
        # L'ORDRE COMPTE : le premier cas qui correspond gagne,
        # donc on met les cas les plus précis en premier.
        case {"payload": {"action": "login", "status": "failed"}}:
            return "échec de connexion"
        case {"level": "ERROR" | "CRITICAL", "payload": {"code": int(code)}}:
            return f"erreur avec code HTTP {code}"
        case {"level": "ERROR" | "CRITICAL", "payload": str(message)}:
            return f"erreur texte : {message}"
        case {"payload": dict()}:
            return "événement JSON"
        case {"payload": str()}:
            return "message texte"

        # --- Tuples de connexion (IP, Port, Protocole) ---
        case (str(ip), 22, "TCP"):
            return f"connexion SSH depuis {ip}"
        case (str(ip), int(port), "TCP" | "UDP" as protocol):
            return f"connexion {protocol} sur le port {port} depuis {ip}"

        case _:                                  # tout le reste
            return "format inconnu"


# ---------------------------------------------------------------------------
# Démonstration : python -m logengine.pipeline
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from pathlib import Path

    from logengine.ingestion import read_multiple_files

    files = [Path("data") / "server_1.log", Path("data") / "server_2.log"]

    # --- a) La normalisation sur un exemple "sale" ---
    messy = parse_line(
        "2026-11-26 08:00:00 |  warning  |  10.0.0.1:80/tcp |  Alice  |   Disk full   "
    )
    print("=== Normalisation (map) ===")
    print("avant :", messy)
    print("après :", normalize_record(messy))

    # --- b) Le pipeline complet sur les vrais fichiers ---
    print("\n=== Pipeline (filter + map) : 5 premiers logs valides ===")
    logs = build_pipeline(read_multiple_files(files))
    for _ in range(5):
        record = next(logs)
        print(f"{record['summary']}  ->  {route_log(record)}")

    total_lines = sum(1 for _ in read_multiple_files(files))
    total_valid = sum(1 for _ in build_pipeline(read_multiple_files(files)))
    print(f"\nLignes lues : {total_lines} | logs valides : {total_valid} "
          f"| lignes éliminées : {total_lines - total_valid}")

    # --- c) match-case sur les 3 formats demandés par l'énoncé ---
    print("\n=== Routage (match-case) ===")
    examples = [
        "### corrupted entry ###",                          # chaîne brute
        "",                                                 # chaîne vide
        {"level": "ERROR", "payload": {"code": 500}},       # dictionnaire
        {"level": "INFO", "payload": "Service started"},    # dictionnaire
        ("10.0.0.66", 22, "TCP"),                           # tuple de connexion
        ("192.168.1.5", 53, "UDP"),                         # tuple de connexion
        42,                                                 # format inconnu
    ]
    for example in examples:
        print(f"{example!r:50} -> {route_log(example)}")