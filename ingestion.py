"""Module 1 : ingestion des logs avec des générateurs, et parsing en dictionnaires.

Idée clé : on ne charge JAMAIS un fichier entier en mémoire.
Les générateurs (yield) produisent les lignes une par une, à la demande.
"""

import json
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

# Un log parsé = un dictionnaire (clé texte -> valeur de type variable)
LogRecord = dict[str, Any]

# Tuple immuable (IP, Port, Protocole) : ce sont des métadonnées fixes
Connection = tuple[str, int, str]

SEPARATOR = " | "
NB_FIELDS = 5
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


# ---------------------------------------------------------------------------
# 1. Générateurs de lecture
# ---------------------------------------------------------------------------

def read_log_file(path: str | Path) -> Iterator[str]:
    """Lit un fichier de logs ligne par ligne grâce à yield.

    À chaque appel de next(), une seule ligne est lue puis renvoyée :
    le fichier n'est jamais chargé entièrement en RAM.
    """
    with open(path, encoding="utf-8") as file:
        for line in file:              # un fichier s'itère déjà ligne par ligne
            yield line.rstrip("\n")    # on enlève le retour à la ligne final


def read_multiple_files(paths: Iterable[str | Path]) -> Iterator[str]:
    """Enchaîne la lecture de plusieurs fichiers avec yield from.

    `yield from read_log_file(p)` revient à écrire :
        for line in read_log_file(p):
            yield line
    """
    for path in paths:
        try:
            yield from read_log_file(path)
        except FileNotFoundError:
            # on prévient et on passe au fichier suivant au lieu de tout arrêter
            print(f"[AVERTISSEMENT] Fichier introuvable, ignoré : {path}")


# ---------------------------------------------------------------------------
# 2. Parsing d'une ligne en dictionnaire
# ---------------------------------------------------------------------------

def parse_connection(raw: str) -> Connection:
    """Transforme '192.168.1.45:22/TCP' en tuple ('192.168.1.45', 22, 'TCP')."""
    address, protocol = raw.split("/")       # '192.168.1.45:22' et 'TCP'
    ip, port = address.rsplit(":", 1)        # '192.168.1.45' et '22'
    return (ip, int(port), protocol)         # int() peut lever ValueError


def parse_payload(raw: str) -> dict[str, Any] | str:
    """Renvoie le payload en dict s'il est en JSON, sinon la chaîne brute."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw                           # ex : 'Disk usage at 85%'
    return data if isinstance(data, dict) else raw


def parse_line(line: str) -> LogRecord | None:
    """Transforme une ligne de log en dictionnaire.

    Renvoie None si la ligne est vide ou mal formée : ces None seront
    ensuite éliminés par filter() dans le module 2.
    """
    parts = line.split(SEPARATOR)
    if len(parts) != NB_FIELDS:
        return None                          # ligne vide ou corrompue

    timestamp, level, connection, user, payload = parts   # déballage

    try:
        return {
            "timestamp": datetime.strptime(timestamp, TIMESTAMP_FORMAT),
            "level": level,
            "connection": parse_connection(connection),
            "user": user,
            "payload": parse_payload(payload),
        }
    except ValueError:                       # date ou port invalide
        return None


def parse_logs(lines: Iterable[str]) -> Iterator[LogRecord | None]:
    """Générateur qui parse les lignes au fur et à mesure (toujours sans liste)."""
    for line in lines:
        yield parse_line(line)


# ---------------------------------------------------------------------------
# Petite démonstration : python -m logengine.ingestion
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    files = [Path("data") / "server_1.log", Path("data") / "server_2.log"]

    records = parse_logs(read_multiple_files(files))   # rien n'est encore lu ici !

    print("Les 3 premiers logs parsés :")
    for _ in range(3):
        print(next(records))

    # On consomme la suite du générateur sans jamais stocker de liste
    total = 3 + sum(1 for _ in records)
    print(f"\nNombre total de lignes lues sur les 2 fichiers : {total}")
