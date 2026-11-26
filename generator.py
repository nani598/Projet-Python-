"""Génération d'un fichier de logs de test (faux logs système/réseau).

Format d'une ligne :
    2026-11-26 14:03:12 | ERROR | 192.168.1.45:22/TCP | alice | {"action": "login", "status": "failed"}

    date heure | niveau | IP:port/protocole | utilisateur | payload (JSON ou texte brut)

Le fichier contient volontairement :
    - des lignes vides et des lignes mal formées (pour tester le filtrage, module 2)
    - des rafales d'échecs de connexion depuis une même IP (pour la force brute, module 3)
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

LEVELS: tuple[str, ...] = ("INFO", "WARNING", "ERROR", "CRITICAL")
LEVEL_WEIGHTS: tuple[int, ...] = (60, 20, 15, 5)  # INFO beaucoup plus fréquent

USERS: tuple[str, ...] = ("alice", "bob", "charlie", "david", "eve", "admin")
PORTS: tuple[tuple[int, str], ...] = ((22, "TCP"), (80, "TCP"), (443, "TCP"), (53, "UDP"))

IPS: tuple[str, ...] = tuple(f"192.168.1.{i}" for i in range(2, 30))
ATTACKER_IPS: tuple[str, ...] = ("10.0.0.66", "203.0.113.13", "198.51.100.7")

RAW_MESSAGES: tuple[str, ...] = (
    "Service started",
    "Disk usage at 85%",
    "Connection timeout",
    "Configuration reloaded",
    "Memory leak suspected",
)


def _format_line(when: datetime, level: str, ip: str, port: int,
                 protocol: str, user: str, payload: str) -> str:
    """Assemble une ligne de log au format du projet."""
    timestamp = when.strftime("%Y-%m-%d %H:%M:%S")
    return f"{timestamp} | {level} | {ip}:{port}/{protocol} | {user} | {payload}"


def _random_payload(level: str) -> str:
    """Renvoie soit un payload JSON, soit un message texte brut."""
    if random.random() < 0.5:
        return random.choice(RAW_MESSAGES)
    failed = level in ("ERROR", "CRITICAL")
    data = {"action": random.choice(["login", "logout", "download", "upload"]),
            "status": "failed" if failed else "success",
            "code": random.choice([401, 403, 404, 500]) if failed else 200}
    return json.dumps(data)


def _brute_force_burst(when: datetime, attempts: int) -> list[str]:
    """Crée une rafale d'échecs de connexion SSH depuis une IP d'attaquant."""
    ip = random.choice(ATTACKER_IPS)
    user = random.choice(("admin", "root"))
    payload = json.dumps({"action": "login", "status": "failed", "code": 401})
    return [_format_line(when + timedelta(seconds=i), "ERROR", ip, 22, "TCP", user, payload)
            for i in range(attempts)]


def generate_log_file(path: str | Path, n_lines: int = 1000, seed: int | None = 42) -> int:
    """Écrit un fichier de logs de test et renvoie le nombre de lignes écrites.

    Le fichier est écrit au fur et à mesure (ligne par ligne), sans construire
    une énorme liste en mémoire.
    """
    if seed is not None:
        random.seed(seed)  # même seed = même fichier à chaque exécution

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    when = datetime(2026, 11, 26, 8, 0, 0)
    written = 0

    with path.open("w", encoding="utf-8") as file:
        while written < n_lines:
            when += timedelta(seconds=random.randint(1, 30))
            roll = random.random()

            if roll < 0.03:  # ligne vide
                lines = [""]
            elif roll < 0.06:  # ligne mal formée
                lines = [random.choice(["### corrupted entry ###", "ERROR missing fields", "   "])]
            elif roll < 0.08:  # attaque par force brute (5 à 8 échecs d'affilée)
                lines = _brute_force_burst(when, random.randint(5, 8))
            else:  # ligne normale
                level = random.choices(LEVELS, weights=LEVEL_WEIGHTS)[0]
                port, protocol = random.choice(PORTS)
                lines = [_format_line(when, level, random.choice(IPS), port, protocol,
                                      random.choice(USERS), _random_payload(level))]

            for line in lines:
                file.write(line + "\n")
                written += 1

    return written


if __name__ == "__main__":
    # Génère 2 fichiers pour pouvoir tester plus tard la lecture multi-fichiers (yield from)
    for name, size in (("server_1.log", 1000), ("server_2.log", 500)):
        count = generate_log_file(Path("data") / name, n_lines=size, seed=len(name) + size)
        print(f"{name} : {count} lignes générées")