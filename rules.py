"""Module 4 (partie 1) : moteur de règles de sécurité modulaire.

Une "règle" est une simple fonction qui reçoit UN log et renvoie :
    - un message d'alerte (str) si le log est suspect ;
    - None sinon.

Les fonctions sont des objets de première classe : on peut les ranger dans
des variables, les passer en argument, lire leur nom (__name__)...
"""

from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any

from logengine.analysis import BLACKLIST
from logengine.ingestion import LogRecord

# Type d'une règle : fonction (log, **config) -> message d'alerte ou None
Rule = Callable[..., str | None]


# ---------------------------------------------------------------------------
# 1. Les règles de sécurité (chacune prend **config et ignore ce qui ne la concerne pas)
# ---------------------------------------------------------------------------

def rule_blacklisted_ip(record: LogRecord, blacklist: frozenset[str] = BLACKLIST,
                        **_: Any) -> str | None:
    """Alerte si l'IP source fait partie de la liste noire."""
    ip = record["connection"][0]
    if ip in blacklist:
        return f"IP blacklistée active : {ip}"
    return None


def rule_critical_level(record: LogRecord, **_: Any) -> str | None:
    """Alerte sur tout log de niveau CRITICAL."""
    if record["level"] == "CRITICAL":
        return f"Événement critique : {record['summary']}"
    return None


def rule_unexpected_port(record: LogRecord, allowed_ports: frozenset[int] = frozenset({80, 443}),
                         **_: Any) -> str | None:
    """Alerte si la connexion utilise un port non autorisé."""
    ip, port, protocol = record["connection"]
    if port not in allowed_ports:
        return f"Port non autorisé {port}/{protocol} depuis {ip}"
    return None


def rule_privileged_login_failure(record: LogRecord,
                                  watched_users: tuple[str, ...] = ("admin", "root"),
                                  **_: Any) -> str | None:
    """Alerte si un compte sensible (admin, root...) rate une connexion."""
    match record:
        case {"user": user, "payload": {"action": "login", "status": "failed"}} \
                if user in watched_users:
            return f"Échec de connexion sur le compte sensible '{user}'"
    return None


# ---------------------------------------------------------------------------
# 2. La fonction maître : *args (les règles) + **kwargs (la configuration)
# ---------------------------------------------------------------------------

def apply_security_rules(*args: Rule, records: Iterable[LogRecord],
                         **kwargs: Any) -> defaultdict[str, list[str]]:
    """Applique un nombre variable de règles sur un flux de logs.

    - *args    : les fonctions-règles, en nombre quelconque (un tuple de fonctions) ;
    - records  : le flux de logs (paramètre nommé obligatoire, placé après *args) ;
    - **kwargs : la configuration (un dict), transmise telle quelle à chaque règle.

    Le flux n'est parcouru qu'UNE seule fois : toutes les règles sont testées
    sur chaque log au moment où il passe.
    """
    if not args:
        raise ValueError("Il faut fournir au moins une règle de sécurité")
    for rule in args:
        if not callable(rule):
            raise TypeError(f"{rule!r} n'est pas une fonction")

    max_alerts: int | None = kwargs.get("max_alerts")   # option de configuration
    alerts: defaultdict[str, list[str]] = defaultdict(list)

    for record in records:
        for rule in args:
            message = rule(record, **kwargs)     # on "déballe" le dict de config
            if message is None:
                continue
            alerts[rule.__name__].append(message)   # __name__ : nom de la fonction
        if max_alerts is not None and sum(map(len, alerts.values())) >= max_alerts:
            break                                # assez d'alertes : on arrête la lecture
    return alerts


# ---------------------------------------------------------------------------
# Démonstration : python -m logengine.rules
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from pathlib import Path

    from logengine.ingestion import read_multiple_files
    from logengine.pipeline import build_pipeline

    files = [Path("data") / "server_1.log", Path("data") / "server_2.log"]

    results = apply_security_rules(
        rule_blacklisted_ip,                     # --- *args : autant de règles qu'on veut
        rule_critical_level,
        rule_unexpected_port,
        rule_privileged_login_failure,
        lambda record, **_: (                    # une règle peut même être une lambda !
            "Activité du compte root" if record["user"] == "root" else None
        ),
        records=build_pipeline(read_multiple_files(files)),
        allowed_ports=frozenset({80, 443, 53}),  # --- **kwargs : configuration
        watched_users=("admin", "root"),
    )

    print("=== Résultat du moteur de règles ===")
    for rule_name, messages in results.items():
        print(f"\n{rule_name} : {len(messages)} alerte(s)")
        for message in messages[:3]:             # on n'affiche que les 3 premières
            print(f"    - {message}")