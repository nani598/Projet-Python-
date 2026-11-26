"""Module 3 : agrégation et analyse des logs.

    - set / frozenset : IP uniques et comparaison avec une liste noire
    - defaultdict     : compteurs sans risque de KeyError
    - while + for + break / continue / else : détection d'attaques par force brute

Rappel : un générateur (ou un map/filter) ne se parcourt qu'UNE SEULE fois.
Chaque fonction ci-dessous consomme donc son propre flux de logs.
"""

from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta

from logengine.ingestion import LogRecord

# Liste noire d'IP : frozenset = ensemble IMMUABLE (on ne peut ni ajouter ni retirer)
BLACKLIST: frozenset[str] = frozenset({
    "10.0.0.66",
    "203.0.113.13",
    "172.16.0.99",
    "192.168.1.13",
})

# Une tentative de connexion = (horodatage, échec ?)
LoginAttempt = tuple[datetime, bool]
# Une attaque détectée = (début de la série, nombre d'échecs consécutifs)
Streak = tuple[datetime, int]


# ---------------------------------------------------------------------------
# 1. Ensembles : set et frozenset
# ---------------------------------------------------------------------------

def ips_with_errors(records: Iterable[LogRecord]) -> set[str]:
    """Ensemble des IP uniques ayant généré au moins un ERROR ou CRITICAL."""
    error_ips: set[str] = set()
    for record in records:
        if record["level"] in ("ERROR", "CRITICAL"):
            error_ips.add(record["connection"][0])   # un set ignore les doublons
    return error_ips


def active_ips(records: Iterable[LogRecord]) -> set[str]:
    """Ensemble de toutes les IP présentes dans les logs (set en compréhension)."""
    return {record["connection"][0] for record in records}


def compare_with_blacklist(ips: set[str],
                           blacklist: frozenset[str] = BLACKLIST) -> dict[str, set[str]]:
    """Applique les 4 opérations d'ensembles entre les IP actives et la liste noire."""
    return {
        "union (|)": ips | blacklist,                   # toutes les IP connues
        "intersection (&)": ips & blacklist,            # IP blacklistées ET actives
        "différence (actives - blacklist)": ips - blacklist,
        "différence (blacklist - actives)": blacklist - ips,   # blacklistées inactives
        "différence symétrique (^)": ips ^ blacklist,   # dans l'un OU l'autre, pas les deux
    }


# ---------------------------------------------------------------------------
# 2. Compteurs avec defaultdict
# ---------------------------------------------------------------------------

def count_by(records: Iterable[LogRecord], field: str) -> defaultdict[str, int]:
    """Compte le nombre de logs pour chaque valeur d'un champ (ex : 'level', 'user').

    Avec un dict classique, counts["alice"] += 1 lèverait KeyError la première fois.
    Avec defaultdict(int), une clé absente vaut automatiquement 0.
    """
    counts: defaultdict[str, int] = defaultdict(int)
    for record in records:
        counts[record[field]] += 1
    return counts


# ---------------------------------------------------------------------------
# 3. Détection d'attaques par force brute
# ---------------------------------------------------------------------------

def group_login_attempts(
        records: Iterable[LogRecord]) -> defaultdict[str, list[LoginAttempt]]:
    """Regroupe les tentatives de connexion par IP, triées par ordre chronologique.

    On ne garde que (horodatage, échec ?) : c'est très léger en mémoire.
    """
    attempts: defaultdict[str, list[LoginAttempt]] = defaultdict(list)
    for record in records:
        payload = record["payload"]
        if not isinstance(payload, dict) or payload.get("action") != "login":
            continue                                   # pas une connexion : on passe
        ip = record["connection"][0]
        attempts[ip].append((record["timestamp"], payload.get("status") == "failed"))

    # Plusieurs fichiers couvrent la même période : on remet tout dans l'ordre du temps
    for ip_attempts in attempts.values():
        ip_attempts.sort()                             # trie les tuples par horodatage
    return attempts


def _continues_streak(attempts: list[LoginAttempt], j: int, max_gap: timedelta) -> bool:
    """Indique si la tentative j prolonge la série.

    C'est le cas si c'est un échec, à moins de `max_gap` de la tentative précédente.
    """
    if j >= len(attempts):
        return False                                   # plus de tentatives
    timestamp, failed = attempts[j]
    if not failed:
        return False                                   # un succès casse la série
    return j == 0 or timedelta(0) <= timestamp - attempts[j - 1][0] <= max_gap


def find_failure_streaks(attempts: list[LoginAttempt], threshold: int,
                         max_gap: timedelta = timedelta(seconds=10)) -> list[Streak]:
    """Cherche les séries d'au moins `threshold` échecs consécutifs et rapprochés.

    - la boucle while avance dans la liste, un "cycle de détection" à la fois ;
    - la boucle for vérifie les `threshold` tentatives du cycle ;
    - break   : la série est interrompue (succès, ou trop de temps écoulé)
                -> le cycle échoue ;
    - else    : exécuté SEULEMENT si le for est allé au bout sans break
                -> `threshold` échecs rapprochés d'affilée = attaque !
    - continue: un succès ne peut pas démarrer une attaque, on passe au suivant.
    """
    if threshold < 1:
        raise ValueError("Le seuil doit être supérieur ou égal à 1")

    streaks: list[Streak] = []
    i = 0
    while i < len(attempts):
        start_time, failed = attempts[i]
        if not failed:
            i += 1
            continue                                   # un succès : cycle suivant

        # --- Début d'un cycle de détection à la position i ---
        for j in range(i + 1, i + threshold):
            if not _continues_streak(attempts, j, max_gap):
                break                                  # série interrompue : cycle raté
        else:
            # Aucun break : `threshold` échecs d'affilée -> attaque confirmée.
            # On mesure la longueur totale de la série avec un while.
            end = i + threshold
            while _continues_streak(attempts, end, max_gap):
                end += 1
            streaks.append((start_time, end - i))
            i = end                                    # on reprend après la série
            continue

        # Cycle raté : une nouvelle série peut commencer au plus tôt à j
        i = j if j < len(attempts) and attempts[j][1] else j + 1

    return streaks


def detect_brute_force(records: Iterable[LogRecord], threshold: int = 5,
                       max_gap_seconds: int = 10) -> dict[str, list[Streak]]:
    """Renvoie {ip: [séries d'échecs]} pour chaque IP suspecte."""
    max_gap = timedelta(seconds=max_gap_seconds)
    suspects: dict[str, list[Streak]] = {}
    for ip, attempts in group_login_attempts(records).items():
        streaks = find_failure_streaks(attempts, threshold, max_gap)
        if streaks:
            suspects[ip] = streaks
    return suspects


# ---------------------------------------------------------------------------
# Démonstration : python -m logengine.analysis
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from collections.abc import Iterator
    from pathlib import Path

    from logengine.ingestion import read_multiple_files
    from logengine.pipeline import build_pipeline

    FILES = [Path("data") / "server_1.log", Path("data") / "server_2.log"]

    def fresh_logs() -> Iterator[LogRecord]:
        """Recrée un flux neuf : un générateur déjà parcouru est vide."""
        return build_pipeline(read_multiple_files(FILES))

    # --- a) Ensembles ---
    print("=== IP uniques ===")
    errors = ips_with_errors(fresh_logs())
    active = active_ips(fresh_logs())
    print(f"IP actives : {len(active)} | IP ayant généré des erreurs : {len(errors)}")

    print("\n=== Comparaison avec la liste noire (frozenset) ===")
    print(f"Liste noire : {sorted(BLACKLIST)}")
    for operation, result in compare_with_blacklist(active).items():
        print(f"{operation:35} -> {len(result):2} IP", end="")
        print(f"  {sorted(result)}" if len(result) <= 4 else "")

    # --- b) Compteurs ---
    print("\n=== Nombre de logs par niveau (defaultdict) ===")
    for level, count in sorted(count_by(fresh_logs(), "level").items()):
        print(f"{level:10} {count:5}")

    print("\n=== Nombre de logs par utilisateur (defaultdict) ===")
    for user, count in sorted(count_by(fresh_logs(), "user").items()):
        print(f"{user:10} {count:5}")

    # --- c) Force brute ---
    print("\n=== Détection de force brute (5 échecs d'affilée, espacés de 10 s max) ===")
    suspects = detect_brute_force(fresh_logs(), threshold=5, max_gap_seconds=10)
    for ip, streaks in suspects.items():
        print(f"{ip} : {len(streaks)} attaque(s)")
        for start, nb_failures in streaks:
            print(f"    - {nb_failures} échecs d'affilée à partir de {start:%H:%M:%S}")

    # Les IP qui attaquent mais ne sont pas encore dans la liste noire
    to_blacklist = set(suspects) - BLACKLIST
    print(f"\nIP à ajouter à la liste noire : {sorted(to_blacklist)}")
    