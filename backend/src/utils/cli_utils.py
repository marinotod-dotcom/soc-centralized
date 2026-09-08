import argparse
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Optional


@dataclass
class ParsedArgs:
    date_from: datetime
    date_to: datetime
    pretty: bool
    only: str
    older_than: str
    reference_fleet: Optional[int]
    collection_date: date            # jour ciblé pour daily_action_plan
    index_override: Optional[str]    # index unique forcé (bypass date_utils)
    local: bool                      # test local : pas de publish MinIO ni de load DB


def get_week_range(week_number: int, year: int) -> tuple[datetime, datetime]:
    monday = datetime.fromisocalendar(year, week_number, 1)
    sunday = datetime.fromisocalendar(year, week_number, 7)
    return (
        monday.replace(hour=0, minute=0, second=0),
        sunday.replace(hour=23, minute=59, second=59),
    )


def parse_args() -> ParsedArgs:
    parser = argparse.ArgumentParser(
        description="Collecte les KPIs Wazuh sur une semaine ISO."
    )

    parser.add_argument(
        "week",
        nargs="?",
        type=int,
        metavar="SEMAINE",
        help="Numéro de semaine ISO (ex: 24). Par défaut : semaine dernière.",
    )

    parser.add_argument(
        "--pretty", action="store_true", help="Affiche le JSON avec indentation."
    )

    parser.add_argument(
        "--only",
        choices=["all", "kpi_report", "action_plan", "daily_action_plan", "coverage"],
        default="all",
        help="Exécute uniquement un pipeline (par défaut : tous).",
    )

    parser.add_argument(
        "--older-than",
        dest="older_than",
        default="30d",
        metavar="DUREE",
        help="Seuil d'inactivité pour le pipeline coverage (ex: 30d, 45d, 90d). Défaut : 30d.",
    )

    parser.add_argument(
        "--reference-fleet",
        dest="reference_fleet",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Taille réelle du parc (déclarée manuellement, ex: 926) pour calculer "
            "le taux de perte du pipeline coverage. Par défaut : nombre exact "
            "d'agents enregistrés dans Wazuh."
        ),
    )

    parser.add_argument(
        "--day",
        dest="day",
        default=None,
        metavar="YYYY-MM-DD",
        help=(
            "Jour de collecte pour daily_action_plan (test local d'un jour précis). "
            "Par défaut : aujourd'hui (résolution samedi+dimanche automatique si lundi)."
        ),
    )

    parser.add_argument(
        "--index",
        dest="index_override",
        default=None,
        metavar="NOM_INDEX",
        help=(
            "Force un index Wazuh précis pour daily_action_plan "
            "(ex: wazuh-alerts-4.x-2026.09.06), bypass la résolution automatique "
            "par date. Pratique pour tester un seul index en local."
        ),
    )

    parser.add_argument(
        "--local",
        action="store_true",
        help=(
            "Mode test local pour daily_action_plan : écrit le JSON sur disque "
            "(./local_output/) sans publier sur MinIO ni charger en base."
        ),
    )

    args = parser.parse_args()

    now = datetime.now()
    iso = now.isocalendar()

    if args.week:
        year = iso[0]
        week_number = args.week
    else:
        last_week = now - timedelta(weeks=1)
        iso_last = last_week.isocalendar()
        year = iso_last[0]
        week_number = iso_last[1]

    date_from, date_to = get_week_range(week_number, year)

    if args.day:
        try:
            collection_date = datetime.strptime(args.day, "%Y-%m-%d").date()
        except ValueError:
            parser.error(f"--day doit être au format YYYY-MM-DD (reçu : {args.day!r})")
    else:
        collection_date = date.today()

    return ParsedArgs(
        date_from=date_from,
        date_to=date_to,
        pretty=args.pretty,
        only=args.only,
        older_than=args.older_than,
        reference_fleet=args.reference_fleet,
        collection_date=collection_date,
        index_override=args.index_override,
        local=args.local,
    )