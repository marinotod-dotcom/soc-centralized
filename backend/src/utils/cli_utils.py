import argparse
from datetime import datetime, timedelta


def get_week_range(week_number: int, year: int) -> tuple[datetime, datetime]:
    monday = datetime.fromisocalendar(year, week_number, 1)
    sunday = datetime.fromisocalendar(year, week_number, 7)
    return (
        monday.replace(hour=0, minute=0, second=0),
        sunday.replace(hour=23, minute=59, second=59),
    )


def parse_args() -> tuple[datetime, datetime, bool, str, str, int | None]:
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
        choices=["all", "kpi_report", "action_plan", "coverage"],
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

    return date_from, date_to, args.pretty, args.only, args.older_than, args.reference_fleet