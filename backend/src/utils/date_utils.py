from datetime import datetime, timedelta


def get_week_range(reference_date: datetime = None) -> tuple[datetime, datetime]:
    """
    Retourne le début (lundi 00:00:00) et la fin (dimanche 23:59:59)
    de la semaine contenant reference_date.
    Par défaut : semaine en cours.
    """
    if reference_date is None:
        reference_date = datetime.now()

    # Lundi de la semaine
    start = reference_date - timedelta(days=reference_date.weekday())
    date_from = start.replace(hour=0, minute=0, second=0, microsecond=0)

    # Dimanche de la semaine
    date_to = date_from + timedelta(days=6)
    date_to = date_to.replace(hour=23, minute=59, second=59, microsecond=0)

    return date_from, date_to


def get_last_week_range() -> tuple[datetime, datetime]:
    """
    Retourne le début et la fin de la semaine précédente.
    """
    last_week = datetime.now() - timedelta(weeks=1)
    return get_week_range(last_week)


def format_for_opensearch(dt: datetime) -> str:
    """
    Formate une datetime au format attendu par OpenSearch.
    Ex: 2026-05-29T00:00:00
    """
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def get_week_label(date: datetime) -> str:
    week = date.isocalendar()[1]
    year = date.year
    return f"S{week:02d}_{year}"
