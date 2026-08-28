from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from src.models.db.vulnerability_tracking import VulnerabilityTracking
from src.models.enums.vulnerability_status_enum import VulnerabilityStatus


class SlaAnalyticsRepository:
    """Lecture seule : requêtes du dashboard vulnérabilités, toutes
    bornées à la semaine courante.

    `last_seen_at` est la colonne mise à jour à chaque scan (upsert),
    donc les CVE encore actifs cette semaine ont un last_seen_at dans
    la fenêtre [week_start, week_end) — c'est ce qui permet de ne
    garder que "les données de cette semaine" plutôt que le cumul
    historique de la table.
    """

    def __init__(self, session: Session):
        self.session = session

    def get_by_severity(self, week_start: datetime, week_end: datetime) -> list[dict]:
        is_validated = VulnerabilityTracking.status == VulnerabilityStatus.VALIDE
        # week_end est une borne exclusive (lundi suivant 00:00) : >= / < plutôt
        # que BETWEEN, qui inclurait à tort minuit pile du lundi suivant.
        in_week = (VulnerabilityTracking.last_seen_at >= week_start) & (
            VulnerabilityTracking.last_seen_at < week_end
        )
        stmt = (
            select(
                VulnerabilityTracking.severity,
                func.count().label("total"),
                func.count(case((is_validated, 1))).label("validated"),
            )
            .where(in_week)
            .group_by(VulnerabilityTracking.severity)
        )
        return [dict(row._mapping) for row in self.session.execute(stmt).all()]

    def get_machines_corrected(self, week_start: datetime, week_end: datetime) -> tuple[int, int]:
        """Machines avec au moins un CVE validé cette semaine, vs total de
        machines ayant au moins un CVE actif cette semaine."""
        in_week = (VulnerabilityTracking.last_seen_at >= week_start) & (
            VulnerabilityTracking.last_seen_at < week_end
        )
        corrected = self.session.scalar(
            select(func.count(func.distinct(VulnerabilityTracking.agent_name))).where(
                in_week, VulnerabilityTracking.status == VulnerabilityStatus.VALIDE
            )
        )
        total = self.session.scalar(
            select(func.count(func.distinct(VulnerabilityTracking.agent_name))).where(in_week)
        )
        return corrected or 0, total or 0

    def get_validated_per_day(self, week_start: datetime, friday_end: datetime) -> list[dict]:
        """Nombre de CVE validés par jour, du lundi (inclus) au vendredi
        (inclus) de la semaine courante. `friday_end` = samedi 00:00
        (borne exclusive)."""
        stmt = (
            select(
                func.date(VulnerabilityTracking.validated_at).label("day"),
                func.count().label("count"),
            )
            .where(
                VulnerabilityTracking.status == VulnerabilityStatus.VALIDE,
                VulnerabilityTracking.validated_at.isnot(None),
                VulnerabilityTracking.validated_at >= week_start,
                VulnerabilityTracking.validated_at < friday_end,
            )
            .group_by(func.date(VulnerabilityTracking.validated_at))
        )
        return [dict(row._mapping) for row in self.session.execute(stmt).all()]
