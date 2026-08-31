from datetime import datetime

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from src.models.db.vulnerability_tracking import VulnerabilityTracking
from src.models.enums.vulnerability_status_enum import VulnerabilityStatus


class SlaAnalyticsRepository:

    def __init__(self, session: Session):
        self.session = session

    def get_by_severity(self, week_start: datetime, week_end: datetime) -> list[dict]:
        is_validated = VulnerabilityTracking.status == VulnerabilityStatus.VALIDE
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
