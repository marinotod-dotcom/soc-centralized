import logging
from datetime import date, datetime, timedelta, timezone

from src.db.session import get_session
from src.models.schemas.sla_analytics import (
    SeverityBreakdown,
    ValidatedPerDay,
    VulnDashboardResponse,
)
from src.repositories.sla_analytics_repository import SlaAnalyticsRepository

logger = logging.getLogger(__name__)


def _pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 1) if denominator else 0.0


class SlaAnalyticsService:
    """
    Décalage scan / traitement : le scan Wazuh d'une semaine N atterrit
    dans vulnerability_tracking (last_seen_at horodaté semaine N), et le
    traitement/validation de ce batch se fait la semaine N+1
    (validated_at horodaté semaine N+1). Donc :

    - by_severity / machines_corrected  -> filtrés sur le batch détecté
      LA SEMAINE DERNIÈRE (c'est le batch actuellement en cours de
      traitement cette semaine).
    - validated_per_day                 -> filtré sur CETTE semaine
      (lundi -> vendredi), où le traitement a réellement lieu.
    """

    def get_dashboard(self) -> VulnDashboardResponse:
        this_monday, _, friday_end = self._week_bounds()
        batch_start = this_monday - timedelta(days=7)  # lundi de la semaine dernière
        batch_end = this_monday                         # borne exclusive = lundi courant

        with get_session() as session:
            repo = SlaAnalyticsRepository(session)
            severity_rows = repo.get_by_severity(batch_start, batch_end)
            machines_corrected, machines_total = repo.get_machines_corrected(batch_start, batch_end)
            per_day_rows = repo.get_validated_per_day(this_monday, friday_end)

        by_severity = [
            SeverityBreakdown(
                severity=r["severity"],
                total=r["total"],
                validated=r["validated"],
                pct_validated=_pct(r["validated"], r["total"]),
            )
            for r in severity_rows
        ]
        total_cve = sum(s.total for s in by_severity)
        total_validated = sum(s.validated for s in by_severity)

        return VulnDashboardResponse(
            total_cve=total_cve,
            total_validated=total_validated,
            pct_validated=_pct(total_validated, total_cve),
            machines_corrected=machines_corrected,
            machines_total=machines_total,
            by_severity=by_severity,
            validated_per_day=self._fill_week_days(per_day_rows, this_monday),
            batch_week_start=batch_start.date(),
            batch_week_end=(batch_end - timedelta(days=1)).date(),
            generated_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _week_bounds(ref: datetime | None = None) -> tuple[datetime, datetime, datetime]:
        """Lundi 00:00 (UTC) de la semaine de `ref`, plus deux bornes
        exclusives : dimanche+1 (semaine complète) et samedi 00:00
        (lundi->vendredi uniquement)."""
        ref = ref or datetime.now(timezone.utc)
        monday = (ref - timedelta(days=ref.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        week_end = monday + timedelta(days=7)
        friday_end = monday + timedelta(days=5)
        return monday, week_end, friday_end

    @staticmethod
    def _fill_week_days(rows: list[dict], monday: datetime) -> list[ValidatedPerDay]:
        """Garantit exactement 5 entrées, lundi à vendredi de la semaine
        courante (0 si aucune validation ce jour-là)."""
        counts_by_day = {r["day"]: r["count"] for r in rows}
        result = []
        for offset in range(5):
            day: date = (monday + timedelta(days=offset)).date()
            result.append(ValidatedPerDay(day=day, count=counts_by_day.get(day, 0)))
        return result
