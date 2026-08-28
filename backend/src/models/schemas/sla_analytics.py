from datetime import date, datetime

from pydantic import BaseModel


class SeverityBreakdown(BaseModel):
    severity: str
    total: int
    validated: int
    pct_validated: float


class ValidatedPerDay(BaseModel):
    day: date
    count: int


class VulnDashboardResponse(BaseModel):
    total_cve: int
    total_validated: int
    pct_validated: float
    machines_corrected: int
    machines_total: int
    by_severity: list[SeverityBreakdown]
    validated_per_day: list[ValidatedPerDay]  # lundi -> vendredi de la semaine courante
    batch_week_start: date  # lundi de la semaine de détection (scan) du batch en cours de traitement
    batch_week_end: date    # dimanche de cette même semaine
    generated_at: datetime
