from .kpi import KPI
from .enums.kpi_unit_enum import KPIUnit
from .enums.kpi_category_enum import KPICategory
from .enums.kpi_severity_enum import KPISeverity

class KPIFactory:

    def __init__(self, category: KPICategory, unit: KPIUnit = KPIUnit.COUNT):
        self._category = category.value
        self._unit = unit.value

    def create(self, request_id: str, severity: KPISeverity, **data) -> KPI:
        return KPI(
            request_id=request_id,
            category=self._category,
            unit=self._unit,
            severity=severity.value,
            data=data,
        )
