from pydantic import BaseModel, Field
from typing import Any, Dict
from datetime import datetime
from .enums.kpi_unit_enum import KPIUnit
from .enums.kpi_category_enum import KPICategory
from .enums.kpi_severity_enum import KPISeverity

class KPI(BaseModel):

    request_id: str
    category: KPICategory
    unit: KPIUnit
    severity: KPISeverity
    collected_at: datetime = Field(default_factory=datetime.now)
    data: Dict[str, Any] = {}

    model_config = {"use_enum_values": True}

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
