from __future__ import annotations

import os
from datetime import datetime

from dotenv import load_dotenv

from src.clients.wazuh_indexer import WazuhIndexerClient
from src.decorador.resilicence_decorador import safe_call
from src.models.enums.kpi_category_enum import KPICategory
from src.models.enums.kpi_severity_enum import KPISeverity
from src.models.kpi_factory import KPIFactory

from .parsers import ComplianceParsers as PC
from .queries import ComplianceQueries as QC

load_dotenv()


class ComplianceCollector:

    CATEGORY = KPICategory.COMPLIANCE

    def __init__(self, indexer_client: WazuhIndexerClient):
        self._client = indexer_client
        self._index = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")
        self._factory = KPIFactory(category=self.CATEGORY)

    def _search(self, body: dict) -> dict:
        return self._client.search(self._index, body)

    def _collect(
        self,
        name: str,
        severity: KPISeverity,
        query: dict,
        parser,
    ) -> dict:
        response = self._search(query)

        return self._factory.create(
            name,
            severity,
            **parser(response),
        )

    @safe_call(fallback=None, label="get_rgpd")
    def rgpd(self, date_from: datetime, date_to: datetime) -> dict:
        return self._collect(
            name="rgpd",
            severity=KPISeverity.MEDIUM,
            query=QC.rgpd(date_from, date_to),
            parser=PC.rgpd,
        )

    @safe_call(fallback=None, label="get_hipaa")
    def hipaa(self, date_from: datetime, date_to: datetime) -> dict:
        return self._collect(
            name="hipaa",
            severity=KPISeverity.MEDIUM,
            query=QC.hipaa(date_from, date_to),
            parser=PC.hipaa,
        )
