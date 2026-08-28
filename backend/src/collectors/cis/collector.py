from __future__ import annotations

import os
from datetime import datetime
from dotenv import load_dotenv
from src.models.kpi_factory import KPIFactory
from src.decorador.resilicence_decorador import safe_call
from .queries import CisBenchmarkQueries as QC
from .parsers import CisBenchmarkParsers as PC
from src.models.enums.kpi_unit_enum import KPIUnit
from src.clients.wazuh_indexer import WazuhIndexerClient
from src.models.enums.kpi_category_enum import KPICategory
from src.models.enums.kpi_severity_enum import KPISeverity

load_dotenv()


class CisBenchmarkCollector:

    CATEGORY = KPICategory.CIS

    def __init__(self, indexer_client: WazuhIndexerClient):
        self._client = indexer_client
        self._index = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")
        self._factory = KPIFactory(category=self.CATEGORY)

    def _search(self, body: dict) -> dict:
        return self._client.search(self._index, body)

    @safe_call(fallback=0, label="get_cis_score_global")
    def get_score_global(self, date_from: datetime, date_to: datetime) -> dict:
        resp = self._search(QC.score_global(date_from, date_to))

        return self._factory.create(
            "cis_score_global", KPISeverity.MEDIUM, **PC.score_global(resp)
        )

    @safe_call(fallback=None, label="get_cis_score_by_policy")
    def get_score_by_policy(self, date_from: datetime, date_to: datetime) -> dict:
        resp = self._search(QC.score_by_policy(date_from, date_to))

        return self._factory.create(
            "cis_score_by_policy", KPISeverity.MEDIUM, policies=PC.score_by_policy(resp)
        )

    @safe_call(fallback=0, label="get_agents_scanned") 
    def agents_scanned(
        self,
        date_from: datetime,
        date_to: datetime
    ) -> dict:
        resp = self._search(
            QC.scanned_agents(date_from,date_to)
        )

        return self._factory.create(
            "cis_scanned_agents", KPISeverity.LOW, policie=PC.scanned_agents(resp)
        )
