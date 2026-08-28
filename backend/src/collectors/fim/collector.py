import os
from datetime import datetime
from dotenv import load_dotenv
from src.decorador.resilicence_decorador import safe_call
from src.models.kpi_factory import KPIFactory
from src.models.enums.kpi_severity_enum import KPISeverity
from src.models.enums.kpi_category_enum import KPICategory
from src.clients.wazuh_indexer import WazuhIndexerClient
from .queries import FimQueries as Q
from .parsers import FimParsers as P

load_dotenv()


class FimCollector:

    CATEGORY = KPICategory.FIM

    def __init__(self, indexer_client: WazuhIndexerClient):
        self._client  = indexer_client
        self._index   = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")
        self._factory = KPIFactory(category=self.CATEGORY)

    def _search(self, body: dict) -> dict:
        return self._client.search(self._index, body)

    @safe_call(fallback=None, label="get_total_event_count")
    def get_total_event_count(self, date_from: datetime, date_to: datetime) -> dict:
        resp = self._search(Q.total_event_count(date_from, date_to))
        return self._factory.create(
            "fim_total_events",
            KPISeverity.LOW,
            **P.total_event_count(resp)
        )

    @safe_call(fallback=None, label="get_event_type_breakdown")
    def get_event_type_breakdown(self, date_from: datetime, date_to: datetime) -> dict:
        resp = self._search(Q.event_type_breakdown(date_from, date_to))
        return self._factory.create(
            "fim_event_type_breakdown",
            KPISeverity.MEDIUM,
            **P.event_type_breakdown(resp)
        )

    @safe_call(fallback=None, label="get_alert_levels_breakdown")
    def get_alert_levels_breakdown(self, date_from: datetime, date_to: datetime) -> dict:
        resp = self._search(Q.alert_levels_breakdown(date_from, date_to))
        return self._factory.create(
            "fim_alert_levels",
            KPISeverity.HIGH,
            **P.alert_levels_breakdown(resp)
        )

    @safe_call(fallback=None, label="get_mode_coverage")
    def get_mode_coverage(self, date_from: datetime, date_to: datetime) -> dict:
        resp = self._search(Q.mode_breakdown(date_from, date_to))
        return self._factory.create(
            "fim_mode_coverage",
            KPISeverity.LOW,
            **P.mode_coverage(resp)
        )


    def collect_all(
        self,
        date_from: datetime,
        date_to: datetime,
    ) -> dict:
        return {
            "total_events":         self.get_total_event_count(date_from, date_to),
            "event_type_breakdown": self.get_event_type_breakdown(date_from, date_to),
            "alert_levels":         self.get_alert_levels_breakdown(date_from, date_to),
            "mode_coverage":        self.get_mode_coverage(date_from, date_to),
        }