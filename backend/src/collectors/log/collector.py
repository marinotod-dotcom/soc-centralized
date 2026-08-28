import os
from datetime import datetime
from dotenv import load_dotenv
from src.models.kpi_factory import KPIFactory
from src.clients.wazuh_indexer import WazuhIndexerClient
from src.clients.wazuh_manager import WazuhManagerClient
from src.models.enums.kpi_category_enum import KPICategory
from src.models.enums.kpi_severity_enum import KPISeverity
from src.models.enums.kpi_unit_enum import KPIUnit
from .queries import LogQueries as Q
from .parsers import LogParsers as P
from src.decorador.resilicence_decorador import safe_call

load_dotenv()

class LogCollector:

    CATEGORY = KPICategory.LOGS

    def __init__(
        self,
        indexer_client: WazuhIndexerClient,
        manager_client: WazuhManagerClient,
    ):
        self._indexer = indexer_client
        self._manager = manager_client
        self._index   = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")
        self._factory = KPIFactory(category=self.CATEGORY)


    def _search(self, body: dict) -> dict:
        return self._indexer.search(self._index, body)

    @safe_call(fallback=None, label="get_agent_summary")
    def get_agent_summary(self) -> dict:
        response = self._manager.get(Q.agent_summary_url())
        parsed   = P.agent_summary(response)
        self._total_declared = parsed["total_declared"]

        return self._factory.create("log_agent_summary", KPISeverity.HIGH,
                         **P.agent_summary(response))

    @safe_call(fallback=None, label="get_never_connected_agents")
    def get_never_connected_agents(self) -> dict:

        if not hasattr(self, "_total_declared"):
            self.get_agent_summary()

        response = self._manager.get(Q.never_connected_agents_url())
        return self._factory.create("log_never_connected_agents", KPISeverity.CRITICAL,
                         **P.never_connected_agents(response, self._total_declared))

    @safe_call(fallback=None, label="get_confirmed_incidents")
    def get_confirmed_incidents(
        self, date_from: datetime, date_to: datetime
    ) -> dict:
        resp = self._search(Q.confirmed_incidents(date_from, date_to))
        return self._factory.create("log_confirmed_incidents", KPISeverity.CRITICAL,
                         **P.confirmed_incidents(resp))
