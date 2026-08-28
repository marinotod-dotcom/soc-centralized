import logging
from typing import Optional

from dotenv import load_dotenv
from src.clients.wazuh_manager import WazuhManagerClient
from .queries import CoverageQueries as Q
from src.decorador.resilicence_decorador import safe_call

load_dotenv()
logger = logging.getLogger(__name__)


class CoverageCollector:
    def __init__(self, manager_client: WazuhManagerClient):
        self._manager = manager_client

    @safe_call(fallback=[], label="get_never_connected_agents")
    def get_never_connected_agents(
        self,
        older_than: str = "30d",
        page_size: int = 500,
        max_pages: int = 200,
    ) -> list[dict]:
        agents: list[dict] = []
        offset = 0
        page = 0

        while page < max_pages:
            page += 1
            url = Q.never_connected_agents_url(
                older_than=older_than, limit=page_size, offset=offset
            )
            response = self._manager.get(url)
            data = response.get("data", {})
            page_items = data.get("affected_items", [])

            if not page_items:
                break

            agents.extend(page_items)
            logger.info(
                "Page %d : %d agents récupérés (total cumulé : %d)",
                page, len(page_items), len(agents),
            )

            total_items = data.get("total_affected_items", 0)
            offset += len(page_items)
            if offset >= total_items:
                break
        else:
            logger.warning(
                "max_pages (%d) atteint — extraction possiblement incomplète, "
                "vérifiez older_than ou les filtres.", max_pages,
            )

        return agents

    @safe_call(fallback=0, label="get_total_registered_agents")
    def get_total_registered_agents(self) -> int:
        url = Q.total_agents_url(limit=1, offset=0)
        response = self._manager.get(url)
        return response.get("data", {}).get("total_affected_items", 0)