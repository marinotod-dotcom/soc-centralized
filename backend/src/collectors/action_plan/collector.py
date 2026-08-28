import os
import logging
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from src.clients.wazuh_indexer import WazuhIndexerClient
from .queries import ActionPlanQueries as Q
from src.decorador.resilicence_decorador import safe_call

load_dotenv()
logger = logging.getLogger(__name__)


class ActionPlanCollector:
    def __init__(self, indexer_client: WazuhIndexerClient):
        self._indexer = indexer_client
        self._index = os.getenv("WAZUH_INDEXER_INDEX_PATTERN", "wazuh-alerts-*")

    def _search(self, body: dict) -> dict:
        return self._indexer.search(self._index, body)

    @safe_call(fallback=[], label="get_vulnerabilities_by_agent")
    def get_vulnerabilities_by_agent(
        self,
        date_from: datetime,
        date_to: datetime,
        page_size: int = 1000,
        max_pages: int = 200,
    ) -> list[dict]:
        buckets: list[dict] = []
        after_key: Optional[dict] = None
        page = 0

        while page < max_pages:
            page += 1
            body = Q.vulnerabilities_by_agent(
                date_from, date_to, after_key=after_key, page_size=page_size
            )
            response = self._search(body)
            agg = response.get("aggregations", {}).get("vulnerabilities_by_agent", {})
            page_buckets = agg.get("buckets", [])

            if not page_buckets:
                break

            buckets.extend(page_buckets)
            logger.info(
                "Page %d : %d buckets récupérés (total cumulé : %d)",
                page, len(page_buckets), len(buckets),
            )

            after_key = agg.get("after_key")
            if not after_key:
                break
        else:
            logger.warning(
                "max_pages (%d) atteint — extraction possiblement incomplète, "
                "vérifiez la fenêtre temporelle ou les filtres.", max_pages,
            )

        return buckets