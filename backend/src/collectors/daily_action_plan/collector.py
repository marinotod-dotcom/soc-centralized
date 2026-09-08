import logging
from typing import Optional

from src.clients.wazuh_indexer import WazuhIndexerClient
from .queries import DailyActionPlanQueries as Q
from src.decorador.resilicence_decorador import safe_call

logger = logging.getLogger(__name__)


class DailyActionPlanCollector:
    def __init__(self, indexer_client: WazuhIndexerClient):
        self._indexer = indexer_client

    def _search(self, index: str, body: dict) -> dict:
        return self._indexer.search(index, body)

    @safe_call(fallback=[], label="get_vulnerabilities_by_agent", critical=True)
    def get_vulnerabilities_by_agent(
        self,
        indices: list[str],
        page_size: int = 1000,
        max_pages: int = 200,
    ) -> list[dict]:
        if not indices:
            logger.warning("Aucun index fourni à get_vulnerabilities_by_agent — retour vide.")
            return []

        index_target = ",".join(indices)
        logger.info("Collecte sur index : %s", index_target)

        buckets: list[dict] = []
        after_key: Optional[dict] = None
        page = 0

        while page < max_pages:
            page += 1
            body = Q.vulnerabilities_by_agent(after_key=after_key, page_size=page_size)
            response = self._search(index_target, body)
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
                "max_pages (%d) atteint — extraction possiblement incomplète sur %s.",
                max_pages, index_target,
            )

        return buckets