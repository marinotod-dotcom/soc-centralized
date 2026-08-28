import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from src.clients.wazuh_indexer import WazuhIndexerClient
from src.collectors.action_plan import ActionPlanCollector

logger = logging.getLogger(__name__)


class ActionPlanService:
    def __init__(self, indexer_client: WazuhIndexerClient):
        self._collector = ActionPlanCollector(indexer_client)

    def generate_data_json(
        self,
        date_from: datetime,
        date_to: datetime,
        output_path: Union[Path, str] = "data.json",
        page_size: int = 1000,
    ) -> Path:
        buckets = self._collector.get_vulnerabilities_by_agent(
            date_from, date_to, page_size=page_size
        )

        payload = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "date_from": date_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "date_to": date_to.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "total_buckets": len(buckets),
            },
            "aggregations": {
                "vulnerabilities_by_agent": {"buckets": buckets}
            },
        }

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, default=str)

        logger.info("data.json généré : %s (%d buckets)", output_path, len(buckets))
        return output_path