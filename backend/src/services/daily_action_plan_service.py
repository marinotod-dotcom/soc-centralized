import json
import logging
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Union

from dotenv import load_dotenv
from src.clients.wazuh_indexer import WazuhIndexerClient
from src.collectors.daily_action_plan import DailyActionPlanCollector
from src.utils.date_utils import (
    DEFAULT_DAILY_INDEX_PATTERN,
    get_collection_indices,
    get_day_label,
)

load_dotenv()
logger = logging.getLogger(__name__)


class DailyActionPlanService:
    def __init__(self, indexer_client: WazuhIndexerClient, index_pattern: str = None):
        self._collector = DailyActionPlanCollector(indexer_client)
        self._index_pattern = index_pattern or os.getenv(
            "WAZUH_INDEXER_INDEX_PATTERN_DAILY", DEFAULT_DAILY_INDEX_PATTERN
        )

    def generate_data_json(
        self,
        collection_date: date,
        output_path: Union[Path, str] = "data.json",
        page_size: int = 1000,
        indices_override: Optional[list[str]] = None,
    ) -> Path:
        indices = indices_override or get_collection_indices(collection_date, self._index_pattern)
        day_label = get_day_label(collection_date)

        buckets = self._collector.get_vulnerabilities_by_agent(
            indices, page_size=page_size
        )

        payload = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "collection_date": day_label,
                "source_indices": indices,
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

        logger.info(
            "data.json généré : %s (%d buckets, index=%s)",
            output_path, len(buckets), ",".join(indices),
        )
        return