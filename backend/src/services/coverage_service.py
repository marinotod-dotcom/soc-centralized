import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from src.clients.wazuh_manager import WazuhManagerClient
from src.collectors.coverage import CoverageCollector

logger = logging.getLogger(__name__)


def _round_loss_rate(value: float) -> float:
    return round(value)

class CoverageService:
    def __init__(self, manager_client: WazuhManagerClient):
        self._collector = CoverageCollector(manager_client)

    def generate_data_json(
        self,
        older_than: str = "30d",
        reference_fleet: Optional[int] = None,
        output_path: Union[Path, str] = "data.json",
        page_size: int = 500,
    ) -> Path:
        agents = self._collector.get_never_connected_agents(
            older_than=older_than, page_size=page_size
        )
        inactive_count = len(agents)

        if reference_fleet is not None:
            fleet_size = reference_fleet
            fleet_source = "manual"
        else:
            fleet_size = self._collector.get_total_registered_agents()
            fleet_source = "wazuh_total"

        loss_rate = (
            _round_loss_rate(inactive_count / fleet_size * 100)
            if fleet_size
            else 0.0
        )

        payload = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "older_than": older_than,
                "reference_fleet": fleet_size,
                "reference_fleet_source": fleet_source,
                "total_agents": inactive_count,
                "loss_rate_percent": loss_rate,
                "target_loss_rate_percent": 1.0,
            },
            "agents": agents,
        }

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, default=str)

        logger.info(
            "data.json généré : %s (%d/%d agents inactifs, %.3f%% de perte, réf=%s)",
            output_path, inactive_count, fleet_size, loss_rate, fleet_source,
        )
        return output_path