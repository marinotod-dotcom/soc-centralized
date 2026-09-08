import logging
import os
import tempfile
from datetime import date
from pathlib import Path
from typing import Optional

from src.loaders import VulnerabilityTrackingLoader
from src.services.daily_action_plan_service import DailyActionPlanService
from src.utils.date_utils import get_day_label
from src.utils.storage_utils import publish_dataset

logger = logging.getLogger(__name__)

MINIO_BUCKET = os.environ.get("MINIO_BUCKET_DASHBOARD", "dashboard-data")
PIPELINE_NAME = "daily_action_plan"


def run_daily_action_plan_pipeline(
    indexer_client,
    base_dir: Path,
    collection_date: Optional[date] = None,
    index_override: Optional[str] = None,
    skip_publish: bool = False,
) -> str:
    collection_date = collection_date or date.today()
    daily_service = DailyActionPlanService(indexer_client=indexer_client)
    day_label = get_day_label(collection_date)
    indices_override = [index_override] if index_override else None

    if skip_publish:
        output_dir = base_dir / "local_output"
        output_dir.mkdir(parents=True, exist_ok=True)
        local_json_path = output_dir / f"data_{day_label}.json"

        daily_service.generate_data_json(
            collection_date,
            output_path=local_json_path,
            indices_override=indices_override,
        )
        print(f"[LOCAL] daily_action_plan écrit dans : {local_json_path}")
        return str(local_json_path)

    with tempfile.TemporaryDirectory() as tmp_dir:
        local_json_path = Path(tmp_dir) / f"data_{day_label}.json"
        daily_service.generate_data_json(
            collection_date,
            output_path=local_json_path,
            indices_override=indices_override,
        )

        publish_dataset(
            local_path=local_json_path,
            bucket=MINIO_BUCKET,
            pipeline_name=PIPELINE_NAME,
            week_label=day_label,
        )
        print(
            f"Dataset publié : s3://{MINIO_BUCKET}/{PIPELINE_NAME}/latest.json "
            f"(archive data_{day_label}.json)"
        )

        try:
            loader = VulnerabilityTrackingLoader(data_json_path=local_json_path)
            nb_loaded = loader.load()
            print(f"Suivi vulnérabilités chargé en base : {nb_loaded} enregistrements ({day_label})")
        except Exception:
            logger.exception("Échec du chargement en base pour %s", local_json_path)

    return f"s3://{MINIO_BUCKET}/{PIPELINE_NAME}/latest.json"