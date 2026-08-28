import logging
import os
import tempfile
from pathlib import Path
from datetime import datetime
from src.loaders import VulnerabilityTrackingLoader
from src.services.action_plan_service import ActionPlanService
from src.utils.date_utils import get_week_label
from src.utils.storage_utils import publish_dataset

logger = logging.getLogger(__name__)

MINIO_BUCKET = os.environ.get("MINIO_BUCKET_DASHBOARD", "dashboard-data")

def run_action_plan_pipeline(
    date_from: datetime,
    date_to: datetime,
    indexer_client,
    base_dir: Path,
) -> str:
    action_plan_service = ActionPlanService(indexer_client=indexer_client)
    week_label = get_week_label(date_to)

    with tempfile.TemporaryDirectory() as tmp_dir:
        local_json_path = Path(tmp_dir) / f"data_{week_label}.json"
        action_plan_service.generate_data_json(date_from, date_to, output_path=local_json_path)

        publish_dataset(
            local_path=local_json_path,
            bucket=MINIO_BUCKET,
            pipeline_name="action_plan",
            week_label=week_label,
        )
        print(f"Dataset publié : s3://{MINIO_BUCKET}/action_plan/latest.json (archive data_{week_label}.json)")

        try:
            loader = VulnerabilityTrackingLoader(data_json_path=local_json_path)
            nb_loaded = loader.load()
            print(f"Suivi vulnérabilités chargé en base : {nb_loaded} enregistrements")
        except Exception:
            logger.exception(
                local_json_path,
            )

    return f"s3://{MINIO_BUCKET}/action_plan/latest.json"