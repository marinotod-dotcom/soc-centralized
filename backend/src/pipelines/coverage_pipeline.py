import logging
import os
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional

from src.services.coverage_service import CoverageService
from src.utils.date_utils import get_week_label
from src.utils.storage_utils import publish_dataset

logger = logging.getLogger(__name__)

MINIO_BUCKET = os.environ.get("MINIO_BUCKET_DASHBOARD", "dashboard-data")


def run_coverage_pipeline(
    date_to: datetime,
    manager_client,
    base_dir: Path,
    older_than: str = "30d",
    reference_fleet: Optional[int] = None,
) -> str:
    coverage_service = CoverageService(manager_client=manager_client)
    week_label = get_week_label(date_to)

    with tempfile.TemporaryDirectory() as tmp_dir:
        local_json_path = Path(tmp_dir) / f"data_{week_label}.json"
        coverage_service.generate_data_json(
            older_than=older_than,
            reference_fleet=reference_fleet,
            output_path=local_json_path,
        )

        publish_dataset(
            local_path=local_json_path,
            bucket=MINIO_BUCKET,
            pipeline_name="coverage",
            week_label=week_label,
        )
        print(f"Dataset publié : s3://{MINIO_BUCKET}/coverage/latest.json (archive data_{week_label}.json)")

    return f"s3://{MINIO_BUCKET}/coverage/latest.json"