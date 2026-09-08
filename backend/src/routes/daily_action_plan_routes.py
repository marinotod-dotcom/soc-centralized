import logging
import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import ORJSONResponse

from src.auth.roles import require_role
from src.utils.storage_utils import list_dataset_days, fetch_dataset_json

logger = logging.getLogger("uvicorn")

router = APIRouter(prefix="/api/daily-action-plan", tags=["daily-action-plan"])

MINIO_BUCKET = os.environ.get("MINIO_BUCKET_DASHBOARD", "dashboard-data")
PIPELINE_NAME = "daily_action_plan"


@router.get("/dates")
def get_available_dates(_=Depends(require_role("technicien", "admin_cyber"))):
    try:
        days = list_dataset_days(bucket=MINIO_BUCKET, pipeline_name=PIPELINE_NAME)
    except Exception:
        logger.exception("Échec de récupération des dates disponibles (daily_action_plan)")
        raise HTTPException(502, "Impossible de récupérer la liste des dates disponibles.")
    return {"dates": sorted(days, reverse=True)}


@router.get("/{day}", response_class=ORJSONResponse)
def get_daily_dataset(day: str, _=Depends(require_role("technicien", "admin_cyber"))):
    try:
        datetime.strptime(day, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(400, "Format de date invalide, attendu YYYY-MM-DD.")

    try:
        data = fetch_dataset_json(bucket=MINIO_BUCKET, pipeline_name=PIPELINE_NAME, label=day)
    except FileNotFoundError:
        raise HTTPException(404, f"Aucune donnée disponible pour le {day}.")
    except Exception:
        logger.exception("Échec de récupération du dataset pour %s", day)
        raise HTTPException(502, "Impossible de récupérer les données pour cette date.")

    return data