import json
import os
import logging
from pathlib import Path
from typing import Any

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def get_minio_client():
    endpoint = os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
    access_key = os.environ.get("MINIO_ACCESS_KEY") or os.environ.get("MINIO_ROOT_USER")
    secret_key = os.environ.get("MINIO_SECRET_KEY") or os.environ.get("MINIO_ROOT_PASSWORD")

    missing = [
        name for name, value in [
            ("MINIO_ACCESS_KEY ou MINIO_ROOT_USER", access_key),
            ("MINIO_SECRET_KEY ou MINIO_ROOT_PASSWORD", secret_key),
        ]
        if not value
    ]
    if missing:
        raise RuntimeError(
            f"Configuration MinIO incomplète pour ce conteneur, variable(s) manquante(s) : "
            f"{', '.join(missing)}. Vérifiez le bloc 'environment' de ce service dans "
            f"docker-compose.yaml."
        )

    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def upload_json(local_path: Path, bucket: str, key: str, client=None) -> None:
    client = client or get_minio_client()
    try:
        client.upload_file(
            str(local_path), bucket, key,
            ExtraArgs={"ContentType": "application/json"},
        )
        logger.info("Uploadé vers MinIO : s3://%s/%s", bucket, key)
    except ClientError:
        logger.exception("Échec upload MinIO : s3://%s/%s", bucket, key)
        raise


def publish_dataset(local_path: Path, bucket: str, pipeline_name: str, week_label: str, client=None) -> None:
    client = client or get_minio_client()
    upload_json(local_path, bucket, f"{pipeline_name}/data_{week_label}.json", client=client)
    upload_json(local_path, bucket, f"{pipeline_name}/latest.json", client=client)


def list_dataset_days(bucket: str, pipeline_name: str, client=None) -> list[str]:
    client = client or get_minio_client()
    prefix = f"{pipeline_name}/data_"

    try:
        paginator = client.get_paginator("list_objects_v2")
        labels: list[str] = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                filename = obj["Key"].rsplit("/", 1)[-1]
                label = filename.removeprefix("data_").removesuffix(".json")
                labels.append(label)
        return labels
    except ClientError:
        logger.exception("Échec listing MinIO : s3://%s/%s*", bucket, prefix)
        raise


def fetch_dataset_json(bucket: str, pipeline_name: str, label: str, client=None) -> dict[str, Any]:
    client = client or get_minio_client()
    key = f"{pipeline_name}/data_{label}.json"

    try:
        response = client.get_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code")
        if error_code in ("NoSuchKey", "404"):
            raise FileNotFoundError(f"Aucun dataset pour s3://{bucket}/{key}") from exc
        logger.exception("Échec fetch MinIO : s3://%s/%s", bucket, key)
        raise

    return json.loads(response["Body"].read())