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
    return boto3.client(
        "s3",
        endpoint_url=os.environ["MINIO_ENDPOINT"],
        aws_access_key_id=os.environ["MINIO_ACCESS_KEY"],
        aws_secret_access_key=os.environ["MINIO_SECRET_KEY"],
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