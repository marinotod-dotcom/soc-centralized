import os

from src.clients.wazuh_indexer import WazuhIndexerClient
from src.clients.wazuh_manager import WazuhManagerClient
from src.models.smtp_config import SMTPConfig


def build_clients() -> tuple[WazuhIndexerClient, WazuhManagerClient]:
    indexer = WazuhIndexerClient(
        host=os.getenv("WAZUH_INDEXER_HOST"),
        username=os.getenv("WAZUH_INDEXER_USERNAME"),
        password=os.getenv("WAZUH_INDEXER_PASSWORD"),
    )

    manager = WazuhManagerClient(
        host=os.getenv("WAZUH_MANAGER_HOST"),
        username=os.getenv("WAZUH_MANAGER_USERNAME"),
        password=os.getenv("WAZUH_MANAGER_PASSWORD"),
    )

    return indexer, manager


def build_smtp_config() -> SMTPConfig:
    return SMTPConfig(
        server=os.getenv("SMTP_SERVER"),
        port=int(os.getenv("SMTP_PORT")),
        username=os.getenv("SMTP_USERNAME"),
        password=os.getenv("SMTP_PASSWORD"),
        sender=os.getenv("SMTP_SENDER"),
    )
