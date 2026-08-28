from __future__ import annotations

import logging
import requests
import urllib3
from src.utils.retry_utils import with_retry
from config.retry_config import INDEXER_RETRY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class WazuhIndexerClient:

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        timeout: int = 180,
        verify_ssl: bool = False,
    ):
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._session = requests.Session()
        self._session.auth = (username, password)
        self._session.verify = verify_ssl
        self._session.headers.update({"Content-Type": "application/json"})

    def _request(self, method: str, path: str, **kwargs) -> dict:
        url = f"{self.host}{path}"

        def _do():
            resp = self._session.request(
                method,
                url,
                timeout=self.timeout,
                **kwargs,
            )
            resp.raise_for_status()
            return resp.json()

        return with_retry(INDEXER_RETRY, _do)

    def search(self, index: str, query: dict) -> dict:
        return self._request("POST", f"/{index}/_search", json=query)

    def count(self, index: str, query: dict | None = None) -> dict:
        return self._request("POST", f"/{index}/_count", json=query or {})

    def health(self) -> dict:
        return self._request("GET", "/_cluster/health")

    def test_connection(self) -> dict:
        return self.health()

    def check_vulnerability_present(self, agent_name: str, cve_id: str) -> bool:
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"agent.name": agent_name}},
                        {"term": {"vulnerability.id": cve_id}},
                    ]
                }
            }
        }
        response = self.search(index="wazuh-states-vulnerabilities-*", query=query)
        return response["hits"]["total"]["value"] > 0