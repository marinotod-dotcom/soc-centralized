from __future__ import annotations

import logging
import requests
import urllib3
from src.utils.retry_utils import with_retry
from config.retry_config import MANAGER_RETRY

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


class WazuhManagerClient:

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        timeout: int = 60,
        verify_ssl: bool = False,
    ):
        self.host = host.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._credentials = (username, password)
        self._token: str | None = None

    def authenticate(self) -> str:
        resp = self._session.post(
            f"{self.host}/security/user/authenticate",
            auth=self._credentials,
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        resp.raise_for_status()

        token = resp.json().get("data", {}).get("token")
        if not token:
            raise ValueError(
                "Token JWT introuvable dans la réponse d'authentification."
            )

        self._token = token
        self._session.headers.update({"Authorization": f"Bearer {self._token}"})
        logger.debug("Authentification Wazuh Manager réussie.")
        return self._token

    def _ensure_authenticated(self) -> None:
        if not self._token:
            self.authenticate()

    def _authenticated_request(self, method: str, path: str, **kwargs) -> dict:
        self._ensure_authenticated()

        def _do():
            resp = self._session.request(
                method,
                f"{self.host}{path}",
                timeout=self.timeout,
                **kwargs,
            )
            resp.raise_for_status()
            return resp.json()

        try:
            return with_retry(MANAGER_RETRY, _do)

        except HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 401:
                logger.warning("Token JWT expiré (401) — re-authentification en cours.")
                self._token = None
                self.authenticate()
                return with_retry(MANAGER_RETRY, _do)
            raise

    def get(self, endpoint: str, params: dict | None = None) -> dict:
        return self._authenticated_request("GET", endpoint, params=params)

    def post(self, endpoint: str, payload: dict | None = None) -> dict:
        return self._authenticated_request("POST", endpoint, json=payload)

    def test_connection(self) -> dict:
        return self.get("/agents", {"limit": 1})
