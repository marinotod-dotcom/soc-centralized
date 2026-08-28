from __future__ import annotations

import logging
import time
import random
from typing import Callable, Type

logger = logging.getLogger(__name__)


class RetryConfig:
    def __init__(
        self,
        max_attempts: int = 3,
        backoff_base: float = 2.0,
        backoff_max: float = 30.0,
        jitter: bool = True,
        retryable_exceptions: tuple[Type[Exception], ...] = (Exception,),
        retryable_status_codes: set[int] = frozenset({500, 502, 503, 504}),
    ):
        self.max_attempts = max_attempts
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.jitter = jitter
        self.retryable_exceptions = retryable_exceptions
        self.retryable_status_codes = set(retryable_status_codes)

    def wait_seconds(self, attempt: int) -> float:
        delay = min(self.backoff_base**attempt, self.backoff_max)
        if self.jitter:
            delay *= 0.5 + random.random() * 0.5
        return delay


def with_retry(config: RetryConfig, fn: Callable, *args, **kwargs):

    from requests.exceptions import HTTPError

    last_exc: Exception | None = None

    for attempt in range(1, config.max_attempts + 1):
        try:
            return fn(*args, **kwargs)

        except HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else None
            if status not in config.retryable_status_codes:
                raise
            last_exc = exc

        except config.retryable_exceptions as exc:
            last_exc = exc

        if attempt == config.max_attempts:
            break

        wait = config.wait_seconds(attempt)
        logger.warning(
            "Retry %d/%d — %s — attente %.1fs (%s)",
            attempt,
            config.max_attempts,
            getattr(fn, "__qualname__", str(fn)),
            wait,
            last_exc,
        )
        time.sleep(wait)

    logger.error(
        "Échec définitif après %d tentatives : %s", config.max_attempts, last_exc
    )
    raise last_exc
