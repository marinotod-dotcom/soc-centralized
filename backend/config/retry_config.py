from requests.exceptions import ConnectionError, Timeout
from src.utils.retry_utils import RetryConfig

INDEXER_RETRY = RetryConfig(
    max_attempts=3,
    backoff_base=2.0,
    backoff_max=30.0,
    jitter=True,
    retryable_exceptions=(ConnectionError, Timeout),
    retryable_status_codes={500, 502, 503, 504},
)

MANAGER_RETRY = RetryConfig(
    max_attempts=3,
    backoff_base=2.0,
    backoff_max=20.0,
    jitter=True,
    retryable_exceptions=(ConnectionError, Timeout),
    retryable_status_codes={500, 502, 503, 504},
)