from __future__ import annotations

import logging
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)


def safe_call(fallback: Any = None, label: str = ""):
    def decorator(fn: Callable) -> Callable:
        name = label or fn.__qualname__

        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                logger.error(
                    "[FALLBACK] %s échoué → %s : %s — valeur de repli retournée",
                    name,
                    type(exc).__name__,
                    exc,
                )
                return fallback

        return wrapper

    return decorator
