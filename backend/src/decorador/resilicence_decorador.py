from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class FailureRegistry:
    _failures: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, label: str, exc: Exception) -> None:
        with self._lock:
            self._failures.append({
                "label": label,
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            })

    @property
    def has_failures(self) -> bool:
        return len(self._failures) > 0

    @property
    def failures(self) -> list[dict]:
        with self._lock:
            return list(self._failures)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()

    def summary(self) -> str:
        if not self.has_failures:
            return "Aucun échec."
        lines = [f"{len(self._failures)} échec(s) durant ce run :"]
        for f in self.failures:
            lines.append(f"  - [{f['label']}] {f['error_type']}: {f['error_message']}")
        return "\n".join(lines)


failure_registry = FailureRegistry()


def safe_call(fallback: Any = None, label: str = "", critical: bool = False):
    def decorator(fn: Callable) -> Callable:
        name = label or fn.__qualname__

        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception as exc:
                logger.exception(
                    "[FALLBACK] %s échoué → %s : %s — valeur de repli retournée",
                    name,
                    type(exc).__name__,
                    exc,
                )
                failure_registry.record(name, exc)

                if critical:
                    raise

                return fallback

        return wrapper

    return decorator