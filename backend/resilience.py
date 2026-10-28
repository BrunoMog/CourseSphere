"""
SRE Resilience Patterns: Timeout, Retry with Exponential Backoff, and Circuit Breaker.
Protects CourseSphere from cascading failures when calling external services (OpenAI, Firebase, DB).
"""

import time
import logging
import functools
from threading import Lock
from typing import Callable, Any

logger = logging.getLogger("coursesphere.resilience")


class CircuitBreakerOpenException(Exception):
    """Raised when the circuit breaker is in OPEN state and fast-failing requests."""
    pass


class CircuitBreaker:
    """
    State machine implementing the Circuit Breaker pattern (CLOSED -> OPEN -> HALF_OPEN).
    """
    STATE_CLOSED = 0
    STATE_HALF_OPEN = 1
    STATE_OPEN = 2

    def __init__(self, name: str, failure_threshold: int = 3, recovery_timeout: float = 30.0):
        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = self.STATE_CLOSED
        self.failure_count = 0
        self.last_failure_time = 0.0
        self._lock = Lock()

    @property
    def state_name(self) -> str:
        if self.state == self.STATE_OPEN:
            return "OPEN"
        if self.state == self.STATE_HALF_OPEN:
            return "HALF_OPEN"
        return "CLOSED"

    def call(self, func: Callable, *args, **kwargs) -> Any:
        with self._lock:
            if self.state == self.STATE_OPEN:
                elapsed = time.time() - self.last_failure_time
                if elapsed >= self.recovery_timeout:
                    self.state = self.STATE_HALF_OPEN
                    logger.info(f"CircuitBreaker [{self.name}] transitioning to HALF_OPEN")
                else:
                    raise CircuitBreakerOpenException(
                        f"Service '{self.name}' is temporarily unavailable (Circuit Breaker OPEN)."
                    )

        try:
            result = func(*args, **kwargs)
        except Exception as exc:
            self._record_failure(exc)
            raise

        self._record_success()
        return result

    def _record_failure(self, exc: Exception):
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                self.state = self.STATE_OPEN
                logger.error(
                    f"CircuitBreaker [{self.name}] tripped to OPEN after {self.failure_count} failures: {exc}"
                )

    def _record_success(self):
        with self._lock:
            if self.state in (self.STATE_HALF_OPEN, self.STATE_OPEN):
                logger.info(f"CircuitBreaker [{self.name}] recovered to CLOSED")
            self.failure_count = 0
            self.state = self.STATE_CLOSED

    def reset(self):
        with self._lock:
            self.failure_count = 0
            self.state = self.STATE_CLOSED
            self.last_failure_time = 0.0


def retry_with_backoff(max_retries: int = 2, base_delay: float = 0.05, max_delay: float = 1.0):
    """
    Decorator that retries transient failures using exponential backoff.
    """
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            while True:
                try:
                    return func(*args, **kwargs)
                except CircuitBreakerOpenException:
                    raise
                except Exception as exc:
                    attempt += 1
                    if attempt > max_retries:
                        raise
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
                    logger.warning(
                        f"Retry {attempt}/{max_retries} for {func.__name__} after {delay:.3f}s due to: {exc}"
                    )
                    time.sleep(delay)
        return wrapper
    return decorator


# Global circuit breakers for external dependencies
CIRCUIT_BREAKERS = {
    "firebase": CircuitBreaker("firebase", failure_threshold=3, recovery_timeout=30.0),
    "openai": CircuitBreaker("openai", failure_threshold=3, recovery_timeout=60.0),
    "database": CircuitBreaker("database", failure_threshold=5, recovery_timeout=15.0),
}
