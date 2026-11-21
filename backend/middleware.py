"""
HTTP middleware: security headers, per-client rate limiting and response timing.

Implemented as pure ASGI middleware so they wrap streaming responses and
never buffer bodies.
"""

import json
import math
import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, Iterable, List, Optional, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

SECURITY_HEADERS: List[Tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
]
API_ONLY_HEADERS: List[Tuple[bytes, bytes]] = [
    (b"cache-control", b"no-store"),
    (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
]
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


def _merge_headers(existing: Iterable[Tuple[bytes, bytes]], extra: Iterable[Tuple[bytes, bytes]]):
    headers = list(existing)
    present = {k.lower() for k, _ in headers}
    for key, value in extra:
        if key not in present:
            headers.append((key, value))
    return headers


class SecurityHeadersMiddleware:
    """Adds defensive response headers. API responses are also marked no-store."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        extra = list(SECURITY_HEADERS)
        if path.startswith("/api/"):
            extra += API_ONLY_HEADERS
        if scope.get("scheme") == "https":
            extra.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))

        async def send_wrapper(message: Message):
            if message["type"] == "http.response.start":
                message["headers"] = _merge_headers(message.get("headers", []), extra)
            await send(message)

        await self.app(scope, receive, send_wrapper)


class SlidingWindowLimiter:
    """In-process sliding-window counter keyed by client identity."""

    def __init__(self, limit: int, window_seconds: int, max_clients: int = 50000):
        self.limit = max(1, int(limit))
        self.window = max(1, int(window_seconds))
        self.max_clients = max_clients
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, now: Optional[float] = None) -> Tuple[bool, int, int]:
        """Record a request. Returns (allowed, remaining, seconds_until_reset)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._hits.get(key)
            if bucket is None:
                if len(self._hits) >= self.max_clients:
                    self._evict(now)
                bucket = self._hits[key] = deque()
            cutoff = now - self.window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                reset = max(1, math.ceil(bucket[0] + self.window - now))
                return False, 0, reset
            bucket.append(now)
            reset = max(1, math.ceil(bucket[0] + self.window - now))
            return True, self.limit - len(bucket), reset

    def _evict(self, now: float) -> None:
        cutoff = now - self.window
        for key in [k for k, v in self._hits.items() if not v or v[-1] <= cutoff]:
            del self._hits[key]
        if len(self._hits) >= self.max_clients:
            self._hits.clear()

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


class RateLimitMiddleware:
    """Per-client-IP rate limiting for HTTP requests (health checks exempt)."""

    EXEMPT_PATHS = ("/health",)

    def __init__(self, app: ASGIApp, limit: Optional[int] = None, window_seconds: Optional[int] = None,
                 settings_provider: Optional[Callable] = None):
        self.app = app
        self._limit = limit
        self._window = window_seconds
        self._settings_provider = settings_provider
        self._limiter: Optional[SlidingWindowLimiter] = None

    @property
    def limiter(self) -> SlidingWindowLimiter:
        if self._limiter is None:
            limit, window = self._limit, self._window
            if (limit is None or window is None) and self._settings_provider is not None:
                settings = self._settings_provider()
                limit = limit if limit is not None else settings.rate_limit_requests
                window = window if window is not None else settings.rate_limit_window
            self._limiter = SlidingWindowLimiter(limit or 100, window or 60)
        return self._limiter

    @staticmethod
    def client_key(scope: Scope) -> str:
        client = scope.get("client")
        return client[0] if client else "unknown"

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http" or scope.get("path", "") in self.EXEMPT_PATHS \
                or scope.get("method") == "OPTIONS":
            await self.app(scope, receive, send)
            return

        limiter = self.limiter
        allowed, remaining, reset = limiter.hit(self.client_key(scope))
        rate_headers = [
            (b"x-ratelimit-limit", str(limiter.limit).encode()),
            (b"x-ratelimit-remaining", str(remaining).encode()),
            (b"x-ratelimit-reset", str(reset).encode()),
        ]
        if not allowed:
            body = json.dumps({
                "error": "Rate limit exceeded",
                "status_code": 429,
                "retry_after_seconds": reset,
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": rate_headers + [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(reset).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        async def send_wrapper(message: Message):
            if message["type"] == "http.response.start":
                message["headers"] = _merge_headers(message.get("headers", []), rate_headers)
            await send(message)

        await self.app(scope, receive, send_wrapper)


class ResponseTimeRecorder:
    """Rolling window of API response times in milliseconds."""

    def __init__(self, maxlen: int = 1000):
        self._samples: Deque[Tuple[float, float, str, int]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self.total_requests = 0
        self.error_responses = 0

    def record(self, duration_ms: float, path: str, status: int) -> None:
        with self._lock:
            self._samples.append((time.time(), duration_ms, path, status))
            self.total_requests += 1
            if status >= 500:
                self.error_responses += 1

    def average_ms(self, last_n: Optional[int] = None) -> Optional[float]:
        with self._lock:
            samples = list(self._samples)[-last_n:] if last_n else list(self._samples)
        if not samples:
            return None
        return round(sum(s[1] for s in samples) / len(samples), 2)

    def percentile_ms(self, pct: float) -> Optional[float]:
        with self._lock:
            values = sorted(s[1] for s in self._samples)
        if not values:
            return None
        index = min(len(values) - 1, max(0, math.ceil(pct / 100 * len(values)) - 1))
        return round(values[index], 2)

    def snapshot(self) -> Dict[str, Optional[float]]:
        return {
            "samples": len(self._samples),
            "average_ms": self.average_ms(),
            "p50_ms": self.percentile_ms(50),
            "p95_ms": self.percentile_ms(95),
            "p99_ms": self.percentile_ms(99),
            "total_requests": self.total_requests,
            "server_errors": self.error_responses,
        }

    def reset(self) -> None:
        with self._lock:
            self._samples.clear()
            self.total_requests = 0
            self.error_responses = 0


response_times = ResponseTimeRecorder()


class RequestTimingMiddleware:
    """Records the latency of every /api/ request into ``response_times``."""

    def __init__(self, app: ASGIApp, recorder: ResponseTimeRecorder = response_times):
        self.app = app
        self.recorder = recorder

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status_holder = {"status": 500}

        async def send_wrapper(message: Message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                elapsed = (time.perf_counter() - start) * 1000
                message["headers"] = _merge_headers(
                    message.get("headers", []), [(b"server-timing", f"app;dur={elapsed:.1f}".encode())])
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            path = scope.get("path", "")
            if path.startswith("/api/"):
                self.recorder.record((time.perf_counter() - start) * 1000, path, status_holder["status"])
