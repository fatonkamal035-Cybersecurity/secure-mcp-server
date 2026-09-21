from __future__ import annotations

from math import ceil
from time import monotonic
from typing import Callable, Iterable

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send


class RateLimitMiddleware:
    """Fixed-window, in-memory rate limiter for selected HTTP paths."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        paths: Iterable[str],
        limit: int = 10,
        window_seconds: float = 60.0,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        if limit <= 0:
            raise ValueError("limit must be greater than zero")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.app = app
        self.paths = frozenset(paths)
        self.limit = limit
        self.window_seconds = float(window_seconds)
        self.clock = clock
        self._buckets: dict[tuple[str, str], tuple[int, int]] = {}

    @staticmethod
    def _client_host(scope: Scope) -> str:
        client = scope.get("client")
        if client is None:
            return "unknown"
        return str(client[0])

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") == "OPTIONS"
            or scope.get("path") not in self.paths
        ):
            await self.app(scope, receive, send)
            return

        now = self.clock()
        window_index = int(now // self.window_seconds)
        key = (scope["path"], self._client_host(scope))

        current = self._buckets.get(key)
        if current is None or current[0] != window_index:
            self._buckets[key] = (window_index, 1)
            await self.app(scope, receive, send)
            return

        count = current[1]
        if count >= self.limit:
            window_end = (window_index + 1) * self.window_seconds
            retry_after = max(1, ceil(window_end - now))

            response = JSONResponse(
                {
                    "error": "rate_limit_exceeded",
                    "error_description": "Too many requests",
                },
                status_code=429,
                headers={
                    "Cache-Control": "no-store",
                    "Retry-After": str(retry_after),
                },
            )
            await response(scope, receive, send)
            return

        self._buckets[key] = (window_index, count + 1)
        await self.app(scope, receive, send)
