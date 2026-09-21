import asyncio

from core.rate_limit import RateLimitMiddleware


class FakeClock:
    def __init__(self, value: float = 0.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_scope(path: str, *, method: str = "POST", host: str = "192.168.1.138") -> dict:
    return {
        "type": "http",
        "method": method,
        "path": path,
        "scheme": "https",
        "query_string": b"",
        "headers": [],
        "client": (host, 12345),
        "server": ("192.168.1.7", 8000),
    }


async def call_middleware(middleware, scope):
    messages = []

    async def receive():
        return {
            "type": "http.request",
            "body": b"",
            "more_body": False,
        }

    async def send(message):
        messages.append(message)

    await middleware(scope, receive, send)

    status = next(
        message["status"]
        for message in messages
        if message["type"] == "http.response.start"
    )
    response_start = next(
        message
        for message in messages
        if message["type"] == "http.response.start"
    )
    headers = dict(response_start["headers"])

    return status, headers, messages


async def noop_app(scope, receive, send):
    await send(
        {
            "type": "http.response.start",
            "status": 204,
            "headers": [],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b"",
            "more_body": False,
        }
    )


def test_rate_limit_blocks_request_11():
    clock = FakeClock()
    middleware = RateLimitMiddleware(
        noop_app,
        paths={"/authorize"},
        limit=10,
        window_seconds=60,
        clock=clock,
    )
    scope = make_scope("/authorize", method="GET")

    async def run():
        for _ in range(10):
            status, _, _ = await call_middleware(middleware, scope)
            assert status == 204

        status, headers, messages = await call_middleware(middleware, scope)
        assert status == 429
        assert headers[b"retry-after"] == str(60).encode()
        assert headers[b"cache-control"] == b"no-store"
        body = next(
            message["body"]
            for message in messages
            if message["type"] == "http.response.body"
        )
        assert b"rate_limit_exceeded" in body
        assert b"Too many requests" in body

    asyncio.run(run())


def test_rate_limit_resets_after_window():
    clock = FakeClock()
    middleware = RateLimitMiddleware(
        noop_app,
        paths={"/token"},
        limit=10,
        window_seconds=60,
        clock=clock,
    )
    scope = make_scope("/token")

    async def run():
        for _ in range(10):
            status, _, _ = await call_middleware(middleware, scope)
            assert status == 204

        status, _, _ = await call_middleware(middleware, scope)
        assert status == 429

        clock.advance(60)

        status, _, _ = await call_middleware(middleware, scope)
        assert status == 204

    asyncio.run(run())


def test_rate_limit_ignores_non_target_paths_and_options():
    clock = FakeClock()
    middleware = RateLimitMiddleware(
        noop_app,
        paths={"/authorize"},
        limit=1,
        window_seconds=60,
        clock=clock,
    )

    async def run():
        other_scope = make_scope("/mcp")
        first_status, _, _ = await call_middleware(middleware, other_scope)
        second_status, _, _ = await call_middleware(middleware, other_scope)
        assert first_status == 204
        assert second_status == 204

        options_scope = make_scope("/authorize", method="OPTIONS")
        first_status, _, _ = await call_middleware(middleware, options_scope)
        second_status, _, _ = await call_middleware(middleware, options_scope)
        assert first_status == 204
        assert second_status == 204

        get_scope = make_scope("/authorize", method="GET")
        first_status, _, _ = await call_middleware(middleware, get_scope)
        second_status, _, _ = await call_middleware(middleware, get_scope)
        assert first_status == 204
        assert second_status == 429

    asyncio.run(run())
