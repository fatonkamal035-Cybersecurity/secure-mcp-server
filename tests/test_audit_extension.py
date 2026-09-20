import asyncio
import logging
from types import SimpleNamespace

import pytest

from core.audit_extension import AuditExtension


def test_audit_extension_success(caplog):
    async def run():
        async def call_next(ctx):
            return "ok"

        params = SimpleNamespace(
            name="kali_info",
            arguments={},
        )

        return await AuditExtension().intercept_tool_call(
            params,
            SimpleNamespace(),
            call_next,
        )

    with caplog.at_level(logging.INFO, logger="mcp.audit"):
        result = asyncio.run(run())

    assert result == "ok"
    assert any(
        "tool_call" in record.message
        and "tool=kali_info" in record.message
        for record in caplog.records
    )
    assert any(
        "tool_result" in record.message
        and "tool=kali_info" in record.message
        and "status=success" in record.message
        for record in caplog.records
    )


def test_audit_extension_error(caplog):
    async def run():
        async def call_next(ctx):
            raise RuntimeError("test failure")

        params = SimpleNamespace(
            name="kali_info",
            arguments={},
        )

        return await AuditExtension().intercept_tool_call(
            params,
            SimpleNamespace(),
            call_next,
        )

    with caplog.at_level(logging.INFO, logger="mcp.audit"):
        with pytest.raises(RuntimeError, match="test failure"):
            asyncio.run(run())

    error_records = [
        record
        for record in caplog.records
        if "tool_result" in record.message
        and "tool=kali_info" in record.message
        and "status=error" in record.message
    ]

    assert error_records
    assert error_records[0].exc_info is not None
