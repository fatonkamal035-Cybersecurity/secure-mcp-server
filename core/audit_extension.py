import logging
from datetime import datetime, timezone

from mcp.server.context import ServerRequestContext
from mcp.server.extension import Extension

from core.audit_sanitizer import sanitize_arguments


logger = logging.getLogger("mcp.audit")


class AuditExtension(Extension):
    identifier = "zerkoth/mcp-audit"

    async def intercept_tool_call(
        self,
        params,
        ctx: ServerRequestContext,
        call_next,
    ):
        timestamp = datetime.now(timezone.utc).isoformat()

        logger.info(
            "tool_call time=%s tool=%s arguments=%r",
            timestamp,
            params.name,
            sanitize_arguments(params.arguments or {}),
        )

        try:
            result = await call_next(ctx)

            logger.info(
                "tool_result time=%s tool=%s status=success",
                timestamp,
                params.name,
            )

            return result

        except Exception:
            logger.exception(
                "tool_result time=%s tool=%s status=error",
                timestamp,
                params.name,
            )
            raise
