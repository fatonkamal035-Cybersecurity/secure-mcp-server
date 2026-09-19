from __future__ import annotations

from html import escape
from urllib.parse import quote

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from core.oauth_provider import SQLiteOAuthProvider


def create_oauth_consent_route(provider: SQLiteOAuthProvider):
    async def consent(request: Request):
        request_id = request.query_params.get("request_id")

        if not request_id:
            return HTMLResponse(
                "<h1>Bad Request</h1><p>request_id diperlukan.</p>",
                status_code=400,
            )

        safe_request_id = escape(request_id)
        decision_url = "/oauth/consent/decision?request_id=" + quote(
            request_id,
            safe="",
        )

        html = f"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>MCP Authorization</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h1>MCP Authorization Request</h1>
    <p>An MCP client is requesting access to this server.</p>

    <p><strong>Requested scope:</strong> mcp:read</p>

    <p>
        <a href="{decision_url}&approved=true">
            Allow access
        </a>
    </p>

    <p>
        <a href="{decision_url}&approved=false">
            Deny access
        </a>
    </p>

    <p><small>Request ID: {safe_request_id}</small></p>
</body>
</html>
"""
        return HTMLResponse(html, status_code=200)

    async def decision(request: Request):
        request_id = request.query_params.get("request_id")
        approved_raw = request.query_params.get("approved")

        if not request_id or approved_raw not in {"true", "false"}:
            return HTMLResponse(
                "<h1>Bad Request</h1>",
                status_code=400,
            )

        try:
            redirect_url = await provider.complete_authorization(
                request_id,
                approved=(approved_raw == "true"),
            )
        except ValueError:
            return HTMLResponse(
                "<h1>Authorization Request Invalid or Expired</h1>",
                status_code=400,
            )

        return RedirectResponse(
            redirect_url,
            status_code=302,
        )

    return consent, decision
