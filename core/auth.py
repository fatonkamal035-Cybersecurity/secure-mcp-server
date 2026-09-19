from typing import Any

import jwt

from mcp.server.auth.provider import AccessToken

from config import (
    JWT_ALGORITHM,
    MCP_ISSUER,
    MCP_RESOURCE,
    PUBLIC_KEY_PATH,
)


class JWTTokenVerifier:
    """Memverifikasi bearer token JWT untuk MCP Server."""

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            public_key = PUBLIC_KEY_PATH.read_bytes()

            payload: dict[str, Any] = jwt.decode(
                token,
                public_key,
                algorithms=[JWT_ALGORITHM],
                audience=MCP_RESOURCE,
                issuer=MCP_ISSUER,
            )

            subject = payload.get("sub")
            client_id = payload.get("client_id", subject)
            scope = payload.get("scope", "")

            if not isinstance(subject, str) or not subject:
                return None

            if not isinstance(client_id, str) or not client_id:
                return None

            scopes = scope.split() if isinstance(scope, str) else []

            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=scopes,
                expires_at=payload.get("exp"),
                resource=MCP_RESOURCE,
                subject=subject,
                claims=payload,
            )

        except (jwt.InvalidTokenError, OSError, ValueError, TypeError):
            return None
