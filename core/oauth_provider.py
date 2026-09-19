from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import jwt

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    OAuthToken,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull

from config import (
    ACCESS_TOKEN_TTL_SECONDS,
    AUTHORIZATION_CODE_TTL_SECONDS,
    AUTHORIZATION_REQUEST_TTL_SECONDS,
    JWT_ALGORITHM,
    MCP_ISSUER,
    MCP_RESOURCE,
    OAUTH_DB_PATH,
    PRIVATE_KEY_PATH,
    PUBLIC_KEY_PATH,
    REFRESH_TOKEN_TTL_SECONDS,
)

ALLOWED_SCOPE = "mcp:read"
PUBLIC_CLIENT_AUTH_METHOD = "none"


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _now() -> int:
    return int(time.time())


class SQLiteOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """SQLite-backed OAuth provider for the local MCP server."""

    def __init__(
        self,
        db_path: Path | str = OAUTH_DB_PATH,
        private_key_path: Path | str = PRIVATE_KEY_PATH,
        public_key_path: Path | str = PUBLIC_KEY_PATH,
    ) -> None:
        self.db_path = Path(db_path)
        self.private_key_path = Path(private_key_path)
        self.public_key_path = Path(public_key_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _load_private_key(self) -> bytes:
        return self.private_key_path.read_bytes()

    def _load_public_key(self) -> bytes:
        return self.public_key_path.read_bytes()

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register only the public native client profile used by this project."""
        if client_info.token_endpoint_auth_method != PUBLIC_CLIENT_AUTH_METHOD:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description=(
                    "Only public clients with token_endpoint_auth_method "
                    "'none' are supported"
                ),
            )

        if client_info.application_type != "native":
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Only native application clients are supported",
            )

        if "authorization_code" not in client_info.grant_types:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="grant_types must include 'authorization_code'",
            )

        if "refresh_token" not in client_info.grant_types:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="grant_types must include 'refresh_token'",
            )

        if "code" not in client_info.response_types:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="response_types must include 'code'",
            )

        if not client_info.redirect_uris:
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="redirect_uris must contain at least one URI",
            )

        if client_info.scope:
            requested_scopes = set(client_info.scope.split())
            if not requested_scopes.issubset({ALLOWED_SCOPE}):
                raise RegistrationError(
                    error="invalid_client_metadata",
                    error_description="Only the 'mcp:read' scope is supported",
                )

        metadata = client_info.model_dump(mode="json")
        now = _now()

        with self._connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO oauth_clients (
                        client_id,
                        client_secret,
                        client_id_issued_at,
                        client_secret_expires_at,
                        client_name,
                        redirect_uris_json,
                        grant_types_json,
                        response_types_json,
                        scope,
                        token_endpoint_auth_method,
                        application_type,
                        metadata_json,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        client_info.client_id,
                        client_info.client_secret,
                        client_info.client_id_issued_at or now,
                        client_info.client_secret_expires_at,
                        client_info.client_name,
                        json.dumps(
                            [str(uri) for uri in client_info.redirect_uris]
                        ),
                        json.dumps(client_info.grant_types),
                        json.dumps(client_info.response_types),
                        client_info.scope or ALLOWED_SCOPE,
                        client_info.token_endpoint_auth_method,
                        client_info.application_type,
                        json.dumps(metadata),
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise RegistrationError(
                    error="invalid_client_metadata",
                    error_description="client_id is already registered",
                ) from exc

    async def get_client(
        self,
        client_id: str,
    ) -> OAuthClientInformationFull | None:
        """Retrieve a registered client."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT metadata_json
                FROM oauth_clients
                WHERE client_id = ?
                """,
                (client_id,),
            ).fetchone()

        if row is None:
            return None

        try:
            metadata = json.loads(row["metadata_json"])
            return OAuthClientInformationFull.model_validate(metadata)
        except (json.JSONDecodeError, TypeError, ValueError):
            return None

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        """Store a short-lived authorization request and redirect to local consent."""
        requested_resource = params.resource or MCP_RESOURCE

        if requested_resource != MCP_RESOURCE:
            raise AuthorizeError(
                error="invalid_target",
                error_description="Unsupported resource",
            )

        scopes = params.scopes or [ALLOWED_SCOPE]

        if not set(scopes).issubset({ALLOWED_SCOPE}):
            raise AuthorizeError(
                error="invalid_scope",
                error_description="Only the 'mcp:read' scope is supported",
            )

        request_id = secrets.token_urlsafe(32)
        now = _now()
        expires_at = now + AUTHORIZATION_REQUEST_TTL_SECONDS

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO authorization_requests (
                    request_id,
                    client_id,
                    state,
                    scopes,
                    code_challenge,
                    redirect_uri,
                    redirect_uri_provided_explicitly,
                    resource,
                    created_at,
                    expires_at,
                    completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    request_id,
                    client.client_id,
                    params.state,
                    " ".join(scopes),
                    params.code_challenge,
                    str(params.redirect_uri),
                    int(params.redirect_uri_provided_explicitly),
                    requested_resource,
                    now,
                    expires_at,
                ),
            )

        return (
            f"{MCP_ISSUER}/oauth/consent"
            f"?request_id={quote(request_id)}"
        )

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        """Load an unconsumed authorization code."""
        code_hash = _hash_token(authorization_code)
        now = _now()

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM authorization_codes
                WHERE code_hash = ?
                  AND client_id = ?
                  AND consumed_at IS NULL
                  AND expires_at >= ?
                """,
                (code_hash, client.client_id, now),
            ).fetchone()

        if row is None:
            return None

        try:
            return AuthorizationCode(
                code=authorization_code,
                scopes=row["scopes"].split(),
                expires_at=float(row["expires_at"]),
                client_id=row["client_id"],
                code_challenge=row["code_challenge"],
                redirect_uri=row["redirect_uri"],
                redirect_uri_provided_explicitly=bool(
                    row["redirect_uri_provided_explicitly"]
                ),
                resource=row["resource"],
                subject=row["subject"],
            )
        except (TypeError, ValueError):
            return None

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        """Consume an authorization code once and issue access/refresh tokens."""
        code_hash = _hash_token(authorization_code.code)
        now = _now()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")

            result = conn.execute(
                """
                UPDATE authorization_codes
                SET consumed_at = ?
                WHERE code_hash = ?
                  AND client_id = ?
                  AND consumed_at IS NULL
                  AND expires_at >= ?
                """,
                (now, code_hash, client.client_id, now),
            )

            if result.rowcount != 1:
                raise TokenError(
                    error="invalid_grant",
                    error_description=(
                        "authorization code is invalid or already consumed"
                    ),
                )

            return self._issue_token_pair(
                conn,
                client_id=client.client_id,
                scopes=authorization_code.scopes,
                subject=authorization_code.subject or client.client_id,
                resource=authorization_code.resource or MCP_RESOURCE,
                now=now,
            )

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        """Load a non-revoked, non-expired refresh token."""
        token_hash = _hash_token(refresh_token)
        now = _now()

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM refresh_tokens
                WHERE token_hash = ?
                  AND client_id = ?
                  AND revoked_at IS NULL
                  AND expires_at >= ?
                """,
                (token_hash, client.client_id, now),
            ).fetchone()

        if row is None:
            return None

        return RefreshToken(
            token=refresh_token,
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            expires_at=row["expires_at"],
            resource=row["resource"],
            subject=row["subject"],
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Rotate a refresh token and issue a fresh access token pair."""
        requested_scopes = scopes or refresh_token.scopes

        if not set(requested_scopes).issubset(set(refresh_token.scopes)):
            raise TokenError(
                error="invalid_scope",
                error_description=(
                    "Requested scope exceeds the originally granted scope"
                ),
            )

        old_hash = _hash_token(refresh_token.token)
        now = _now()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")

            result = conn.execute(
                """
                UPDATE refresh_tokens
                SET revoked_at = ?
                WHERE token_hash = ?
                  AND client_id = ?
                  AND revoked_at IS NULL
                  AND expires_at >= ?
                """,
                (now, old_hash, client.client_id, now),
            )

            if result.rowcount != 1:
                raise TokenError(
                    error="invalid_grant",
                    error_description="refresh token is invalid or revoked",
                )

            return self._issue_token_pair(
                conn,
                client_id=client.client_id,
                scopes=requested_scopes,
                subject=refresh_token.subject or client.client_id,
                resource=refresh_token.resource or MCP_RESOURCE,
                now=now,
            )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Verify an Ed25519 JWT and enforce server-side revocation."""
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                self._load_public_key(),
                algorithms=[JWT_ALGORITHM],
                audience=MCP_RESOURCE,
                issuer=MCP_ISSUER,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "exp",
                        "iat",
                        "jti",
                        "client_id",
                        "scope",
                    ]
                },
            )
        except (
            jwt.InvalidTokenError,
            OSError,
            ValueError,
            TypeError,
        ):
            return None

        jti = payload.get("jti")
        subject = payload.get("sub")
        client_id = payload.get("client_id")
        scope = payload.get("scope")
        expires_at = payload.get("exp")

        if not all(
            isinstance(value, str) and value
            for value in (jti, subject, client_id, scope)
        ):
            return None

        if not isinstance(expires_at, (int, float)):
            return None

        token_hash = _hash_token(token)
        now = _now()

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT *
                FROM access_tokens
                WHERE token_hash = ?
                  AND jti = ?
                  AND revoked_at IS NULL
                  AND expires_at >= ?
                """,
                (token_hash, jti, now),
            ).fetchone()

        if row is None:
            return None

        if row["client_id"] != client_id:
            return None

        if row["subject"] != subject:
            return None

        if row["scopes"] != scope:
            return None

        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scope.split(),
            expires_at=int(expires_at),
            resource=row["resource"] or MCP_RESOURCE,
            subject=subject,
            claims=payload,
        )

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        """Revoke an access/refresh token and its linked pair."""
        token_hash = _hash_token(token.token)
        now = _now()

        with self._connect() as conn:
            access_row = conn.execute(
                """
                SELECT refresh_token_hash
                FROM access_tokens
                WHERE token_hash = ?
                """,
                (token_hash,),
            ).fetchone()

            if access_row is not None:
                refresh_hash = access_row["refresh_token_hash"]

                conn.execute(
                    """
                    UPDATE access_tokens
                    SET revoked_at = COALESCE(revoked_at, ?)
                    WHERE token_hash = ?
                    """,
                    (now, token_hash),
                )

                if refresh_hash:
                    conn.execute(
                        """
                        UPDATE refresh_tokens
                        SET revoked_at = COALESCE(revoked_at, ?)
                        WHERE token_hash = ?
                        """,
                        (now, refresh_hash),
                    )
                return

            refresh_row = conn.execute(
                """
                SELECT token_hash
                FROM refresh_tokens
                WHERE token_hash = ?
                """,
                (token_hash,),
            ).fetchone()

            if refresh_row is not None:
                conn.execute(
                    """
                    UPDATE refresh_tokens
                    SET revoked_at = COALESCE(revoked_at, ?)
                    WHERE token_hash = ?
                    """,
                    (now, token_hash),
                )

                conn.execute(
                    """
                    UPDATE access_tokens
                    SET revoked_at = COALESCE(revoked_at, ?)
                    WHERE refresh_token_hash = ?
                    """,
                    (now, token_hash),
                )

    def _issue_token_pair(
        self,
        conn: sqlite3.Connection,
        *,
        client_id: str,
        scopes: list[str],
        subject: str,
        resource: str,
        now: int,
    ) -> OAuthToken:
        """Issue one short-lived JWT and one opaque refresh token."""
        if resource != MCP_RESOURCE:
            raise TokenError(
                error="invalid_target",
                error_description="Unsupported resource",
            )

        access_expires_at = now + ACCESS_TOKEN_TTL_SECONDS
        refresh_expires_at = now + REFRESH_TOKEN_TTL_SECONDS

        access_jti = secrets.token_urlsafe(24)
        access_token = jwt.encode(
            {
                "iss": MCP_ISSUER,
                "aud": MCP_RESOURCE,
                "sub": subject,
                "client_id": client_id,
                "scope": " ".join(scopes),
                "jti": access_jti,
                "iat": now,
                "exp": access_expires_at,
            },
            self._load_private_key(),
            algorithm=JWT_ALGORITHM,
        )

        refresh_token = secrets.token_urlsafe(32)

        access_hash = _hash_token(access_token)
        refresh_hash = _hash_token(refresh_token)

        conn.execute(
            """
            INSERT INTO refresh_tokens (
                token_hash,
                client_id,
                scopes,
                expires_at,
                resource,
                subject,
                issued_at,
                revoked_at,
                replaced_by_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            """,
            (
                refresh_hash,
                client_id,
                " ".join(scopes),
                refresh_expires_at,
                resource,
                subject,
                now,
            ),
        )

        conn.execute(
            """
            INSERT INTO access_tokens (
                token_hash,
                client_id,
                scopes,
                expires_at,
                resource,
                subject,
                jti,
                refresh_token_hash,
                issued_at,
                revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                access_hash,
                client_id,
                " ".join(scopes),
                access_expires_at,
                resource,
                subject,
                access_jti,
                refresh_hash,
                now,
            ),
        )

        return OAuthToken(
            access_token=access_token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            scope=" ".join(scopes),
            refresh_token=refresh_token,
        )

    async def complete_authorization(
        self,
        request_id: str,
        approved: bool,
    ) -> str:
        """Complete a pending request and redirect the client."""
        now = _now()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")

            row = conn.execute(
                """
                SELECT *
                FROM authorization_requests
                WHERE request_id = ?
                  AND completed_at IS NULL
                  AND expires_at >= ?
                """,
                (request_id, now),
            ).fetchone()

            if row is None:
                raise ValueError(
                    "authorization request is invalid or expired"
                )

            conn.execute(
                """
                UPDATE authorization_requests
                SET completed_at = ?
                WHERE request_id = ?
                  AND completed_at IS NULL
                """,
                (now, request_id),
            )

            if not approved:
                return construct_redirect_uri(
                    row["redirect_uri"],
                    error="access_denied",
                    state=row["state"],
                )

            code = secrets.token_urlsafe(32)
            code_hash = _hash_token(code)
            code_expires_at = now + AUTHORIZATION_CODE_TTL_SECONDS

            conn.execute(
                """
                INSERT INTO authorization_codes (
                    code_hash,
                    client_id,
                    scopes,
                    expires_at,
                    code_challenge,
                    code_challenge_method,
                    redirect_uri,
                    redirect_uri_provided_explicitly,
                    resource,
                    subject,
                    consumed_at,
                    created_at
                ) VALUES (
                    ?, ?, ?, ?, ?, 'S256', ?, ?, ?, ?, NULL, ?
                )
                """,
                (
                    code_hash,
                    row["client_id"],
                    row["scopes"],
                    code_expires_at,
                    row["code_challenge"],
                    row["redirect_uri"],
                    row["redirect_uri_provided_explicitly"],
                    row["resource"] or MCP_RESOURCE,
                    row["client_id"],
                    now,
                ),
            )

            return construct_redirect_uri(
                row["redirect_uri"],
                code=code,
                state=row["state"],
            )
