from config import MCP_RESOURCE
import asyncio
import shutil
from pathlib import Path

import pytest
from mcp.shared.auth import OAuthClientInformationFull

from core.oauth_provider import SQLiteOAuthProvider


def make_test_db(tmp_path: Path) -> Path:
    source = Path("data/oauth.db")
    target = tmp_path / "oauth.db"
    shutil.copy2(source, target)
    return target


def test_register_and_get_public_client(tmp_path):
    db_path = make_test_db(tmp_path)

    provider = SQLiteOAuthProvider(db_path=db_path)

    client = OAuthClientInformationFull(
        client_id="test-termux",
        client_secret=None,
        client_id_issued_at=0,
        client_secret_expires_at=None,
        client_name="Termux MCP Test",
        redirect_uris=["http://127.0.0.1:8765/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="mcp:read",
        token_endpoint_auth_method="none",
        application_type="native",
    )

    async def run_test():
        await provider.register_client(client)
        return await provider.get_client("test-termux")

    loaded = asyncio.run(run_test())

    assert loaded is not None
    assert loaded.client_id == "test-termux"
    assert loaded.client_secret is None
    assert loaded.token_endpoint_auth_method == "none"
    assert loaded.application_type == "native"
    assert loaded.scope == "mcp:read"

def test_authorize_creates_pending_request(tmp_path):
    import asyncio
    import sqlite3

    db_path = make_test_db(tmp_path)
    provider = SQLiteOAuthProvider(db_path=db_path)

    client = OAuthClientInformationFull(
        client_id="test-termux-auth",
        client_secret=None,
        client_id_issued_at=0,
        client_secret_expires_at=None,
        client_name="Termux OAuth Test",
        redirect_uris=["http://127.0.0.1:8765/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="mcp:read",
        token_endpoint_auth_method="none",
        application_type="native",
    )

    async def run_test():
        await provider.register_client(client)

        from mcp.server.auth.provider import AuthorizationParams

        params = AuthorizationParams(
            state="test-state",
            scopes=["mcp:read"],
            code_challenge="test-code-challenge",
            redirect_uri="http://127.0.0.1:8765/callback",
            redirect_uri_provided_explicitly=True,
            resource=MCP_RESOURCE,
        )

        return await provider.authorize(client, params)

    consent_url = asyncio.run(run_test())

    assert "/oauth/consent?request_id=" in consent_url

    request_id = consent_url.split("request_id=", 1)[1]

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT client_id, state, scopes, code_challenge,
                   redirect_uri, completed_at
            FROM authorization_requests
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()

    assert row is not None
    assert row[0] == "test-termux-auth"
    assert row[1] == "test-state"
    assert row[2] == "mcp:read"
    assert row[3] == "test-code-challenge"
    assert row[4] == "http://127.0.0.1:8765/callback"
    assert row[5] is None

def test_authorization_code_is_single_use(tmp_path):
    import asyncio
    from urllib.parse import parse_qs, urlparse

    db_path = make_test_db(tmp_path)
    provider = SQLiteOAuthProvider(db_path=db_path)

    client = OAuthClientInformationFull(
        client_id="test-code-client",
        client_secret=None,
        client_id_issued_at=0,
        client_secret_expires_at=None,
        client_name="Termux Code Test",
        redirect_uris=["http://127.0.0.1:8765/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="mcp:read",
        token_endpoint_auth_method="none",
        application_type="native",
    )

    async def run_test():
        await provider.register_client(client)

        from mcp.server.auth.provider import AuthorizationParams

        params = AuthorizationParams(
            state="single-use-state",
            scopes=["mcp:read"],
            code_challenge="test-code-challenge",
            redirect_uri="http://127.0.0.1:8765/callback",
            redirect_uri_provided_explicitly=True,
            resource=MCP_RESOURCE,
        )

        consent_url = await provider.authorize(client, params)
        request_id = parse_qs(
            urlparse(consent_url).query
        )["request_id"][0]

        redirect_url = await provider.complete_authorization(
            request_id,
            approved=True,
        )

        query = parse_qs(urlparse(redirect_url).query)
        code = query["code"][0]

        authorization_code = await provider.load_authorization_code(
            client,
            code,
        )

        assert authorization_code is not None

        token = await provider.exchange_authorization_code(
            client,
            authorization_code,
        )

        assert token.access_token
        assert token.refresh_token
        assert token.token_type.lower() == "bearer"
        assert token.scope == "mcp:read"

        replay = await provider.load_authorization_code(client, code)
        assert replay is None

    asyncio.run(run_test())

def test_access_token_and_refresh_rotation(tmp_path):
    import asyncio

    db_path = make_test_db(tmp_path)
    provider = SQLiteOAuthProvider(db_path=db_path)

    client = OAuthClientInformationFull(
        client_id="test-refresh-client",
        client_secret=None,
        client_id_issued_at=0,
        client_secret_expires_at=None,
        client_name="Termux Refresh Test",
        redirect_uris=["http://127.0.0.1:8765/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="mcp:read",
        token_endpoint_auth_method="none",
        application_type="native",
    )

    async def run_test():
        await provider.register_client(client)

        from mcp.server.auth.provider import AuthorizationParams

        params = AuthorizationParams(
            state="refresh-state",
            scopes=["mcp:read"],
            code_challenge="test-code-challenge",
            redirect_uri="http://127.0.0.1:8765/callback",
            redirect_uri_provided_explicitly=True,
            resource=MCP_RESOURCE,
        )

        consent_url = await provider.authorize(client, params)

        from urllib.parse import parse_qs, urlparse

        request_id = parse_qs(
            urlparse(consent_url).query
        )["request_id"][0]

        redirect_url = await provider.complete_authorization(
            request_id,
            approved=True,
        )

        code = parse_qs(
            urlparse(redirect_url).query
        )["code"][0]

        authorization_code = await provider.load_authorization_code(
            client,
            code,
        )

        assert authorization_code is not None

        first_token = await provider.exchange_authorization_code(
            client,
            authorization_code,
        )

        loaded_access = await provider.load_access_token(
            first_token.access_token
        )

        assert loaded_access is not None
        assert loaded_access.client_id == "test-refresh-client"
        assert loaded_access.subject == "test-refresh-client"
        assert loaded_access.scopes == ["mcp:read"]

        loaded_refresh = await provider.load_refresh_token(
            client,
            first_token.refresh_token,
        )

        assert loaded_refresh is not None

        second_token = await provider.exchange_refresh_token(
            client,
            loaded_refresh,
            ["mcp:read"],
        )

        assert second_token.access_token != first_token.access_token
        assert second_token.refresh_token != first_token.refresh_token

        old_refresh = await provider.load_refresh_token(
            client,
            first_token.refresh_token,
        )

        assert old_refresh is None

        new_refresh = await provider.load_refresh_token(
            client,
            second_token.refresh_token,
        )

        assert new_refresh is not None

        second_access = await provider.load_access_token(
            second_token.access_token
        )

        assert second_access is not None

    asyncio.run(run_test())

def test_token_revocation_invalidates_token_pair(tmp_path):
    import asyncio
    from urllib.parse import parse_qs, urlparse

    db_path = make_test_db(tmp_path)
    provider = SQLiteOAuthProvider(db_path=db_path)

    client = OAuthClientInformationFull(
        client_id="test-revoke-client",
        client_secret=None,
        client_id_issued_at=0,
        client_secret_expires_at=None,
        client_name="Termux Revoke Test",
        redirect_uris=["http://127.0.0.1:8765/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="mcp:read",
        token_endpoint_auth_method="none",
        application_type="native",
    )

    async def run_test():
        await provider.register_client(client)

        from mcp.server.auth.provider import AuthorizationParams

        params = AuthorizationParams(
            state="revoke-state",
            scopes=["mcp:read"],
            code_challenge="test-code-challenge",
            redirect_uri="http://127.0.0.1:8765/callback",
            redirect_uri_provided_explicitly=True,
            resource=MCP_RESOURCE,
        )

        consent_url = await provider.authorize(client, params)

        request_id = parse_qs(
            urlparse(consent_url).query
        )["request_id"][0]

        redirect_url = await provider.complete_authorization(
            request_id,
            approved=True,
        )

        code = parse_qs(
            urlparse(redirect_url).query
        )["code"][0]

        authorization_code = await provider.load_authorization_code(
            client,
            code,
        )

        assert authorization_code is not None

        token = await provider.exchange_authorization_code(
            client,
            authorization_code,
        )

        assert await provider.load_access_token(
            token.access_token
        ) is not None

        assert await provider.load_refresh_token(
            client,
            token.refresh_token
        ) is not None

        loaded_access = await provider.load_access_token(
            token.access_token
        )

        assert loaded_access is not None

        await provider.revoke_token(loaded_access)

        assert await provider.load_access_token(
            token.access_token
        ) is None

        assert await provider.load_refresh_token(
            client,
            token.refresh_token
        ) is None

    asyncio.run(run_test())
