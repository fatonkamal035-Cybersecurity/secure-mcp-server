import asyncio
import base64
import hashlib
import json
import secrets
import sqlite3
import ssl
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx2

from config import OAUTH_DB_PATH


BASE_URL = "https://192.168.1.7:8000"
CERT_PATH = Path("secrets/tls/mcp-server.crt")


def cleanup_oauth_data(client_id: str) -> None:
    tables = (
        "authorization_requests",
        "authorization_codes",
        "access_tokens",
        "refresh_tokens",
        "oauth_clients",
    )

    with sqlite3.connect(OAUTH_DB_PATH) as con:
        with con:
            for table in tables:
                con.execute(
                    f"DELETE FROM {table} WHERE client_id = ?",
                    (client_id,),
                )

        remaining = 0
        for table in tables:
            remaining += con.execute(
                f"SELECT COUNT(*) FROM {table} WHERE client_id = ?",
                (client_id,),
            ).fetchone()[0]

    if remaining != 0:
        raise AssertionError(
            f"OAuth cleanup gagal untuk client_id={client_id}"
        )


def pkce_pair():
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def sse_json(response):
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    raise AssertionError("SSE data tidak ditemukan")


async def integration_flow():
    client_id = None
    try:
        verifier, challenge = pkce_pair()
        redirect_uri = "http://127.0.0.1:8765/callback"
        state = secrets.token_urlsafe(16)

        ssl_context = ssl.create_default_context(cafile=str(CERT_PATH))

        async with httpx2.AsyncClient(
            verify=ssl_context,
            follow_redirects=False,
            timeout=15.0,
        ) as client:

            # OAuth Authorization Server Discovery
            response = await client.get(
                f"{BASE_URL}/.well-known/oauth-authorization-server"
            )
            assert response.status_code == 200
            discovery = response.json()
            assert discovery["issuer"] == BASE_URL
            assert discovery["token_endpoint"] == f"{BASE_URL}/token"
            assert discovery["authorization_endpoint"] == f"{BASE_URL}/authorize"
            assert discovery["registration_endpoint"] == f"{BASE_URL}/register"
            assert discovery["scopes_supported"] == ["mcp:read"]
            assert discovery["response_types_supported"] == ["code"]
            assert discovery["grant_types_supported"] == ["authorization_code", "refresh_token"]
            assert set(discovery["token_endpoint_auth_methods_supported"]) == {"client_secret_post", "client_secret_basic"}
            assert discovery["revocation_endpoint"] == f"{BASE_URL}/revoke"
            assert set(discovery["revocation_endpoint_auth_methods_supported"]) == {"client_secret_post", "client_secret_basic"}
            assert discovery["code_challenge_methods_supported"] == ["S256"]

            # Protected Resource Metadata
            response = await client.get(
                f"{BASE_URL}/.well-known/oauth-protected-resource/mcp"
            )
            assert response.status_code == 200
            metadata = response.json()
            assert metadata["resource"] == f"{BASE_URL}/mcp"
            assert metadata["authorization_servers"] == [BASE_URL]
            assert metadata["scopes_supported"] == ["mcp:read"]
            assert metadata["bearer_methods_supported"] == ["header"]

            # Dynamic Client Registration
            response = await client.post(
                f"{BASE_URL}/register",
                json={
                    "client_name": "pytest-integration",
                    "application_type": "native",
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                    "redirect_uris": [redirect_uri],
                    "scope": "mcp:read",
                },
            )
            assert response.status_code == 201
            registration = response.json()
            client_id = registration["client_id"]
            assert registration["client_name"] == "pytest-integration"
            assert registration["application_type"] == "native"
            assert registration["token_endpoint_auth_method"] == "none"
            assert registration["grant_types"] == ["authorization_code", "refresh_token"]
            assert registration["response_types"] == ["code"]
            assert registration["redirect_uris"] == [redirect_uri]
            assert registration["scope"] == "mcp:read"
            assert isinstance(registration["client_id"], str)
            assert registration["client_id"]
            assert isinstance(registration["client_id_issued_at"], int)

            # Authorization
            response = await client.get(
                f"{BASE_URL}/authorize",
                params={
                    "client_id": client_id,
                    "response_type": "code",
                    "redirect_uri": redirect_uri,
                    "scope": "mcp:read",
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "resource": f"{BASE_URL}/mcp",
                },
            )
            assert response.status_code == 302
            consent_url = response.headers["location"]
            consent_location = urlparse(consent_url)
            assert consent_location.scheme == "https"
            assert consent_location.netloc == urlparse(BASE_URL).netloc
            assert consent_location.path == "/oauth/consent"
            consent_query = parse_qs(consent_location.query)
            assert set(consent_query) == {"request_id"}
            assert len(consent_query["request_id"]) == 1
            assert consent_query["request_id"][0]

            # Consent page
            response = await client.get(consent_url)
            assert response.status_code == 200
            assert "mcp:read" in response.text
            assert "MCP Authorization Request" in response.text
            assert f"Request ID: {consent_query["request_id"][0]}" in response.text
            assert "approved=true" in response.text
            assert "approved=false" in response.text

            # Approve consent
            response = await client.get(
                f"{BASE_URL}/oauth/consent/decision",
                params={
                    "request_id": parse_qs(urlparse(consent_url).query)["request_id"][0],
                    "approved": "true",
                },
            )
            assert response.status_code == 302

            callback = urlparse(response.headers["location"])
            callback_query = parse_qs(callback.query)
            assert callback_query["state"][0] == state
            code = callback_query["code"][0]

            # PKCE dengan verifier yang salah harus ditolak
            response = await client.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": secrets.token_urlsafe(32),
                    "resource": f"{BASE_URL}/mcp",
                },
            )
            assert response.status_code == 400
            error_data = response.json()
            assert error_data["error"] == "invalid_grant"
            assert error_data["error_description"] == "incorrect code_verifier"

            # Token exchange
            response = await client.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                    "resource": f"{BASE_URL}/mcp",
                },
            )
            assert response.status_code == 200
            token_data = response.json()
            access_token = token_data["access_token"]
            assert isinstance(token_data["access_token"], str)
            assert token_data["access_token"]
            assert isinstance(token_data["expires_in"], int)
            assert token_data["expires_in"] > 0

            assert token_data["token_type"] == "Bearer"
            assert token_data["scope"] == "mcp:read"
            assert token_data["refresh_token"]
            refresh_token = token_data["refresh_token"]

            # Refresh token rotation
            response = await client.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                    "resource": f"{BASE_URL}/mcp",
                },
            )
            assert response.status_code == 200
            rotated_token_data = response.json()
            assert rotated_token_data["token_type"] == "Bearer"
            assert rotated_token_data["scope"] == "mcp:read"
            assert isinstance(rotated_token_data["access_token"], str)
            assert rotated_token_data["access_token"]
            assert isinstance(rotated_token_data["expires_in"], int)
            assert rotated_token_data["expires_in"] > 0
            assert isinstance(rotated_token_data["refresh_token"], str)
            assert rotated_token_data["refresh_token"]
            assert rotated_token_data["access_token"] != access_token
            assert rotated_token_data["refresh_token"] != refresh_token

            # Refresh token lama tidak boleh digunakan kembali
            response = await client.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                    "resource": f"{BASE_URL}/mcp",
                },
            )
            assert response.status_code == 400
            old_refresh_error = response.json()
            assert old_refresh_error["error"] == "invalid_grant"
            assert old_refresh_error["error_description"] == "refresh token does not exist"

            access_token = rotated_token_data["access_token"]
            refresh_token = rotated_token_data["refresh_token"]

            # Authorization code hanya boleh digunakan sekali
            response = await client.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": client_id,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                    "resource": f"{BASE_URL}/mcp",
                },
            )
            assert response.status_code == 400
            replay_error = response.json()
            assert replay_error["error"] == "invalid_grant"
            assert replay_error["error_description"] == "authorization code does not exist"

            # /mcp tanpa token harus ditolak
            response = await client.post(
                f"{BASE_URL}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "pytest-integration",
                            "version": "1.0",
                        },
                    },
                },
            )
            assert response.status_code == 401

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }

            # MCP initialize dengan token
            response = await client.post(
                f"{BASE_URL}/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {
                            "name": "pytest-integration",
                            "version": "1.0",
                        },
                    },
                },
            )
            assert response.status_code == 200
            session_id = response.headers.get("mcp-session-id")
            assert session_id
            initialize = sse_json(response)
            assert initialize["result"]["serverInfo"]["name"] == "KaliServer"
            assert "tools" in initialize["result"]["capabilities"]

            session_headers = {
                **headers,
                "Mcp-Session-Id": session_id,
            }

            # MCP initialized notification
            response = await client.post(
                f"{BASE_URL}/mcp",
                headers=session_headers,
                json={
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
            )
            assert response.status_code == 202

            # tools/list
            response = await client.post(
                f"{BASE_URL}/mcp",
                headers=session_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
            )
            assert response.status_code == 200
            tools_result = sse_json(response)["result"]["tools"]
            tool_names = {tool["name"] for tool in tools_result}

            assert tool_names == {
                "kali_info",
                "system_status",
                "disk_status",
                "memory_status",
                "network_status",
                "network_interfaces",
                "read_text_file",
            }

            # Snapshot audit log before authenticated tools/call
            audit_log_path = Path("logs/audit.log")
            audit_log_offset = audit_log_path.stat().st_size

            # tools/call
            response = await client.post(
                f"{BASE_URL}/mcp",
                headers=session_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "kali_info",
                        "arguments": {},
                    },
                },
            )
            assert response.status_code == 200
            call_result = sse_json(response)["result"]
            assert call_result["isError"] is False
            assert call_result["structuredContent"]["result"] == "Kali MCP Server aktif."

            # Auth credentials must not appear in newly written audit log entries
            with audit_log_path.open("rb") as audit_log:
                audit_log.seek(audit_log_offset)
                new_audit_log = audit_log.read().decode("utf-8", errors="replace")

            assert access_token not in new_audit_log
            assert f"Bearer {access_token}" not in new_audit_log

            # OAuth token revocation
            response = await client.post(
                f"{BASE_URL}/revoke",
                data={
                    "token": access_token,
                    "token_type_hint": "access_token",
                    "client_id": client_id,
                    "client_secret": "",
                },
            )
            assert response.status_code == 200
            assert response.text == ""
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["pragma"] == "no-cache"

            # Refresh token terkait access token yang direvoke harus ikut ditolak
            response = await client.post(
                f"{BASE_URL}/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "refresh_token": refresh_token,
                    "resource": f"{BASE_URL}/mcp",
                },
            )
            assert response.status_code == 400
            revoked_refresh_error = response.json()
            assert revoked_refresh_error["error"] == "invalid_grant"
            assert revoked_refresh_error["error_description"] == "refresh token does not exist"

            # Revoke token yang tidak dikenal harus tetap berhasil tanpa body
            response = await client.post(
                f"{BASE_URL}/revoke",
                data={
                    "token": "definitely-not-a-real-token",
                    "token_type_hint": "access_token",
                    "client_id": client_id,
                    "client_secret": "",
                },
            )
            assert response.status_code == 200
            assert response.text == ""
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["pragma"] == "no-cache"

            # Revoked access token must no longer access MCP
            response = await client.post(
                f"{BASE_URL}/mcp",
                headers=session_headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/list",
                    "params": {},
                },
            )
            assert response.status_code == 401
    finally:
        if client_id is not None:
            cleanup_oauth_data(client_id)

def test_oauth_mcp_integration():
    asyncio.run(integration_flow())
