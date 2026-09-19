from mcp.server import MCPServer
from mcp.server.auth.settings import (
    AuthSettings,
    ClientRegistrationOptions,
    RevocationOptions,
)

from core.security import ensure_non_root
from core.audit_extension import AuditExtension
from core.oauth_provider import SQLiteOAuthProvider
from core.oauth_routes import create_oauth_consent_route
from config import MCP_HOST, MCP_PORT, MCP_ISSUER, MCP_RESOURCE, TLS_CERT_PATH, TLS_KEY_PATH

import logging
import uvicorn

from tools import (
    kali_info,
    system_status,
    disk_status,
    memory_status,
    network_status,
    network_interfaces,
    read_text_file,
)

logging.basicConfig(
    filename="logs/audit.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

oauth_provider = SQLiteOAuthProvider()
consent_route, decision_route = create_oauth_consent_route(oauth_provider)

mcp = MCPServer(
    "KaliServer",
    auth_server_provider=oauth_provider,
    auth=AuthSettings(
        issuer_url=MCP_ISSUER,
        resource_server_url=MCP_RESOURCE,
        required_scopes=["mcp:read"],
        validate_token_resource=True,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["mcp:read"],
            default_scopes=["mcp:read"],
        ),
        revocation_options=RevocationOptions(
            enabled=True,
        ),
    ),
    extensions=[AuditExtension()],
)

ensure_non_root()

mcp.tool()(kali_info)
mcp.tool()(system_status)
mcp.tool()(disk_status)
mcp.tool()(memory_status)
mcp.tool()(network_status)
mcp.tool()(network_interfaces)
mcp.tool()(read_text_file)

mcp.custom_route(
    "/oauth/consent",
    methods=["GET"],
    name="oauth_consent",
)(consent_route)

mcp.custom_route(
    "/oauth/consent/decision",
    methods=["GET"],
    name="oauth_consent_decision",
)(decision_route)

if __name__ == "__main__":
    app = mcp.streamable_http_app(host=MCP_HOST)

    uvicorn.run(
        app,
        host=MCP_HOST,
        port=MCP_PORT,
        ssl_certfile=str(TLS_CERT_PATH),
        ssl_keyfile=str(TLS_KEY_PATH),
    )
