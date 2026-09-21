import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8000"))

MCP_PUBLIC_HOST = os.getenv("MCP_PUBLIC_HOST", "192.168.1.7")

MCP_ISSUER = os.getenv(
    "MCP_ISSUER",
    f"https://{MCP_PUBLIC_HOST}:{MCP_PORT}",
)

MCP_RESOURCE = os.getenv(
    "MCP_RESOURCE",
    f"{MCP_ISSUER}/mcp",
)

JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "EdDSA")

PUBLIC_KEY_PATH = Path(
    os.getenv(
        "MCP_PUBLIC_KEY_PATH",
        str(BASE_DIR / "secrets" / "jwt-ed25519-public.pem"),
    )
)

OAUTH_DB_PATH = Path(
    os.getenv(
        "OAUTH_DB_PATH",
        str(BASE_DIR / "data" / "oauth.db"),
    )
)

PRIVATE_KEY_PATH = Path(
    os.getenv(
        "MCP_PRIVATE_KEY_PATH",
        str(BASE_DIR / "secrets" / "jwt-ed25519-private.pem"),
    )
)

AUTHORIZATION_REQUEST_TTL_SECONDS = int(
    os.getenv("AUTHORIZATION_REQUEST_TTL_SECONDS", "300")
)

AUTHORIZATION_CODE_TTL_SECONDS = int(
    os.getenv("AUTHORIZATION_CODE_TTL_SECONDS", "300")
)

ACCESS_TOKEN_TTL_SECONDS = int(
    os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900")
)

REFRESH_TOKEN_TTL_SECONDS = int(
    os.getenv("REFRESH_TOKEN_TTL_SECONDS", "2592000")
)

TLS_CERT_PATH = Path(
    os.getenv(
        "MCP_TLS_CERT_PATH",
        str(BASE_DIR / "secrets" / "tls" / "mcp-server.crt"),
    )
)

TLS_KEY_PATH = Path(
    os.getenv(
        "MCP_TLS_KEY_PATH",
        str(BASE_DIR / "secrets" / "tls" / "mcp-server.key"),
    )
)

OAUTH_RATE_LIMIT = int(
    os.getenv("OAUTH_RATE_LIMIT", "10")
)

OAUTH_RATE_LIMIT_WINDOW_SECONDS = float(
    os.getenv("OAUTH_RATE_LIMIT_WINDOW_SECONDS", "60")
)
