import asyncio
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization

from core.auth import JWTTokenVerifier
from config import MCP_ISSUER as ISSUER, MCP_RESOURCE as RESOURCE


PRIVATE_KEY_PATH = (
    Path(__file__).resolve().parent.parent
    / "secrets"
    / "jwt-ed25519-private.pem"
)


def make_token(**claims):
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None,
    )

    payload = {
        "sub": "termux",
        "client_id": "termux",
        "scope": "mcp:read",
        "iss": ISSUER,
        "aud": RESOURCE,
        "exp": int(time.time()) + 300,
    }
    payload.update(claims)

    return jwt.encode(
        payload,
        private_key,
        algorithm="EdDSA",
    )


def test_valid_token():
    token = make_token()

    result = asyncio.run(
        JWTTokenVerifier().verify_token(token)
    )

    assert result is not None
    assert result.client_id == "termux"
    assert "mcp:read" in result.scopes


def test_invalid_token():
    result = asyncio.run(
        JWTTokenVerifier().verify_token("token-salah")
    )

    assert result is None


def test_expired_token():
    token = make_token(exp=int(time.time()) - 1)

    result = asyncio.run(
        JWTTokenVerifier().verify_token(token)
    )

    assert result is None


def test_wrong_audience():
    token = make_token(aud="http://wrong-resource/mcp")

    result = asyncio.run(
        JWTTokenVerifier().verify_token(token)
    )

    assert result is None


def test_wrong_issuer():
    token = make_token(iss="wrong-issuer")

    result = asyncio.run(
        JWTTokenVerifier().verify_token(token)
    )

    assert result is None
