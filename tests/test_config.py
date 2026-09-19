import os
import subprocess
import sys


def run_config_with_env(extra_env=None):
    env = os.environ.copy()

    if extra_env:
        env.update(extra_env)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import config; "
                "print(config.MCP_HOST); "
                "print(config.MCP_PORT); "
                "print(config.MCP_ISSUER); "
                "print(config.MCP_RESOURCE); "
                "print(config.JWT_ALGORITHM)"
            ),
        ],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )

    return result.stdout.splitlines()


def test_config_defaults():
    values = run_config_with_env(
        {
            "MCP_HOST": "0.0.0.0",
            "MCP_PORT": "8000",
            "MCP_PUBLIC_HOST": "192.168.1.7",
            "MCP_ISSUER": "http://192.168.1.7:8000",
            "MCP_RESOURCE": "http://192.168.1.7:8000/mcp",
            "JWT_ALGORITHM": "EdDSA",
        }
    )

    assert values == [
        "0.0.0.0",
        "8000",
        "http://192.168.1.7:8000",
        "http://192.168.1.7:8000/mcp",
        "EdDSA",
    ]


def test_config_custom_host():
    values = run_config_with_env(
        {
            "MCP_HOST": "127.0.0.1",
            "MCP_PORT": "9000",
            "MCP_PUBLIC_HOST": "10.0.0.5",
            "MCP_ISSUER": "http://10.0.0.5:9000",
            "MCP_RESOURCE": "http://10.0.0.5:9000/mcp",
            "JWT_ALGORITHM": "EdDSA",
        }
    )

    assert values == [
        "127.0.0.1",
        "9000",
        "http://10.0.0.5:9000",
        "http://10.0.0.5:9000/mcp",
        "EdDSA",
    ]
