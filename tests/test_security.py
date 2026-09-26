import os
import pytest

from core.security import ensure_non_root


def test_ensure_non_root():
    if os.geteuid() == 0:
        with pytest.raises(PermissionError, match="MCP server tidak boleh dijalankan sebagai root"):
            ensure_non_root()
    else:
        ensure_non_root()

def test_ensure_non_root_rejects_root(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with pytest.raises(
        PermissionError,
        match="MCP server tidak boleh dijalankan sebagai root",
    ):
        ensure_non_root()
