def ensure_non_root() -> None:
    """Pastikan MCP server tidak berjalan sebagai root."""
    import os

    if os.geteuid() == 0:
        raise PermissionError(
            "MCP server tidak boleh dijalankan sebagai root."
        )
