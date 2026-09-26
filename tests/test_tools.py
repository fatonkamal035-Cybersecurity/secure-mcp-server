import asyncio

from server import mcp
from tools import (
    kali_info,
    system_status,
    disk_status,
    memory_status,
    network_status,
    network_interfaces,
)


EXPECTED_TOOL_NAMES = {
    "kali_info",
    "system_status",
    "disk_status",
    "memory_status",
    "network_status",
    "network_interfaces",
    "read_text_file",
}


def test_kali_info():
    result = kali_info()
    assert "Kali MCP Server aktif." in result


def test_system_status():
    result = system_status()
    assert "OS:" in result
    assert "Hostname:" in result
    assert "Python:" in result


def test_disk_status():
    result = disk_status()
    assert "Disk total:" in result
    assert "Disk terpakai:" in result
    assert "Disk bebas:" in result


def test_disk_status_uses_disk_usage_result(monkeypatch):
    from tools import system_tools

    monkeypatch.setattr(
        "shutil.disk_usage",
        lambda path: (10 * 1024**3, 4 * 1024**3, 6 * 1024**3),
    )

    result = system_tools.disk_status()

    assert "Disk total: 10.0 GB" in result
    assert "Disk terpakai: 4.0 GB" in result
    assert "Disk bebas: 6.0 GB" in result


def test_memory_status():
    result = memory_status()
    assert "RAM total:" in result
    assert "RAM terpakai:" in result
    assert "RAM tersedia:" in result


def test_memory_status_parses_meminfo(monkeypatch):
    from tools import system_tools

    meminfo = (
        "MemTotal:       2097152 kB\n"
        "MemAvailable:   1572864 kB\n"
    )

    def fake_open(*args, **kwargs):
        from io import StringIO
        return StringIO(meminfo)

    monkeypatch.setattr("builtins.open", fake_open)

    result = system_tools.memory_status()

    assert "RAM total: 2.0 GB" in result
    assert "RAM terpakai: 0.5 GB" in result
    assert "RAM tersedia: 1.5 GB" in result


def test_network_status():
    result = network_status()
    assert "Hostname:" in result
    assert "IP lokal:" in result


def test_network_status_handles_resolution_error(monkeypatch):
    from tools import system_tools

    monkeypatch.setattr(
        "socket.gethostname",
        lambda: "test-host",
    )

    def raise_resolution_error(hostname):
        import socket
        raise socket.gaierror("resolution failed")

    monkeypatch.setattr(
        "socket.gethostbyname",
        raise_resolution_error,
    )

    result = system_tools.network_status()

    assert result == "Hostname: test-host\nIP lokal: Tidak tersedia"


def test_network_interfaces_uses_fixed_command(monkeypatch):
    from tools import network_tools

    captured = {}

    class FakeResult:
        stdout = "1: lo    inet 127.0.0.1/8 scope host lo"

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return FakeResult()

    monkeypatch.setattr(network_tools.subprocess, "run", fake_run)

    result = network_tools.network_interfaces()

    assert result == "lo: 127.0.0.1/8"
    assert captured["command"] == ["ip", "-4", "-o", "addr", "show"]
    assert captured["kwargs"] == {
        "capture_output": True,
        "text": True,
        "check": True,
        "timeout": 5,
    }


def test_network_interfaces():
    result = network_interfaces()

    assert isinstance(result, str)
    assert result.strip()

    for line in result.splitlines():
        interface, address = line.split(": ", 1)
        assert interface
        assert address
        assert "/" in address


def test_mcp_registers_only_allowlisted_tools():
    tools = asyncio.run(mcp.list_tools())
    actual_tool_names = {tool.name for tool in tools}

    assert actual_tool_names == EXPECTED_TOOL_NAMES
